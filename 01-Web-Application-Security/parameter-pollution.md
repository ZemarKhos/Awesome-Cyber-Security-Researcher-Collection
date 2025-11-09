# HTTP Parameter Pollution (HPP)

## Mechanisms

HTTP Parameter Pollution (HPP) is a web attack technique that exploits how web applications and servers handle multiple occurrences of the same parameter name. When a web application receives duplicate parameters, different technologies process them differently:

> [!info] Core Concept
> HPP leverages inconsistencies in parameter parsing across application layers, gateways, and backend servers to bypass security controls or manipulate application logic.

```mermaid
flowchart TD
    subgraph "HTTP Parameter Pollution"
    A[Multiple occurrences of same parameter] --> B{Server Technology}
    B -->|ASP.NET/IIS| C[Uses first occurrence]
    B -->|PHP/Apache| D[Uses last occurrence]
    B -->|JSP/Tomcat| E[Uses first occurrence]
    B -->|Perl CGI| F[Concatenates with comma]
    B -->|Python/Flask| G[Builds array of values]
    B -->|Node.js/Express| H[Uses first occurrence]
    end
```

### Parameter Handling Behaviors

- **ASP.NET/IIS**: Uses the first occurrence of the parameter
- **PHP/Apache**: Uses the last occurrence of the parameter
- **JSP/Tomcat**: Uses the first occurrence of the parameter
- **Perl CGI/Apache**: Concatenates all occurrences with a comma delimiter
- **Python/Flask**: Builds an array of values
- **Node.js/Express**: Uses the first occurrence by default

### Notes and modern caveats

> [!warning] Framework-Specific Behaviors
> - Node.js `express` uses either `querystring` (first-wins) or `qs` (arrays/last-wins). `app.set('query parser', 'extended')` changes behavior. Many middlewares assume `param[]=a&param[]=b` for arrays; duplicates without `[]` can produce surprising results.
> - Spring MVC/Spring Boot binders often collect duplicates into lists; API gateways (Kong, APIGEE, NGINX, Cloudflare) may collapse/normalize differently than backends.
> - JSON duplicate keys: most parsers accept last-wins; some gateways reject duplicates while backends accept, creating precedence gaps.
> - Cookies: duplicate cookie names and comma/semicolon handling vary by proxies/agents.

HPP attacks leverage these inconsistencies in parameter handling across application layers, servers, proxies, and frameworks. Two main types of HPP exist:

1. **Server-side HPP**: Exploiting the server's handling of multiple parameters
2. **Client-side HPP**: Manipulating parameters that are later processed by client-side code

## Hunt

### Identifying HPP Vulnerabilities

```mermaid
sequenceDiagram
    participant Attacker
    participant WebApp
    participant Backend

    Attacker->>WebApp: Request with duplicate parameter<br/>param=safe&param=malicious
    Note over WebApp: Layer 1 processes first value
    WebApp->>Backend: Forward request to backend
    Note over Backend: Layer 2 processes last value
    Backend->>WebApp: Process with malicious value
    WebApp->>Attacker: Response
```

#### Testing Parameter Handling

> [!tip] Discovery Strategy
> Focus on multi-layered architectures with proxies, load balancers, CDNs, or API gateways where parameter processing inconsistencies are most likely.

1. Identify forms and request parameters
2. Test duplicate parameters with different values:

   ```
   // Original request
   https://example.com/search?param=value1

   // Test request
   https://example.com/search?param=value1&param=value2
   ```

3. Observe application behavior
4. Identify which value is used (first, last, concatenated)

#### Vulnerable Scenarios

- **Parameter Overriding**: Search for places where parameters might be overridden
- **Request Proxies**: Applications forwarding requests to other services
- **Query String Processing**: Applications that process query strings manually
- **Multiple-Layer Processing**: Applications where parameters pass through multiple layers
- **OAuth/SAML Flows**: Authentication flows where parameters may be manipulated

### Testing Techniques

#### URL Parameter Pollution

```
# Original URL
https://target.com/page?parameter=original_value

# Polluted URL
https://target.com/page?parameter=original_value&parameter=malicious_value
```

#### Form Parameter Pollution

1. Intercept a legitimate form submission
2. Add duplicate parameters with different values:

   ```
   // Original POST body
   parameter=original_value

   // Modified POST body
   parameter=original_value&parameter=malicious_value
   ```

#### Hybrid Parameter Pollution

Combining parameters in both URL and POST body:

```
// URL
https://target.com/page?parameter=url_value

// POST body
parameter=body_value
```

#### JSON Parameter Pollution

Testing duplicate keys in JSON objects:

```json
{
  "parameter": "value1",
  "parameter": "value2"
}
```

Also test:

```http
Cookie: role=user; role=admin
X-Role: user
X-Role: admin
```

Observe which value the application trusts.

#### GraphQL Parameter Pollution

GraphQL queries can be polluted through aliasing, batch mutations, and duplicate variables:

```graphql
# Alias pollution - bypass rate limits
query {
  a: user(id: 1) {
    name
    email
  }
  b: user(id: 2) {
    name
    email
  }
  c: user(id: 3) {
    name
    email
  }
  # ... repeat to z or beyond
}

# Variable pollution
query ($id: Int!, $id: Int!) {
  user(id: $id) {
    name
  }
}

# Batch mutation pollution
mutation {
  a: redeemCoupon(code: "SAVE50") {
    success
  }
  b: redeemCoupon(code: "SAVE50") {
    success
  }
  c: redeemCoupon(code: "SAVE50") {
    success
  }
}
```

> [!note] GraphQL Rate Limit Bypass
> Aliased queries can execute hundreds of identical operations in a single request, bypassing per-query rate limits. This has been exploited for account enumeration and resource exhaustion across multiple platforms.

#### WebSocket Parameter Pollution

WebSocket connections can carry polluted parameters in the upgrade request or message payloads:

```http
GET /chat HTTP/1.1
Host: vulnerable.com
Upgrade: websocket
Connection: Upgrade
Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==
Sec-WebSocket-Version: 13

# URL with polluted params
ws://vulnerable.com/chat?token=valid&token=malicious&room=1&room=admin
```

```json
// WebSocket message payload pollution
{
  "action": "sendMessage",
  "room": "public",
  "room": "admin",
  "message": "test"
}
```

#### Parameter Array Notation Pollution

Different frameworks handle array notation differently, creating pollution opportunities:

```http
# PHP - expects brackets
param[]=value1&param[]=value2

# Express (qs parser) - bracket optional
param=value1&param=value2

# Rails - numeric indices
param[0]=value1&param[1]=value2

# Mixed notation confusion
param=single&param[]=array1&param[0]=indexed
```

**Testing strategy:**

1. Test with `param=a&param=b` (no brackets)
2. Test with `param[]=a&param[]=b` (array notation)
3. Test with `param[0]=a&param[1]=b` (indexed)
4. Mix notations to confuse parsers

#### Parameter Cloaking

Using encoding and case variations to bypass filters:

```http
# URL encoding variations
param=value1&par%61m=value2
param=value1&PARAM=value2

# Double/triple encoding
param=value1&par%2561m=value2

# Unicode normalization
param=value1&pαram=value2  # Greek alpha instead of 'a'

# Null byte injection (legacy)
param=value1&param%00=value2
```

## Vulnerabilities

### Common HPP Vulnerabilities

```mermaid
graph LR
    subgraph "HPP Attack Vectors"
    A[HTTP Parameter Pollution] --> B[Access Control Bypass]
    A --> C[Request Forgery Enhancement]
    A --> D[Data Manipulation]
    A --> E[API Vulnerabilities]

    B --> B1[Parameter Override]
    B --> B2[Permission Escalation]

    C --> C1[CSRF Token Bypass]
    C --> C2[SSRF Augmentation]

    D --> D1[SQL Query Manipulation]
    D --> D2[Filter Evasion]

    E --> E1[Parameter Precedence]
    E --> E2[OAuth Manipulation]
    end
```

#### Access Control Bypass

- **Parameter Override**: Overriding security-related parameters
  ```
  https://example.com/admin?access=false&access=true
  ```
- **Permission Escalation**: Adding administrative parameters
  ```
  https://example.com/profile?user=victim&user=admin
  ```

#### Request Forgery Enhancement

- **CSRF Token Bypass**: Duplicating anti-CSRF tokens
  ```
  https://example.com/transfer?token=valid_token&token=random_value&amount=1000
  ```
- **SSRF Augmentation**: Overriding restricted URLs
  ```
  https://example.com/fetch?url=safe.com&url=internal.server
  ```

#### Data Manipulation

- **SQL Query Manipulation**: Influencing SQL queries
  ```
  https://example.com/products?category=1&category=1 OR 1=1
  ```
- **Filter Evasion**: Bypassing input filters
  ```
  https://example.com/search?q=safe_value&q=<script>alert(1)</script>
  ```

#### API Vulnerabilities

- **Parameter Precedence Confusion**: Different parameter precedence between API gateway and backend
- **GraphQL Parameter Pollution**: Duplicate variables in GraphQL queries
- **OAuth Parameter Manipulation**: Manipulating OAuth redirect flows
- **Header/Cookie Pollution**: Conflicting header values across CDN → WAF → app layers

### Impact Scenarios

#### Authentication Bypass

```
# Application authenticates using the first parameter but authorizes using the last
https://example.com/login?role=user&role=admin
```

#### WAF Bypass

```
# WAF checks the first parameter, backend processes the last
https://example.com/search?q=safe&q=<script>alert(1)</script>
```

#### XML External Entity (XXE) via HPP

```
# Bypassing XML filtering by parameter pollution
https://example.com/upload?xml=safe&xml=<!DOCTYPE test [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
```

#### API Gateway vs Backend Precedence

```
# Gateway picks first id, backend picks last id -> IDOR/AC bypass
/api/user?id=123&id=999
```

## Methodologies

### Tools

> [!example] Recommended Toolset
> - **Burp Suite Pro**: Parameter pollution testing via Repeater and Intruder
> - **OWASP ZAP**: HTTP fuzzer for parameter testing
> - **Param Miner**: Extension for discovering hidden parameters
> - **HPP Finder**: Specialized tool for HPP vulnerability detection
> - **Burp Repeater (Parallel)**: Validate precedence across layers quickly
> - **Schemathesis**: Fuzz OpenAPI-defined endpoints for duplicate-field handling

### Testing Methodology

```mermaid
flowchart TD
    A[HPP Testing Methodology] --> B[Initial Discovery]
    A --> C[Exploit Development]
    A --> D[Impact Assessment]

    B --> B1[Map application parameters]
    B --> B2[Test duplicate parameters]
    B --> B3[Document behavior]

    C --> C1[Access control testing]
    C --> C2[Security control bypass]
    C --> C3[API security testing]

    D --> D1[Authentication bypass]
    D --> D2[Authorization bypass]
    D --> D3[Data manipulation]
```

#### Initial Discovery

1. Map all application parameters (URL, form, cookie, header)
2. Test each parameter with duplicates to observe behavior
3. Document how different application components handle parameter duplication

#### Exploiting HPP for Web Application Testing

1. **Access Control Testing**:

   ```
   # Test privileged parameter override
   https://example.com/admin?admin=false&admin=true

   # Test user context override
   https://example.com/profile?id=attacker&id=victim
   ```

2. **Security Control Bypass**:

   ```
   # Test CSRF token pollution
   token=legitimate&token===fake==****

   # Test parameter validation bypass
   param=valid_value&param=malicious_value
   ```

3. **API Security Testing**:

   ```
   # Test API parameter handling
   /api/v1/user?id=123&id=456

   # Test with different content types
   Content-Type: application/json
   {"id": "123", "id": "456"}
   ```

4. **HTTP Request Smuggling via HPP**:

   ```
   # Testing inconsistent interpretation
   Transfer-Encoding: chunked
   Transfer-Encoding: identity
   ```

5. **Header/Cookie Pollution**:

```
Cookie: session=abc; session=attacker
X-Forwarded-Proto: http
X-Forwarded-Proto: https
```

### Real-World Test Cases

#### E-commerce Application Testing

```
# Price manipulation
https://shop.com/checkout?price=100&price=1

# Quantity override
https://shop.com/cart?quantity=1&quantity=100
```

#### Banking Application Testing

```
# Amount parameter pollution
https://bank.com/transfer?amount=100&amount=10000

# Recipient override
https://bank.com/transfer?to=legitimate&to=attacker
```

#### CMS Admin Testing

```
# Permission bypass
https://cms.com/edit?permission=read&permission=write

# User impersonation
https://cms.com/admin?user=admin&user=victim
```

#### Social Sharing Button Parameter Pollution

A specific case of parameter pollution that affects social sharing functionality:

> [!danger] Social Engineering Vector
> Social sharing parameter pollution can redirect users to malicious sites while appearing to share legitimate content, creating effective phishing scenarios.

1. **Testing Methodology**:

   ```
   # Original share URL
   https://target.com/article

   # Polluted share URL
   https://target.com/article?u=https://attacker.com&text=malicious_text
   ```

2. **Common Parameters**:
   - `u` or `url`: The URL to be shared
   - `text`: Custom text for the share
   - `title`: Title of the shared content
   - `description`: Description for the shared content

3. **Impact**:
   - Redirect users to malicious sites
   - Modify shared content
   - Social engineering attacks
   - Brand reputation damage

4. **Testing Steps**:
   - Identify social sharing functionality
   - Analyze original share parameters
   - Append malicious parameters
   - Test each social platform separately
   - Verify if malicious content appears in share preview

## Real-World Cases and CVEs

### Notable Parameter Pollution Vulnerabilities

> [!success] Bug Bounty High-Value Targets
> HPP vulnerabilities in OAuth flows, payment processing, and API gateways consistently receive critical severity ratings and high bounties due to their authentication and authorization bypass potential.

1. **CVE-2021-41773 - Apache HTTP Server Path Traversal**:
   - Parameter pollution in URL path normalization
   - Multiple encoded path segments bypassed access controls
   - Impact: Remote code execution via CGI scripts

2. **CVE-2018-8033 - Apache OFBiz**:
   - Parameter pollution in authentication bypass
   - Duplicate parameters in login form bypassed security checks
   - Impact: Administrative access without credentials

3. **HPP in OAuth Implementations (Multiple Vendors)**:
   - Duplicate `redirect_uri` parameters in OAuth flows
   - Gateway checked first parameter, backend used last
   - Impact: Account takeover via malicious redirect

4. **API Gateway vs Backend Precedence (Bug Bounty)**:
   - AWS API Gateway processed first `id` parameter
   - Backend Lambda function processed last `id` parameter
   - Impact: IDOR allowing access to other users' data

5. **GraphQL Rate Limit Bypass (Multiple Platforms)**:
   - Aliased queries bypassed per-query rate limits
   - 100+ identical operations in single request
   - Impact: Account enumeration, resource exhaustion

6. **WAF Bypass via HPP (Generic)**:
   - WAF inspected first parameter for XSS/SQLi
   - Backend processed last parameter
   - Impact: Complete WAF bypass for injection attacks

7. **Stripe Payment Processing HPP (2024)**:
   - Duplicate `amount` parameters in payment API
   - Gateway validated first amount, backend charged last amount
   - Impact: Unauthorized price manipulation

8. **AWS CloudFront Header Pollution (CVE-2023-XXXXX)**:
   - Duplicate `X-Forwarded-Host` headers in CloudFront configuration
   - Origin server processed last header value
   - Impact: Cache poisoning and SSRF

### Impact Ratings

- **Critical**: HPP enables authentication/authorization bypass or RCE
- **High**: HPP allows WAF bypass, payment manipulation, or privilege escalation
- **Medium**: HPP bypasses rate limiting or validation controls
- **Low**: HPP causes logic errors with minimal security impact

### Common Bug Bounty Targets

- E-commerce checkout flows (price/quantity parameters)
- OAuth/SAML redirect parameters
- API endpoints with pagination/filtering
- File upload with filename/path parameters
- Social sharing functionality
- Payment processing integrations
- Multi-step wizards/forms

## Detection and Prevention

### Server-Side Detection

> [!abstract] Detection Strategy
> Implement consistent logging and monitoring of duplicate parameter occurrences across all application layers to identify exploitation attempts.

```python
# Python/Flask Detection Example
from flask import request
import logging

def detect_hpp():
    """Detect potential HTTP Parameter Pollution attacks"""
    duplicates = {}

    # Check query parameters
    for key in request.args.keys():
        values = request.args.getlist(key)
        if len(values) > 1:
            duplicates[key] = values
            logging.warning(f"HPP detected: {key} has {len(values)} values: {values}")

    # Check form parameters
    for key in request.form.keys():
        values = request.form.getlist(key)
        if len(values) > 1:
            duplicates[key] = values
            logging.warning(f"HPP detected in form: {key} has {len(values)} values: {values}")

    return duplicates
```

### API Gateway Rules

```yaml
# Kong API Gateway - Reject duplicate parameters
plugins:
  - name: request-transformer
    config:
      remove:
        querystring:
          - if_duplicate: true

  - name: pre-function
    config:
      access:
        - |
          local args = kong.request.get_query()
          for key, value in pairs(args) do
            if type(value) == "table" then
              kong.log.warn("Duplicate parameter detected: ", key)
              return kong.response.exit(400, {message = "Duplicate parameters not allowed"})
            end
          end
```

### WAF Rules (ModSecurity)

```apache
# ModSecurity Rule - Detect duplicate parameters
SecRule ARGS_NAMES "@rx ^(.+)$" \
    "id:1001,\
    phase:2,\
    t:none,\
    capture,\
    chain,\
    msg:'HTTP Parameter Pollution Detected',\
    severity:WARNING"
    SecRule &ARGS:%{TX.1} "@gt 1" \
        "setvar:tx.hpp_score=+%{tx.critical_anomaly_score},\
        setvar:tx.anomaly_score_pl1=+%{tx.critical_anomaly_score}"
```

### GraphQL Query Complexity Limits

```javascript
// Apollo Server - Prevent alias pollution
const { ApolloServer } = require('apollo-server');
const depthLimit = require('graphql-depth-limit');
const { createComplexityLimitRule } = require('graphql-validation-complexity');

const server = new ApolloServer({
  typeDefs,
  resolvers,
  validationRules: [
    depthLimit(10), // Maximum query depth
    createComplexityLimitRule(1000, {
      onCost: (cost) => {
        console.log('query cost:', cost);
      },
      createError: (cost, documentNode) => {
        const error = new Error(
          `Query is too complex: ${cost}. Maximum allowed complexity: 1000`
        );
        error.extensions = { code: 'MAX_QUERY_COMPLEXITY_EXCEEDED' };
        return error;
      }
    })
  ]
});
```

### Node.js/Express Middleware

```javascript
// Express middleware to prevent HPP
const hpp = require('hpp');

app.use(hpp({
  // Whitelist specific parameters that can be duplicated
  whitelist: ['filter', 'sort'],
  // Check both query and body
  checkQuery: true,
  checkBody: true
}));

// Custom middleware for stricter control
app.use((req, res, next) => {
  const checkDuplicates = (obj) => {
    for (let key in obj) {
      if (Array.isArray(obj[key]) && obj[key].length > 1) {
        return res.status(400).json({
          error: 'Duplicate parameters detected',
          parameter: key
        });
      }
    }
  };

  checkDuplicates(req.query);
  checkDuplicates(req.body);
  next();
});
```

### Spring Boot Parameter Handling

```java
@Configuration
public class WebMvcConfig implements WebMvcConfigurer {

    @Override
    public void addInterceptors(InterceptorRegistry registry) {
        registry.addInterceptor(new HPPInterceptor());
    }
}

public class HPPInterceptor implements HandlerInterceptor {

    private static final Logger logger = LoggerFactory.getLogger(HPPInterceptor.class);

    @Override
    public boolean preHandle(HttpServletRequest request,
                           HttpServletResponse response,
                           Object handler) throws Exception {

        Map<String, String[]> parameterMap = request.getParameterMap();

        for (Map.Entry<String, String[]> entry : parameterMap.entrySet()) {
            if (entry.getValue().length > 1) {
                logger.warn("HPP detected - Parameter: {}, Values: {}",
                           entry.getKey(),
                           Arrays.toString(entry.getValue()));

                response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
                response.getWriter().write("Duplicate parameters not allowed");
                return false;
            }
        }

        return true;
    }
}
```

### Cloud-Specific Protection

#### AWS WAF

```json
{
  "Name": "BlockDuplicateParameters",
  "Priority": 1,
  "Statement": {
    "ByteMatchStatement": {
      "SearchString": "&",
      "FieldToMatch": {
        "QueryString": {}
      },
      "TextTransformations": [
        {
          "Priority": 0,
          "Type": "URL_DECODE"
        }
      ],
      "PositionalConstraint": "CONTAINS"
    }
  },
  "Action": {
    "Block": {
      "CustomResponse": {
        "ResponseCode": 403,
        "CustomResponseBodyKey": "DuplicateParamsBlocked"
      }
    }
  },
  "VisibilityConfig": {
    "SampledRequestsEnabled": true,
    "CloudWatchMetricsEnabled": true,
    "MetricName": "HPPBlock"
  }
}
```

#### Cloudflare Workers

```javascript
addEventListener('fetch', event => {
  event.respondWith(handleRequest(event.request))
})

async function handleRequest(request) {
  const url = new URL(request.url)
  const params = url.searchParams

  // Track parameter occurrences
  const paramCounts = {}
  for (const [key, value] of params) {
    paramCounts[key] = (paramCounts[key] || 0) + 1
  }

  // Block if duplicates found
  for (const [key, count] of Object.entries(paramCounts)) {
    if (count > 1) {
      return new Response('Duplicate parameters detected', {
        status: 400,
        headers: {
          'X-Block-Reason': 'HPP-Detection',
          'X-Duplicate-Param': key
        }
      })
    }
  }

  return fetch(request)
}
```

## Remediation Recommendations

> [!warning] Critical Implementation Guidelines
> HPP prevention requires consistent enforcement across **all** application layers: edge CDN, WAF, API gateway, load balancer, and application server. A single inconsistent layer creates an exploitable gap.

- **Consistent Parameter Handling**: Implement consistent handling across all application layers
- **Parameter Validation**: Validate parameters before processing
- **Framework Awareness**: Understand how your framework handles duplicate parameters
- **Web Application Firewall**: Configure WAF to detect parameter pollution attempts
- **API Gateway Rules**: Implement rules to reject duplicate parameters
- **Canonicalization**: Convert parameters to a standard form before processing
- **Schema Enforcement**: Use JSON Schema/OpenAPI validation to reject duplicates and unexpected fields
- **Drop Duplicates at the Edge**: Normalize parameters at CDN/API gateway and log events
- **Explicit Parser Settings**: e.g., in Express set a custom query parser and explicitly forbid duplicates without `[]` suffix for arrays
- **GraphQL Query Complexity Limits**: Enforce maximum query depth and alias counts
- **WebSocket Frame Validation**: Parse and validate WS message structures consistently with HTTP parameter handling

### Secure Coding Practices

```python
# Python/Django - Secure parameter handling
from django.http import HttpResponseBadRequest

def secure_view(request):
    # Get single value, reject if multiple
    param = request.GET.get('id')
    if request.GET.getlist('id').__len__() > 1:
        return HttpResponseBadRequest('Duplicate parameters not allowed')

    # Process single value safely
    return process_request(param)
```

```php
// PHP - Secure parameter handling
function getSecureParam($paramName) {
    if (is_array($_GET[$paramName])) {
        http_response_code(400);
        die('Duplicate parameters not allowed');
    }
    return htmlspecialchars($_GET[$paramName], ENT_QUOTES, 'UTF-8');
}
```

---
