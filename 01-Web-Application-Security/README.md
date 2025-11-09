# Web Application Security

Detailed notes on web application vulnerabilities, attack vectors, and defense mechanisms.

## 📋 Content

### Injection Attacks

- **[SQL Injection](./sql-injection.md)**: Code injection in database queries
- **[Cross-Site Scripting (XSS)](./xss.md)**: Client-side script injection
- **[Server-Side Template Injection (SSTI)](./ssti.md)**: Code execution through template engines
- **[XML External Entity (XXE)](./xxe.md)**: XML parser vulnerabilities

### Access Control Issues

- **[Insecure Direct Object References (IDOR)](./idor.md)**: Authorization vulnerabilities
- **[Insecure Deserialization](./insecure-deserialization.md)**: Object serialization vulnerabilities

### Server-Side Attacks

- **[Server-Side Request Forgery (SSRF)](./ssrf.md)**: Server-side request manipulation
- **[Request Smuggling](./req-smuggle.md)**: HTTP request smuggling

### Authentication & Authorization

- **[JWT Security](./jwt.md)**: JSON Web Token vulnerabilities
- **[OAuth Security](./oauth.md)**: OAuth protocol vulnerabilities

### API Security

- **[GraphQL Security](./graphql.md)**: GraphQL vulnerabilities and attacks
- **[Parameter Pollution](./parameter-pollution.md)**: HTTP parameter pollution

### Advanced Attacks

- **[Race Condition](./race-condition.md)**: Time-of-check to time-of-use vulnerabilities
- **[Open Redirect](./open-redirect.md)**: URL redirection vulnerabilities
- **[WAF Bypass](./waf-bypass.md)**: Web Application Firewall bypass techniques

## 🎯 Learning Path

### Foundation (1-2 months)
1. **HTTP Protocol**: Request/response structure, headers, methods
2. **Web Technologies**: HTML, JavaScript, JSON, XML
3. **Browser DevTools**: Network tab, console, debugging
4. **Basic Concepts**: Client vs server, cookies, sessions

### Beginner (2-4 months)
1. **Injection Basics**: SQL Injection, XSS fundamentals
2. **Access Control**: IDOR, path traversal
3. **Authentication**: Session management, JWT basics
4. **OWASP Top 10**: Understanding common vulnerabilities

### Intermediate (4-8 months)
1. **Advanced XSS**: DOM-based, mutation, CSP bypass
2. **Advanced SQLi**: Boolean blind, time-based, stacked queries
3. **SSRF**: Exploitation, cloud metadata abuse
4. **Deserialization**: Language-specific attacks
5. **API Security**: GraphQL, REST API testing

### Advanced (8+ months)
1. **Race Conditions**: TOCTOU, limit bypass
2. **Request Smuggling**: HTTP/2, smuggling attacks
3. **XXE**: Out-of-band, SSRF via XXE
4. **WAF Bypass**: Encoding, obfuscation, rule evasion
5. **Chain Exploits**: Combining multiple vulnerabilities

## 🛠️ Essential Tools

### Proxy & Interception
- **Burp Suite**: Industry-standard web proxy
- **OWASP ZAP**: Open-source alternative
- **mitmproxy**: Python-based proxy
- **Caido**: Modern web security toolkit

### Scanners
- **Nuclei**: Template-based scanner
- **ffuf**: Fast web fuzzer
- **httpx**: HTTP toolkit
- **SQLMap**: Automated SQL injection tool

### Browser Extensions
- **Wappalyzer**: Technology detector
- **FoxyProxy**: Proxy manager
- **Cookie Editor**: Cookie manipulation
- **JWT Decoder**: JWT analysis

### Utilities
- **curl / httpie**: CLI HTTP clients
- **jq**: JSON processor
- **xmllint**: XML processor
- **base64 / urlencode**: Encoding utilities

## 📚 Resources

### Practice Platforms
- [PortSwigger Web Security Academy](https://portswigger.net/web-security) - Free labs
- [HackTheBox](https://www.hackthebox.com/) - Hands-on challenges
- [TryHackMe](https://tryhackme.com/) - Guided paths
- [PentesterLab](https://pentesterlab.com/) - Focused exercises

### Documentation
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- [HackerOne Hacktivity](https://hackerone.com/hacktivity)
- [PortSwigger Research](https://portswigger.net/research)

### Bug Bounty Platforms
- [HackerOne](https://hackerone.com/)
- [Bugcrowd](https://www.bugcrowd.com/)
- [Intigriti](https://www.intigriti.com/)
- [YesWeHack](https://yeswehack.com/)

### Books
- "The Web Application Hacker's Handbook" - Dafydd Stuttard & Marcus Pinto
- "Real-World Bug Hunting" - Peter Yaworski
- "Bug Bounty Bootcamp" - Vickie Li
- "Web Security Testing Cookbook" - Paco Hope & Ben Walther

## 🎓 Certification Paths

- **eWPT** (eLearnSecurity Web Application Penetration Tester)
- **OSWA** (Offensive Security Web Assessor)
- **BSCP** (Burp Suite Certified Practitioner)
- **GWAPT** (GIAC Web Application Penetration Tester)

## 🏆 Practice Strategy

### Daily Practice (30-60 min)
1. Solve 1-2 PortSwigger labs
2. Review 1 HackerOne disclosed report
3. Practice with different tools

### Weekly Goals
1. Complete a specific vulnerability category
2. Write up 2-3 detailed notes
3. Attempt 1-2 CTF challenges

### Monthly Milestones
1. Master one OWASP Top 10 category
2. Find bugs in bug bounty programs
3. Build a personal methodology

## ⚠️ Legal and Ethical Guidelines

- **Always obtain written permission** before testing
- **Only test authorized systems** (your own, bug bounty programs, CTF platforms)
- **Follow responsible disclosure** for found vulnerabilities
- **Respect scope and rules** of engagement
- **Never access, modify, or delete** data without permission

---

**Last Updated**: 2025-01
**Difficulty**: 🟢 Beginner - 🟡 Intermediate
**Prerequisites**: Basic web knowledge, HTTP protocol understanding
