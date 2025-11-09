# 🔴 Offensive Security

Modern offensive security techniques, red teaming methodologies, and attack frameworks.

## 📋 Contents

### [01 - Initial Access Techniques](./01-initial-access-techniques.md)
Comprehensive guide to modern initial access vectors and techniques:
- **Email & Phishing**: Modern phishing techniques, email security bypasses
- **OAuth Attacks**: Token theft, consent phishing, device code flows
- **Cloud Misconfigurations**: Azure, AWS, GCP exploitation
- **Command & Control**: C2 setup, infrastructure, redirectors
- **EDR Evasion**: Memory-based execution, process injection, hook bypasses
- **Payload Delivery**: Hosting strategies, infection vectors, delivery chains
- **VBA/Macro Techniques**: Office document weaponization
- **MSI Exploitation**: Windows Installer abuse
- **Emerging Vectors**: AI/LLM attacks, supply chain, mobile, IoT

**Level**: Intermediate to Advanced
**Updated**: 2025
**Prerequisites**: Basic understanding of Windows internals, networking

---

### [02 - EDR Bypass Techniques](./02-edr-bypass-techniques.md)
Deep dive into Endpoint Detection and Response evasion:
- **AV vs EDR**: Fundamental differences and detection methods
- **Windows Execution Flow**: User-mode to kernel-mode transitions
- **Hook Evasion**: Inline hooks, IAT/EAT hooks, bypass techniques
- **ETW Silencing**: Event Tracing for Windows manipulation
- **Memory-Based Evasion**: Direct syscalls, unhooking, Heaven's Gate
- **Process Manipulation**: Hollowing, doppelgänging, herpaderping
- **Network-Based Silencing**: Driver exploitation, ETW provider manipulation
- **Modern EDR Bypass**: Defender, CrowdStrike, SentinelOne, Carbon Black
- **Blue Team Detection**: How to detect these bypass attempts

**Level**: Advanced
**Updated**: 2025
**Prerequisites**: Windows internals, assembly, debugging skills

---

## 🎯 Learning Path

### Beginner Path
1. Start with basic Windows internals concepts
2. Understand PE file format and execution flow
3. Learn basic AV bypass techniques
4. Practice with simple payload delivery

### Intermediate Path
1. Study EDR architecture and detection methods
2. Master process injection techniques
3. Learn memory-based evasion
4. Understand ETW and its role in detection

### Advanced Path
1. Deep dive into kernel-mode interactions
2. Study modern EDR bypass techniques
3. Master direct syscall implementations
4. Develop custom evasion techniques

## 🛠️ Recommended Tools

### Analysis & Debugging
- **IDA Pro / Ghidra**: Reverse engineering
- **x64dbg / WinDbg**: Dynamic analysis
- **Process Hacker**: Process monitoring
- **API Monitor**: API call tracing

### Development
- **Visual Studio**: C/C++ development
- **Donut**: Shellcode generation
- **Invoke-Obfuscation**: PowerShell obfuscation
- **ScareCrow**: Payload creation framework

### Testing
- **Seatbelt**: Situational awareness
- **SharpHound**: AD enumeration
- **Rubeus**: Kerberos abuse
- **Mimikatz**: Credential extraction

## 📚 Additional Resources

### Books
- "Red Team Development and Operations" by Joe Vest
- "Operator Handbook: Red Team + OSINT + Blue Team Reference"
- "Adversarial Tradecraft in Cybersecurity"

### Online Resources
- [MITRE ATT&CK](https://attack.mitre.org/)
- [LOLBAS Project](https://lolbas-project.github.io/)
- [Red Canary Threat Detection Report](https://redcanary.com/threat-detection-report/)
- [SpecterOps Blog](https://posts.specterops.io/)

### Training
- RTO (Red Team Operations) by Zero-Point Security
- CRTO (Certified Red Team Operator) by Sektor7
- OSEP (Offensive Security Experienced Penetration Tester)

## ⚠️ Legal Notice

All techniques documented here are for **authorized security testing only**. Unauthorized access to computer systems is illegal. Always ensure you have explicit written permission before conducting any security testing.

## 🔄 Update Log

- **2025-01**: Enhanced EDR bypass techniques with modern detections
- **2025-01**: Added emerging attack vectors (AI/LLM, supply chain)
- **2025-01**: Updated with Windows 11 24H2 specific techniques
- **2024-12**: Initial offensive security section created

---

**Difficulty Ratings**:
- 🟢 Beginner: Basic understanding required
- 🟡 Intermediate: Solid foundation needed
- 🔴 Advanced: Expert-level knowledge required
- ⚫ Expert: Cutting-edge research level
