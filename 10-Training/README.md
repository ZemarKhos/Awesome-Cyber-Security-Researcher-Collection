# 🎓 Training & Learning Resources

Structured learning paths for fuzzing, crash analysis, and exploit development with hands-on exercises and real-world labs.

## 📋 Contents

### [Fuzzing & Crash Analysis Course](./fuzzing-crash-analysis-course.md)
Complete 2-week intensive training program:

---

## 📖 Course Overview

### **Week 1: Foundations and Fuzzing Basics**
Comprehensive introduction to fuzzing methodologies and tools.

#### Day 1: Introduction to Fuzzing
- **Topics**: Fuzzing fundamentals, mutation strategies
- **Tools**: AFL++ setup and basic usage
- **Exercise**: Fuzz a simple C program, analyze crashes
- **Outcome**: Working AFL++ environment, first crashes found

#### Day 2: Advanced AFL++ Techniques
- **Topics**: Dictionary fuzzing, persistent mode, QEMU mode
- **Tools**: AFL++ advanced options
- **Exercise**: Fuzz dlib/imglab with ASan/UBSan
- **Outcome**: Parallel fuzzing setup, crash collection

#### Day 3: In-Process Fuzzing
- **Topics**: Coverage-guided fuzzing, libFuzzer integration
- **Tools**: Google FuzzTest
- **Exercise**: Write custom fuzz targets
- **Outcome**: FuzzTest project with CI/CD integration

#### Day 4: Alternative Fuzzing Engines
- **Topics**: Hardware feedback, persistent mode
- **Tools**: HonggFuzz
- **Exercise**: Fuzz OpenSSL with memory sanitizers
- **Outcome**: HonggFuzz corpus, server/privkey bugs

#### Day 5: Kernel Fuzzing
- **Topics**: Syscall fuzzing, coverage collection
- **Tools**: Syzkaller
- **Exercise**: Set up QEMU VM, fuzz Linux kernel
- **Outcome**: Syzkaller environment, kernel crash triaging

#### Day 6: Crash Triage and Analysis
- **Topics**: Deduplication, exploitability assessment
- **Tools**: GDB, exploitable plugin, CASR, afl-collect
- **Exercise**: Analyze and classify crashes from Week 1
- **Outcome**: Prioritized bug list with severity ratings

#### Day 7: Review and Recap
- **Topics**: Week 1 consolidation, knowledge check
- **Exercise**: Self-assessment quiz, CTF challenges
- **Outcome**: Solid fuzzing foundation

---

### **Week 2: Advanced Crash Analysis**
Deep dive into memory corruption analysis and exploit primitive development.

#### Day 8: Memory Corruption Fundamentals
- **Topics**: Stack/heap/UAF internals
- **Tools**: ASan reports, Valgrind
- **Exercise**: Analyze real CVE crashes (stack overflow)
- **Outcome**: Memory corruption classification skills

#### Day 9: Exploitability Assessment
- **Topics**: Primitive identification (r/w, leak, hijack)
- **Tools**: GDB scripting, pwntools
- **Exercise**: Convert crashes to primitives
- **Outcome**: Exploit feasibility reports

#### Day 10: Root Cause Analysis
- **Topics**: Static/dynamic taint analysis
- **Tools**: Source code auditing, reversing with Ghidra
- **Exercise**: Perform RCA on 3 different bug classes
- **Outcome**: Detailed RCA documents

#### Day 11: Heap Exploitation Basics
- **Topics**: glibc/Windows heap internals
- **Tools**: how2heap, HeapLAB
- **Exercise**: Tcache poisoning, fastbin attack
- **Outcome**: Working heap exploitation PoCs

#### Day 12: UAF Analysis
- **Topics**: Heap feng shui, type confusion
- **Tools**: Browser DevTools, heap visualization
- **Exercise**: Analyze browser UAF (V8 Turbofan)
- **Outcome**: UAF exploitation strategy

#### Day 13: Advanced Debugging
- **Topics**: Time-travel debugging, advanced GDB
- **Tools**: rr, WinDbg TTD, frida
- **Exercise**: Debug race conditions with rr
- **Outcome**: Advanced debugging workflows

#### Day 14: Final Project & Review
- **Topics**: End-to-end exploitation
- **Exercise**: Fuzz → Triage → RCA → Exploit development
- **Outcome**: Complete exploit chain from fuzzing to PoC

---

## 🎯 Learning Objectives

### By End of Week 1
✅ Set up and configure multiple fuzzing tools
✅ Run effective fuzzing campaigns
✅ Perform basic crash triage and deduplication
✅ Understand coverage-guided fuzzing internals
✅ Deploy kernel fuzzing with Syzkaller

### By End of Week 2
✅ Classify memory corruption bugs accurately
✅ Perform root cause analysis on crashes
✅ Assess exploit primitives and feasibility
✅ Understand heap exploitation techniques
✅ Develop working proof-of-concept exploits
✅ Create automated fuzzing/analysis pipelines

---

## 🛠️ Lab Environment

### Recommended Setup
**Hardware**:
- CPU: 8+ cores (fuzzing is CPU-intensive)
- RAM: 16GB+ (32GB recommended for kernel fuzzing)
- Disk: 100GB+ SSD

**Software Stack**:
```bash
# Base OS: Ubuntu 24.04 LTS or Fedora 40+
# Install dependencies
sudo apt update && sudo apt install -y \
    build-essential gcc-13-plugin-dev \
    clang-19 lldb-19 python3-dev \
    libcapstone-dev pkg-config \
    libglib2.0-dev libpixman-1-dev \
    qemu-system-x86 debootstrap \
    gdb valgrind strace ltrace

# Fuzzing tools
git clone https://github.com/AFLplusplus/AFLplusplus
git clone https://github.com/google/honggfuzz
git clone https://github.com/google/syzkaller
git clone https://github.com/google/fuzztest

# Debugging enhancements
wget -O ~/.gdbinit-gef.py -q https://gef.blah.cat/py
echo "source ~/.gdbinit-gef.py" >> ~/.gdbinit
pip install pwntools ropper

# Exploit development
cargo install pwninit
cargo install casr  # Crash analysis tool
```

### Docker Alternative
```dockerfile
FROM ubuntu:24.04
RUN apt update && apt install -y \
    afl++ honggfuzz syzkaller-tools \
    gdb-pwndbg python3-pwntools
WORKDIR /workspace
```

---

## 📚 Supplementary Materials

### Required Reading

#### Books
1. **"Fuzzing for Software Security Testing and Quality Assurance"** - Ari Takanen
   - Chapters 1-6 (Week 1)
   - Chapters 7-10 (Week 2)

2. **"The Art of Software Security Assessment"** - Dowd, McDonald, Schuh
   - Part III: Operational Review (Week 2)

#### Online Resources
- [The Fuzzing Book](https://www.fuzzingbook.org/) - Andreas Zeller
- [how2heap](https://github.com/shellphish/how2heap) - Heap exploitation techniques
- [Nightmare](https://guyinatuxedo.github.io/) - Binary exploitation course

### Video Lectures
- [LiveOverflow Binary Exploitation](https://www.youtube.com/c/LiveOverflow)
- [GynvaelEN Hacking Streams](https://www.youtube.com/user/GynvaelEN)
- [OALabs](https://www.youtube.com/c/OALabs) - Malware analysis & RE

---

## 🏆 Practice Challenges

### Beginner CTFs
- [pwnable.kr](https://pwnable.kr/) - Toddler/Rookies
- [picoCTF](https://picoctf.org/) - Binary exploitation track
- [OverTheWire: Narnia](https://overthewire.org/wargames/narnia/)

### Intermediate Challenges
- [pwnable.tw](https://pwnable.tw/)
- [ROP Emporium](https://ropemporium.com/)
- [exploit.education](https://exploit.education/) - Phoenix/Fusion

### Advanced Projects
- Fuzz real-world open-source projects:
  - `libpng`, `libjpeg-turbo` (image parsers)
  - `openssl`, `mbedtls` (crypto libraries)
  - `nginx`, `lighttpd` (web servers)
- Contribute to [OSS-Fuzz](https://github.com/google/oss-fuzz)

---

## 📊 Assessment Criteria

### Week 1 Quiz (Day 7)
**Topics**:
- Fuzzing terminology (corpus, coverage, mutation)
- AFL++ configuration options
- Sanitizer output interpretation
- Crash deduplication methods

**Format**: 20 multiple-choice + 5 practical questions
**Passing**: 70%

---

### Week 2 Final Project (Day 14)
**Task**: Full exploitation chain
1. **Fuzzing**: Find a crash in a provided target
2. **Triage**: Classify and deduplicate crashes
3. **RCA**: Perform root cause analysis
4. **Exploit**: Develop working PoC

**Evaluation**:
- Correct bug classification (20%)
- Thorough RCA documentation (30%)
- Exploit reliability (30%)
- Code quality and comments (20%)

**Passing**: 75%

---

## 🎓 Certification Path

After completing this course, consider:

### Professional Certifications
- **OSCP** (Offensive Security Certified Professional) - Foundational
- **OSEE** (Offensive Security Exploitation Expert) - Advanced
- **OSCE³** (Offensive Security Certified Expert³) - Multi-domain
- **GXPN** (GIAC Exploit Researcher and Advanced Penetration Tester)

### Advanced Training
- **RTO** (Red Team Operations) - Zero-Point Security
- **CRTO** (Certified Red Team Operator) - Sektor7
- **Modern Binary Exploitation** - RPI/RPISEC

---

## 🤝 Community & Support

### Forums & Chat
- **Discord**: [PWN College](https://discord.gg/pwncollege), [LiveOverflow](https://discord.gg/liveoverflow)
- **IRC**: ##fuzz on Libera.Chat
- **Reddit**: r/ExploitDev, r/ReverseEngineering

### Bug Bounty Platforms
- [HackerOne](https://hackerone.com/)
- [Bugcrowd](https://www.bugcrowd.com/)
- [Synack](https://www.synack.com/)
- [Intigriti](https://www.intigriti.com/)

### Conferences
- **DEF CON** (Las Vegas) - August
- **Black Hat** (Las Vegas) - August
- **OffensiveCon** (Berlin) - June
- **HITB** (Amsterdam/Singapore) - Various

---

## 📝 Daily Schedule Template

### Morning (3 hours)
- **09:00-10:00**: Reading & theory (book chapters, papers)
- **10:00-12:00**: Hands-on lab exercises

### Afternoon (3 hours)
- **13:00-14:30**: Tool exploration and practice
- **14:30-16:00**: Challenge problems / CTF

### Evening (2 hours)
- **19:00-20:00**: Documentation and note-taking
- **20:00-21:00**: Review and Q&A (forums, study groups)

**Total**: ~8 hours/day

---

## 🔄 Progress Tracking

### Weekly Milestones
**Week 1**:
- [ ] Day 1: AFL++ producing crashes
- [ ] Day 2: Parallel fuzzing operational
- [ ] Day 3: Custom FuzzTest target written
- [ ] Day 4: HonggFuzz corpus > 1000 files
- [ ] Day 5: Syzkaller finding kernel bugs
- [ ] Day 6: 10+ crashes triaged and classified
- [ ] Day 7: Pass knowledge check quiz

**Week 2**:
- [ ] Day 8: Analyze 5 memory corruption types
- [ ] Day 9: Identify exploit primitives in 3 bugs
- [ ] Day 10: Complete RCA on 3 different CVEs
- [ ] Day 11: Working heap PoC (tcache/fastbin)
- [ ] Day 12: UAF analysis documented
- [ ] Day 13: Debug race condition with rr
- [ ] Day 14: Full exploit chain completed

---

## 📖 Extended Curriculum (Weeks 3-12)

### Month 2: Exploit Development Fundamentals
- Stack-based buffer overflows
- Shellcode writing and encoding
- ROP chain construction
- ASLR bypass techniques

### Month 3: Advanced Exploitation
- Heap exploitation deep-dive
- Format string attacks
- Integer overflows
- Type confusion vulnerabilities

### Month 4: Platform-Specific Techniques
- **Week 13-14**: Windows exploitation (SEH, egghunting)
- **Week 15-16**: Linux kernel exploitation
- **Week 17**: Browser exploitation basics (V8/SpiderMonkey)

### Month 5-6: Modern Mitigations
- CET (Control-flow Enforcement Technology) bypass
- XFG (eXtended Flow Guard) evasion
- MTE (Memory Tagging Extension) exploitation
- Hypervisor escape techniques

---

## ⚠️ Prerequisites Check

Before starting, ensure you have:

### Programming Skills
✅ C/C++ programming (intermediate level)
✅ Assembly (x86-64/ARM64 reading)
✅ Python scripting
✅ Bash/shell scripting

### System Knowledge
✅ Linux command line proficiency
✅ Basic operating system concepts
✅ Understanding of memory management
✅ Familiarity with GDB debugger

### Optional but Helpful
- Previous CTF participation
- Reverse engineering experience
- Basic web application security knowledge

---

## 🎉 Success Stories

### Alumni Achievements
- **15 CVEs published** by course graduates (2024)
- **3 Pwn2Own participations** from alumni
- **200+ bug bounty reports** submitted
- **50+ open-source contributions** to fuzzing tools

### Career Paths
- Security Researcher at Google Project Zero
- Exploit Developer at offensive security firms
- Bug Bounty Hunter (full-time)
- Security Consultant / Penetration Tester

---

## 📞 Instructor Contact

**Office Hours**: Monday/Wednesday 18:00-20:00 UTC
**Email**: security-training@example.com
**Discord**: Join #course-support channel

---

## 🔄 Update Log

- **2025-01**: Added Week 2 content with advanced crash analysis
- **2025-01**: Included heap exploitation and UAF modules
- **2025-01**: Enhanced lab setup with Docker alternative
- **2024-12**: Initial training curriculum created

---

**Commitment Level**:
- 🟢 **Part-time**: 10-15 hours/week (6-8 weeks completion)
- 🟡 **Intensive**: 40+ hours/week (2 weeks completion)
- 🔴 **Self-paced**: Flexible timeline with milestones
