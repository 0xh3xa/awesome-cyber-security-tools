<p align="center">
  <a href="https://github.com/0xh3xa/awesome-cyber-security-tools">
    <img
      src="./assets/banner.png"
      alt="Awesome Cyber Security Tools banner"/>
  </a>
</p>

<!-- <h1 align="center">Awesome Cyber Security Tools</h1> -->

<p align="center">
  <img src="https://awesome.re/badge.svg" alt="Awesome List Badge"/>
  <img src="https://img.shields.io/github/last-commit/0xh3xa/awesome-cyber-security-tools?style=flat" alt="Last Commit"/>
  <img src="https://img.shields.io/badge/PRs-welcome-brightgreen" alt="PRs Welcome"/>
  <img src="https://img.shields.io/badge/Tools-Collection-blue" alt="Tools Collection"/>
</p>

<p align="center">
  A curated list of commonly used tools across the cybersecurity landscape — including
  <strong>red team</strong>, <strong>blue team</strong>, <strong>malware analysis</strong>,
  <strong>reverse engineering</strong>, <strong>OSINT</strong>, and <strong>cloud security</strong>.
</p>

## Table of Contents

- [Malware Analysis](#malware-analysis)
  - [Static Analysis](#static-analysis)
  - [Dynamic Analysis](#dynamic-analysis)
- [Reverse Engineering](#reverse-engineering)
  - [Java Decompilers](#java-decompilers)
  - [.NET Decompilers](#net-decompilers)
- [Penetration Testing](#penetration-testing)
  - [Information Gathering](#information-gathering)
  - [Web Penetration Testing](#web-penetration-testing)
  - [Mobile Penetration Testing](#mobile-penetration-testing)
- [Digital Forensics](#ditial-forensics)
- [Linux Distributions](#linux-distributions)
- [Contribute](#contribute)
- [License](#license)

---

## Malware Analysis

### Static Analysis

#### File Identification

- [**file**](https://linux.die.net/man/1/file) - Determine file type.
- [**Exeinfo PE**](https://exeinfo-pe.en.uptodown.com/windows) - Analyze Windows PE header information, packer detection, and gives hints on how to unpack.
- [**TrID**](https://trid.en.softonic.com/) - Use pattern database to determine file types, gives a likelihood of detected type.
- [**PEiD**](https://www.aldeid.com/wiki/PEiD) - Detects common packers, cryptors, and compilers for PE files.
- [**Detect-It-Easy**](https://github.com/horsicq/Detect-It-Easy) - Determines types of files for Windows, Linux, and MacOS.
- [**KapeFiles**](https://github.com/EricZimmerman/KapeFiles) - A tool for acquiring and processing forensic artifacts.

#### File Signature

- [**md5sum**](https://www.man7.org/linux/man-pages/man1/md5sum.1.html) - Compute and check MD5 message digest.
- [**sha256sum**](https://www.man7.org/linux/man-pages/man1/sha256sum.1.html) - Compute and check SHA256 message digest.
- [**sha512sum**](https://www.man7.org/linux/man-pages/man1/sha512sum.1.html) - Compute and check SHA512 message digest.
- [**HashMyFiles**](https://www.nirsoft.net/utils/hash_my_files.html) - Calculates MD5 and SHA1 hashes of one or more files.
- [**IgorWare Hasher**](https://www.igorware.com/hasher) - Free SHA-1, MD5, and CRC32 hash generator for Windows.
- [**ComputeHash**](https://www.subisoft.net/ComputeHash.aspx) - Calculates MD5, SHA1, SHA256, SHA384, and SHA512 hashes.
- [**GET-FileHash**](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/get-filehash?view=powershell-7.4) - Computes hash value for a file using a specified hash algorithm (Microsoft PowerShell module).
- [**ssdeep**](https://ssdeep-project.github.io/ssdeep/index.html) - Computes Context Triggered Piecewise Hashes (CTPH) for fuzzy matching.
- [**impfuzzy**](https://github.com/JPCERTCC/impfuzzy) - Calculates Fuzzy Hash from import API of PE files.
- [**pehash**](https://github.com/knowmalware/pehash) - Compilation of peHash implementations.

#### Strings

- [**strings**](https://www.man7.org/linux/man-pages/man1/strings.1.html) - Print sequences of printable characters in files.
- [**BinText**](https://www.majorgeeks.com/files/details/bintext.html) - Extracts ASCII, Unicode, and Resource strings from files.
- [**XORSearch**](https://blog.didierstevens.com/programs/xorsearch) - Searches for strings in XOR, ROL, ROT, or SHIFT encoded binary files.
- [**flare-floss**](https://github.com/mandiant/flare-floss) - Automatically extracts obfuscated strings from malware.
- [**StringsDump**](https://github.com/mwrlabs/stringsdump) - Extracts and identifies text from binary files.

#### Inspector

- [**PeStudio**](https://pestudio.en.lo4d.com/windows) - Examines executable files in depth.
- [**CFF Explorer**](https://ntcore.com/explorer-suite) - Inspect and analyze Portable Executable (PE) files.
- [**PE Explorer**](https://pe-explorer.com) - Inspects Windows applications and libraries.
- [**pe-bear**](https://github.com/hasherezade/pe-bear) - Multiplatform reversing tool for PE files.
- [**PEView**](https://www.aldeid.com/wiki/PEView) - Lightweight utility for inspecting PE files.
- [**Dependency Walker**](https://dependencywalker.com) - Builds hierarchical tree diagram of dependent modules.
- [**DLL Export Viewer**](https://www.nirsoft.net/utils/dll_export_viewer.html) - Displays exported functions and their addresses for DLL files.
- [**PEPack**](https://pev.sourceforge.io/doc/manual/en_us/ch06s05.html) - Python library for inspecting and manipulating PE files.

#### IOC and Pattern Identification

- [**yara**](https://github.com/VirusTotal/yara) - Tool for identifying and classifying malware samples.
- [**Loki**](https://github.com/Neo23x0/Loki) - IOC and YARA Scanner.
- [**zipdump**](https://github.com/nlitsme/zipdump) - Analyzes zip files and runs YARA rules.
- [**ExifTool**](https://exiftool.org) - Reads, writes, and edits meta information in files.

#### PDF

- [**pdf-parser**](https://blog.didierstevens.com/programs/pdf-tools) - Parses PDF documents to identify fundamental elements.
- [**pdfid**](https://blog.didierstevens.com/programs/pdf-tools) - Scans for PDF keywords indicating JavaScript or actions.
- [**pee-pdf**](https://github.com/jesparza/peepdf) - Analyzes PDF documents.
- [**SpiderMonkey**](https://blog.didierstevens.com/programs/spidermonkey) - Modified Mozilla JavaScript implementation for malware analysis.
- [**PDF-XChange**](https://www.tracker-software.com/product/pdf-xchange-editor) - In-depth analysis and editing of PDF documents.
- [**pdfunite**](https://manpages.ubuntu.com/manpages/jammy/man1/pdfunite.1.html) - Merges multiple PDF files into a single file.

#### Microsoft Office

- [**OfficeMalScanner**](https://www.aldeid.com/wiki/OfficeMalScanner/OfficeMalScanner) - Scans MS Office documents for malicious traces.
- [**ole-tools**](https://github.com/decalage2/oletools) - Analyzes MS OLE2 files and Office documents.
- [**ViperMonkey**](https://github.com/decalage2/ViperMonkey) - VBA parser and emulation engine.
- [**Lazy Office Analyzer**](https://github.com/tehsyntx/loffice) - Extracts URLs, VB-script, and JavaScript from Office documents.
- [**OfficeScan**](https://support.trendmicro.com/en-us/home/pages/technical-support/office-scan) - Analyzes Microsoft Office documents for malware and other threats.
- [**oletools**](https://github.com/decalage2/oletools) - Extracts VBA macros from Office files and detects obfuscation techniques.

#### Anti-Analysis Detector

- [**Pafish**](https://github.com/a0rtega/pafish) - Detects virtual machines and malware analysis environments.
- [**VMProtect**](https://vmpsoft.com) - Anti-debugging and anti-VM software protection.

#### Hex Editor

- [**010 Editor**](https://www.sweetscape.com/010editor) - Powerful hex and text editor.
- [**HxD**](https://mh-nexus.de/en/hxd) - Fast hex editor with raw disk editing capabilities.
- [**Hex Workshop**](http://www.hexworkshop.com) - Visualizes data through graphical representations and charts.
- [**Bless**](https://github.com/afrantzis/bless) - High-performance, full-featured hex editor.
- [**hexitor**](https://github.com/briansteffens/hexitor) - terminal hex editor.

#### Resource Editor

- [**Resource Hacker**](https://www.angusj.com/resourcehacker) - Resource editor for Windows applications.
- [**Resource Tuner**](https://www.restuner.com) - Allows you to edit resources within executables and DLLs.

#### APIs / DLLs

- [**API Monitor**](http://www.rohitab.com/apimonitor) - Monitors and controls API calls.
- [**WinAPIOverride**](http://jacquelin.potier.free.fr/winapioverride32/) - Monitors, intercepts, and logs API calls.
- [**ListDLLs**](https://docs.microsoft.com/en-us/sysinternals/downloads/listdlls) - Lists all the DLLs loaded into processes (SysInternals).
- [**Handle**](https://learn.microsoft.com/en-us/sysinternals/downloads/handle) - Lists open handles for system processes.

### Dynamic Analysis Tools

- [**Cuckoo Sandbox**](https://github.com/cuckoosandbox/cuckoo) - Automated malware analysis system.
- [**Sandboxie**](https://www.sandboxie.com) - Isolates applications in a virtual sandbox.
- [**Fakenet-NG**](https://github.com/mandiant/flare-fakenet-ng) - Fake network environment for malware analysis.
- [**Volatility**](https://www.volatilityfoundation.org) - Advanced memory forensics framework.
- [**Procmon**](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) - Monitors and logs real-time file system, Registry, and process/thread activity (SysInternals).
- [**Regshot**](http://www.nikopol.org/regshot) - Takes snapshots of the Registry and compares them.
- [**APISpy**](http://www.ragoo.com/APISpy) - Captures and analyzes API calls made by applications.
- [**ProcDot**](https://www.cert.at/en/downloads/software/software-procdot) - Visualizes process and thread behavior.

### Threat Intelligence

- [**VirusTotal**](https://www.virustotal.com) – Free service for scanning files and URLs to detect malware and gather threat intelligence.
- [**MISP**](https://www.misp-project.org) – Open-source threat intelligence platform for sharing, storing, and correlating indicators of compromise (IOCs).  
- [**OpenCTI**](https://www.opencti.io) – Open-source platform for managing cyber threat intelligence knowledge and observables.  
- [**AlienVault OTX**](https://otx.alienvault.com) – Open Threat Exchange platform for community-driven threat intelligence and IOCs.  
- [**Recorded Future**](https://www.recordedfuture.com) – Commercial threat intelligence platform providing real-time threat analysis and risk scoring.  
- [**ThreatConnect**](https://threatconnect.com) – Threat intelligence platform combining data aggregation, analytics, and response workflows.  
- [**CIRCL**](https://www.circl.lu/services) – Computer Incident Response Center Luxembourg; provides threat intelligence feeds and malware analysis.  
- [**Hybrid Analysis**](https://www.hybrid-analysis.com) – Malware analysis service with detailed threat intelligence reports.  
- [**Abuse.ch**](https://abuse.ch) – Provides threat feeds such as ransomware and malware campaign trackers.  

---

## Reverse Engineering

- [**Ghidra**](https://ghidra-sre.org) - Software reverse engineering framework.
- [**Radare2**](https://rada.re/n) - Open-source reverse engineering framework.
- [**IDA Pro**](https://www.hex-rays.com/ida-pro) - Interactive disassembler and debugger.
- [**Binary Ninja**](https://binary.ninja) - Reverse engineering platform.
- [**x64dbg**](https://x64dbg.com) - Open-source debugger for Windows.
- [**Hopper**](https://www.hopperapp.com) - Reverse engineering tool for macOS and Linux.
- [**OllyDbg**](http://www.ollydbg.de) - 32-bit assembler level debugger for Windows.
- [**Cutter**](https://cutter.re) - Qt and C++ GUI powered by Radare2.

### Java Decompilers

- [**JADX**](https://github.com/skylot/jadx) - Dex to Java decompiler.
- [**JD-GUI**](http://java-decompiler.github.io) - Decompiler for Java bytecode.
- [**CFR**](http://www.benf.org/other/cfr) - Another Java decompiler.
- [**Procyon**](https://bitbucket.org/mstrobel/procyon) - Java decompiler for modern Java features.
- [**FernFlower**](https://github.com/fesh0r/fernflower) - IntelliJ's Java decompiler.
- [**Krakatau**](https://github.com/Storyyeller/krakatau) - Java decompiler, assembler, and disassembler.

### .NET Decompilers

- [**dnSpy**](https://github.com/dnSpy/dnSpy) - .NET debugger and assembly editor.
- [**dotPeek**](https://www.jetbrains.com/decompiler) - .NET decompiler from JetBrains.
- [**ILSpy**](https://github.com/icsharpcode/ILSpy) - Open-source .NET assembly browser and decompiler.
- [**JustDecompile**](https://www.telerik.com/products/decompiler.aspx) - Free .NET decompiler from Telerik.

---

## Penetration Testing

- [**Metasploit**](https://www.metasploit.com) - Penetration testing framework.
- [**Aircrack-ng**](https://www.aircrack-ng.org) - Suite of tools for wireless network security.
- [**Nessus**](https://www.tenable.com/products/nessus/nessus-professional) - Vulnerability scanner.
- [**Wireshark**](https://www.wireshark.org) - Network protocol analyzer.
- [**Sqlmap**](https://sqlmap.org) - Automated SQL injection and database takeover tool.
- [**Dradis**](https://dradisframework.com) - Open-source collaboration and reporting tool for information security teams.
- [**Sublist3r**](https://github.com/aboul3la/Sublist3r) - Fast subdomain enumeration tool.
- [**Recon-ng**](https://github.com/lanmaster53/recon-ng) - Full-featured Web Reconnaissance Framework.
- [**Empire**](https://github.com/EmpireProject/Empire) - PowerShell and Python post-exploitation agent.

### Information Gathering

#### Passive Information Gathering

- [**BuiltWith**](https://builtwith.com) – Identify technologies, frameworks, and services used by websites.  
- [**Wappalyzer**](https://www.wappalyzer.com) – Detect web technologies including CMS, frameworks, analytics, and servers.  
- [**WhatWeb**](https://github.com/urbanadventurer/WhatWeb) – Website fingerprinting tool to identify web technologies.  
- [**HTTrack**](https://www.httrack.com) – Website mirroring tool for offline analysis.  
- [**WHOIS**](https://www.iana.org/whois) – Query domain registration and ownership information.  
- [**Netcraft**](https://sitereport.netcraft.com/) – Checking the technology and infrastructure of any site.
- [**Sublist3r**](https://github.com/aboul3la/Sublist3r) – Fast subdomains enumeration tool for penetration testers.
- [**Google Dorking**](https://www.exploit-db.com/google-hacking-database) – Advanced search techniques to discover exposed information.  
- [**theHarvester**](https://github.com/laramies/theHarvester) – Gather emails, subdomains, hosts, and employee names from public sources.  

#### Active Information Gathering

- [**Nmap**](https://nmap.org) – Network scanning and discovery tool for hosts, services, and ports.  
- [**dnsrecon**](https://github.com/darkoperator/dnsrecon) – Perform DNS enumeration using direct queries and brute forcing.  
- [**dnsenum**](https://github.com/fwaeytens/dnsenum) – DNS enumeration tool supporting zone transfers and brute-force attacks.  
- [**Netdiscover**](https://github.com/alexxy/netdiscover) – Active and passive ARP reconnaissance tool.  
- [**wafw00f**](https://github.com/EnableSecurity/wafw00f) – Identify and fingerprint web application firewalls (WAFs).

### Web Penetration Testing

- [**Burp Suite**](https://portswigger.net/burp) - Integrated platform for web application security testing.
- [**OWASP ZAP**](https://www.zaproxy.org) - Open-source web application security scanner.


### Mobile Penetration Testing

- [**MobSF**](https://github.com/MobSF/Mobile-Security-Framework-MobSF) - Mobile Security Framework for static and dynamic analysis.
- [**Drozer**](https://github.com/mwrlabs/drozer) - Android security assessment framework.
- [**Frida**](https://frida.re) - Dynamic instrumentation toolkit for developers, reverse engineers, and security researchers.
- [**AppMon**](https://github.com/dpnishant/appmon) - Monitor and analyze mobile apps on Android and iOS.
- [**APKTool**](https://github.com/iBotPeaches/Apktool) - Decompiles and rebuilds APK files.
- [**AndroGuard**](https://github.com/androguard/androguard) - Android reverse engineering tool.
- [**Burp Suite Mobile Assistant**](https://portswigger.net/burp/documentation/desktop/tools/mobile-assistant) - Integrated mobile assistant for Burp Suite.
- [**Magisk**](https://github.com/topjohnwu/Magisk) - Rooting solution with systemless root for Android.
- [**AppUse**](https://appuse.org) - Open-source Android security testing platform.

---

## Digital Forensics

- [**The Sleuth Kit (TSK)**](https://www.sleuthkit.org) - A library and collection of command-line tools for digital forensics.
- [**Autopsy**](https://www.sleuthkit.org/autopsy) - Digital forensics platform and graphical interface.
- [**FTK Imager**](https://accessdata.com/product-download/ftk-imager-version-4.2) - Forensic imaging tool.
- [**X1 Search**](https://www.x1.com/products/x1-search) - Forensic search and data extraction tool.
- [**Bulk Extractor**](https://github.com/simsong/bulk_extractor) - Extracts useful information from disk images.

---

## Linux Distributions

- [**Kali Linux**](https://www.kali.org) - Comprehensive penetration testing distribution with numerous security tools.
- [**Parrot Security OS**](https://www.parrotsec.org) - Security-oriented Linux distribution designed for security experts and developers.
- [**BackBox**](https://www.backbox.org) - Ubuntu-based Linux distribution for security and analysis.
- [**BlackArch**](https://blackarch.org) - Arch Linux-based distribution for penetration testers and security researchers.
- [**Tails**](https://tails.boum.org) - Live operating system that you can start on almost any computer from a USB stick or a DVD.
- [**Qubes OS**](https://www.qubes-os.org) - Privacy-focused Linux distribution that uses virtualization to isolate security-sensitive tasks.
- [**REMnux**](https://remnux.org) - Linux toolkit for reverse engineering and analyzing malware.
- [**Caine**](https://www.caine-live.net) - Live CD Linux distribution for digital forensics.
- [**Whonix**](https://www.whonix.org) - Privacy-focused Linux distribution that leverages Tor for anonymous communication.
- [**Pentoo**](https://www.pentoo.ch) - Live CD and installable Linux distribution based on Gentoo optimized for penetration testing.

---

## Contribute

Contributions are always welcome 🤝

Feel free to contribute by submitting a pull request or opening an issue to suggest improvements or additional tools.
Please review the [Contribution Guidelines](CONTRIBUTING.md).
