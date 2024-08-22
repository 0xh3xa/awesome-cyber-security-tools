# Awesome Cyber Security Tools
[![Awesome](https://cdn.rawgit.com/sindresorhus/awesome/d7305f38d29fed78fa85652e3a63e154dd8e8829/media/badge.svg)](https://github.com/sindresorhus/awesome)

A curated list of common tools used in security across different specialties.

## Table of Contents

- [Malware Reversing](#malware-reversing)
  - [Static Analysis](#static-analysis)
  - [Dynamic Analysis](#dynamic-analysis)
- [Reverse Engineering](#reverse-engineering)
- [Penetration Testing](#penetration-testing)
- [Contribute](#contribute)
- [License](#license)

## Malware Reversing

### Static Analysis

**File Identification**

* [file](https://linux.die.net/man/1/file) - Determine file type.
* [exeinfo PE](https://exeinfo-pe.en.uptodown.com/windows) - Analyze Windows PE header information, packer detection, and gives hints on how to unpack.
* [trID](https://trid.en.softonic.com/) - Use pattern database to determine file types, gives a likelihood of detected type.
* [PeiD](https://www.aldeid.com/wiki/PEiD) - Detects common packers, cryptors, and compilers for PE files.
* [Detect-It-Easy](https://github.com/horsicq/Detect-It-Easy) - Determines types of files for Windows, Linux, and MacOS.

**File Signature**

* [md5sum](https://www.man7.org/linux/man-pages/man1/md5sum.1.html) - Compute and check MD5 message digest.
* [HashMyFile](https://www.nirsoft.net/utils/hash_my_files.html) - Calculates MD5 and SHA1 hashes of one or more files.
* [Hasher](https://www.igorware.com/hasher) - Free SHA-1, MD5, and CRC32 hash generator for Windows.
* [ComputeHash](https://www.subisoft.net/ComputeHash.aspx) - Calculates MD5, SHA1, SHA256, SHA384, and SHA512 hashes.
* [GET-FileHash](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/get-filehash?view=powershell-7.4) - Computes hash value for a file using a specified hash algorithm.
* [ssdeep](https://ssdeep-project.github.io/ssdeep/index.html) - Computes context triggered piecewise hashes (CTPH) for fuzzy matching.
* [impfuzzy](https://github.com/JPCERTCC/impfuzzy) - Calculates Fuzzy Hash from import API of PE files.
* [pehash](https://github.com/knowmalware/pehash) - Compilation of peHash implementations.

**Strings**

* [strings](https://www.man7.org/linux/man-pages/man1/strings.1.html) - Print sequences of printable characters in files.
* [binText](https://www.majorgeeks.com/files/details/bintext.html) - Extracts ASCII, Unicode, and Resource strings from files.
* [xorsearch](https://blog.didierstevens.com/programs/xorsearch) - Searches for strings in XOR, ROL, ROT, or SHIFT encoded binary files.
* [floss64](https://github.com/mandiant/flare-floss) - Automatically extracts obfuscated strings from malware.
* [StringsDump](https://github.com/mwrlabs/stringsdump) - Extracts and identifies text from binary files.

**PE Inspector**

* [PeStudio](https://pestudio.en.lo4d.com/windows) - Examines executable files in depth.
* [CFF Explorer](https://ntcore.com/explorer-suite) - Inspect and analyze Portable Executable (PE) files.
* [PE Explorer](https://pe-explorer.com) - Inspects Windows applications and libraries.
* [PE Bear](https://github.com/hasherezade/pe-bear) - Multiplatform reversing tool for PE files.
* [Peview](https://www.aldeid.com/wiki/PEView) - Lightweight utility for inspecting PE files.
* [Dependency Walker](https://dependencywalker.com) - Builds hierarchical tree diagram of dependent modules.
* [DLL Export Viewer](https://www.nirsoft.net/utils/dll_export_viewer.html) - Displays exported functions and their addresses for DLL files.

**IOC and Pattern Identification**

* [yara](https://github.com/VirusTotal/yara) - Tool for identifying and classifying malware samples.
* [Loki](https://github.com/Neo23x0/Loki) - IOC and YARA Scanner.
* [zipdump](https://github.com/nlitsme/zipdump) - Analyzes zip files and runs YARA rules.
* [exiftool](https://exiftool.org) - Reads, writes, and edits meta information in files.

**PDF**

* [pdf-parser](https://blog.didierstevens.com/programs/pdf-tools) - Parses PDF documents to identify fundamental elements.
* [pdfid](https://blog.didierstevens.com/programs/pdf-tools) - Scans for PDF keywords indicating JavaScript or actions.
* [pee-pdf](https://github.com/jesparza/peepdf) - Analyzes PDF documents.
* [spidermonkey](https://blog.didierstevens.com/programs/spidermonkey) - Modified Mozilla JavaScript implementation for malware analysis.
* [PDF-XChange Editor](https://www.tracker-software.com/product/pdf-xchange-editor) - In-depth analysis and editing of PDF documents.

**Office**

* [officeMalScanner](https://www.aldeid.com/wiki/OfficeMalScanner/OfficeMalScanner) - Scans MS Office documents for malicious traces.
* [ole-tools](https://github.com/decalage2/oletools) - Analyzes MS OLE2 files and Office documents.
* [vipermonkey](https://github.com/decalage2/ViperMonkey) - VBA parser and emulation engine.
* [lazy office analyzer](https://github.com/tehsyntx/loffice) - Extracts URLs, VB-script, and JavaScript from Office documents.

**Anti-Analysis Detector**

* [Pefish](https://github.com/a0rtega/pafish) - Detects virtual machines and malware analysis environments.

**Hex Editor**

* [010 Editor](https://www.sweetscape.com/010editor) - Powerful hex and text editor.
* [HxD](https://mh-nexus.de/en/hxd) - Fast hex editor with raw disk editing capabilities.
* [Hex Workshop](http://www.hexworkshop.com) - Visualizes data through graphical representations and charts.

**Resource Editor**

* [Resource Hacker](https://www.angusj.com/resourcehacker) - Resource editor for Windows applications.

**APIs / DLLs**

* [API Monitor](http://www.rohitab.com/apimonitor) - Monitors and controls API calls.
* [WinAPIOverride](http://jacquelin.potier.free.fr/winapioverride32) - Advanced API monitoring software.
* [ListDLLs](https://learn.microsoft.com/en-us/sysinternals/downloads/listdlls) - Reports DLLs loaded into processes.
* [handle](https://learn.microsoft.com/en-us/sysinternals/downloads/handle) - Displays information about open handles for processes.
* [WinObj](https://learn.microsoft.com/en-us/sysinternals/downloads/winobj) - Displays information on the NT Object Manager's namespace.

### Dynamic Analysis

**Process Monitoring**

* [RegShot](https://github.com/microsoft/Detours) - Registry compare utility.
* [RegistryChangeView](https://www.nirsoft.net/utils/registry_changes_view.html) - Compares Windows Registry snapshots.
* [Process Explorer](https://learn.microsoft.com/en-us/sysinternals/downloads/process-explorer) - Advanced system monitoring tool.
* [Hacker Process](https://processhacker.sourceforge.io) - Monitors system resources, debugs software, and detects malware.
* [ProcMon](https://learn.microsoft.com/en-us/sysinternals/downloads/procmon) - Real-time file system, Registry, and process/thread activity monitoring.
* [FileActivityWatch](https://www.nirsoft.net/utils/file_activity_watch.html) - Displays file read/write/delete operations.
* [FolderChangeWatch](https://www.nirsoft.net/utils/folder_changes_view.html) - Monitors folder or disk drive changes.
* [winapioverride](http://jacquelin.potier.free.fr/winapioverride32) - API monitoring software.
* [ProcDot](https://procdot.com) - Visualizes ProcMon output and integrates network packets in graph view.

**Startup**

* [Autoruns](https://learn.microsoft.com/en-us/sysinternals/downloads/autoruns) - Monitors auto-starting locations.

**Networking**

* [FakeNet-NG](https://github.com/mandiant/flare-fakenet-ng) - Dynamic network analysis tool.
* [Wireshark](https://www.wireshark.org) - Network protocol analyzer.
* [TCPView](https://learn.microsoft.com/en-us/sysinternals/downloads/tcpview) - Displays TCP and UDP endpoints.

**Emulators**

* [JSDetox](https://github.com/svent/jsdetox) - JavaScript malware analysis tool.
* [scDbg](http://sandsprite.github.io/scDbg/) - Sandbox environment for analyzing malware.
* [unicorn](https://github.com/unicorn-engine/unicorn) - Lightweight multi-platform CPU emulator.

**Debuggers**

* [OllyDbg](http://www.ollydbg.de) - Assembly-level debugger for Windows.
* [x64dbg](https://x64dbg.com) - Open-source x64/x32 debugger.
* [Ghidra](https://ghidra-sre.org) - Software reverse engineering suite.

## Reverse Engineering

* [Ghidra](https://ghidra-sre.org) - Software reverse engineering suite.
* [IDA Pro](https://www.hex-rays.com/ida-pro) - Advanced disassembler and debugger.
* [Binary Ninja](https://binary.ninja) - Binary analysis platform.
* [Radare2](https://rada.re/n) - Unix-like open-source reverse engineering framework.
* [x64dbg](https://x64dbg.com) - Open-source x64/x32 debugger.
* [Hopper](https://www.hopperapp.com) - Reverse engineering tool for macOS and Linux.

## Penetration Testing

**Reconnaissance**

* [Maltego](https://www.paterva.com) - Open-source intelligence and forensics application.
* [Shodan](https://www.shodan.io) - Search engine for Internet-connected devices.
* [Recon-ng](https://github.com/lanmaster53/recon-ng) - Web reconnaissance framework.
* [Censys](https://censys.io) - Search engine for Internet-connected data.
* [TheHarvester](https://github.com/laramies/theHarvester) - Gathers email accounts and domain/subdomain names.

**Scanning**

* [Nmap](https://nmap.org) - Network discovery and security auditing tool.
* [Nessus](https://www.tenable.com/products/nessus/nessus-professional) - Vulnerability scanner.
* [OpenVAS](https://www.openvas.org) - Open-source vulnerability scanner.
* [Masscan](https://github.com/robertdavidgraham/masscan) - Fast network port scanner.
* [Nikto](https://cirt.net/Nikto2) - Web server scanner.
* [Qualys](https://www.qualys.com) - Cloud-based security and compliance suite.

**Exploitation**

* [Metasploit Framework](https://www.metasploit.com) - Penetration testing software.
* [BeEF](https://beefproject.com) - Browser exploitation framework.
* [Veil-Framework](https://www.veil-framework.com) - Evasion tools for penetration testing.
* [Empire](https://github.com/EmpireProject/Empire) - Post-exploitation framework.
* [Koadic](https://github.com/zerosum0x0/koadic) - Windows command and control framework.
* [Cobalt Strike](https://www.cobaltstrike.com) - Adversary simulation and Red Team operations software.

**Post-Exploitation**

* [BloodHound](https://github.com/BloodHoundAD/BloodHound) - Active Directory enumeration and attack simulation.
* [Responder](https://github.com/SpiderLabs/Responder) - LLMNR, NBT-NS and MDNS poisoner.
* [Mimikatz](https://github.com/gentilkiwi/mimikatz) - Credential extraction and manipulation.
* [PowerSploit](https://github.com/PowerShellEmpire/PowerSploit) - PowerShell Post-Exploitation Framework.
* [Impacket](https://github.com/SecureAuthCorp/impacket) - Collection of Python classes for working with network protocols.

**Social Engineering**

* [Social-Engineer Toolkit (SET)](https://github.com/trustedsec/social-engineer-toolkit) - Framework for social engineering attacks.
* [King Phisher](https://github.com/king-phisher/king-phisher) - Phishing campaign toolkit.
* [Gophish](https://github.com/gophish/gophish) - Open-source phishing framework.
* [Evil-WinRM](https://github.com/Hackplayers/evil-winrm) - WinRM exploitation tool for penetration testing.

**Web Application Testing**

* [Burp Suite](https://portswigger.net/burp) - Integrated platform for performing security testing of web applications.
* [OWASP ZAP](https://owasp.org/www-project-zap/) - Web application security scanner.
* [Wapiti](https://wapiti.sourceforge.io) - Web application vulnerability scanner.
* [Arachni](https://www.arachni-scanner.com) - High-performance security scanner for web applications.
* [Skipfish](https://code.google.com/archive/p/skipfish) - Web application security scanner.
* [Nikto](https://cirt.net/Nikto2) - Web server scanner.

**Wireless Network Testing**

* [Aircrack-ng](https://www.aircrack-ng.org) - Suite of tools for assessing WiFi network security.
* [Kismet](https://kismetwireless.net) - Network detector, packet sniffer, and IDS.
* [Reaver](https://code.google.com/archive/p/reaver-wps) - WPS brute force attack tool.
* [Fern WiFi Cracker](https://github.com/savio-code/fern-wifi-cracker) - Wireless security auditing and attack software.

**Forensics**

* [Autopsy](https://www.sleuthkit.org/autopsy/) - Digital forensics platform.
* [Sleuth Kit](https://www.sleuthkit.org) - Collection of command-line tools for digital forensics.
* [Volatility](https://www.volatilityfoundation.org) - Advanced memory forensics framework.
* [X1 Search](https://www.x1.com) - Enterprise search software for forensic investigations.
* [FTK Imager](https://accessdata.com/product-download/ftk-imager-version-4.2.0) - Disk imaging tool for forensics.
* [Caine](https://www.caine-live.net) - Live system for digital forensics analysis.

## Contribute

Feel free to contribute to this repository! Please follow these guidelines for submitting pull requests:

1. **Fork the Repository**: Click on the "Fork" button at the top right of this page to create your own copy of this repository.
2. **Make Changes**: Create a new branch, make your changes, and commit them with clear, descriptive messages.
3. **Submit Pull Request**: Push your changes to your fork and submit a pull request.

## License

This repository is licensed under the [MIT License](LICENSE).
