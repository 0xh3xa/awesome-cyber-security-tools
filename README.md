# Awesome Cyber Security Tools
[![Awesome](https://cdn.rawgit.com/sindresorhus/awesome/d7305f38d29fed78fa85652e3a63e154dd8e8829/media/badge.svg)](https://github.com/sindresorhus/awesome)

List of common tools used in security across different specialties.

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

**File identification**

* [file](https://linux.die.net/man/1/file) - Determine file type.
* [exeinfo PE](https://exeinfo-pe.en.uptodown.com/windows) - Analyze Windows PE header information, packer detection, and gives hints on how to unpack.
* [trID](https://trid.en.softonic.com/) - Use pattern database to determine file types, gives a likelihood of detected type.
* [PeiD](https://www.aldeid.com/wiki/PEiD) - PEiD detects most common packers, cryptors and compilers for PE files.
* [Detect-It-Easy](https://github.com/horsicq/Detect-It-Easy) - a program for determining types of files for Windows, Linux and MacOS.

**File signature**

* [md5sum](https://www.man7.org/linux/man-pages/man1/md5sum.1.html) - compute and check MD5 message digest.
* [HashMyFile](https://www.nirsoft.net/utils/hash_my_files.html) - small utility that allows you to calculate the MD5 and SHA1 hashes of one or more files in your system.
* [Hasher](https://www.igorware.com/hasher) - is a free SHA-1, MD5 and CRC32 hash generator for Windows, both 64bit and 32bit versions are available.
* [ComputeHash](https://www.subisoft.net/ComputeHash.aspx) - is an easy-to-use free application that calculates the MD5, SHA1, SHA256, SHA384 and SHA512 hash of selected file.
* [GET-FileHash](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/get-filehash?view=powershell-7.4) - Computes the hash value for a file by using a specified hash algorithm.
* [ssdeep](https://ssdeep-project.github.io/ssdeep/index.html) - a program for computing context triggered piecewise hashes (CTPH). Also called fuzzy hashes, CTPH can match inputs that have homologies.
* [impfuzzy](https://github.com/JPCERTCC/impfuzzy) - is Fuzzy Hash calculated from import API of PE files.
* [pehash](https://github.com/knowmalware/pehash) - a compilation of peHash implementations.

**Strings**

* [strings](https://www.man7.org/linux/man-pages/man1/strings.1.html) - print the sequences of printable characters in files.
* [binText](https://www.majorgeeks.com/files/details/bintext.html) - is a small, fast and powerful text extractor that will be of particular interest to programmers. BinText can find Ascii, Unicode and Resource strings in a file.
* [xorsearch](https://blog.didierstevens.com/programs/xorsearch) - is a program to search for a given string in an XOR, ROL, ROT or SHIFT encoded binary file.
* [floss64](https://github.com/mandiant/flare-floss) - obfuscated String Solver - Automatically extract obfuscated strings from malware.

**PE Inspector**

* [PeStudio](https://pestudio.en.lo4d.com/windows) - is a portable program which is able to examine executable files in depth. It supports both 32-bit and 64-bit EXE files.
* [CFF Explorer](https://ntcore.com/explorer-suite) - is a software tool designed for inspecting and analyzing Portable Executable (PE) files.
* [PE Explorer](https://pe-explorer.com) - is the most feature-packed program for inspecting the inner workings of your own software, and more importantly, third party Windows applications and libraries.
* [PE Bear](https://github.com/hasherezade/pe-bear) - is a multiplatform reversing tool for PE files. Its objective is to deliver fast and flexible “first view” for malware analysts, stable and capable to handle malformed PE files.
* [Peview](https://www.aldeid.com/wiki/PEView) - is a lightweight, standalone utility designed to inspect and analyze the structure and content of Portable Executable (PE) files.
* [Dependency Walker](https://dependencywalker.com) - is a free utility that scans any 32-bit or 64-bit Windows module (exe, dll, ocx, sys, etc.) and builds a hierarchical tree diagram of all dependent modules.
* [DLL export viewer](https://www.nirsoft.net/utils/dll_export_viewer.html) - a utility that displays the list of all exported functions and their virtual memory addresses for the specified DLL files.

**IOC and Pattern Identification**

* [yara](https://github.com/VirusTotal/yara) - is a tool aimed at (but not limited to) helping malware researchers to identify and classify malware samples.
* [Loki](https://github.com/Neo23x0/Loki) - a simple IOC and YARA Scanner.
* [zipdump](https://github.com/nlitsme/zipdump) - analyze zipfile, either local, or from url and run yara on it.
* [exiftool](https://exiftool.org) - is a platform-independent Perl library plus a command-line application for reading, writing and editing meta information in a wide variety of files.

**PDF**

* [pdf-parser](https://blog.didierstevens.com/programs/pdf-tools) - parse a PDF document to identify the fundamental elements used in the analyzed file.
* [pdfid](https://blog.didierstevens.com/programs/pdf-tools) - scan a file to look for certain PDF keywords, allowing you to identify PDF documents that contain JavaScript or execute an action when opened. PDFiD will also handle name obfuscation.
* [pee-pdf](https://github.com/jesparza/peepdf) - powerful Python tool to analyze PDF documents.
* [spidermonkey](https://blog.didierstevens.com/programs/spidermonkey) -  is a modified version of Mozilla’s C implementation of JavaScript, with some extra functions to help with malware analysis.

**Office**

* [officeMalScanner](https://www.aldeid.com/wiki/OfficeMalScanner/OfficeMalScanner) - is a MS Office forensic tool to scan for malicious traces, like shellcode heuristics, PE-files or embedded OLE streams.
* [ole-tools](https://github.com/decalage2/oletools) - python tools to analyze MS OLE2 files (Structured Storage, Compound File Binary Format) and MS Office documents, for malware analysis, forensics and debugging.
* [vipermonkey](https://github.com/decalage2/ViperMonkey) - a VBA parser and emulation engine to analyze malicious macros.
* [lazy office analyzer](https://github.com/tehsyntx/loffice) - is making use of WinAppDbg to extract URLs' from Office documents but also VB-script and Javascript.

**Anti-Analysis Detector**

* [Pefish](https://github.com/a0rtega/pafish) - is a testing tool that uses different techniques to detect virtual machines and malware analysis environments in the same way that malware families do.

**Hex Editor**

* [010 Editor](https://www.sweetscape.com/010editor) - is a powerful hex and text editor designed for editing and analyzing binary files, hex data, and text files.
* [HxD](https://mh-nexus.de/en/hxd) - is a carefully designed and fast hex editor which, additionally to raw disk editing and modifying of main memory (RAM), handles files of any size.
* [HxD](https://mh-nexus.de/en/hxd) - is a carefully designed and fast hex editor which, additionally to raw disk editing and modifying of main memory (RAM), handles files of any size.
* [Hex Workshop](http://www.hexworkshop.com) - helps you visualize your data through graphical representations and charts.

**Resource Editor**

* [Resource Hacker](https://www.angusj.com/resourcehacker) - is a resource editor for 32bit and 64bit Windows applications.

**APIs / DLLs**

* [API Monitor](http://www.rohitab.com/apimonitor) - is a free software that lets you monitor and control API calls made by applications and services.
* [WinAPIOverride](http://jacquelin.potier.free.fr/winapioverride32) - is an advanced api monitoring software for 32 and 64 bits processes.
* [ListDLLs](https://learn.microsoft.com/en-us/sysinternals/downloads/listdlls) - is a utility that reports the DLLs loaded into processes.
* [handle](https://learn.microsoft.com/en-us/sysinternals/downloads/handle) - is a utility that displays information about open handles for any process in the system.
* [WinObj](https://learn.microsoft.com/en-us/sysinternals/downloads/winobj) - is a program that uses the native Windows API (provided by NTDLL.DLL) to access and display information on the NT Object Manager's namespace.

### Dynamic Analysis

**Process Monitoring**

* [RegShot](https://github.com/microsoft/Detours) - is a small, free and open-source registry compare utility that allows you to quickly take a snapshot of your registry and then compare it with a second one.
* [RegistryChangeView](https://www.nirsoft.net/utils/registry_changes_view.html) - is a tool for Windows that allows you to take a snapshot of Windows Registry and later compare it with another Registry snapshots, with the current Registry or with Registry files stored in a shadow copy created by Windows.
* [Process Explorer](https://learn.microsoft.com/en-us/sysinternals/downloads/process-explorer) - is an advanced system monitoring tool for Windows developed by Microsoft's Sysinternals team.
* [Hacker Process](https://processhacker.sourceforge.io) - a free, powerful, multi-purpose tool that helps you monitor system resources, debug software and detect malware.
* [ProcMon](https://learn.microsoft.com/en-us/sysinternals/downloads/procmon) - is an advanced monitoring tool for Windows that shows real-time file system, Registry and process/thread activity.
* [FileActivityWatch](https://www.nirsoft.net/utils/file_activity_watch.html) - is a tool for Windows that displays information about every read/write/delete operation of files occurs on your system.
* [FolderChangeWatch](https://www.nirsoft.net/utils/folder_changes_view.html) - is a simple tool that monitors the folder or disk drive that you choose and lists every filename that is being modified, created, or deleted while the folder is being monitored.
* [winapioverride](http://jacquelin.potier.free.fr/winapioverride32) - is an advanced api monitoring software for 32 and 64 bits processes.
* [ProcDot](https://procdot.com) - visualizes the ProcMon output and integrate network packets in graph view.

**Startup**

 * [Autoruns](https://learn.microsoft.com/en-us/sysinternals/downloads/autoruns) -  the most comprehensive knowledge of auto-starting locations of any startup monitor, shows you what programs are configured to run during system bootup or login, and when you start various built-in Windows applications like Internet Explorer, Explorer and media players.

**Networking**

* [FakeNet-NG](https://github.com/mandiant/flare-fakenet-ng) - is a next generation dynamic network analysis tool for malware analysts and penetration testers.
* [Wireshark](https://www.wireshark.org) - the world's most popular network protocol analyzer.
* [TCPView](https://learn.microsoft.com/en-us/sysinternals/downloads/tcpview) - is a Windows program that will show you detailed listings of all TCP and UDP endpoints on your system, including the local and remote addresses and state of TCP connections.

**Emulators**

* [JSDetox](https://github.com/svent/jsdetox) - is a Javascript malware analysis tool using static analysis / deobfuscation techniques and an execution engine featuring HTML DOM emulation.
* [scDbg](http://sandsprite.com/blogs/index.php?uid=7&pid=152) - is a shellcode analysis application built around the libemu emulation library. When run it will display to the user all of the Windows API the shellcode attempts to call.

### Memory Analysis

* [Volatility](https://volatilityfoundation.org) -  is a powerful open-source memory forensics framework used for analyzing volatile memory (RAM) dumps from computer systems.

---

## Reverse Engineering

* [gdb](https://sourceware.org/gdb) - is a powerful command-line debugger available on various Unix-like operating systems, including Linux.
* [IDA](https://hex-rays.com) - is a highly advanced and widely used disassembler and decompiler software suite.
* [OllyDbg](https://www.ollydbg.de/download.htm) - is a popular and powerful debugger for Windows platforms, primarily used for analyzing and debugging binary executable files.
* [ImmunityDbg](https://www.immunityinc.com/products/debugger) - is a powerful new way to write exploits, analyze malware, and reverse engineer binary files.
* [x64dbg](https://x64dbg.com) - is an powerful debugger for Windows, specifically designed to debug 64-bit applications.
* [WinDbg](https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger) - is a debugger that can be used to analyze crash dumps, debug live user-mode and kernel-mode code, and examine CPU registers and memory.
* [rundll32](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/rundll32) - Loads and runs 32-bit dynamic-link libraries (DLLs).
* [Ghidra](https://ghidra-sre.org) - suite of tools developed by NSA's Research Directorate in support of the Cybersecurity mission.
* [Binary Ninja](https://binary.ninja) - is an interactive decompiler, disassembler, debugger, and binary analysis platform built by reverse engineers, for reverse engineers.
* [Cutter](https://github.com/rizinorg/cutter) - is a free and open-source reverse engineering platform powered by rizin.
* [Rizin](https://github.com/rizinorg/rizin) - is portable and it can be used to analyze binaries, disassemble code, debug programs, as a forensic tool, as a scriptable command-line hexadecimal editor able to open disk files, and much more!.
* [Hopper](https://www.hopperapp.com/index.html) - disassembler, the reverse engineering tool that lets you disassemble, decompile and debug your applications.

**Java/Android**

* [javap](https://docs.oracle.com/javase/8/docs/technotes/tools/windows/javap.html) - Disassembles one or more class files.
* [javac](https://docs.oracle.com/en/java/javase/17/docs/specs/man/javac.html) - Reads source files that contain module, package and type declarations written in the Java programming language, and compiles them into class files that run on the Java Virtual Machine.
* [Bytecode viewer](https://www.bytecodeviewer.com) - is a graphical tool used primarily for reverse engineering and analyzing Java bytecode.
* [jadx](https://github.com/skylot/jadx) - Dex to Java decompiler.
* [jd-gui](https://github.com/java-decompiler/jd-gui) - a standalone graphical utility that displays Java sources from CLASS files.
* [apktool](https://apktool.org) - a tool for reverse engineering Android apk files.
* [mobsf](https://apktool.org) - a tool for reverse engineering Android apk files.

**.Net**

* [Dnspy](https://github.com/dnSpy/dnSpy) - is a debugger and .NET assembly editor. You can use it to edit and debug assemblies even if you don't have any source code available.
* [ildasm](https://learn.microsoft.com/en-us/dotnet/framework/tools/ildasm-exe-il-disassembler) - is a companion tool to the IL Assembler (Ilasm.exe). Ildasm.exe takes a portable executable (PE) file that contains intermediate language (IL) code and creates a text file suitable as input to Ilasm.exe.

**Flash**

* [JPEXS](https://github.com/jindrapetrik/jpexs-decompiler) - Open source Flash SWF decompiler and editor.

**Obfuscators**

* [ProGuard](https://github.com/Guardsquare/proguard) - is a free shrinker, optimizer, obfuscator, and preverifier for Java bytecode.

**Packers**

* [UPX](https://github.com/upx/upx) - a free, secure, portable, extendable, high-performance executable packer for several executable formats.
* [PE Compact](https://bitsum.com/portfolio/pecompact) - is a Windows executable compressor.
* [ASPack](http://aspack.com/aspack.html) -  is an advanced solution created to provide Win32 EXE file packing and to protect them against non-professional reverse engineering.

---

## Penetration Testing


## Contribute

Contributions are most welcome, please adhere to the [contribution guidelines](Contributing.md).

**[⬆ back to top](#malware-reversing)**

## License

[![Creative Commons License](http://i.creativecommons.org/l/by/4.0/88x31.png)](http://creativecommons.org/licenses/by/4.0/)

This work is licensed under a [Creative Commons Attribution 4.0 International License](http://creativecommons.org/licenses/by/4.0/).
