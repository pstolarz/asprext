asprext
=======

This project arose as a result of my work on analysis of x86-targeted anti-piracy
software: ASProtect v1.6/1.7. On that time ASProtect seemed to be a quite decent
piece of software, which (among other means) extensively used various VM
emulation techniques to guard important parts of the protected target like:
crucial parts of code, Original Entry Point (OEP) location, imports calls etc.

`asprext` is a WindDbg extension consisting of a set of tools, which I wrote
for the purpose of my analysis allowing effectively reverse engineering this
software.

NOTE: Since I have no more time (and interest) to further work on this, I
abandoned the project. If someone is interested in this topic and wants to
continue work on it, feel free to contact me.

Notes
-----

Some notes on the directories structure:

* `.\analysis` contains my annotated disassembly notes and other files helpful
  during the analysis.

* `.\script` contains set of WindDbg unpacking scripts. The main script is
  `.\script\main` launched by:

      0:000> $$>a< main mod_base

  where `mod_base` specifies an address of unpacked, ASPR-protected module.

  NOTE: The scripts extensively use other of my WinDbg extensions: `dumpext`
  and `scriptext`, therefore they may serve as an illustration of usage of
  those extensions.

  https://github.com/pstolarz/dumpext  
  https://github.com/pstolarz/scriptext

* `.\test` contains some x86 apps, ASPR protected (on various level of
  protection), and unpacked versions of them. Used for testing the extension.

* The rest constitutes the project sources. For x86 disassembly BSD-licensed
  NASM code has been used (slightly patched):

  http://www.nasm.us

Disclaimer
----------

THE PROJECT IS MEANT FOR EDUCATIONAL PURPOSE ONLY. THE AUTHOR TAKES NO
RESPONSIBILITY OR LIABILITY CAUSED BY USING THIS SOFTWARE FOR ANY OTHER PURPOSES.

License
-------
GNU GENERAL PUBLIC LICENSE v2. See LICENSE file for details.
