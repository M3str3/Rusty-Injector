
.\example\messagebox\messagebox.exe:     file format pei-i386

Characteristics 0x107
	relocations stripped
	executable
	line numbers stripped
	32 bit words

Time/Date		Wed Mar 20 17:09:18 2024
Magic			010b	(PE32)
MajorLinkerVersion	2
MinorLinkerVersion	32
SizeOfCode		00003200
SizeOfInitializedData	00005400
SizeOfUninitializedData	00000200
AddressOfEntryPoint	000012f0
BaseOfCode		00001000
BaseOfData		00005000
ImageBase		00400000
SectionAlignment	00001000
FileAlignment		00000200
MajorOSystemVersion	4
MinorOSystemVersion	0
MajorImageVersion	1
MinorImageVersion	0
MajorSubsystemVersion	4
MinorSubsystemVersion	0
Win32Version		00000000
SizeOfImage		00013000
SizeOfHeaders		00000400
CheckSum		0001b3f0
Subsystem		00000002	(Windows GUI)
DllCharacteristics	00000000
SizeOfStackReserve	00200000
SizeOfStackCommit	00001000
SizeOfHeapReserve	00100000
SizeOfHeapCommit	00001000
LoaderFlags		00000000
NumberOfRvaAndSizes	00000010

The Data Directory
Entry 0 00000000 00000000 Export Directory [.edata (or where ever we found it)]
Entry 1 00009000 000006ec Import Directory [parts of .idata]
Entry 2 00000000 00000000 Resource Directory [.rsrc]
Entry 3 00000000 00000000 Exception Directory [.pdata]
Entry 4 00000000 00000000 Security Directory
Entry 5 00000000 00000000 Base Relocation Directory [.reloc]
Entry 6 00000000 00000000 Debug Directory
Entry 7 00000000 00000000 Description Directory
Entry 8 00000000 00000000 Special Directory
Entry 9 0000b004 00000018 Thread Storage Directory [.tls]
Entry a 00000000 00000000 Load Configuration Directory
Entry b 00000000 00000000 Bound Import Directory
Entry c 00009174 000000fc Import Address Table Directory
Entry d 00000000 00000000 Delay Import Directory
Entry e 00000000 00000000 CLR Runtime Header
Entry f 00000000 00000000 Reserved

There is an import table in .idata at 0x409000

The Import Tables (interpreted .idata section contents)
 vma:            Hint    Time      Forward  DLL       First
                 Table   Stamp     Chain    Name      Thunk
 00009000	00009078 00000000 00000000 0000960c 00009174

	DLL Name: KERNEL32.dll
	vma:  Hint/Ord Member-Name Bound-To
	9270	  208  DeleteCriticalSection
	9288	  237  EnterCriticalSection
	92a0	  280  ExitProcess
	92ae	  301  FindClose
	92ba	  305  FindFirstFileA
	92cc	  322  FindNextFileA
	92dc	  353  FreeLibrary
	92ea	  389  GetCommandLineA
	92fc	  511  GetLastError
	930c	  528  GetModuleFileNameA
	9322	  530  GetModuleHandleA
	9336	  578  GetProcAddress
	9348	  607  GetStartupInfoA
	935a	  735  InitializeCriticalSection
	9376	  815  LeaveCriticalSection
	938e	  818  LoadLibraryA
	939e	 1132  SetUnhandledExceptionFilter
	93bc	 1165  TlsGetValue
	93ca	 1205  VirtualProtect
	93dc	 1207  VirtualQuery

 00009014	000090cc 00000000 00000000 00009624 000091c8

	DLL Name: msvcrt.dll
	vma:  Hint/Ord Member-Name Bound-To
	93ec	   81  _strdup
	93f6	   83  _stricoll

 00009028	000090d8 00000000 00000000 000096b4 000091d4

	DLL Name: msvcrt.dll
	vma:  Hint/Ord Member-Name Bound-To
	9402	   89  __getmainargs
	9412	  120  __mb_cur_max
	9422	  132  __p__environ
	9432	  134  __p__fmode
	9440	  140  __p__pgmptr
	944e	  154  __set_app_type
	9460	  215  _cexit
	946a	  280  _errno
	9474	  319  _fpreset
	9480	  345  _fullpath
	948c	  412  _iob
	9494	  417  _isctype
	94a0	  681  _msize
	94aa	  684  _onexit
	94b4	  693  _pctype
	94be	  748  _setmode
	94ca	 1078  abort
	94d2	 1086  atexit
	94dc	 1093  calloc
	94e6	 1137  fwrite
	94f0	 1182  malloc
	94fa	 1189  mbstowcs
	9506	 1194  memcpy
	9510	 1196  memmove
	951a	 1222  setlocale
	9526	 1224  signal
	9530	 1237  strcoll
	953a	 1244  strlen
	9544	 1272  tolower
	954e	 1279  vfprintf
	955a	 1320  wcstombs
	9566	 1126  free
	956e	 1215  realloc

 0000903c	00009160 00000000 00000000 000096c4 0000925c

	DLL Name: USER32.dll
	vma:  Hint/Ord Member-Name Bound-To
	9578	  440  MessageBoxW

 00009050	00009168 00000000 00000000 000096d8 00009264

	DLL Name: libgcc_s_dw2-1.dll
	vma:  Hint/Ord Member-Name Bound-To
	9588	   37  __deregister_frame_info
	95a4	  107  __register_frame_info

 00009064	00000000 00000000 00000000 00000000 00000000

