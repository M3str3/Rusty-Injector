
.\example\helloworld\hello_world.exe:     file format pei-i386

Characteristics 0x107
	relocations stripped
	executable
	line numbers stripped
	32 bit words

Time/Date		Thu Mar 28 17:49:09 2024
Magic			010b	(PE32)
MajorLinkerVersion	2
MinorLinkerVersion	32
SizeOfCode		00003000
SizeOfInitializedData	00005200
SizeOfUninitializedData	00000200
AddressOfEntryPoint	000012d0
BaseOfCode		00001000
BaseOfData		00004000
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
SizeOfImage		00012000
SizeOfHeaders		00000400
CheckSum		00015c98
Subsystem		00000003	(Windows CUI)
DllCharacteristics	00000000
SizeOfStackReserve	00200000
SizeOfStackCommit	00001000
SizeOfHeapReserve	00100000
SizeOfHeapCommit	00001000
LoaderFlags		00000000
NumberOfRvaAndSizes	00000010

The Data Directory
Entry 0 00000000 00000000 Export Directory [.edata (or where ever we found it)]
Entry 1 00008000 00000624 Import Directory [parts of .idata]
Entry 2 00000000 00000000 Resource Directory [.rsrc]
Entry 3 00000000 00000000 Exception Directory [.pdata]
Entry 4 00000000 00000000 Security Directory
Entry 5 00000000 00000000 Base Relocation Directory [.reloc]
Entry 6 00000000 00000000 Debug Directory
Entry 7 00000000 00000000 Description Directory
Entry 8 00000000 00000000 Special Directory
Entry 9 0000a004 00000018 Thread Storage Directory [.tls]
Entry a 00000000 00000000 Load Configuration Directory
Entry b 00000000 00000000 Bound Import Directory
Entry c 00008138 000000e8 Import Address Table Directory
Entry d 00000000 00000000 Delay Import Directory
Entry e 00000000 00000000 CLR Runtime Header
Entry f 00000000 00000000 Reserved

There is an import table in .idata at 0x408000

The Import Tables (interpreted .idata section contents)
 vma:            Hint    Time      Forward  DLL       First
                 Table   Stamp     Chain    Name      Thunk
 00008000	00008050 00000000 00000000 0000856c 00008138

	DLL Name: KERNEL32.dll
	vma:  Hint/Ord Member-Name Bound-To
	8220	  208  DeleteCriticalSection
	8238	  237  EnterCriticalSection
	8250	  280  ExitProcess
	825e	  301  FindClose
	826a	  305  FindFirstFileA
	827c	  322  FindNextFileA
	828c	  353  FreeLibrary
	829a	  389  GetCommandLineA
	82ac	  511  GetLastError
	82bc	  528  GetModuleFileNameA
	82d2	  530  GetModuleHandleA
	82e6	  578  GetProcAddress
	82f8	  735  InitializeCriticalSection
	8314	  815  LeaveCriticalSection
	832c	  818  LoadLibraryA
	833c	 1132  SetUnhandledExceptionFilter
	835a	 1165  TlsGetValue
	8368	 1205  VirtualProtect
	837a	 1207  VirtualQuery

 00008014	000080a0 00000000 00000000 00008584 00008188

	DLL Name: msvcrt.dll
	vma:  Hint/Ord Member-Name Bound-To
	838a	   81  _strdup
	8394	   83  _stricoll

 00008028	000080ac 00000000 00000000 00008618 00008194

	DLL Name: msvcrt.dll
	vma:  Hint/Ord Member-Name Bound-To
	83a0	   89  __getmainargs
	83b0	  120  __mb_cur_max
	83c0	  132  __p__environ
	83d0	  134  __p__fmode
	83de	  140  __p__pgmptr
	83ec	  154  __set_app_type
	83fe	  215  _cexit
	8408	  280  _errno
	8412	  319  _fpreset
	841e	  345  _fullpath
	842a	  412  _iob
	8432	  417  _isctype
	843e	  681  _msize
	8448	  684  _onexit
	8452	  693  _pctype
	845c	  748  _setmode
	8468	 1078  abort
	8470	 1086  atexit
	847a	 1093  calloc
	8484	 1137  fwrite
	848e	 1182  malloc
	8498	 1189  mbstowcs
	84a4	 1194  memcpy
	84ae	 1196  memmove
	84b8	 1203  printf
	84c2	 1222  setlocale
	84ce	 1224  signal
	84d8	 1237  strcoll
	84e2	 1244  strlen
	84ec	 1272  tolower
	84f6	 1279  vfprintf
	8502	 1320  wcstombs
	850e	 1126  free
	8516	 1215  realloc

 0000803c	00000000 00000000 00000000 00000000 00000000

