
.\example\helloworld\hello_world.exe:     file format pei-i386


Disassembly of section .text:

00401000 <.text>:
  401000:	83 ec 1c             	sub    $0x1c,%esp
  401003:	8b 44 24 20          	mov    0x20(%esp),%eax
  401007:	8b 00                	mov    (%eax),%eax
  401009:	8b 00                	mov    (%eax),%eax
  40100b:	3d 93 00 00 c0       	cmp    $0xc0000093,%eax
  401010:	74 1b                	je     40102d <.text+0x2d>
  401012:	77 4c                	ja     401060 <.text+0x60>
  401014:	3d 1d 00 00 c0       	cmp    $0xc000001d,%eax
  401019:	0f 84 cc 00 00 00    	je     4010eb <.text+0xeb>
  40101f:	76 7f                	jbe    4010a0 <.text+0xa0>
  401021:	05 73 ff ff 3f       	add    $0x3fffff73,%eax
  401026:	31 d2                	xor    %edx,%edx
  401028:	83 f8 04             	cmp    $0x4,%eax
  40102b:	77 27                	ja     401054 <.text+0x54>
  40102d:	c7 44 24 04 00 00 00 	movl   $0x0,0x4(%esp)
  401034:	00 
  401035:	c7 04 24 08 00 00 00 	movl   $0x8,(%esp)
  40103c:	e8 53 2e 00 00       	call   403e94 <_signal>
  401041:	83 f8 01             	cmp    $0x1,%eax
  401044:	0f 84 d6 00 00 00    	je     401120 <.text+0x120>
  40104a:	85 c0                	test   %eax,%eax
  40104c:	0f 85 fe 00 00 00    	jne    401150 <.text+0x150>
  401052:	31 d2                	xor    %edx,%edx
  401054:	89 d0                	mov    %edx,%eax
  401056:	83 c4 1c             	add    $0x1c,%esp
  401059:	c2 04 00             	ret    $0x4
  40105c:	8d 74 26 00          	lea    0x0(%esi,%eiz,1),%esi
  401060:	3d 94 00 00 c0       	cmp    $0xc0000094,%eax
  401065:	75 79                	jne    4010e0 <.text+0xe0>
  401067:	c7 44 24 04 00 00 00 	movl   $0x0,0x4(%esp)
  40106e:	00 
  40106f:	c7 04 24 08 00 00 00 	movl   $0x8,(%esp)
  401076:	e8 19 2e 00 00       	call   403e94 <_signal>
  40107b:	83 f8 01             	cmp    $0x1,%eax
  40107e:	75 ca                	jne    40104a <.text+0x4a>
  401080:	c7 44 24 04 01 00 00 	movl   $0x1,0x4(%esp)
  401087:	00 
  401088:	c7 04 24 08 00 00 00 	movl   $0x8,(%esp)
  40108f:	e8 00 2e 00 00       	call   403e94 <_signal>
  401094:	ba ff ff ff ff       	mov    $0xffffffff,%edx
  401099:	eb b9                	jmp    401054 <.text+0x54>
  40109b:	8d 74 26 00          	lea    0x0(%esi,%eiz,1),%esi
  40109f:	90                   	nop
  4010a0:	3d 05 00 00 c0       	cmp    $0xc0000005,%eax
  4010a5:	75 ab                	jne    401052 <.text+0x52>
  4010a7:	c7 44 24 04 00 00 00 	movl   $0x0,0x4(%esp)
  4010ae:	00 
  4010af:	c7 04 24 0b 00 00 00 	movl   $0xb,(%esp)
  4010b6:	e8 d9 2d 00 00       	call   403e94 <_signal>
  4010bb:	83 f8 01             	cmp    $0x1,%eax
  4010be:	0f 84 9f 00 00 00    	je     401163 <.text+0x163>
  4010c4:	85 c0                	test   %eax,%eax
  4010c6:	74 8a                	je     401052 <.text+0x52>
  4010c8:	c7 04 24 0b 00 00 00 	movl   $0xb,(%esp)
  4010cf:	ff d0                	call   *%eax
  4010d1:	ba ff ff ff ff       	mov    $0xffffffff,%edx
  4010d6:	e9 79 ff ff ff       	jmp    401054 <.text+0x54>
  4010db:	8d 74 26 00          	lea    0x0(%esi,%eiz,1),%esi
  4010df:	90                   	nop
  4010e0:	3d 96 00 00 c0       	cmp    $0xc0000096,%eax
  4010e5:	0f 85 67 ff ff ff    	jne    401052 <.text+0x52>
  4010eb:	c7 44 24 04 00 00 00 	movl   $0x0,0x4(%esp)
  4010f2:	00 
  4010f3:	c7 04 24 04 00 00 00 	movl   $0x4,(%esp)
  4010fa:	e8 95 2d 00 00       	call   403e94 <_signal>
  4010ff:	83 f8 01             	cmp    $0x1,%eax
  401102:	74 7b                	je     40117f <.text+0x17f>
  401104:	85 c0                	test   %eax,%eax
  401106:	0f 84 46 ff ff ff    	je     401052 <.text+0x52>
  40110c:	c7 04 24 04 00 00 00 	movl   $0x4,(%esp)
  401113:	ff d0                	call   *%eax
  401115:	ba ff ff ff ff       	mov    $0xffffffff,%edx
  40111a:	e9 35 ff ff ff       	jmp    401054 <.text+0x54>
  40111f:	90                   	nop
  401120:	c7 44 24 04 01 00 00 	movl   $0x1,0x4(%esp)
  401127:	00 
  401128:	c7 04 24 08 00 00 00 	movl   $0x8,(%esp)
  40112f:	e8 60 2d 00 00       	call   403e94 <_signal>
  401134:	c7 04 24 00 00 00 00 	movl   $0x0,(%esp)
  40113b:	e8 a0 0f 00 00       	call   4020e0 <_fesetenv>
  401140:	ba ff ff ff ff       	mov    $0xffffffff,%edx
  401145:	e9 0a ff ff ff       	jmp    401054 <.text+0x54>
  40114a:	8d b6 00 00 00 00    	lea    0x0(%esi),%esi
  401150:	c7 04 24 08 00 00 00 	movl   $0x8,(%esp)
  401157:	ff d0                	call   *%eax
  401159:	ba ff ff ff ff       	mov    $0xffffffff,%edx
  40115e:	e9 f1 fe ff ff       	jmp    401054 <.text+0x54>
  401163:	c7 44 24 04 01 00 00 	movl   $0x1,0x4(%esp)
  40116a:	00 
  40116b:	c7 04 24 0b 00 00 00 	movl   $0xb,(%esp)
  401172:	e8 1d 2d 00 00       	call   403e94 <_signal>
  401177:	83 ca ff             	or     $0xffffffff,%edx
  40117a:	e9 d5 fe ff ff       	jmp    401054 <.text+0x54>
  40117f:	c7 44 24 04 01 00 00 	movl   $0x1,0x4(%esp)
  401186:	00 
  401187:	c7 04 24 04 00 00 00 	movl   $0x4,(%esp)
  40118e:	e8 01 2d 00 00       	call   403e94 <_signal>
  401193:	83 ca ff             	or     $0xffffffff,%edx
  401196:	e9 b9 fe ff ff       	jmp    401054 <.text+0x54>
  40119b:	8d 74 26 00          	lea    0x0(%esi,%eiz,1),%esi
  40119f:	90                   	nop
  4011a0:	53                   	push   %ebx
  4011a1:	83 ec 18             	sub    $0x18,%esp
  4011a4:	a1 5c 51 40 00       	mov    0x40515c,%eax
  4011a9:	85 c0                	test   %eax,%eax
  4011ab:	74 1c                	je     4011c9 <.text+0x1c9>
  4011ad:	c7 44 24 08 00 00 00 	movl   $0x0,0x8(%esp)
  4011b4:	00 
  4011b5:	c7 44 24 04 02 00 00 	movl   $0x2,0x4(%esp)
  4011bc:	00 
  4011bd:	c7 04 24 00 00 00 00 	movl   $0x0,(%esp)
  4011c4:	ff d0                	call   *%eax
  4011c6:	83 ec 0c             	sub    $0xc,%esp
  4011c9:	c7 04 24 00 10 40 00 	movl   $0x401000,(%esp)
  4011d0:	e8 77 2d 00 00       	call   403f4c <_SetUnhandledExceptionFilter@4>
  4011d5:	83 ec 04             	sub    $0x4,%esp
  4011d8:	e8 c3 06 00 00       	call   4018a0 <___cpu_features_init>
  4011dd:	a1 08 40 40 00       	mov    0x404008,%eax
  4011e2:	89 04 24             	mov    %eax,(%esp)
  4011e5:	e8 f6 0e 00 00       	call   4020e0 <_fesetenv>
  4011ea:	e8 51 02 00 00       	call   401440 <__setargv>
  4011ef:	a1 20 70 40 00       	mov    0x407020,%eax
  4011f4:	85 c0                	test   %eax,%eax
  4011f6:	75 4a                	jne    401242 <.text+0x242>
  4011f8:	e8 1f 2d 00 00       	call   403f1c <___p__fmode>
  4011fd:	8b 15 0c 40 40 00    	mov    0x40400c,%edx
  401203:	89 10                	mov    %edx,(%eax)
  401205:	e8 e6 0c 00 00       	call   401ef0 <__pei386_runtime_relocator>
  40120a:	83 e4 f0             	and    $0xfffffff0,%esp
  40120d:	e8 3e 08 00 00       	call   401a50 <___main>
  401212:	e8 0d 2d 00 00       	call   403f24 <___p__environ>
  401217:	8b 00                	mov    (%eax),%eax
  401219:	89 44 24 08          	mov    %eax,0x8(%esp)
  40121d:	a1 00 70 40 00       	mov    0x407000,%eax
  401222:	89 44 24 04          	mov    %eax,0x4(%esp)
  401226:	a1 04 70 40 00       	mov    0x407004,%eax
  40122b:	89 04 24             	mov    %eax,(%esp)
  40122e:	e8 dd 01 00 00       	call   401410 <_main>
  401233:	89 c3                	mov    %eax,%ebx
  401235:	e8 d2 2c 00 00       	call   403f0c <__cexit>
  40123a:	89 1c 24             	mov    %ebx,(%esp)
  40123d:	e8 72 2d 00 00       	call   403fb4 <_ExitProcess@4>
  401242:	8b 1d bc 81 40 00    	mov    0x4081bc,%ebx
  401248:	89 44 24 04          	mov    %eax,0x4(%esp)
  40124c:	a3 0c 40 40 00       	mov    %eax,0x40400c
  401251:	8b 43 10             	mov    0x10(%ebx),%eax
  401254:	89 04 24             	mov    %eax,(%esp)
  401257:	e8 88 2c 00 00       	call   403ee4 <__setmode>
  40125c:	a1 20 70 40 00       	mov    0x407020,%eax
  401261:	89 44 24 04          	mov    %eax,0x4(%esp)
  401265:	8b 43 30             	mov    0x30(%ebx),%eax
  401268:	89 04 24             	mov    %eax,(%esp)
  40126b:	e8 74 2c 00 00       	call   403ee4 <__setmode>
  401270:	a1 20 70 40 00       	mov    0x407020,%eax
  401275:	89 44 24 04          	mov    %eax,0x4(%esp)
  401279:	8b 43 50             	mov    0x50(%ebx),%eax
  40127c:	89 04 24             	mov    %eax,(%esp)
  40127f:	e8 60 2c 00 00       	call   403ee4 <__setmode>
  401284:	e9 6f ff ff ff       	jmp    4011f8 <.text+0x1f8>
  401289:	8d b4 26 00 00 00 00 	lea    0x0(%esi,%eiz,1),%esi

00401290 <__mingw32_init_mainargs>:
  401290:	83 ec 3c             	sub    $0x3c,%esp
  401293:	8d 44 24 2c          	lea    0x2c(%esp),%eax
  401297:	c7 44 24 04 00 70 40 	movl   $0x407000,0x4(%esp)
  40129e:	00 
  40129f:	89 44 24 10          	mov    %eax,0x10(%esp)
  4012a3:	a1 04 40 40 00       	mov    0x404004,%eax
  4012a8:	c7 04 24 04 70 40 00 	movl   $0x407004,(%esp)
  4012af:	83 e0 01             	and    $0x1,%eax
  4012b2:	c7 44 24 2c 00 00 00 	movl   $0x0,0x2c(%esp)
  4012b9:	00 
  4012ba:	89 44 24 0c          	mov    %eax,0xc(%esp)
  4012be:	8d 44 24 28          	lea    0x28(%esp),%eax
  4012c2:	89 44 24 08          	mov    %eax,0x8(%esp)
  4012c6:	e8 61 2c 00 00       	call   403f2c <___getmainargs>
  4012cb:	83 c4 3c             	add    $0x3c,%esp
  4012ce:	c3                   	ret    
  4012cf:	90                   	nop

004012d0 <_mainCRTStartup>:
  4012d0:	83 ec 1c             	sub    $0x1c,%esp
  4012d3:	c7 04 24 01 00 00 00 	movl   $0x1,(%esp)
  4012da:	ff 15 a8 81 40 00    	call   *0x4081a8
  4012e0:	e8 bb fe ff ff       	call   4011a0 <.text+0x1a0>
  4012e5:	8d b4 26 00 00 00 00 	lea    0x0(%esi,%eiz,1),%esi
  4012ec:	8d 74 26 00          	lea    0x0(%esi,%eiz,1),%esi

004012f0 <_WinMainCRTStartup>:
  4012f0:	83 ec 1c             	sub    $0x1c,%esp
  4012f3:	c7 04 24 02 00 00 00 	movl   $0x2,(%esp)
  4012fa:	ff 15 a8 81 40 00    	call   *0x4081a8
  401300:	e8 9b fe ff ff       	call   4011a0 <.text+0x1a0>
  401305:	8d b4 26 00 00 00 00 	lea    0x0(%esi,%eiz,1),%esi
  40130c:	8d 74 26 00          	lea    0x0(%esi,%eiz,1),%esi

00401310 <_atexit>:
  401310:	ff 25 d8 81 40 00    	jmp    *0x4081d8
  401316:	8d b4 26 00 00 00 00 	lea    0x0(%esi,%eiz,1),%esi
  40131d:	8d 76 00             	lea    0x0(%esi),%esi

00401320 <__onexit>:
  401320:	ff 25 c8 81 40 00    	jmp    *0x4081c8
  401326:	90                   	nop
  401327:	90                   	nop
  401328:	90                   	nop
  401329:	90                   	nop
  40132a:	90                   	nop
  40132b:	90                   	nop
  40132c:	90                   	nop
  40132d:	90                   	nop
  40132e:	90                   	nop
  40132f:	90                   	nop

00401330 <___gcc_register_frame>:
  401330:	55                   	push   %ebp
  401331:	89 e5                	mov    %esp,%ebp
  401333:	56                   	push   %esi
  401334:	53                   	push   %ebx
  401335:	83 ec 10             	sub    $0x10,%esp
  401338:	c7 04 24 00 50 40 00 	movl   $0x405000,(%esp)
  40133f:	e8 30 2c 00 00       	call   403f74 <_GetModuleHandleA@4>
  401344:	83 ec 04             	sub    $0x4,%esp
  401347:	85 c0                	test   %eax,%eax
  401349:	74 75                	je     4013c0 <___gcc_register_frame+0x90>
  40134b:	c7 04 24 00 50 40 00 	movl   $0x405000,(%esp)
  401352:	89 c3                	mov    %eax,%ebx
  401354:	e8 fb 2b 00 00       	call   403f54 <_LoadLibraryA@4>
  401359:	83 ec 04             	sub    $0x4,%esp
  40135c:	a3 70 70 40 00       	mov    %eax,0x407070
  401361:	c7 44 24 04 13 50 40 	movl   $0x405013,0x4(%esp)
  401368:	00 
  401369:	89 1c 24             	mov    %ebx,(%esp)
  40136c:	e8 fb 2b 00 00       	call   403f6c <_GetProcAddress@8>
  401371:	83 ec 08             	sub    $0x8,%esp
  401374:	89 c6                	mov    %eax,%esi
  401376:	c7 44 24 04 29 50 40 	movl   $0x405029,0x4(%esp)
  40137d:	00 
  40137e:	89 1c 24             	mov    %ebx,(%esp)
  401381:	e8 e6 2b 00 00       	call   403f6c <_GetProcAddress@8>
  401386:	a3 00 40 40 00       	mov    %eax,0x404000
  40138b:	83 ec 08             	sub    $0x8,%esp
  40138e:	85 f6                	test   %esi,%esi
  401390:	74 11                	je     4013a3 <___gcc_register_frame+0x73>
  401392:	c7 44 24 04 08 70 40 	movl   $0x407008,0x4(%esp)
  401399:	00 
  40139a:	c7 04 24 c8 60 40 00 	movl   $0x4060c8,(%esp)
  4013a1:	ff d6                	call   *%esi
  4013a3:	c7 04 24 e0 13 40 00 	movl   $0x4013e0,(%esp)
  4013aa:	e8 61 ff ff ff       	call   401310 <_atexit>
  4013af:	8d 65 f8             	lea    -0x8(%ebp),%esp
  4013b2:	5b                   	pop    %ebx
  4013b3:	5e                   	pop    %esi
  4013b4:	5d                   	pop    %ebp
  4013b5:	c3                   	ret    
  4013b6:	8d b4 26 00 00 00 00 	lea    0x0(%esi,%eiz,1),%esi
  4013bd:	8d 76 00             	lea    0x0(%esi),%esi
  4013c0:	c7 05 00 40 40 00 00 	movl   $0x0,0x404000
  4013c7:	00 00 00 
  4013ca:	be 00 00 00 00       	mov    $0x0,%esi
  4013cf:	eb bd                	jmp    40138e <___gcc_register_frame+0x5e>
  4013d1:	8d b4 26 00 00 00 00 	lea    0x0(%esi,%eiz,1),%esi
  4013d8:	8d b4 26 00 00 00 00 	lea    0x0(%esi,%eiz,1),%esi
  4013df:	90                   	nop

004013e0 <___gcc_deregister_frame>:
  4013e0:	55                   	push   %ebp
  4013e1:	89 e5                	mov    %esp,%ebp
  4013e3:	83 ec 18             	sub    $0x18,%esp
  4013e6:	a1 00 40 40 00       	mov    0x404000,%eax
  4013eb:	85 c0                	test   %eax,%eax
  4013ed:	74 09                	je     4013f8 <___gcc_deregister_frame+0x18>
  4013ef:	c7 04 24 c8 60 40 00 	movl   $0x4060c8,(%esp)
  4013f6:	ff d0                	call   *%eax
  4013f8:	a1 70 70 40 00       	mov    0x407070,%eax
  4013fd:	85 c0                	test   %eax,%eax
  4013ff:	74 0b                	je     40140c <___gcc_deregister_frame+0x2c>
  401401:	89 04 24             	mov    %eax,(%esp)
  401404:	e8 8b 2b 00 00       	call   403f94 <_FreeLibrary@4>
  401409:	83 ec 04             	sub    $0x4,%esp
  40140c:	c9                   	leave  
  40140d:	c3                   	ret    
  40140e:	90                   	nop
  40140f:	90                   	nop

00401410 <_main>:
  401410:	55                   	push   %ebp
  401411:	89 e5                	mov    %esp,%ebp
  401413:	83 e4 f0             	and    $0xfffffff0,%esp
  401416:	83 ec 10             	sub    $0x10,%esp
  401419:	e8 32 06 00 00       	call   401a50 <___main>
  40141e:	c7 04 24 44 50 40 00 	movl   $0x405044,(%esp)
  401425:	e8 7a 2a 00 00       	call   403ea4 <_printf>
  40142a:	b8 00 00 00 00       	mov    $0x0,%eax
  40142f:	c9                   	leave  
  401430:	c3                   	ret    
  401431:	90                   	nop
  401432:	90                   	nop
  401433:	90                   	nop
  401434:	66 90                	xchg   %ax,%ax
  401436:	66 90                	xchg   %ax,%ax
  401438:	66 90                	xchg   %ax,%ax
  40143a:	66 90                	xchg   %ax,%ax
  40143c:	66 90                	xchg   %ax,%ax
  40143e:	66 90                	xchg   %ax,%ax

00401440 <__setargv>:
  401440:	55                   	push   %ebp
  401441:	89 e5                	mov    %esp,%ebp
  401443:	57                   	push   %edi
  401444:	56                   	push   %esi
  401445:	53                   	push   %ebx
  401446:	81 ec 4c 01 00 00    	sub    $0x14c,%esp
  40144c:	f6 05 04 40 40 00 02 	testb  $0x2,0x404004
  401453:	75 13                	jne    401468 <__setargv+0x28>
  401455:	e8 36 fe ff ff       	call   401290 <__mingw32_init_mainargs>
  40145a:	8d 65 f4             	lea    -0xc(%ebp),%esp
  40145d:	5b                   	pop    %ebx
  40145e:	5e                   	pop    %esi
  40145f:	5f                   	pop    %edi
  401460:	5d                   	pop    %ebp
  401461:	c3                   	ret    
  401462:	8d b6 00 00 00 00    	lea    0x0(%esi),%esi
  401468:	e8 1f 2b 00 00       	call   403f8c <_GetCommandLineA@0>
  40146d:	89 a5 c0 fe ff ff    	mov    %esp,-0x140(%ebp)
  401473:	89 04 24             	mov    %eax,(%esp)
  401476:	89 c3                	mov    %eax,%ebx
  401478:	e8 07 2a 00 00       	call   403e84 <_strlen>
  40147d:	8d 44 00 11          	lea    0x11(%eax,%eax,1),%eax
  401481:	c1 e8 04             	shr    $0x4,%eax
  401484:	c1 e0 04             	shl    $0x4,%eax
  401487:	e8 a4 29 00 00       	call   403e30 <___chkstk_ms>
  40148c:	c7 85 f0 fe ff ff 00 	movl   $0x0,-0x110(%ebp)
  401493:	00 00 00 
  401496:	29 c4                	sub    %eax,%esp
  401498:	0f be 3b             	movsbl (%ebx),%edi
  40149b:	a1 04 40 40 00       	mov    0x404004,%eax
  4014a0:	8d 74 24 10          	lea    0x10(%esp),%esi
  4014a4:	89 b5 c8 fe ff ff    	mov    %esi,-0x138(%ebp)
  4014aa:	25 00 44 00 00       	and    $0x4400,%eax
  4014af:	83 c8 10             	or     $0x10,%eax
  4014b2:	89 85 c4 fe ff ff    	mov    %eax,-0x13c(%ebp)
  4014b8:	8d 43 01             	lea    0x1(%ebx),%eax
  4014bb:	89 fb                	mov    %edi,%ebx
  4014bd:	89 85 d4 fe ff ff    	mov    %eax,-0x12c(%ebp)
  4014c3:	85 ff                	test   %edi,%edi
  4014c5:	0f 84 e4 00 00 00    	je     4015af <__setargv+0x16f>
  4014cb:	c7 85 cc fe ff ff 00 	movl   $0x0,-0x134(%ebp)
  4014d2:	00 00 00 
  4014d5:	89 f0                	mov    %esi,%eax
  4014d7:	31 d2                	xor    %edx,%edx
  4014d9:	c7 85 d0 fe ff ff 00 	movl   $0x0,-0x130(%ebp)
  4014e0:	00 00 00 
  4014e3:	8d 74 26 00          	lea    0x0(%esi,%eiz,1),%esi
  4014e7:	90                   	nop
  4014e8:	80 fb 3f             	cmp    $0x3f,%bl
  4014eb:	0f 8f e7 02 00 00    	jg     4017d8 <__setargv+0x398>
  4014f1:	80 fb 21             	cmp    $0x21,%bl
  4014f4:	0f 8f e6 01 00 00    	jg     4016e0 <__setargv+0x2a0>
  4014fa:	8d 34 10             	lea    (%eax,%edx,1),%esi
  4014fd:	85 d2                	test   %edx,%edx
  4014ff:	0f 84 70 03 00 00    	je     401875 <__setargv+0x435>
  401505:	8d 76 00             	lea    0x0(%esi),%esi
  401508:	83 c0 01             	add    $0x1,%eax
  40150b:	c6 40 ff 5c          	movb   $0x5c,-0x1(%eax)
  40150f:	39 f0                	cmp    %esi,%eax
  401511:	75 f5                	jne    401508 <__setargv+0xc8>
  401513:	8b 85 d0 fe ff ff    	mov    -0x130(%ebp),%eax
  401519:	85 c0                	test   %eax,%eax
  40151b:	0f 85 27 01 00 00    	jne    401648 <__setargv+0x208>
  401521:	a1 98 81 40 00       	mov    0x408198,%eax
  401526:	83 38 01             	cmpl   $0x1,(%eax)
  401529:	0f 85 f1 00 00 00    	jne    401620 <__setargv+0x1e0>
  40152f:	a1 cc 81 40 00       	mov    0x4081cc,%eax
  401534:	8b 00                	mov    (%eax),%eax
  401536:	f6 04 78 40          	testb  $0x40,(%eax,%edi,2)
  40153a:	0f 84 f8 00 00 00    	je     401638 <__setargv+0x1f8>
  401540:	39 b5 c8 fe ff ff    	cmp    %esi,-0x138(%ebp)
  401546:	0f 82 44 01 00 00    	jb     401690 <__setargv+0x250>
  40154c:	8b 9d cc fe ff ff    	mov    -0x134(%ebp),%ebx
  401552:	85 db                	test   %ebx,%ebx
  401554:	0f 85 36 01 00 00    	jne    401690 <__setargv+0x250>
  40155a:	c7 85 cc fe ff ff 00 	movl   $0x0,-0x134(%ebp)
  401561:	00 00 00 
  401564:	89 f0                	mov    %esi,%eax
  401566:	31 d2                	xor    %edx,%edx
  401568:	e9 e2 00 00 00       	jmp    40164f <__setargv+0x20f>
  40156d:	89 c2                	mov    %eax,%edx
  40156f:	90                   	nop
  401570:	39 95 c8 fe ff ff    	cmp    %edx,-0x138(%ebp)
  401576:	72 0a                	jb     401582 <__setargv+0x142>
  401578:	8b 8d cc fe ff ff    	mov    -0x134(%ebp),%ecx
  40157e:	85 c9                	test   %ecx,%ecx
  401580:	74 2d                	je     4015af <__setargv+0x16f>
  401582:	8d 85 e4 fe ff ff    	lea    -0x11c(%ebp),%eax
  401588:	c6 02 00             	movb   $0x0,(%edx)
  40158b:	89 44 24 0c          	mov    %eax,0xc(%esp)
  40158f:	c7 44 24 08 00 00 00 	movl   $0x0,0x8(%esp)
  401596:	00 
  401597:	8b 85 c4 fe ff ff    	mov    -0x13c(%ebp),%eax
  40159d:	89 44 24 04          	mov    %eax,0x4(%esp)
  4015a1:	8b 85 c8 fe ff ff    	mov    -0x138(%ebp),%eax
  4015a7:	89 04 24             	mov    %eax,(%esp)
  4015aa:	e8 81 1b 00 00       	call   403130 <___mingw_glob>
  4015af:	8b 85 e8 fe ff ff    	mov    -0x118(%ebp),%eax
  4015b5:	a3 04 70 40 00       	mov    %eax,0x407004
  4015ba:	8b 85 ec fe ff ff    	mov    -0x114(%ebp),%eax
  4015c0:	a3 00 70 40 00       	mov    %eax,0x407000
  4015c5:	8b a5 c0 fe ff ff    	mov    -0x140(%ebp),%esp
  4015cb:	e8 44 29 00 00       	call   403f14 <___p__pgmptr>
  4015d0:	8b 00                	mov    (%eax),%eax
  4015d2:	85 c0                	test   %eax,%eax
  4015d4:	0f 85 80 fe ff ff    	jne    40145a <__setargv+0x1a>
  4015da:	8d 9d e4 fe ff ff    	lea    -0x11c(%ebp),%ebx
  4015e0:	c7 44 24 08 04 01 00 	movl   $0x104,0x8(%esp)
  4015e7:	00 
  4015e8:	89 5c 24 04          	mov    %ebx,0x4(%esp)
  4015ec:	c7 04 24 00 00 00 00 	movl   $0x0,(%esp)
  4015f3:	e8 84 29 00 00       	call   403f7c <_GetModuleFileNameA@12>
  4015f8:	83 e8 01             	sub    $0x1,%eax
  4015fb:	83 ec 0c             	sub    $0xc,%esp
  4015fe:	3d 02 01 00 00       	cmp    $0x102,%eax
  401603:	0f 87 51 fe ff ff    	ja     40145a <__setargv+0x1a>
  401609:	e8 06 29 00 00       	call   403f14 <___p__pgmptr>
  40160e:	89 1c 24             	mov    %ebx,(%esp)
  401611:	89 c6                	mov    %eax,%esi
  401613:	e8 4c 28 00 00       	call   403e64 <_strdup>
  401618:	89 06                	mov    %eax,(%esi)
  40161a:	e9 3b fe ff ff       	jmp    40145a <__setargv+0x1a>
  40161f:	90                   	nop
  401620:	c7 44 24 04 40 00 00 	movl   $0x40,0x4(%esp)
  401627:	00 
  401628:	89 3c 24             	mov    %edi,(%esp)
  40162b:	e8 c4 28 00 00       	call   403ef4 <__isctype>
  401630:	85 c0                	test   %eax,%eax
  401632:	0f 85 08 ff ff ff    	jne    401540 <__setargv+0x100>
  401638:	83 ff 09             	cmp    $0x9,%edi
  40163b:	0f 84 ff fe ff ff    	je     401540 <__setargv+0x100>
  401641:	8d b4 26 00 00 00 00 	lea    0x0(%esi,%eiz,1),%esi
  401648:	88 1e                	mov    %bl,(%esi)
  40164a:	8d 46 01             	lea    0x1(%esi),%eax
  40164d:	31 d2                	xor    %edx,%edx
  40164f:	83 85 d4 fe ff ff 01 	addl   $0x1,-0x12c(%ebp)
  401656:	8b bd d4 fe ff ff    	mov    -0x12c(%ebp),%edi
  40165c:	0f be 7f ff          	movsbl -0x1(%edi),%edi
  401660:	89 fb                	mov    %edi,%ebx
  401662:	85 ff                	test   %edi,%edi
  401664:	0f 85 7e fe ff ff    	jne    4014e8 <__setargv+0xa8>
  40166a:	85 d2                	test   %edx,%edx
  40166c:	0f 84 fb fe ff ff    	je     40156d <__setargv+0x12d>
  401672:	01 c2                	add    %eax,%edx
  401674:	8d 74 26 00          	lea    0x0(%esi,%eiz,1),%esi
  401678:	83 c0 01             	add    $0x1,%eax
  40167b:	c6 40 ff 5c          	movb   $0x5c,-0x1(%eax)
  40167f:	39 d0                	cmp    %edx,%eax
  401681:	75 f5                	jne    401678 <__setargv+0x238>
  401683:	e9 e8 fe ff ff       	jmp    401570 <__setargv+0x130>
  401688:	8d b4 26 00 00 00 00 	lea    0x0(%esi,%eiz,1),%esi
  40168f:	90                   	nop
  401690:	8d 85 e4 fe ff ff    	lea    -0x11c(%ebp),%eax
  401696:	c6 06 00             	movb   $0x0,(%esi)
  401699:	89 44 24 0c          	mov    %eax,0xc(%esp)
  40169d:	c7 44 24 08 00 00 00 	movl   $0x0,0x8(%esp)
  4016a4:	00 
  4016a5:	8b b5 c4 fe ff ff    	mov    -0x13c(%ebp),%esi
  4016ab:	89 74 24 04          	mov    %esi,0x4(%esp)
  4016af:	8b bd c8 fe ff ff    	mov    -0x138(%ebp),%edi
  4016b5:	83 ce 01             	or     $0x1,%esi
  4016b8:	89 3c 24             	mov    %edi,(%esp)
  4016bb:	e8 70 1a 00 00       	call   403130 <___mingw_glob>
  4016c0:	89 b5 c4 fe ff ff    	mov    %esi,-0x13c(%ebp)
  4016c6:	89 f8                	mov    %edi,%eax
  4016c8:	31 d2                	xor    %edx,%edx
  4016ca:	c7 85 cc fe ff ff 00 	movl   $0x0,-0x134(%ebp)
  4016d1:	00 00 00 
  4016d4:	e9 76 ff ff ff       	jmp    40164f <__setargv+0x20f>
  4016d9:	8d b4 26 00 00 00 00 	lea    0x0(%esi,%eiz,1),%esi
  4016e0:	8d 4b de             	lea    -0x22(%ebx),%ecx
  4016e3:	80 f9 1d             	cmp    $0x1d,%cl
  4016e6:	0f 87 0e fe ff ff    	ja     4014fa <__setargv+0xba>
  4016ec:	0f b6 c9             	movzbl %cl,%ecx
  4016ef:	ff 24 8d 50 50 40 00 	jmp    *0x405050(,%ecx,4)
  4016f6:	8d 72 ff             	lea    -0x1(%edx),%esi
  4016f9:	83 ff 7f             	cmp    $0x7f,%edi
  4016fc:	0f 94 c1             	sete   %cl
  4016ff:	89 cf                	mov    %ecx,%edi
  401701:	8b 8d d0 fe ff ff    	mov    -0x130(%ebp),%ecx
  401707:	85 c9                	test   %ecx,%ecx
  401709:	0f 95 c1             	setne  %cl
  40170c:	09 f9                	or     %edi,%ecx
  40170e:	85 d2                	test   %edx,%edx
  401710:	0f 84 66 01 00 00    	je     40187c <__setargv+0x43c>
  401716:	8d 54 30 01          	lea    0x1(%eax,%esi,1),%edx
  40171a:	8d b6 00 00 00 00    	lea    0x0(%esi),%esi
  401720:	83 c0 01             	add    $0x1,%eax
  401723:	c6 40 ff 5c          	movb   $0x5c,-0x1(%eax)
  401727:	39 d0                	cmp    %edx,%eax
  401729:	75 f5                	jne    401720 <__setargv+0x2e0>
  40172b:	89 d6                	mov    %edx,%esi
  40172d:	84 c9                	test   %cl,%cl
  40172f:	0f 84 13 ff ff ff    	je     401648 <__setargv+0x208>
  401735:	c6 02 7f             	movb   $0x7f,(%edx)
  401738:	8d 72 01             	lea    0x1(%edx),%esi
  40173b:	e9 08 ff ff ff       	jmp    401648 <__setargv+0x208>
  401740:	f6 05 04 40 40 00 10 	testb  $0x10,0x404004
  401747:	0f 84 ad fd ff ff    	je     4014fa <__setargv+0xba>
  40174d:	89 d1                	mov    %edx,%ecx
  40174f:	d1 f9                	sar    %ecx
  401751:	0f 84 33 01 00 00    	je     40188a <__setargv+0x44a>
  401757:	01 c1                	add    %eax,%ecx
  401759:	8d b4 26 00 00 00 00 	lea    0x0(%esi,%eiz,1),%esi
  401760:	83 c0 01             	add    $0x1,%eax
  401763:	c6 40 ff 5c          	movb   $0x5c,-0x1(%eax)
  401767:	39 c8                	cmp    %ecx,%eax
  401769:	75 f5                	jne    401760 <__setargv+0x320>
  40176b:	83 bd d0 fe ff ff 22 	cmpl   $0x22,-0x130(%ebp)
  401772:	74 09                	je     40177d <__setargv+0x33d>
  401774:	83 e2 01             	and    $0x1,%edx
  401777:	0f 84 de 00 00 00    	je     40185b <__setargv+0x41b>
  40177d:	c6 01 27             	movb   $0x27,(%ecx)
  401780:	8d 41 01             	lea    0x1(%ecx),%eax
  401783:	31 d2                	xor    %edx,%edx
  401785:	c7 85 cc fe ff ff 01 	movl   $0x1,-0x134(%ebp)
  40178c:	00 00 00 
  40178f:	e9 bb fe ff ff       	jmp    40164f <__setargv+0x20f>
  401794:	89 d1                	mov    %edx,%ecx
  401796:	d1 f9                	sar    %ecx
  401798:	0f 84 e5 00 00 00    	je     401883 <__setargv+0x443>
  40179e:	01 c1                	add    %eax,%ecx
  4017a0:	83 c0 01             	add    $0x1,%eax
  4017a3:	c6 40 ff 5c          	movb   $0x5c,-0x1(%eax)
  4017a7:	39 c8                	cmp    %ecx,%eax
  4017a9:	75 f5                	jne    4017a0 <__setargv+0x360>
  4017ab:	83 bd d0 fe ff ff 27 	cmpl   $0x27,-0x130(%ebp)
  4017b2:	74 7c                	je     401830 <__setargv+0x3f0>
  4017b4:	83 e2 01             	and    $0x1,%edx
  4017b7:	75 77                	jne    401830 <__setargv+0x3f0>
  4017b9:	83 b5 d0 fe ff ff 22 	xorl   $0x22,-0x130(%ebp)
  4017c0:	89 c8                	mov    %ecx,%eax
  4017c2:	31 d2                	xor    %edx,%edx
  4017c4:	c7 85 cc fe ff ff 01 	movl   $0x1,-0x134(%ebp)
  4017cb:	00 00 00 
  4017ce:	e9 7c fe ff ff       	jmp    40164f <__setargv+0x20f>
  4017d3:	8d 74 26 00          	lea    0x0(%esi,%eiz,1),%esi
  4017d7:	90                   	nop
  4017d8:	80 fb 5a             	cmp    $0x5a,%bl
  4017db:	0f 8e 19 fd ff ff    	jle    4014fa <__setargv+0xba>
  4017e1:	8d 4b a5             	lea    -0x5b(%ebx),%ecx
  4017e4:	80 f9 24             	cmp    $0x24,%cl
  4017e7:	0f 87 0d fd ff ff    	ja     4014fa <__setargv+0xba>
  4017ed:	0f b6 c9             	movzbl %cl,%ecx
  4017f0:	ff 24 8d c8 50 40 00 	jmp    *0x4050c8(,%ecx,4)
  4017f7:	83 bd d0 fe ff ff 27 	cmpl   $0x27,-0x130(%ebp)
  4017fe:	74 50                	je     401850 <__setargv+0x410>
  401800:	83 c2 01             	add    $0x1,%edx
  401803:	e9 47 fe ff ff       	jmp    40164f <__setargv+0x20f>
  401808:	8d 72 ff             	lea    -0x1(%edx),%esi
  40180b:	f6 05 04 40 40 00 20 	testb  $0x20,0x404004
  401812:	0f 85 e1 fe ff ff    	jne    4016f9 <__setargv+0x2b9>
  401818:	b9 01 00 00 00       	mov    $0x1,%ecx
  40181d:	85 d2                	test   %edx,%edx
  40181f:	0f 85 f1 fe ff ff    	jne    401716 <__setargv+0x2d6>
  401825:	89 c2                	mov    %eax,%edx
  401827:	e9 09 ff ff ff       	jmp    401735 <__setargv+0x2f5>
  40182c:	8d 74 26 00          	lea    0x0(%esi,%eiz,1),%esi
  401830:	c6 01 22             	movb   $0x22,(%ecx)
  401833:	8d 41 01             	lea    0x1(%ecx),%eax
  401836:	31 d2                	xor    %edx,%edx
  401838:	c7 85 cc fe ff ff 01 	movl   $0x1,-0x134(%ebp)
  40183f:	00 00 00 
  401842:	e9 08 fe ff ff       	jmp    40164f <__setargv+0x20f>
  401847:	8d b4 26 00 00 00 00 	lea    0x0(%esi,%eiz,1),%esi
  40184e:	66 90                	xchg   %ax,%ax
  401850:	c6 00 5c             	movb   $0x5c,(%eax)
  401853:	83 c0 01             	add    $0x1,%eax
  401856:	e9 f4 fd ff ff       	jmp    40164f <__setargv+0x20f>
  40185b:	83 b5 d0 fe ff ff 27 	xorl   $0x27,-0x130(%ebp)
  401862:	89 c8                	mov    %ecx,%eax
  401864:	31 d2                	xor    %edx,%edx
  401866:	c7 85 cc fe ff ff 01 	movl   $0x1,-0x134(%ebp)
  40186d:	00 00 00 
  401870:	e9 da fd ff ff       	jmp    40164f <__setargv+0x20f>
  401875:	89 c6                	mov    %eax,%esi
  401877:	e9 97 fc ff ff       	jmp    401513 <__setargv+0xd3>
  40187c:	89 c2                	mov    %eax,%edx
  40187e:	e9 a8 fe ff ff       	jmp    40172b <__setargv+0x2eb>
  401883:	89 c1                	mov    %eax,%ecx
  401885:	e9 21 ff ff ff       	jmp    4017ab <__setargv+0x36b>
  40188a:	89 c1                	mov    %eax,%ecx
  40188c:	e9 da fe ff ff       	jmp    40176b <__setargv+0x32b>
  401891:	90                   	nop
  401892:	90                   	nop
  401893:	90                   	nop
  401894:	90                   	nop
  401895:	90                   	nop
  401896:	90                   	nop
  401897:	90                   	nop
  401898:	90                   	nop
  401899:	90                   	nop
  40189a:	90                   	nop
  40189b:	90                   	nop
  40189c:	90                   	nop
  40189d:	90                   	nop
  40189e:	90                   	nop
  40189f:	90                   	nop

004018a0 <___cpu_features_init>:
  4018a0:	9c                   	pushf  
  4018a1:	9c                   	pushf  
  4018a2:	58                   	pop    %eax
  4018a3:	89 c2                	mov    %eax,%edx
  4018a5:	35 00 00 20 00       	xor    $0x200000,%eax
  4018aa:	50                   	push   %eax
  4018ab:	9d                   	popf   
  4018ac:	9c                   	pushf  
  4018ad:	58                   	pop    %eax
  4018ae:	9d                   	popf   
  4018af:	31 d0                	xor    %edx,%eax
  4018b1:	a9 00 00 20 00       	test   $0x200000,%eax
  4018b6:	0f 84 e9 00 00 00    	je     4019a5 <___cpu_features_init+0x105>
  4018bc:	53                   	push   %ebx
  4018bd:	31 c0                	xor    %eax,%eax
  4018bf:	0f a2                	cpuid  
  4018c1:	85 c0                	test   %eax,%eax
  4018c3:	0f 84 db 00 00 00    	je     4019a4 <___cpu_features_init+0x104>
  4018c9:	b8 01 00 00 00       	mov    $0x1,%eax
  4018ce:	0f a2                	cpuid  
  4018d0:	31 c0                	xor    %eax,%eax
  4018d2:	f6 c6 01             	test   $0x1,%dh
  4018d5:	74 03                	je     4018da <___cpu_features_init+0x3a>
  4018d7:	83 c8 01             	or     $0x1,%eax
  4018da:	f6 c5 20             	test   $0x20,%ch
  4018dd:	74 05                	je     4018e4 <___cpu_features_init+0x44>
  4018df:	0d 80 00 00 00       	or     $0x80,%eax
  4018e4:	f6 c6 80             	test   $0x80,%dh
  4018e7:	74 03                	je     4018ec <___cpu_features_init+0x4c>
  4018e9:	83 c8 02             	or     $0x2,%eax
  4018ec:	f7 c2 00 00 80 00    	test   $0x800000,%edx
  4018f2:	74 03                	je     4018f7 <___cpu_features_init+0x57>
  4018f4:	83 c8 04             	or     $0x4,%eax
  4018f7:	f7 c2 00 00 00 01    	test   $0x1000000,%edx
  4018fd:	74 6d                	je     40196c <___cpu_features_init+0xcc>
  4018ff:	83 c8 08             	or     $0x8,%eax
  401902:	55                   	push   %ebp
  401903:	89 e5                	mov    %esp,%ebp
  401905:	81 ec 00 02 00 00    	sub    $0x200,%esp
  40190b:	83 e4 f0             	and    $0xfffffff0,%esp
  40190e:	0f ae 04 24          	fxsave (%esp)
  401912:	8b 9c 24 c8 00 00 00 	mov    0xc8(%esp),%ebx
  401919:	81 b4 24 c8 00 00 00 	xorl   $0x13c0de,0xc8(%esp)
  401920:	de c0 13 00 
  401924:	0f ae 0c 24          	fxrstor (%esp)
  401928:	89 9c 24 c8 00 00 00 	mov    %ebx,0xc8(%esp)
  40192f:	0f ae 04 24          	fxsave (%esp)
  401933:	87 9c 24 c8 00 00 00 	xchg   %ebx,0xc8(%esp)
  40193a:	0f ae 0c 24          	fxrstor (%esp)
  40193e:	33 9c 24 c8 00 00 00 	xor    0xc8(%esp),%ebx
  401945:	c9                   	leave  
  401946:	81 fb de c0 13 00    	cmp    $0x13c0de,%ebx
  40194c:	75 1e                	jne    40196c <___cpu_features_init+0xcc>
  40194e:	f7 c2 00 00 00 02    	test   $0x2000000,%edx
  401954:	74 03                	je     401959 <___cpu_features_init+0xb9>
  401956:	83 c8 10             	or     $0x10,%eax
  401959:	f7 c2 00 00 00 04    	test   $0x4000000,%edx
  40195f:	74 03                	je     401964 <___cpu_features_init+0xc4>
  401961:	83 c8 20             	or     $0x20,%eax
  401964:	f6 c1 01             	test   $0x1,%cl
  401967:	74 03                	je     40196c <___cpu_features_init+0xcc>
  401969:	83 c8 40             	or     $0x40,%eax
  40196c:	a3 24 70 40 00       	mov    %eax,0x407024
  401971:	b8 00 00 00 80       	mov    $0x80000000,%eax
  401976:	0f a2                	cpuid  
  401978:	3d 00 00 00 80       	cmp    $0x80000000,%eax
  40197d:	76 25                	jbe    4019a4 <___cpu_features_init+0x104>
  40197f:	b8 01 00 00 80       	mov    $0x80000001,%eax
  401984:	0f a2                	cpuid  
  401986:	31 c0                	xor    %eax,%eax
  401988:	85 d2                	test   %edx,%edx
  40198a:	79 05                	jns    401991 <___cpu_features_init+0xf1>
  40198c:	b8 00 01 00 00       	mov    $0x100,%eax
  401991:	f7 c2 00 00 00 40    	test   $0x40000000,%edx
  401997:	74 05                	je     40199e <___cpu_features_init+0xfe>
  401999:	0d 00 02 00 00       	or     $0x200,%eax
  40199e:	09 05 24 70 40 00    	or     %eax,0x407024
  4019a4:	5b                   	pop    %ebx
  4019a5:	f3 c3                	repz ret 
  4019a7:	90                   	nop
  4019a8:	90                   	nop
  4019a9:	90                   	nop
  4019aa:	90                   	nop
  4019ab:	90                   	nop
  4019ac:	90                   	nop
  4019ad:	90                   	nop
  4019ae:	90                   	nop
  4019af:	90                   	nop

004019b0 <___do_global_dtors>:
  4019b0:	a1 10 40 40 00       	mov    0x404010,%eax
  4019b5:	8b 00                	mov    (%eax),%eax
  4019b7:	85 c0                	test   %eax,%eax
  4019b9:	74 25                	je     4019e0 <___do_global_dtors+0x30>
  4019bb:	83 ec 0c             	sub    $0xc,%esp
  4019be:	66 90                	xchg   %ax,%ax
  4019c0:	ff d0                	call   *%eax
  4019c2:	a1 10 40 40 00       	mov    0x404010,%eax
  4019c7:	8d 50 04             	lea    0x4(%eax),%edx
  4019ca:	8b 40 04             	mov    0x4(%eax),%eax
  4019cd:	89 15 10 40 40 00    	mov    %edx,0x404010
  4019d3:	85 c0                	test   %eax,%eax
  4019d5:	75 e9                	jne    4019c0 <___do_global_dtors+0x10>
  4019d7:	83 c4 0c             	add    $0xc,%esp
  4019da:	c3                   	ret    
  4019db:	8d 74 26 00          	lea    0x0(%esi,%eiz,1),%esi
  4019df:	90                   	nop
  4019e0:	c3                   	ret    
  4019e1:	8d b4 26 00 00 00 00 	lea    0x0(%esi,%eiz,1),%esi
  4019e8:	8d b4 26 00 00 00 00 	lea    0x0(%esi,%eiz,1),%esi
  4019ef:	90                   	nop

004019f0 <___do_global_ctors>:
  4019f0:	53                   	push   %ebx
  4019f1:	83 ec 18             	sub    $0x18,%esp
  4019f4:	8b 1d e0 3f 40 00    	mov    0x403fe0,%ebx
  4019fa:	83 fb ff             	cmp    $0xffffffff,%ebx
  4019fd:	74 29                	je     401a28 <___do_global_ctors+0x38>
  4019ff:	85 db                	test   %ebx,%ebx
  401a01:	74 11                	je     401a14 <___do_global_ctors+0x24>
  401a03:	8d 74 26 00          	lea    0x0(%esi,%eiz,1),%esi
  401a07:	90                   	nop
  401a08:	ff 14 9d e0 3f 40 00 	call   *0x403fe0(,%ebx,4)
  401a0f:	83 eb 01             	sub    $0x1,%ebx
  401a12:	75 f4                	jne    401a08 <___do_global_ctors+0x18>
  401a14:	c7 04 24 b0 19 40 00 	movl   $0x4019b0,(%esp)
  401a1b:	e8 f0 f8 ff ff       	call   401310 <_atexit>
  401a20:	83 c4 18             	add    $0x18,%esp
  401a23:	5b                   	pop    %ebx
  401a24:	c3                   	ret    
  401a25:	8d 76 00             	lea    0x0(%esi),%esi
  401a28:	31 c0                	xor    %eax,%eax
  401a2a:	8d b6 00 00 00 00    	lea    0x0(%esi),%esi
  401a30:	89 c3                	mov    %eax,%ebx
  401a32:	83 c0 01             	add    $0x1,%eax
  401a35:	8b 14 85 e0 3f 40 00 	mov    0x403fe0(,%eax,4),%edx
  401a3c:	85 d2                	test   %edx,%edx
  401a3e:	75 f0                	jne    401a30 <___do_global_ctors+0x40>
  401a40:	eb bd                	jmp    4019ff <___do_global_ctors+0xf>
  401a42:	8d b4 26 00 00 00 00 	lea    0x0(%esi,%eiz,1),%esi
  401a49:	8d b4 26 00 00 00 00 	lea    0x0(%esi,%eiz,1),%esi

00401a50 <___main>:
  401a50:	a1 28 70 40 00       	mov    0x407028,%eax
  401a55:	85 c0                	test   %eax,%eax
  401a57:	74 07                	je     401a60 <___main+0x10>
  401a59:	c3                   	ret    
  401a5a:	8d b6 00 00 00 00    	lea    0x0(%esi),%esi
  401a60:	c7 05 28 70 40 00 01 	movl   $0x1,0x407028
  401a67:	00 00 00 
  401a6a:	eb 84                	jmp    4019f0 <___do_global_ctors>
  401a6c:	90                   	nop
  401a6d:	90                   	nop
  401a6e:	90                   	nop
  401a6f:	90                   	nop

00401a70 <.text>:
  401a70:	83 ec 1c             	sub    $0x1c,%esp
  401a73:	8b 44 24 24          	mov    0x24(%esp),%eax
  401a77:	83 f8 03             	cmp    $0x3,%eax
  401a7a:	74 14                	je     401a90 <.text+0x20>
  401a7c:	85 c0                	test   %eax,%eax
  401a7e:	74 10                	je     401a90 <.text+0x20>
  401a80:	b8 01 00 00 00       	mov    $0x1,%eax
  401a85:	83 c4 1c             	add    $0x1c,%esp
  401a88:	c2 0c 00             	ret    $0xc
  401a8b:	8d 74 26 00          	lea    0x0(%esi,%eiz,1),%esi
  401a8f:	90                   	nop
  401a90:	89 44 24 04          	mov    %eax,0x4(%esp)
  401a94:	8b 54 24 28          	mov    0x28(%esp),%edx
  401a98:	8b 44 24 20          	mov    0x20(%esp),%eax
  401a9c:	89 54 24 08          	mov    %edx,0x8(%esp)
  401aa0:	89 04 24             	mov    %eax,(%esp)
  401aa3:	e8 48 02 00 00       	call   401cf0 <___mingw_TLScallback>
  401aa8:	b8 01 00 00 00       	mov    $0x1,%eax
  401aad:	83 c4 1c             	add    $0x1c,%esp
  401ab0:	c2 0c 00             	ret    $0xc
  401ab3:	8d b4 26 00 00 00 00 	lea    0x0(%esi,%eiz,1),%esi
  401aba:	8d b6 00 00 00 00    	lea    0x0(%esi),%esi

00401ac0 <___dyn_tls_init@12>:
  401ac0:	56                   	push   %esi
  401ac1:	53                   	push   %ebx
  401ac2:	83 ec 14             	sub    $0x14,%esp
  401ac5:	83 3d 64 70 40 00 02 	cmpl   $0x2,0x407064
  401acc:	8b 44 24 24          	mov    0x24(%esp),%eax
  401ad0:	74 0a                	je     401adc <___dyn_tls_init@12+0x1c>
  401ad2:	c7 05 64 70 40 00 02 	movl   $0x2,0x407064
  401ad9:	00 00 00 
  401adc:	83 f8 02             	cmp    $0x2,%eax
  401adf:	74 17                	je     401af8 <___dyn_tls_init@12+0x38>
  401ae1:	83 f8 01             	cmp    $0x1,%eax
  401ae4:	74 52                	je     401b38 <___dyn_tls_init@12+0x78>
  401ae6:	83 c4 14             	add    $0x14,%esp
  401ae9:	b8 01 00 00 00       	mov    $0x1,%eax
  401aee:	5b                   	pop    %ebx
  401aef:	5e                   	pop    %esi
  401af0:	c2 0c 00             	ret    $0xc
  401af3:	8d 74 26 00          	lea    0x0(%esi,%eiz,1),%esi
  401af7:	90                   	nop
  401af8:	b8 14 90 40 00       	mov    $0x409014,%eax
  401afd:	2d 14 90 40 00       	sub    $0x409014,%eax
  401b02:	89 c6                	mov    %eax,%esi
  401b04:	c1 fe 02             	sar    $0x2,%esi
  401b07:	85 c0                	test   %eax,%eax
  401b09:	7e db                	jle    401ae6 <___dyn_tls_init@12+0x26>
  401b0b:	31 db                	xor    %ebx,%ebx
  401b0d:	8d 76 00             	lea    0x0(%esi),%esi
  401b10:	8b 04 9d 14 90 40 00 	mov    0x409014(,%ebx,4),%eax
  401b17:	85 c0                	test   %eax,%eax
  401b19:	74 02                	je     401b1d <___dyn_tls_init@12+0x5d>
  401b1b:	ff d0                	call   *%eax
  401b1d:	83 c3 01             	add    $0x1,%ebx
  401b20:	39 de                	cmp    %ebx,%esi
  401b22:	7f ec                	jg     401b10 <___dyn_tls_init@12+0x50>
  401b24:	83 c4 14             	add    $0x14,%esp
  401b27:	b8 01 00 00 00       	mov    $0x1,%eax
  401b2c:	5b                   	pop    %ebx
  401b2d:	5e                   	pop    %esi
  401b2e:	c2 0c 00             	ret    $0xc
  401b31:	8d b4 26 00 00 00 00 	lea    0x0(%esi,%eiz,1),%esi
  401b38:	8b 44 24 28          	mov    0x28(%esp),%eax
  401b3c:	c7 44 24 04 01 00 00 	movl   $0x1,0x4(%esp)
  401b43:	00 
  401b44:	89 44 24 08          	mov    %eax,0x8(%esp)
  401b48:	8b 44 24 20          	mov    0x20(%esp),%eax
  401b4c:	89 04 24             	mov    %eax,(%esp)
  401b4f:	e8 9c 01 00 00       	call   401cf0 <___mingw_TLScallback>
  401b54:	83 c4 14             	add    $0x14,%esp
  401b57:	b8 01 00 00 00       	mov    $0x1,%eax
  401b5c:	5b                   	pop    %ebx
  401b5d:	5e                   	pop    %esi
  401b5e:	c2 0c 00             	ret    $0xc
  401b61:	8d b4 26 00 00 00 00 	lea    0x0(%esi,%eiz,1),%esi
  401b68:	8d b4 26 00 00 00 00 	lea    0x0(%esi,%eiz,1),%esi
  401b6f:	90                   	nop

00401b70 <___tlregdtor>:
  401b70:	31 c0                	xor    %eax,%eax
  401b72:	c3                   	ret    
  401b73:	90                   	nop
  401b74:	90                   	nop
  401b75:	90                   	nop
  401b76:	90                   	nop
  401b77:	90                   	nop
  401b78:	90                   	nop
  401b79:	90                   	nop
  401b7a:	90                   	nop
  401b7b:	90                   	nop
  401b7c:	90                   	nop
  401b7d:	90                   	nop
  401b7e:	90                   	nop
  401b7f:	90                   	nop

00401b80 <.text>:
  401b80:	56                   	push   %esi
  401b81:	53                   	push   %ebx
  401b82:	83 ec 14             	sub    $0x14,%esp
  401b85:	c7 04 24 44 70 40 00 	movl   $0x407044,(%esp)
  401b8c:	e8 2b 24 00 00       	call   403fbc <_EnterCriticalSection@4>
  401b91:	8b 1d 3c 70 40 00    	mov    0x40703c,%ebx
  401b97:	83 ec 04             	sub    $0x4,%esp
  401b9a:	85 db                	test   %ebx,%ebx
  401b9c:	74 2d                	je     401bcb <.text+0x4b>
  401b9e:	66 90                	xchg   %ax,%ax
  401ba0:	8b 03                	mov    (%ebx),%eax
  401ba2:	89 04 24             	mov    %eax,(%esp)
  401ba5:	e8 9a 23 00 00       	call   403f44 <_TlsGetValue@4>
  401baa:	83 ec 04             	sub    $0x4,%esp
  401bad:	89 c6                	mov    %eax,%esi
  401baf:	e8 d0 23 00 00       	call   403f84 <_GetLastError@0>
  401bb4:	85 c0                	test   %eax,%eax
  401bb6:	75 0c                	jne    401bc4 <.text+0x44>
  401bb8:	85 f6                	test   %esi,%esi
  401bba:	74 08                	je     401bc4 <.text+0x44>
  401bbc:	8b 43 04             	mov    0x4(%ebx),%eax
  401bbf:	89 34 24             	mov    %esi,(%esp)
  401bc2:	ff d0                	call   *%eax
  401bc4:	8b 5b 08             	mov    0x8(%ebx),%ebx
  401bc7:	85 db                	test   %ebx,%ebx
  401bc9:	75 d5                	jne    401ba0 <.text+0x20>
  401bcb:	c7 04 24 44 70 40 00 	movl   $0x407044,(%esp)
  401bd2:	e8 85 23 00 00       	call   403f5c <_LeaveCriticalSection@4>
  401bd7:	83 ec 04             	sub    $0x4,%esp
  401bda:	83 c4 14             	add    $0x14,%esp
  401bdd:	5b                   	pop    %ebx
  401bde:	5e                   	pop    %esi
  401bdf:	c3                   	ret    

00401be0 <____w64_mingwthr_add_key_dtor>:
  401be0:	a1 40 70 40 00       	mov    0x407040,%eax
  401be5:	85 c0                	test   %eax,%eax
  401be7:	75 07                	jne    401bf0 <____w64_mingwthr_add_key_dtor+0x10>
  401be9:	c3                   	ret    
  401bea:	8d b6 00 00 00 00    	lea    0x0(%esi),%esi
  401bf0:	53                   	push   %ebx
  401bf1:	83 ec 18             	sub    $0x18,%esp
  401bf4:	c7 44 24 04 0c 00 00 	movl   $0xc,0x4(%esp)
  401bfb:	00 
  401bfc:	c7 04 24 01 00 00 00 	movl   $0x1,(%esp)
  401c03:	e8 cc 22 00 00       	call   403ed4 <_calloc>
  401c08:	89 c3                	mov    %eax,%ebx
  401c0a:	85 c0                	test   %eax,%eax
  401c0c:	74 40                	je     401c4e <____w64_mingwthr_add_key_dtor+0x6e>
  401c0e:	8b 44 24 20          	mov    0x20(%esp),%eax
  401c12:	c7 04 24 44 70 40 00 	movl   $0x407044,(%esp)
  401c19:	89 03                	mov    %eax,(%ebx)
  401c1b:	8b 44 24 24          	mov    0x24(%esp),%eax
  401c1f:	89 43 04             	mov    %eax,0x4(%ebx)
  401c22:	e8 95 23 00 00       	call   403fbc <_EnterCriticalSection@4>
  401c27:	a1 3c 70 40 00       	mov    0x40703c,%eax
  401c2c:	89 1d 3c 70 40 00    	mov    %ebx,0x40703c
  401c32:	83 ec 04             	sub    $0x4,%esp
  401c35:	c7 04 24 44 70 40 00 	movl   $0x407044,(%esp)
  401c3c:	89 43 08             	mov    %eax,0x8(%ebx)
  401c3f:	e8 18 23 00 00       	call   403f5c <_LeaveCriticalSection@4>
  401c44:	31 c0                	xor    %eax,%eax
  401c46:	83 ec 04             	sub    $0x4,%esp
  401c49:	83 c4 18             	add    $0x18,%esp
  401c4c:	5b                   	pop    %ebx
  401c4d:	c3                   	ret    
  401c4e:	83 c8 ff             	or     $0xffffffff,%eax
  401c51:	eb f6                	jmp    401c49 <____w64_mingwthr_add_key_dtor+0x69>
  401c53:	8d b4 26 00 00 00 00 	lea    0x0(%esi,%eiz,1),%esi
  401c5a:	8d b6 00 00 00 00    	lea    0x0(%esi),%esi

00401c60 <____w64_mingwthr_remove_key_dtor>:
  401c60:	53                   	push   %ebx
  401c61:	83 ec 18             	sub    $0x18,%esp
  401c64:	a1 40 70 40 00       	mov    0x407040,%eax
  401c69:	8b 5c 24 20          	mov    0x20(%esp),%ebx
  401c6d:	85 c0                	test   %eax,%eax
  401c6f:	75 0f                	jne    401c80 <____w64_mingwthr_remove_key_dtor+0x20>
  401c71:	83 c4 18             	add    $0x18,%esp
  401c74:	31 c0                	xor    %eax,%eax
  401c76:	5b                   	pop    %ebx
  401c77:	c3                   	ret    
  401c78:	8d b4 26 00 00 00 00 	lea    0x0(%esi,%eiz,1),%esi
  401c7f:	90                   	nop
  401c80:	c7 04 24 44 70 40 00 	movl   $0x407044,(%esp)
  401c87:	e8 30 23 00 00       	call   403fbc <_EnterCriticalSection@4>
  401c8c:	a1 3c 70 40 00       	mov    0x40703c,%eax
  401c91:	83 ec 04             	sub    $0x4,%esp
  401c94:	85 c0                	test   %eax,%eax
  401c96:	74 28                	je     401cc0 <____w64_mingwthr_remove_key_dtor+0x60>
  401c98:	31 c9                	xor    %ecx,%ecx
  401c9a:	eb 0c                	jmp    401ca8 <____w64_mingwthr_remove_key_dtor+0x48>
  401c9c:	8d 74 26 00          	lea    0x0(%esi,%eiz,1),%esi
  401ca0:	89 c1                	mov    %eax,%ecx
  401ca2:	85 d2                	test   %edx,%edx
  401ca4:	74 1a                	je     401cc0 <____w64_mingwthr_remove_key_dtor+0x60>
  401ca6:	89 d0                	mov    %edx,%eax
  401ca8:	8b 10                	mov    (%eax),%edx
  401caa:	39 da                	cmp    %ebx,%edx
  401cac:	8b 50 08             	mov    0x8(%eax),%edx
  401caf:	75 ef                	jne    401ca0 <____w64_mingwthr_remove_key_dtor+0x40>
  401cb1:	85 c9                	test   %ecx,%ecx
  401cb3:	74 2b                	je     401ce0 <____w64_mingwthr_remove_key_dtor+0x80>
  401cb5:	89 51 08             	mov    %edx,0x8(%ecx)
  401cb8:	89 04 24             	mov    %eax,(%esp)
  401cbb:	e8 a0 04 00 00       	call   402160 <___mingw_aligned_free>
  401cc0:	c7 04 24 44 70 40 00 	movl   $0x407044,(%esp)
  401cc7:	e8 90 22 00 00       	call   403f5c <_LeaveCriticalSection@4>
  401ccc:	31 c0                	xor    %eax,%eax
  401cce:	83 ec 04             	sub    $0x4,%esp
  401cd1:	83 c4 18             	add    $0x18,%esp
  401cd4:	5b                   	pop    %ebx
  401cd5:	c3                   	ret    
  401cd6:	8d b4 26 00 00 00 00 	lea    0x0(%esi,%eiz,1),%esi
  401cdd:	8d 76 00             	lea    0x0(%esi),%esi
  401ce0:	89 15 3c 70 40 00    	mov    %edx,0x40703c
  401ce6:	eb d0                	jmp    401cb8 <____w64_mingwthr_remove_key_dtor+0x58>
  401ce8:	8d b4 26 00 00 00 00 	lea    0x0(%esi,%eiz,1),%esi
  401cef:	90                   	nop

00401cf0 <___mingw_TLScallback>:
  401cf0:	83 ec 1c             	sub    $0x1c,%esp
  401cf3:	8b 44 24 24          	mov    0x24(%esp),%eax
  401cf7:	83 f8 01             	cmp    $0x1,%eax
  401cfa:	74 14                	je     401d10 <___mingw_TLScallback+0x20>
  401cfc:	83 f8 03             	cmp    $0x3,%eax
  401cff:	74 5f                	je     401d60 <___mingw_TLScallback+0x70>
  401d01:	85 c0                	test   %eax,%eax
  401d03:	74 2b                	je     401d30 <___mingw_TLScallback+0x40>
  401d05:	b8 01 00 00 00       	mov    $0x1,%eax
  401d0a:	83 c4 1c             	add    $0x1c,%esp
  401d0d:	c3                   	ret    
  401d0e:	66 90                	xchg   %ax,%ax
  401d10:	a1 40 70 40 00       	mov    0x407040,%eax
  401d15:	85 c0                	test   %eax,%eax
  401d17:	74 7f                	je     401d98 <___mingw_TLScallback+0xa8>
  401d19:	c7 05 40 70 40 00 01 	movl   $0x1,0x407040
  401d20:	00 00 00 
  401d23:	b8 01 00 00 00       	mov    $0x1,%eax
  401d28:	83 c4 1c             	add    $0x1c,%esp
  401d2b:	c3                   	ret    
  401d2c:	8d 74 26 00          	lea    0x0(%esi,%eiz,1),%esi
  401d30:	a1 40 70 40 00       	mov    0x407040,%eax
  401d35:	85 c0                	test   %eax,%eax
  401d37:	75 47                	jne    401d80 <___mingw_TLScallback+0x90>
  401d39:	a1 40 70 40 00       	mov    0x407040,%eax
  401d3e:	83 f8 01             	cmp    $0x1,%eax
  401d41:	75 c2                	jne    401d05 <___mingw_TLScallback+0x15>
  401d43:	c7 04 24 44 70 40 00 	movl   $0x407044,(%esp)
  401d4a:	c7 05 40 70 40 00 00 	movl   $0x0,0x407040
  401d51:	00 00 00 
  401d54:	e8 6b 22 00 00       	call   403fc4 <_DeleteCriticalSection@4>
  401d59:	83 ec 04             	sub    $0x4,%esp
  401d5c:	eb a7                	jmp    401d05 <___mingw_TLScallback+0x15>
  401d5e:	66 90                	xchg   %ax,%ax
  401d60:	a1 40 70 40 00       	mov    0x407040,%eax
  401d65:	85 c0                	test   %eax,%eax
  401d67:	74 9c                	je     401d05 <___mingw_TLScallback+0x15>
  401d69:	e8 12 fe ff ff       	call   401b80 <.text>
  401d6e:	b8 01 00 00 00       	mov    $0x1,%eax
  401d73:	83 c4 1c             	add    $0x1c,%esp
  401d76:	c3                   	ret    
  401d77:	8d b4 26 00 00 00 00 	lea    0x0(%esi,%eiz,1),%esi
  401d7e:	66 90                	xchg   %ax,%ax
  401d80:	e8 fb fd ff ff       	call   401b80 <.text>
  401d85:	a1 40 70 40 00       	mov    0x407040,%eax
  401d8a:	83 f8 01             	cmp    $0x1,%eax
  401d8d:	0f 85 72 ff ff ff    	jne    401d05 <___mingw_TLScallback+0x15>
  401d93:	eb ae                	jmp    401d43 <___mingw_TLScallback+0x53>
  401d95:	8d 76 00             	lea    0x0(%esi),%esi
  401d98:	c7 04 24 44 70 40 00 	movl   $0x407044,(%esp)
  401d9f:	e8 c0 21 00 00       	call   403f64 <_InitializeCriticalSection@4>
  401da4:	83 ec 04             	sub    $0x4,%esp
  401da7:	e9 6d ff ff ff       	jmp    401d19 <___mingw_TLScallback+0x29>
  401dac:	90                   	nop
  401dad:	90                   	nop
  401dae:	90                   	nop
  401daf:	90                   	nop

00401db0 <.text>:
  401db0:	56                   	push   %esi
  401db1:	53                   	push   %ebx
  401db2:	83 ec 14             	sub    $0x14,%esp
  401db5:	a1 bc 81 40 00       	mov    0x4081bc,%eax
  401dba:	c7 44 24 08 17 00 00 	movl   $0x17,0x8(%esp)
  401dc1:	00 
  401dc2:	8d 74 24 24          	lea    0x24(%esp),%esi
  401dc6:	8d 58 40             	lea    0x40(%eax),%ebx
  401dc9:	c7 44 24 04 01 00 00 	movl   $0x1,0x4(%esp)
  401dd0:	00 
  401dd1:	89 5c 24 0c          	mov    %ebx,0xc(%esp)
  401dd5:	c7 04 24 60 51 40 00 	movl   $0x405160,(%esp)
  401ddc:	e8 eb 20 00 00       	call   403ecc <_fwrite>
  401de1:	8b 44 24 20          	mov    0x20(%esp),%eax
  401de5:	89 74 24 08          	mov    %esi,0x8(%esp)
  401de9:	89 1c 24             	mov    %ebx,(%esp)
  401dec:	89 44 24 04          	mov    %eax,0x4(%esp)
  401df0:	e8 7f 20 00 00       	call   403e74 <_vfprintf>
  401df5:	e8 e2 20 00 00       	call   403edc <_abort>
  401dfa:	8d b6 00 00 00 00    	lea    0x0(%esi),%esi
  401e00:	55                   	push   %ebp
  401e01:	57                   	push   %edi
  401e02:	89 d7                	mov    %edx,%edi
  401e04:	56                   	push   %esi
  401e05:	89 ce                	mov    %ecx,%esi
  401e07:	53                   	push   %ebx
  401e08:	89 c3                	mov    %eax,%ebx
  401e0a:	83 ec 3c             	sub    $0x3c,%esp
  401e0d:	8d 44 24 14          	lea    0x14(%esp),%eax
  401e11:	c7 44 24 08 1c 00 00 	movl   $0x1c,0x8(%esp)
  401e18:	00 
  401e19:	89 44 24 04          	mov    %eax,0x4(%esp)
  401e1d:	89 1c 24             	mov    %ebx,(%esp)
  401e20:	e8 0f 21 00 00       	call   403f34 <_VirtualQuery@12>
  401e25:	83 ec 0c             	sub    $0xc,%esp
  401e28:	85 c0                	test   %eax,%eax
  401e2a:	0f 84 a4 00 00 00    	je     401ed4 <.text+0x124>
  401e30:	8b 44 24 28          	mov    0x28(%esp),%eax
  401e34:	83 f8 40             	cmp    $0x40,%eax
  401e37:	74 05                	je     401e3e <.text+0x8e>
  401e39:	83 f8 04             	cmp    $0x4,%eax
  401e3c:	75 22                	jne    401e60 <.text+0xb0>
  401e3e:	85 f6                	test   %esi,%esi
  401e40:	74 10                	je     401e52 <.text+0xa2>
  401e42:	31 c0                	xor    %eax,%eax
  401e44:	0f b6 0c 07          	movzbl (%edi,%eax,1),%ecx
  401e48:	88 0c 03             	mov    %cl,(%ebx,%eax,1)
  401e4b:	83 c0 01             	add    $0x1,%eax
  401e4e:	39 f0                	cmp    %esi,%eax
  401e50:	72 f2                	jb     401e44 <.text+0x94>
  401e52:	83 c4 3c             	add    $0x3c,%esp
  401e55:	5b                   	pop    %ebx
  401e56:	5e                   	pop    %esi
  401e57:	5f                   	pop    %edi
  401e58:	5d                   	pop    %ebp
  401e59:	c3                   	ret    
  401e5a:	8d b6 00 00 00 00    	lea    0x0(%esi),%esi
  401e60:	8b 44 24 20          	mov    0x20(%esp),%eax
  401e64:	8d 6c 24 10          	lea    0x10(%esp),%ebp
  401e68:	c7 44 24 08 40 00 00 	movl   $0x40,0x8(%esp)
  401e6f:	00 
  401e70:	89 6c 24 0c          	mov    %ebp,0xc(%esp)
  401e74:	89 44 24 04          	mov    %eax,0x4(%esp)
  401e78:	8b 44 24 14          	mov    0x14(%esp),%eax
  401e7c:	89 04 24             	mov    %eax,(%esp)
  401e7f:	e8 b8 20 00 00       	call   403f3c <_VirtualProtect@16>
  401e84:	83 ec 10             	sub    $0x10,%esp
  401e87:	8b 4c 24 28          	mov    0x28(%esp),%ecx
  401e8b:	85 f6                	test   %esi,%esi
  401e8d:	74 10                	je     401e9f <.text+0xef>
  401e8f:	31 d2                	xor    %edx,%edx
  401e91:	0f b6 04 17          	movzbl (%edi,%edx,1),%eax
  401e95:	88 04 13             	mov    %al,(%ebx,%edx,1)
  401e98:	83 c2 01             	add    $0x1,%edx
  401e9b:	39 f2                	cmp    %esi,%edx
  401e9d:	72 f2                	jb     401e91 <.text+0xe1>
  401e9f:	83 f9 40             	cmp    $0x40,%ecx
  401ea2:	74 ae                	je     401e52 <.text+0xa2>
  401ea4:	83 f9 04             	cmp    $0x4,%ecx
  401ea7:	74 a9                	je     401e52 <.text+0xa2>
  401ea9:	8b 44 24 10          	mov    0x10(%esp),%eax
  401ead:	89 6c 24 0c          	mov    %ebp,0xc(%esp)
  401eb1:	89 44 24 08          	mov    %eax,0x8(%esp)
  401eb5:	8b 44 24 20          	mov    0x20(%esp),%eax
  401eb9:	89 44 24 04          	mov    %eax,0x4(%esp)
  401ebd:	8b 44 24 14          	mov    0x14(%esp),%eax
  401ec1:	89 04 24             	mov    %eax,(%esp)
  401ec4:	e8 73 20 00 00       	call   403f3c <_VirtualProtect@16>
  401ec9:	83 ec 10             	sub    $0x10,%esp
  401ecc:	83 c4 3c             	add    $0x3c,%esp
  401ecf:	5b                   	pop    %ebx
  401ed0:	5e                   	pop    %esi
  401ed1:	5f                   	pop    %edi
  401ed2:	5d                   	pop    %ebp
  401ed3:	c3                   	ret    
  401ed4:	89 5c 24 08          	mov    %ebx,0x8(%esp)
  401ed8:	c7 44 24 04 1c 00 00 	movl   $0x1c,0x4(%esp)
  401edf:	00 
  401ee0:	c7 04 24 78 51 40 00 	movl   $0x405178,(%esp)
  401ee7:	e8 c4 fe ff ff       	call   401db0 <.text>
  401eec:	8d 74 26 00          	lea    0x0(%esi,%eiz,1),%esi

00401ef0 <__pei386_runtime_relocator>:
  401ef0:	a1 5c 70 40 00       	mov    0x40705c,%eax
  401ef5:	85 c0                	test   %eax,%eax
  401ef7:	74 07                	je     401f00 <__pei386_runtime_relocator+0x10>
  401ef9:	c3                   	ret    
  401efa:	8d b6 00 00 00 00    	lea    0x0(%esi),%esi
  401f00:	c7 05 5c 70 40 00 01 	movl   $0x1,0x40705c
  401f07:	00 00 00 
  401f0a:	b8 2c 57 40 00       	mov    $0x40572c,%eax
  401f0f:	2d 2c 57 40 00       	sub    $0x40572c,%eax
  401f14:	83 f8 07             	cmp    $0x7,%eax
  401f17:	7e e0                	jle    401ef9 <__pei386_runtime_relocator+0x9>
  401f19:	57                   	push   %edi
  401f1a:	56                   	push   %esi
  401f1b:	53                   	push   %ebx
  401f1c:	83 ec 20             	sub    $0x20,%esp
  401f1f:	8b 15 2c 57 40 00    	mov    0x40572c,%edx
  401f25:	83 f8 0b             	cmp    $0xb,%eax
  401f28:	0f 8f 92 00 00 00    	jg     401fc0 <__pei386_runtime_relocator+0xd0>
  401f2e:	bb 2c 57 40 00       	mov    $0x40572c,%ebx
  401f33:	85 d2                	test   %edx,%edx
  401f35:	0f 85 3a 01 00 00    	jne    402075 <__pei386_runtime_relocator+0x185>
  401f3b:	8b 43 04             	mov    0x4(%ebx),%eax
  401f3e:	85 c0                	test   %eax,%eax
  401f40:	0f 85 2f 01 00 00    	jne    402075 <__pei386_runtime_relocator+0x185>
  401f46:	8b 43 08             	mov    0x8(%ebx),%eax
  401f49:	83 f8 01             	cmp    $0x1,%eax
  401f4c:	0f 85 78 01 00 00    	jne    4020ca <__pei386_runtime_relocator+0x1da>
  401f52:	8d b6 00 00 00 00    	lea    0x0(%esi),%esi
  401f58:	83 c3 0c             	add    $0xc,%ebx
  401f5b:	81 fb 2c 57 40 00    	cmp    $0x40572c,%ebx
  401f61:	73 4c                	jae    401faf <__pei386_runtime_relocator+0xbf>
  401f63:	8b 03                	mov    (%ebx),%eax
  401f65:	8b 4b 04             	mov    0x4(%ebx),%ecx
  401f68:	0f b6 53 08          	movzbl 0x8(%ebx),%edx
  401f6c:	8d b8 00 00 40 00    	lea    0x400000(%eax),%edi
  401f72:	8d b1 00 00 40 00    	lea    0x400000(%ecx),%esi
  401f78:	8b 80 00 00 40 00    	mov    0x400000(%eax),%eax
  401f7e:	83 fa 10             	cmp    $0x10,%edx
  401f81:	0f 84 89 00 00 00    	je     402010 <__pei386_runtime_relocator+0x120>
  401f87:	83 fa 20             	cmp    $0x20,%edx
  401f8a:	75 64                	jne    401ff0 <__pei386_runtime_relocator+0x100>
  401f8c:	29 f8                	sub    %edi,%eax
  401f8e:	03 06                	add    (%esi),%eax
  401f90:	b9 04 00 00 00       	mov    $0x4,%ecx
  401f95:	83 c3 0c             	add    $0xc,%ebx
  401f98:	89 44 24 1c          	mov    %eax,0x1c(%esp)
  401f9c:	8d 54 24 1c          	lea    0x1c(%esp),%edx
  401fa0:	89 f0                	mov    %esi,%eax
  401fa2:	e8 59 fe ff ff       	call   401e00 <.text+0x50>
  401fa7:	81 fb 2c 57 40 00    	cmp    $0x40572c,%ebx
  401fad:	72 b4                	jb     401f63 <__pei386_runtime_relocator+0x73>
  401faf:	83 c4 20             	add    $0x20,%esp
  401fb2:	5b                   	pop    %ebx
  401fb3:	5e                   	pop    %esi
  401fb4:	5f                   	pop    %edi
  401fb5:	c3                   	ret    
  401fb6:	8d b4 26 00 00 00 00 	lea    0x0(%esi,%eiz,1),%esi
  401fbd:	8d 76 00             	lea    0x0(%esi),%esi
  401fc0:	85 d2                	test   %edx,%edx
  401fc2:	0f 85 a8 00 00 00    	jne    402070 <__pei386_runtime_relocator+0x180>
  401fc8:	a1 30 57 40 00       	mov    0x405730,%eax
  401fcd:	89 c7                	mov    %eax,%edi
  401fcf:	0b 3d 34 57 40 00    	or     0x405734,%edi
  401fd5:	0f 85 e5 00 00 00    	jne    4020c0 <__pei386_runtime_relocator+0x1d0>
  401fdb:	8b 15 38 57 40 00    	mov    0x405738,%edx
  401fe1:	bb 38 57 40 00       	mov    $0x405738,%ebx
  401fe6:	e9 48 ff ff ff       	jmp    401f33 <__pei386_runtime_relocator+0x43>
  401feb:	8d 74 26 00          	lea    0x0(%esi,%eiz,1),%esi
  401fef:	90                   	nop
  401ff0:	83 fa 08             	cmp    $0x8,%edx
  401ff3:	74 4b                	je     402040 <__pei386_runtime_relocator+0x150>
  401ff5:	89 54 24 04          	mov    %edx,0x4(%esp)
  401ff9:	c7 04 24 e0 51 40 00 	movl   $0x4051e0,(%esp)
  402000:	c7 44 24 1c 00 00 00 	movl   $0x0,0x1c(%esp)
  402007:	00 
  402008:	e8 a3 fd ff ff       	call   401db0 <.text>
  40200d:	8d 76 00             	lea    0x0(%esi),%esi
  402010:	0f b7 91 00 00 40 00 	movzwl 0x400000(%ecx),%edx
  402017:	66 85 d2             	test   %dx,%dx
  40201a:	79 06                	jns    402022 <__pei386_runtime_relocator+0x132>
  40201c:	81 ca 00 00 ff ff    	or     $0xffff0000,%edx
  402022:	29 fa                	sub    %edi,%edx
  402024:	b9 02 00 00 00       	mov    $0x2,%ecx
  402029:	01 d0                	add    %edx,%eax
  40202b:	8d 54 24 1c          	lea    0x1c(%esp),%edx
  40202f:	89 44 24 1c          	mov    %eax,0x1c(%esp)
  402033:	89 f0                	mov    %esi,%eax
  402035:	e8 c6 fd ff ff       	call   401e00 <.text+0x50>
  40203a:	e9 19 ff ff ff       	jmp    401f58 <__pei386_runtime_relocator+0x68>
  40203f:	90                   	nop
  402040:	0f b6 0e             	movzbl (%esi),%ecx
  402043:	84 c9                	test   %cl,%cl
  402045:	79 06                	jns    40204d <__pei386_runtime_relocator+0x15d>
  402047:	81 c9 00 ff ff ff    	or     $0xffffff00,%ecx
  40204d:	29 f9                	sub    %edi,%ecx
  40204f:	8d 54 24 1c          	lea    0x1c(%esp),%edx
  402053:	01 c8                	add    %ecx,%eax
  402055:	b9 01 00 00 00       	mov    $0x1,%ecx
  40205a:	89 44 24 1c          	mov    %eax,0x1c(%esp)
  40205e:	89 f0                	mov    %esi,%eax
  402060:	e8 9b fd ff ff       	call   401e00 <.text+0x50>
  402065:	e9 ee fe ff ff       	jmp    401f58 <__pei386_runtime_relocator+0x68>
  40206a:	8d b6 00 00 00 00    	lea    0x0(%esi),%esi
  402070:	bb 2c 57 40 00       	mov    $0x40572c,%ebx
  402075:	81 fb 2c 57 40 00    	cmp    $0x40572c,%ebx
  40207b:	0f 83 2e ff ff ff    	jae    401faf <__pei386_runtime_relocator+0xbf>
  402081:	8d b4 26 00 00 00 00 	lea    0x0(%esi,%eiz,1),%esi
  402088:	8b 53 04             	mov    0x4(%ebx),%edx
  40208b:	8b 03                	mov    (%ebx),%eax
  40208d:	b9 04 00 00 00       	mov    $0x4,%ecx
  402092:	83 c3 08             	add    $0x8,%ebx
  402095:	03 82 00 00 40 00    	add    0x400000(%edx),%eax
  40209b:	8d b2 00 00 40 00    	lea    0x400000(%edx),%esi
  4020a1:	8d 54 24 1c          	lea    0x1c(%esp),%edx
  4020a5:	89 44 24 1c          	mov    %eax,0x1c(%esp)
  4020a9:	89 f0                	mov    %esi,%eax
  4020ab:	e8 50 fd ff ff       	call   401e00 <.text+0x50>
  4020b0:	81 fb 2c 57 40 00    	cmp    $0x40572c,%ebx
  4020b6:	72 d0                	jb     402088 <__pei386_runtime_relocator+0x198>
  4020b8:	83 c4 20             	add    $0x20,%esp
  4020bb:	5b                   	pop    %ebx
  4020bc:	5e                   	pop    %esi
  4020bd:	5f                   	pop    %edi
  4020be:	c3                   	ret    
  4020bf:	90                   	nop
  4020c0:	bb 2c 57 40 00       	mov    $0x40572c,%ebx
  4020c5:	e9 74 fe ff ff       	jmp    401f3e <__pei386_runtime_relocator+0x4e>
  4020ca:	89 44 24 04          	mov    %eax,0x4(%esp)
  4020ce:	c7 04 24 ac 51 40 00 	movl   $0x4051ac,(%esp)
  4020d5:	e8 d6 fc ff ff       	call   401db0 <.text>
  4020da:	90                   	nop
  4020db:	90                   	nop
  4020dc:	90                   	nop
  4020dd:	90                   	nop
  4020de:	90                   	nop
  4020df:	90                   	nop

004020e0 <_fesetenv>:
  4020e0:	83 ec 1c             	sub    $0x1c,%esp
  4020e3:	8b 44 24 20          	mov    0x20(%esp),%eax
  4020e7:	c7 44 24 0c 80 1f 00 	movl   $0x1f80,0xc(%esp)
  4020ee:	00 
  4020ef:	83 f8 fd             	cmp    $0xfffffffd,%eax
  4020f2:	74 4c                	je     402140 <_fesetenv+0x60>
  4020f4:	83 f8 fc             	cmp    $0xfffffffc,%eax
  4020f7:	74 2f                	je     402128 <_fesetenv+0x48>
  4020f9:	85 c0                	test   %eax,%eax
  4020fb:	74 53                	je     402150 <_fesetenv+0x70>
  4020fd:	83 f8 ff             	cmp    $0xffffffff,%eax
  402100:	74 48                	je     40214a <_fesetenv+0x6a>
  402102:	83 f8 fe             	cmp    $0xfffffffe,%eax
  402105:	74 2b                	je     402132 <_fesetenv+0x52>
  402107:	d9 20                	fldenv (%eax)
  402109:	0f b7 40 1c          	movzwl 0x1c(%eax),%eax
  40210d:	89 44 24 0c          	mov    %eax,0xc(%esp)
  402111:	f6 05 24 70 40 00 10 	testb  $0x10,0x407024
  402118:	74 05                	je     40211f <_fesetenv+0x3f>
  40211a:	0f ae 54 24 0c       	ldmxcsr 0xc(%esp)
  40211f:	31 c0                	xor    %eax,%eax
  402121:	83 c4 1c             	add    $0x1c,%esp
  402124:	c3                   	ret    
  402125:	8d 76 00             	lea    0x0(%esi),%esi
  402128:	c7 05 14 40 40 00 fe 	movl   $0xfffffffe,0x404014
  40212f:	ff ff ff 
  402132:	ff 15 b4 81 40 00    	call   *0x4081b4
  402138:	eb d7                	jmp    402111 <_fesetenv+0x31>
  40213a:	8d b6 00 00 00 00    	lea    0x0(%esi),%esi
  402140:	c7 05 14 40 40 00 ff 	movl   $0xffffffff,0x404014
  402147:	ff ff ff 
  40214a:	db e3                	fninit 
  40214c:	eb c3                	jmp    402111 <_fesetenv+0x31>
  40214e:	66 90                	xchg   %ax,%ax
  402150:	a1 14 40 40 00       	mov    0x404014,%eax
  402155:	eb a6                	jmp    4020fd <_fesetenv+0x1d>
  402157:	90                   	nop
  402158:	90                   	nop
  402159:	90                   	nop
  40215a:	90                   	nop
  40215b:	90                   	nop
  40215c:	90                   	nop
  40215d:	90                   	nop
  40215e:	90                   	nop
  40215f:	90                   	nop

00402160 <___mingw_aligned_free>:
  402160:	83 ec 2c             	sub    $0x2c,%esp
  402163:	8d 44 24 10          	lea    0x10(%esp),%eax
  402167:	89 44 24 04          	mov    %eax,0x4(%esp)
  40216b:	8b 44 24 30          	mov    0x30(%esp),%eax
  40216f:	89 04 24             	mov    %eax,(%esp)
  402172:	e8 99 1a 00 00       	call   403c10 <___mingw_memalign_base>
  402177:	89 04 24             	mov    %eax,(%esp)
  40217a:	ff 15 14 82 40 00    	call   *0x408214
  402180:	83 c4 2c             	add    $0x2c,%esp
  402183:	c3                   	ret    
  402184:	90                   	nop
  402185:	90                   	nop
  402186:	90                   	nop
  402187:	90                   	nop
  402188:	90                   	nop
  402189:	90                   	nop
  40218a:	90                   	nop
  40218b:	90                   	nop
  40218c:	90                   	nop
  40218d:	90                   	nop
  40218e:	90                   	nop
  40218f:	90                   	nop

00402190 <.text>:
  402190:	55                   	push   %ebp
  402191:	57                   	push   %edi
  402192:	56                   	push   %esi
  402193:	53                   	push   %ebx
  402194:	83 ec 3c             	sub    $0x3c,%esp
  402197:	0f be 28             	movsbl (%eax),%ebp
  40219a:	89 54 24 1c          	mov    %edx,0x1c(%esp)
  40219e:	89 4c 24 28          	mov    %ecx,0x28(%esp)
  4021a2:	89 eb                	mov    %ebp,%ebx
  4021a4:	83 fd 2d             	cmp    $0x2d,%ebp
  4021a7:	0f 84 db 00 00 00    	je     402288 <.text+0xf8>
  4021ad:	89 c2                	mov    %eax,%edx
  4021af:	83 fd 5d             	cmp    $0x5d,%ebp
  4021b2:	0f 84 d0 00 00 00    	je     402288 <.text+0xf8>
  4021b8:	8b 44 24 28          	mov    0x28(%esp),%eax
  4021bc:	25 00 40 00 00       	and    $0x4000,%eax
  4021c1:	89 44 24 20          	mov    %eax,0x20(%esp)
  4021c5:	89 e8                	mov    %ebp,%eax
  4021c7:	89 d5                	mov    %edx,%ebp
  4021c9:	89 da                	mov    %ebx,%edx
  4021cb:	89 c3                	mov    %eax,%ebx
  4021cd:	eb 0b                	jmp    4021da <.text+0x4a>
  4021cf:	90                   	nop
  4021d0:	89 d6                	mov    %edx,%esi
  4021d2:	2b 74 24 1c          	sub    0x1c(%esp),%esi
  4021d6:	85 f6                	test   %esi,%esi
  4021d8:	74 64                	je     40223e <.text+0xae>
  4021da:	8d 7d 01             	lea    0x1(%ebp),%edi
  4021dd:	89 de                	mov    %ebx,%esi
  4021df:	83 fb 5d             	cmp    $0x5d,%ebx
  4021e2:	0f 84 d0 00 00 00    	je     4022b8 <.text+0x128>
  4021e8:	83 fb 2d             	cmp    $0x2d,%ebx
  4021eb:	0f 84 b7 00 00 00    	je     4022a8 <.text+0x118>
  4021f1:	85 db                	test   %ebx,%ebx
  4021f3:	0f 84 bf 00 00 00    	je     4022b8 <.text+0x128>
  4021f9:	83 fe 2f             	cmp    $0x2f,%esi
  4021fc:	0f 84 b6 00 00 00    	je     4022b8 <.text+0x128>
  402202:	83 fe 5c             	cmp    $0x5c,%esi
  402205:	0f 84 ad 00 00 00    	je     4022b8 <.text+0x128>
  40220b:	0f be 1f             	movsbl (%edi),%ebx
  40220e:	89 fd                	mov    %edi,%ebp
  402210:	89 f2                	mov    %esi,%edx
  402212:	8b 44 24 20          	mov    0x20(%esp),%eax
  402216:	85 c0                	test   %eax,%eax
  402218:	75 b6                	jne    4021d0 <.text+0x40>
  40221a:	89 14 24             	mov    %edx,(%esp)
  40221d:	89 54 24 24          	mov    %edx,0x24(%esp)
  402221:	e8 56 1c 00 00       	call   403e7c <_tolower>
  402226:	89 c6                	mov    %eax,%esi
  402228:	8b 44 24 1c          	mov    0x1c(%esp),%eax
  40222c:	89 04 24             	mov    %eax,(%esp)
  40222f:	e8 48 1c 00 00       	call   403e7c <_tolower>
  402234:	8b 54 24 24          	mov    0x24(%esp),%edx
  402238:	29 c6                	sub    %eax,%esi
  40223a:	85 f6                	test   %esi,%esi
  40223c:	75 9c                	jne    4021da <.text+0x4a>
  40223e:	89 d9                	mov    %ebx,%ecx
  402240:	8b 5c 24 28          	mov    0x28(%esp),%ebx
  402244:	89 ea                	mov    %ebp,%edx
  402246:	83 e3 20             	and    $0x20,%ebx
  402249:	8d 42 01             	lea    0x1(%edx),%eax
  40224c:	80 f9 5d             	cmp    $0x5d,%cl
  40224f:	74 69                	je     4022ba <.text+0x12a>
  402251:	80 f9 7f             	cmp    $0x7f,%cl
  402254:	74 17                	je     40226d <.text+0xdd>
  402256:	84 c9                	test   %cl,%cl
  402258:	74 5e                	je     4022b8 <.text+0x128>
  40225a:	0f b6 4a 01          	movzbl 0x1(%edx),%ecx
  40225e:	89 c2                	mov    %eax,%edx
  402260:	8d 42 01             	lea    0x1(%edx),%eax
  402263:	80 f9 5d             	cmp    $0x5d,%cl
  402266:	74 52                	je     4022ba <.text+0x12a>
  402268:	80 f9 7f             	cmp    $0x7f,%cl
  40226b:	75 e9                	jne    402256 <.text+0xc6>
  40226d:	0f b6 4a 01          	movzbl 0x1(%edx),%ecx
  402271:	85 db                	test   %ebx,%ebx
  402273:	0f 85 1f 02 00 00    	jne    402498 <.text+0x308>
  402279:	8d 72 02             	lea    0x2(%edx),%esi
  40227c:	89 c2                	mov    %eax,%edx
  40227e:	89 f0                	mov    %esi,%eax
  402280:	eb d4                	jmp    402256 <.text+0xc6>
  402282:	8d b6 00 00 00 00    	lea    0x0(%esi),%esi
  402288:	0f b6 48 01          	movzbl 0x1(%eax),%ecx
  40228c:	8d 50 01             	lea    0x1(%eax),%edx
  40228f:	3b 6c 24 1c          	cmp    0x1c(%esp),%ebp
  402293:	0f 84 a7 01 00 00    	je     402440 <.text+0x2b0>
  402299:	0f be e9             	movsbl %cl,%ebp
  40229c:	e9 17 ff ff ff       	jmp    4021b8 <.text+0x28>
  4022a1:	8d b4 26 00 00 00 00 	lea    0x0(%esi,%eiz,1),%esi
  4022a8:	0f be 5d 01          	movsbl 0x1(%ebp),%ebx
  4022ac:	80 fb 5d             	cmp    $0x5d,%bl
  4022af:	74 17                	je     4022c8 <.text+0x138>
  4022b1:	0f be f3             	movsbl %bl,%esi
  4022b4:	85 f6                	test   %esi,%esi
  4022b6:	75 20                	jne    4022d8 <.text+0x148>
  4022b8:	31 c0                	xor    %eax,%eax
  4022ba:	83 c4 3c             	add    $0x3c,%esp
  4022bd:	5b                   	pop    %ebx
  4022be:	5e                   	pop    %esi
  4022bf:	5f                   	pop    %edi
  4022c0:	5d                   	pop    %ebp
  4022c1:	c3                   	ret    
  4022c2:	8d b6 00 00 00 00    	lea    0x0(%esi),%esi
  4022c8:	89 fd                	mov    %edi,%ebp
  4022ca:	ba 2d 00 00 00       	mov    $0x2d,%edx
  4022cf:	e9 3e ff ff ff       	jmp    402212 <.text+0x82>
  4022d4:	8d 74 26 00          	lea    0x0(%esi,%eiz,1),%esi
  4022d8:	8d 7d 02             	lea    0x2(%ebp),%edi
  4022db:	89 6c 24 24          	mov    %ebp,0x24(%esp)
  4022df:	89 d5                	mov    %edx,%ebp
  4022e1:	89 7c 24 2c          	mov    %edi,0x2c(%esp)
  4022e5:	89 f7                	mov    %esi,%edi
  4022e7:	8b 74 24 20          	mov    0x20(%esp),%esi
  4022eb:	eb 10                	jmp    4022fd <.text+0x16d>
  4022ed:	8d 76 00             	lea    0x0(%esi),%esi
  4022f0:	89 eb                	mov    %ebp,%ebx
  4022f2:	2b 5c 24 1c          	sub    0x1c(%esp),%ebx
  4022f6:	83 c5 01             	add    $0x1,%ebp
  4022f9:	85 db                	test   %ebx,%ebx
  4022fb:	74 27                	je     402324 <.text+0x194>
  4022fd:	39 fd                	cmp    %edi,%ebp
  4022ff:	7d 7f                	jge    402380 <.text+0x1f0>
  402301:	85 f6                	test   %esi,%esi
  402303:	75 eb                	jne    4022f0 <.text+0x160>
  402305:	89 2c 24             	mov    %ebp,(%esp)
  402308:	83 c5 01             	add    $0x1,%ebp
  40230b:	e8 6c 1b 00 00       	call   403e7c <_tolower>
  402310:	89 c3                	mov    %eax,%ebx
  402312:	8b 44 24 1c          	mov    0x1c(%esp),%eax
  402316:	89 04 24             	mov    %eax,(%esp)
  402319:	e8 5e 1b 00 00       	call   403e7c <_tolower>
  40231e:	29 c3                	sub    %eax,%ebx
  402320:	85 db                	test   %ebx,%ebx
  402322:	75 d9                	jne    4022fd <.text+0x16d>
  402324:	8b 54 24 24          	mov    0x24(%esp),%edx
  402328:	8b 4c 24 28          	mov    0x28(%esp),%ecx
  40232c:	8b 7c 24 2c          	mov    0x2c(%esp),%edi
  402330:	0f b6 52 02          	movzbl 0x2(%edx),%edx
  402334:	83 e1 20             	and    $0x20,%ecx
  402337:	8d 47 01             	lea    0x1(%edi),%eax
  40233a:	80 fa 5d             	cmp    $0x5d,%dl
  40233d:	0f 84 77 ff ff ff    	je     4022ba <.text+0x12a>
  402343:	80 fa 7f             	cmp    $0x7f,%dl
  402346:	74 1f                	je     402367 <.text+0x1d7>
  402348:	84 d2                	test   %dl,%dl
  40234a:	0f 84 68 ff ff ff    	je     4022b8 <.text+0x128>
  402350:	0f b6 57 01          	movzbl 0x1(%edi),%edx
  402354:	89 c7                	mov    %eax,%edi
  402356:	8d 47 01             	lea    0x1(%edi),%eax
  402359:	80 fa 5d             	cmp    $0x5d,%dl
  40235c:	0f 84 58 ff ff ff    	je     4022ba <.text+0x12a>
  402362:	80 fa 7f             	cmp    $0x7f,%dl
  402365:	75 e1                	jne    402348 <.text+0x1b8>
  402367:	0f b6 57 01          	movzbl 0x1(%edi),%edx
  40236b:	85 c9                	test   %ecx,%ecx
  40236d:	0f 85 bd 00 00 00    	jne    402430 <.text+0x2a0>
  402373:	8d 5f 02             	lea    0x2(%edi),%ebx
  402376:	89 c7                	mov    %eax,%edi
  402378:	89 d8                	mov    %ebx,%eax
  40237a:	eb cc                	jmp    402348 <.text+0x1b8>
  40237c:	8d 74 26 00          	lea    0x0(%esi,%eiz,1),%esi
  402380:	89 fe                	mov    %edi,%esi
  402382:	89 ea                	mov    %ebp,%edx
  402384:	8b 7c 24 2c          	mov    0x2c(%esp),%edi
  402388:	8b 6c 24 24          	mov    0x24(%esp),%ebp
  40238c:	89 7c 24 24          	mov    %edi,0x24(%esp)
  402390:	89 f7                	mov    %esi,%edi
  402392:	89 d6                	mov    %edx,%esi
  402394:	89 6c 24 2c          	mov    %ebp,0x2c(%esp)
  402398:	8b 6c 24 20          	mov    0x20(%esp),%ebp
  40239c:	eb 0f                	jmp    4023ad <.text+0x21d>
  40239e:	66 90                	xchg   %ax,%ax
  4023a0:	89 f3                	mov    %esi,%ebx
  4023a2:	2b 5c 24 1c          	sub    0x1c(%esp),%ebx
  4023a6:	83 ee 01             	sub    $0x1,%esi
  4023a9:	85 db                	test   %ebx,%ebx
  4023ab:	74 2b                	je     4023d8 <.text+0x248>
  4023ad:	39 fe                	cmp    %edi,%esi
  4023af:	0f 8e eb 00 00 00    	jle    4024a0 <.text+0x310>
  4023b5:	85 ed                	test   %ebp,%ebp
  4023b7:	75 e7                	jne    4023a0 <.text+0x210>
  4023b9:	89 34 24             	mov    %esi,(%esp)
  4023bc:	83 ee 01             	sub    $0x1,%esi
  4023bf:	e8 b8 1a 00 00       	call   403e7c <_tolower>
  4023c4:	89 c3                	mov    %eax,%ebx
  4023c6:	8b 44 24 1c          	mov    0x1c(%esp),%eax
  4023ca:	89 04 24             	mov    %eax,(%esp)
  4023cd:	e8 aa 1a 00 00       	call   403e7c <_tolower>
  4023d2:	29 c3                	sub    %eax,%ebx
  4023d4:	85 db                	test   %ebx,%ebx
  4023d6:	75 d5                	jne    4023ad <.text+0x21d>
  4023d8:	8b 54 24 2c          	mov    0x2c(%esp),%edx
  4023dc:	8b 4c 24 28          	mov    0x28(%esp),%ecx
  4023e0:	8b 7c 24 24          	mov    0x24(%esp),%edi
  4023e4:	0f b6 52 02          	movzbl 0x2(%edx),%edx
  4023e8:	83 e1 20             	and    $0x20,%ecx
  4023eb:	8d 47 01             	lea    0x1(%edi),%eax
  4023ee:	80 fa 5d             	cmp    $0x5d,%dl
  4023f1:	0f 84 c3 fe ff ff    	je     4022ba <.text+0x12a>
  4023f7:	80 fa 7f             	cmp    $0x7f,%dl
  4023fa:	74 1f                	je     40241b <.text+0x28b>
  4023fc:	84 d2                	test   %dl,%dl
  4023fe:	0f 84 b4 fe ff ff    	je     4022b8 <.text+0x128>
  402404:	0f b6 57 01          	movzbl 0x1(%edi),%edx
  402408:	89 c7                	mov    %eax,%edi
  40240a:	8d 47 01             	lea    0x1(%edi),%eax
  40240d:	80 fa 5d             	cmp    $0x5d,%dl
  402410:	0f 84 a4 fe ff ff    	je     4022ba <.text+0x12a>
  402416:	80 fa 7f             	cmp    $0x7f,%dl
  402419:	75 e1                	jne    4023fc <.text+0x26c>
  40241b:	0f b6 57 01          	movzbl 0x1(%edi),%edx
  40241f:	85 c9                	test   %ecx,%ecx
  402421:	0f 85 89 00 00 00    	jne    4024b0 <.text+0x320>
  402427:	8d 5f 02             	lea    0x2(%edi),%ebx
  40242a:	89 c7                	mov    %eax,%edi
  40242c:	89 d8                	mov    %ebx,%eax
  40242e:	eb cc                	jmp    4023fc <.text+0x26c>
  402430:	89 c7                	mov    %eax,%edi
  402432:	e9 00 ff ff ff       	jmp    402337 <.text+0x1a7>
  402437:	8d b4 26 00 00 00 00 	lea    0x0(%esi,%eiz,1),%esi
  40243e:	66 90                	xchg   %ax,%ax
  402440:	8b 5c 24 28          	mov    0x28(%esp),%ebx
  402444:	83 e3 20             	and    $0x20,%ebx
  402447:	8d 42 01             	lea    0x1(%edx),%eax
  40244a:	80 f9 5d             	cmp    $0x5d,%cl
  40244d:	0f 84 67 fe ff ff    	je     4022ba <.text+0x12a>
  402453:	80 f9 7f             	cmp    $0x7f,%cl
  402456:	74 1f                	je     402477 <.text+0x2e7>
  402458:	84 c9                	test   %cl,%cl
  40245a:	0f 84 58 fe ff ff    	je     4022b8 <.text+0x128>
  402460:	0f b6 4a 01          	movzbl 0x1(%edx),%ecx
  402464:	89 c2                	mov    %eax,%edx
  402466:	8d 42 01             	lea    0x1(%edx),%eax
  402469:	80 f9 5d             	cmp    $0x5d,%cl
  40246c:	0f 84 48 fe ff ff    	je     4022ba <.text+0x12a>
  402472:	80 f9 7f             	cmp    $0x7f,%cl
  402475:	75 e1                	jne    402458 <.text+0x2c8>
  402477:	0f b6 4a 01          	movzbl 0x1(%edx),%ecx
  40247b:	85 db                	test   %ebx,%ebx
  40247d:	75 11                	jne    402490 <.text+0x300>
  40247f:	8d 72 02             	lea    0x2(%edx),%esi
  402482:	89 c2                	mov    %eax,%edx
  402484:	89 f0                	mov    %esi,%eax
  402486:	eb d0                	jmp    402458 <.text+0x2c8>
  402488:	8d b4 26 00 00 00 00 	lea    0x0(%esi,%eiz,1),%esi
  40248f:	90                   	nop
  402490:	89 c2                	mov    %eax,%edx
  402492:	eb b3                	jmp    402447 <.text+0x2b7>
  402494:	8d 74 26 00          	lea    0x0(%esi,%eiz,1),%esi
  402498:	89 c2                	mov    %eax,%edx
  40249a:	e9 aa fd ff ff       	jmp    402249 <.text+0xb9>
  40249f:	90                   	nop
  4024a0:	89 fe                	mov    %edi,%esi
  4024a2:	8b 7c 24 24          	mov    0x24(%esp),%edi
  4024a6:	e9 4e fd ff ff       	jmp    4021f9 <.text+0x69>
  4024ab:	8d 74 26 00          	lea    0x0(%esi,%eiz,1),%esi
  4024af:	90                   	nop
  4024b0:	89 c7                	mov    %eax,%edi
  4024b2:	e9 34 ff ff ff       	jmp    4023eb <.text+0x25b>
  4024b7:	8d b4 26 00 00 00 00 	lea    0x0(%esi,%eiz,1),%esi
  4024be:	66 90                	xchg   %ax,%ax
  4024c0:	55                   	push   %ebp
  4024c1:	89 c5                	mov    %eax,%ebp
  4024c3:	57                   	push   %edi
  4024c4:	56                   	push   %esi
  4024c5:	89 d6                	mov    %edx,%esi
  4024c7:	53                   	push   %ebx
  4024c8:	83 ec 2c             	sub    $0x2c,%esp
  4024cb:	0f b6 3a             	movzbl (%edx),%edi
  4024ce:	0f be 10             	movsbl (%eax),%edx
  4024d1:	89 fb                	mov    %edi,%ebx
  4024d3:	89 d0                	mov    %edx,%eax
  4024d5:	80 fb 2e             	cmp    $0x2e,%bl
  4024d8:	0f 84 32 01 00 00    	je     402610 <.text+0x480>
  4024de:	8d 5d 01             	lea    0x1(%ebp),%ebx
  4024e1:	85 d2                	test   %edx,%edx
  4024e3:	0f 84 f9 00 00 00    	je     4025e2 <.text+0x452>
  4024e9:	89 cf                	mov    %ecx,%edi
  4024eb:	83 e7 20             	and    $0x20,%edi
  4024ee:	89 7c 24 14          	mov    %edi,0x14(%esp)
  4024f2:	89 f7                	mov    %esi,%edi
  4024f4:	3c 3f                	cmp    $0x3f,%al
  4024f6:	0f 84 f4 00 00 00    	je     4025f0 <.text+0x460>
  4024fc:	3c 5b                	cmp    $0x5b,%al
  4024fe:	0f 84 9c 00 00 00    	je     4025a0 <.text+0x410>
  402504:	3c 2a                	cmp    $0x2a,%al
  402506:	74 5b                	je     402563 <.text+0x3d3>
  402508:	f6 c1 20             	test   $0x20,%cl
  40250b:	75 09                	jne    402516 <.text+0x386>
  40250d:	83 fa 7f             	cmp    $0x7f,%edx
  402510:	0f 84 42 01 00 00    	je     402658 <.text+0x4c8>
  402516:	0f be 06             	movsbl (%esi),%eax
  402519:	84 c0                	test   %al,%al
  40251b:	74 75                	je     402592 <.text+0x402>
  40251d:	89 44 24 10          	mov    %eax,0x10(%esp)
  402521:	f6 c5 40             	test   $0x40,%ch
  402524:	0f 85 d6 00 00 00    	jne    402600 <.text+0x470>
  40252a:	89 14 24             	mov    %edx,(%esp)
  40252d:	89 4c 24 1c          	mov    %ecx,0x1c(%esp)
  402531:	89 54 24 18          	mov    %edx,0x18(%esp)
  402535:	e8 42 19 00 00       	call   403e7c <_tolower>
  40253a:	89 c5                	mov    %eax,%ebp
  40253c:	8b 44 24 10          	mov    0x10(%esp),%eax
  402540:	89 04 24             	mov    %eax,(%esp)
  402543:	e8 34 19 00 00       	call   403e7c <_tolower>
  402548:	8b 4c 24 1c          	mov    0x1c(%esp),%ecx
  40254c:	8b 54 24 18          	mov    0x18(%esp),%edx
  402550:	29 c5                	sub    %eax,%ebp
  402552:	85 ed                	test   %ebp,%ebp
  402554:	0f 84 9f 00 00 00    	je     4025f9 <.text+0x469>
  40255a:	2b 54 24 10          	sub    0x10(%esp),%edx
  40255e:	eb 32                	jmp    402592 <.text+0x402>
  402560:	83 c3 01             	add    $0x1,%ebx
  402563:	0f b6 03             	movzbl (%ebx),%eax
  402566:	3c 2a                	cmp    $0x2a,%al
  402568:	74 f6                	je     402560 <.text+0x3d0>
  40256a:	31 d2                	xor    %edx,%edx
  40256c:	84 c0                	test   %al,%al
  40256e:	74 22                	je     402592 <.text+0x402>
  402570:	89 ce                	mov    %ecx,%esi
  402572:	81 ce 00 00 01 00    	or     $0x10000,%esi
  402578:	89 f1                	mov    %esi,%ecx
  40257a:	89 fa                	mov    %edi,%edx
  40257c:	89 d8                	mov    %ebx,%eax
  40257e:	e8 3d ff ff ff       	call   4024c0 <.text+0x330>
  402583:	85 c0                	test   %eax,%eax
  402585:	74 09                	je     402590 <.text+0x400>
  402587:	83 c7 01             	add    $0x1,%edi
  40258a:	80 7f ff 00          	cmpb   $0x0,-0x1(%edi)
  40258e:	75 e8                	jne    402578 <.text+0x3e8>
  402590:	89 c2                	mov    %eax,%edx
  402592:	83 c4 2c             	add    $0x2c,%esp
  402595:	89 d0                	mov    %edx,%eax
  402597:	5b                   	pop    %ebx
  402598:	5e                   	pop    %esi
  402599:	5f                   	pop    %edi
  40259a:	5d                   	pop    %ebp
  40259b:	c3                   	ret    
  40259c:	8d 74 26 00          	lea    0x0(%esi,%eiz,1),%esi
  4025a0:	0f be 16             	movsbl (%esi),%edx
  4025a3:	85 d2                	test   %edx,%edx
  4025a5:	0f 84 32 01 00 00    	je     4026dd <.text+0x54d>
  4025ab:	80 7d 01 21          	cmpb   $0x21,0x1(%ebp)
  4025af:	74 7f                	je     402630 <.text+0x4a0>
  4025b1:	89 d8                	mov    %ebx,%eax
  4025b3:	89 4c 24 10          	mov    %ecx,0x10(%esp)
  4025b7:	e8 d4 fb ff ff       	call   402190 <.text>
  4025bc:	89 c5                	mov    %eax,%ebp
  4025be:	85 c0                	test   %eax,%eax
  4025c0:	0f 84 03 01 00 00    	je     4026c9 <.text+0x539>
  4025c6:	0f b6 00             	movzbl (%eax),%eax
  4025c9:	8b 4c 24 10          	mov    0x10(%esp),%ecx
  4025cd:	0f be d0             	movsbl %al,%edx
  4025d0:	8d 5d 01             	lea    0x1(%ebp),%ebx
  4025d3:	83 c6 01             	add    $0x1,%esi
  4025d6:	85 d2                	test   %edx,%edx
  4025d8:	0f 85 14 ff ff ff    	jne    4024f2 <.text+0x362>
  4025de:	0f b6 7f 01          	movzbl 0x1(%edi),%edi
  4025e2:	89 f8                	mov    %edi,%eax
  4025e4:	0f be d0             	movsbl %al,%edx
  4025e7:	f7 da                	neg    %edx
  4025e9:	eb a7                	jmp    402592 <.text+0x402>
  4025eb:	8d 74 26 00          	lea    0x0(%esi,%eiz,1),%esi
  4025ef:	90                   	nop
  4025f0:	80 3e 00             	cmpb   $0x0,(%esi)
  4025f3:	0f 84 da 00 00 00    	je     4026d3 <.text+0x543>
  4025f9:	0f b6 03             	movzbl (%ebx),%eax
  4025fc:	89 dd                	mov    %ebx,%ebp
  4025fe:	eb cd                	jmp    4025cd <.text+0x43d>
  402600:	89 d5                	mov    %edx,%ebp
  402602:	29 c5                	sub    %eax,%ebp
  402604:	e9 49 ff ff ff       	jmp    402552 <.text+0x3c2>
  402609:	8d b4 26 00 00 00 00 	lea    0x0(%esi,%eiz,1),%esi
  402610:	80 fa 2e             	cmp    $0x2e,%dl
  402613:	74 5b                	je     402670 <.text+0x4e0>
  402615:	f7 c1 00 00 01 00    	test   $0x10000,%ecx
  40261b:	0f 85 bd fe ff ff    	jne    4024de <.text+0x34e>
  402621:	83 ea 2e             	sub    $0x2e,%edx
  402624:	e9 69 ff ff ff       	jmp    402592 <.text+0x402>
  402629:	8d b4 26 00 00 00 00 	lea    0x0(%esi,%eiz,1),%esi
  402630:	8d 5d 02             	lea    0x2(%ebp),%ebx
  402633:	89 4c 24 10          	mov    %ecx,0x10(%esp)
  402637:	89 d8                	mov    %ebx,%eax
  402639:	e8 52 fb ff ff       	call   402190 <.text>
  40263e:	8b 4c 24 10          	mov    0x10(%esp),%ecx
  402642:	89 c2                	mov    %eax,%edx
  402644:	0f b6 45 02          	movzbl 0x2(%ebp),%eax
  402648:	85 d2                	test   %edx,%edx
  40264a:	74 2c                	je     402678 <.text+0x4e8>
  40264c:	89 dd                	mov    %ebx,%ebp
  40264e:	e9 7a ff ff ff       	jmp    4025cd <.text+0x43d>
  402653:	8d 74 26 00          	lea    0x0(%esi,%eiz,1),%esi
  402657:	90                   	nop
  402658:	0f be 55 01          	movsbl 0x1(%ebp),%edx
  40265c:	85 d2                	test   %edx,%edx
  40265e:	0f 84 b2 fe ff ff    	je     402516 <.text+0x386>
  402664:	8d 5d 02             	lea    0x2(%ebp),%ebx
  402667:	e9 aa fe ff ff       	jmp    402516 <.text+0x386>
  40266c:	8d 74 26 00          	lea    0x0(%esi,%eiz,1),%esi
  402670:	8d 5d 01             	lea    0x1(%ebp),%ebx
  402673:	e9 71 fe ff ff       	jmp    4024e9 <.text+0x359>
  402678:	3c 5d                	cmp    $0x5d,%al
  40267a:	75 0c                	jne    402688 <.text+0x4f8>
  40267c:	0f b6 45 03          	movzbl 0x3(%ebp),%eax
  402680:	8d 5d 03             	lea    0x3(%ebp),%ebx
  402683:	8d 74 26 00          	lea    0x0(%esi,%eiz,1),%esi
  402687:	90                   	nop
  402688:	8d 6b 01             	lea    0x1(%ebx),%ebp
  40268b:	3c 5d                	cmp    $0x5d,%al
  40268d:	74 15                	je     4026a4 <.text+0x514>
  40268f:	3c 7f                	cmp    $0x7f,%al
  402691:	74 1d                	je     4026b0 <.text+0x520>
  402693:	84 c0                	test   %al,%al
  402695:	74 32                	je     4026c9 <.text+0x539>
  402697:	0f b6 43 01          	movzbl 0x1(%ebx),%eax
  40269b:	89 eb                	mov    %ebp,%ebx
  40269d:	8d 6b 01             	lea    0x1(%ebx),%ebp
  4026a0:	3c 5d                	cmp    $0x5d,%al
  4026a2:	75 eb                	jne    40268f <.text+0x4ff>
  4026a4:	0f b6 43 01          	movzbl 0x1(%ebx),%eax
  4026a8:	e9 20 ff ff ff       	jmp    4025cd <.text+0x43d>
  4026ad:	8d 76 00             	lea    0x0(%esi),%esi
  4026b0:	8b 54 24 14          	mov    0x14(%esp),%edx
  4026b4:	0f b6 43 01          	movzbl 0x1(%ebx),%eax
  4026b8:	85 d2                	test   %edx,%edx
  4026ba:	75 09                	jne    4026c5 <.text+0x535>
  4026bc:	8d 53 02             	lea    0x2(%ebx),%edx
  4026bf:	89 eb                	mov    %ebp,%ebx
  4026c1:	89 d5                	mov    %edx,%ebp
  4026c3:	eb ce                	jmp    402693 <.text+0x503>
  4026c5:	89 eb                	mov    %ebp,%ebx
  4026c7:	eb bf                	jmp    402688 <.text+0x4f8>
  4026c9:	ba 5d 00 00 00       	mov    $0x5d,%edx
  4026ce:	e9 bf fe ff ff       	jmp    402592 <.text+0x402>
  4026d3:	ba 3f 00 00 00       	mov    $0x3f,%edx
  4026d8:	e9 b5 fe ff ff       	jmp    402592 <.text+0x402>
  4026dd:	ba 5b 00 00 00       	mov    $0x5b,%edx
  4026e2:	e9 ab fe ff ff       	jmp    402592 <.text+0x402>
  4026e7:	8d b4 26 00 00 00 00 	lea    0x0(%esi,%eiz,1),%esi
  4026ee:	66 90                	xchg   %ax,%ax
  4026f0:	57                   	push   %edi
  4026f1:	8d 48 01             	lea    0x1(%eax),%ecx
  4026f4:	56                   	push   %esi
  4026f5:	53                   	push   %ebx
  4026f6:	89 c3                	mov    %eax,%ebx
  4026f8:	0f be 00             	movsbl (%eax),%eax
  4026fb:	85 c0                	test   %eax,%eax
  4026fd:	74 61                	je     402760 <.text+0x5d0>
  4026ff:	c1 ea 05             	shr    $0x5,%edx
  402702:	31 ff                	xor    %edi,%edi
  402704:	89 d6                	mov    %edx,%esi
  402706:	83 f6 01             	xor    $0x1,%esi
  402709:	83 e6 01             	and    $0x1,%esi
  40270c:	eb 23                	jmp    402731 <.text+0x5a1>
  40270e:	66 90                	xchg   %ax,%ax
  402710:	83 f8 2a             	cmp    $0x2a,%eax
  402713:	74 6b                	je     402780 <.text+0x5f0>
  402715:	83 f8 3f             	cmp    $0x3f,%eax
  402718:	74 66                	je     402780 <.text+0x5f0>
  40271a:	83 f8 5b             	cmp    $0x5b,%eax
  40271d:	89 cb                	mov    %ecx,%ebx
  40271f:	0f 94 c0             	sete   %al
  402722:	0f b6 c0             	movzbl %al,%eax
  402725:	89 c7                	mov    %eax,%edi
  402727:	0f be 03             	movsbl (%ebx),%eax
  40272a:	83 c1 01             	add    $0x1,%ecx
  40272d:	85 c0                	test   %eax,%eax
  40272f:	74 2f                	je     402760 <.text+0x5d0>
  402731:	83 f8 7f             	cmp    $0x7f,%eax
  402734:	75 06                	jne    40273c <.text+0x5ac>
  402736:	89 f2                	mov    %esi,%edx
  402738:	84 d2                	test   %dl,%dl
  40273a:	75 2c                	jne    402768 <.text+0x5d8>
  40273c:	85 ff                	test   %edi,%edi
  40273e:	74 d0                	je     402710 <.text+0x580>
  402740:	83 ff 01             	cmp    $0x1,%edi
  402743:	7e 05                	jle    40274a <.text+0x5ba>
  402745:	83 f8 5d             	cmp    $0x5d,%eax
  402748:	74 36                	je     402780 <.text+0x5f0>
  40274a:	89 cb                	mov    %ecx,%ebx
  40274c:	83 f8 21             	cmp    $0x21,%eax
  40274f:	74 d6                	je     402727 <.text+0x597>
  402751:	89 cb                	mov    %ecx,%ebx
  402753:	83 c7 01             	add    $0x1,%edi
  402756:	83 c1 01             	add    $0x1,%ecx
  402759:	0f be 03             	movsbl (%ebx),%eax
  40275c:	85 c0                	test   %eax,%eax
  40275e:	75 d1                	jne    402731 <.text+0x5a1>
  402760:	5b                   	pop    %ebx
  402761:	5e                   	pop    %esi
  402762:	5f                   	pop    %edi
  402763:	c3                   	ret    
  402764:	8d 74 26 00          	lea    0x0(%esi,%eiz,1),%esi
  402768:	80 7b 01 00          	cmpb   $0x0,0x1(%ebx)
  40276c:	8d 4b 02             	lea    0x2(%ebx),%ecx
  40276f:	74 18                	je     402789 <.text+0x5f9>
  402771:	85 ff                	test   %edi,%edi
  402773:	74 a5                	je     40271a <.text+0x58a>
  402775:	eb da                	jmp    402751 <.text+0x5c1>
  402777:	8d b4 26 00 00 00 00 	lea    0x0(%esi,%eiz,1),%esi
  40277e:	66 90                	xchg   %ax,%ax
  402780:	5b                   	pop    %ebx
  402781:	b8 01 00 00 00       	mov    $0x1,%eax
  402786:	5e                   	pop    %esi
  402787:	5f                   	pop    %edi
  402788:	c3                   	ret    
  402789:	31 c0                	xor    %eax,%eax
  40278b:	eb d3                	jmp    402760 <.text+0x5d0>
  40278d:	8d 76 00             	lea    0x0(%esi),%esi
  402790:	57                   	push   %edi
  402791:	56                   	push   %esi
  402792:	89 c6                	mov    %eax,%esi
  402794:	53                   	push   %ebx
  402795:	89 d3                	mov    %edx,%ebx
  402797:	83 ec 10             	sub    $0x10,%esp
  40279a:	8b 42 0c             	mov    0xc(%edx),%eax
  40279d:	03 42 04             	add    0x4(%edx),%eax
  4027a0:	8d 04 85 08 00 00 00 	lea    0x8(,%eax,4),%eax
  4027a7:	89 44 24 04          	mov    %eax,0x4(%esp)
  4027ab:	8b 42 08             	mov    0x8(%edx),%eax
  4027ae:	89 04 24             	mov    %eax,(%esp)
  4027b1:	e8 1a 15 00 00       	call   403cd0 <___mingw_realloc>
  4027b6:	85 c0                	test   %eax,%eax
  4027b8:	74 26                	je     4027e0 <.text+0x650>
  4027ba:	8b 4b 04             	mov    0x4(%ebx),%ecx
  4027bd:	8b 53 0c             	mov    0xc(%ebx),%edx
  4027c0:	89 43 08             	mov    %eax,0x8(%ebx)
  4027c3:	8d 79 01             	lea    0x1(%ecx),%edi
  4027c6:	01 d1                	add    %edx,%ecx
  4027c8:	01 fa                	add    %edi,%edx
  4027ca:	89 7b 04             	mov    %edi,0x4(%ebx)
  4027cd:	89 34 88             	mov    %esi,(%eax,%ecx,4)
  4027d0:	c7 04 90 00 00 00 00 	movl   $0x0,(%eax,%edx,4)
  4027d7:	83 c4 10             	add    $0x10,%esp
  4027da:	31 c0                	xor    %eax,%eax
  4027dc:	5b                   	pop    %ebx
  4027dd:	5e                   	pop    %esi
  4027de:	5f                   	pop    %edi
  4027df:	c3                   	ret    
  4027e0:	83 c4 10             	add    $0x10,%esp
  4027e3:	b8 01 00 00 00       	mov    $0x1,%eax
  4027e8:	5b                   	pop    %ebx
  4027e9:	5e                   	pop    %esi
  4027ea:	5f                   	pop    %edi
  4027eb:	c3                   	ret    
  4027ec:	8d 74 26 00          	lea    0x0(%esi,%eiz,1),%esi
  4027f0:	56                   	push   %esi
  4027f1:	89 d6                	mov    %edx,%esi
  4027f3:	53                   	push   %ebx
  4027f4:	89 c3                	mov    %eax,%ebx
  4027f6:	83 ec 14             	sub    $0x14,%esp
  4027f9:	8b 00                	mov    (%eax),%eax
  4027fb:	85 c0                	test   %eax,%eax
  4027fd:	74 05                	je     402804 <.text+0x674>
  4027ff:	e8 ec ff ff ff       	call   4027f0 <.text+0x660>
  402804:	8b 43 08             	mov    0x8(%ebx),%eax
  402807:	85 c0                	test   %eax,%eax
  402809:	74 04                	je     40280f <.text+0x67f>
  40280b:	85 f6                	test   %esi,%esi
  40280d:	75 21                	jne    402830 <.text+0x6a0>
  40280f:	8b 43 04             	mov    0x4(%ebx),%eax
  402812:	85 c0                	test   %eax,%eax
  402814:	74 07                	je     40281d <.text+0x68d>
  402816:	89 f2                	mov    %esi,%edx
  402818:	e8 d3 ff ff ff       	call   4027f0 <.text+0x660>
  40281d:	89 1c 24             	mov    %ebx,(%esp)
  402820:	e8 3b f9 ff ff       	call   402160 <___mingw_aligned_free>
  402825:	83 c4 14             	add    $0x14,%esp
  402828:	5b                   	pop    %ebx
  402829:	5e                   	pop    %esi
  40282a:	c3                   	ret    
  40282b:	8d 74 26 00          	lea    0x0(%esi,%eiz,1),%esi
  40282f:	90                   	nop
  402830:	89 f2                	mov    %esi,%edx
  402832:	e8 59 ff ff ff       	call   402790 <.text+0x600>
  402837:	eb d6                	jmp    40280f <.text+0x67f>
  402839:	8d b4 26 00 00 00 00 	lea    0x0(%esi,%eiz,1),%esi
  402840:	56                   	push   %esi
  402841:	89 c6                	mov    %eax,%esi
  402843:	53                   	push   %ebx
  402844:	83 ec 14             	sub    $0x14,%esp
  402847:	8b 40 0c             	mov    0xc(%eax),%eax
  40284a:	8d 58 01             	lea    0x1(%eax),%ebx
  40284d:	8d 04 9d 00 00 00 00 	lea    0x0(,%ebx,4),%eax
  402854:	89 04 24             	mov    %eax,(%esp)
  402857:	e8 68 16 00 00       	call   403ec4 <_malloc>
  40285c:	89 46 08             	mov    %eax,0x8(%esi)
  40285f:	85 c0                	test   %eax,%eax
  402861:	74 21                	je     402884 <.text+0x6f4>
  402863:	c7 46 04 00 00 00 00 	movl   $0x0,0x4(%esi)
  40286a:	85 db                	test   %ebx,%ebx
  40286c:	7e 0e                	jle    40287c <.text+0x6ec>
  40286e:	66 90                	xchg   %ax,%ax
  402870:	83 eb 01             	sub    $0x1,%ebx
  402873:	c7 04 98 00 00 00 00 	movl   $0x0,(%eax,%ebx,4)
  40287a:	75 f4                	jne    402870 <.text+0x6e0>
  40287c:	31 c0                	xor    %eax,%eax
  40287e:	83 c4 14             	add    $0x14,%esp
  402881:	5b                   	pop    %ebx
  402882:	5e                   	pop    %esi
  402883:	c3                   	ret    
  402884:	b8 03 00 00 00       	mov    $0x3,%eax
  402889:	eb f3                	jmp    40287e <.text+0x6ee>
  40288b:	8d 74 26 00          	lea    0x0(%esi,%eiz,1),%esi
  40288f:	90                   	nop
  402890:	55                   	push   %ebp
  402891:	89 e5                	mov    %esp,%ebp
  402893:	57                   	push   %edi
  402894:	56                   	push   %esi
  402895:	53                   	push   %ebx
  402896:	83 ec 6c             	sub    $0x6c,%esp
  402899:	89 45 c4             	mov    %eax,-0x3c(%ebp)
  40289c:	89 55 d0             	mov    %edx,-0x30(%ebp)
  40289f:	89 4d c8             	mov    %ecx,-0x38(%ebp)
  4028a2:	80 e6 04             	and    $0x4,%dh
  4028a5:	0f 85 3d 01 00 00    	jne    4029e8 <.text+0x858>
  4028ab:	8b 7d c4             	mov    -0x3c(%ebp),%edi
  4028ae:	89 65 bc             	mov    %esp,-0x44(%ebp)
  4028b1:	89 3c 24             	mov    %edi,(%esp)
  4028b4:	e8 cb 15 00 00       	call   403e84 <_strlen>
  4028b9:	8d 50 01             	lea    0x1(%eax),%edx
  4028bc:	83 c0 10             	add    $0x10,%eax
  4028bf:	c1 e8 04             	shr    $0x4,%eax
  4028c2:	c1 e0 04             	shl    $0x4,%eax
  4028c5:	e8 66 15 00 00       	call   403e30 <___chkstk_ms>
  4028ca:	29 c4                	sub    %eax,%esp
  4028cc:	8d 44 24 0c          	lea    0xc(%esp),%eax
  4028d0:	89 54 24 08          	mov    %edx,0x8(%esp)
  4028d4:	89 7c 24 04          	mov    %edi,0x4(%esp)
  4028d8:	89 04 24             	mov    %eax,(%esp)
  4028db:	e8 d4 15 00 00       	call   403eb4 <_memcpy>
  4028e0:	89 04 24             	mov    %eax,(%esp)
  4028e3:	e8 a8 09 00 00       	call   403290 <___mingw_dirname>
  4028e8:	c7 45 e4 00 00 00 00 	movl   $0x0,-0x1c(%ebp)
  4028ef:	89 45 c0             	mov    %eax,-0x40(%ebp)
  4028f2:	89 c7                	mov    %eax,%edi
  4028f4:	8d 45 d8             	lea    -0x28(%ebp),%eax
  4028f7:	e8 44 ff ff ff       	call   402840 <.text+0x6b0>
  4028fc:	89 45 d4             	mov    %eax,-0x2c(%ebp)
  4028ff:	85 c0                	test   %eax,%eax
  402901:	0f 85 81 03 00 00    	jne    402c88 <.text+0xaf8>
  402907:	85 ff                	test   %edi,%edi
  402909:	74 12                	je     40291d <.text+0x78d>
  40290b:	8b 55 d0             	mov    -0x30(%ebp),%edx
  40290e:	89 f8                	mov    %edi,%eax
  402910:	e8 db fd ff ff       	call   4026f0 <.text+0x560>
  402915:	85 c0                	test   %eax,%eax
  402917:	0f 85 f9 05 00 00    	jne    402f16 <.text+0xd86>
  40291d:	8b 75 c0             	mov    -0x40(%ebp),%esi
  402920:	89 e3                	mov    %esp,%ebx
  402922:	89 34 24             	mov    %esi,(%esp)
  402925:	e8 5a 15 00 00       	call   403e84 <_strlen>
  40292a:	83 c0 10             	add    $0x10,%eax
  40292d:	c1 e8 04             	shr    $0x4,%eax
  402930:	c1 e0 04             	shl    $0x4,%eax
  402933:	e8 f8 14 00 00       	call   403e30 <___chkstk_ms>
  402938:	29 c4                	sub    %eax,%esp
  40293a:	89 f2                	mov    %esi,%edx
  40293c:	8d 7c 24 0c          	lea    0xc(%esp),%edi
  402940:	89 f9                	mov    %edi,%ecx
  402942:	eb 10                	jmp    402954 <.text+0x7c4>
  402944:	8d 74 26 00          	lea    0x0(%esi,%eiz,1),%esi
  402948:	83 c1 01             	add    $0x1,%ecx
  40294b:	89 f2                	mov    %esi,%edx
  40294d:	88 41 ff             	mov    %al,-0x1(%ecx)
  402950:	84 c0                	test   %al,%al
  402952:	74 1b                	je     40296f <.text+0x7df>
  402954:	0f b6 02             	movzbl (%edx),%eax
  402957:	8d 72 01             	lea    0x1(%edx),%esi
  40295a:	3c 7f                	cmp    $0x7f,%al
  40295c:	75 ea                	jne    402948 <.text+0x7b8>
  40295e:	0f b6 42 01          	movzbl 0x1(%edx),%eax
  402962:	83 c1 01             	add    $0x1,%ecx
  402965:	83 c2 02             	add    $0x2,%edx
  402968:	88 41 ff             	mov    %al,-0x1(%ecx)
  40296b:	84 c0                	test   %al,%al
  40296d:	75 e5                	jne    402954 <.text+0x7c4>
  40296f:	89 3c 24             	mov    %edi,(%esp)
  402972:	e8 ed 14 00 00       	call   403e64 <_strdup>
  402977:	c7 45 d4 01 00 00 00 	movl   $0x1,-0x2c(%ebp)
  40297e:	89 dc                	mov    %ebx,%esp
  402980:	85 c0                	test   %eax,%eax
  402982:	0f 84 00 03 00 00    	je     402c88 <.text+0xaf8>
  402988:	8d 55 d8             	lea    -0x28(%ebp),%edx
  40298b:	e8 00 fe ff ff       	call   402790 <.text+0x600>
  402990:	89 45 d4             	mov    %eax,-0x2c(%ebp)
  402993:	8b 4d d4             	mov    -0x2c(%ebp),%ecx
  402996:	85 c9                	test   %ecx,%ecx
  402998:	0f 85 ea 02 00 00    	jne    402c88 <.text+0xaf8>
  40299e:	8b 5d c4             	mov    -0x3c(%ebp),%ebx
  4029a1:	0f b6 43 01          	movzbl 0x1(%ebx),%eax
  4029a5:	3c 2f                	cmp    $0x2f,%al
  4029a7:	0f 84 33 03 00 00    	je     402ce0 <.text+0xb50>
  4029ad:	3c 5c                	cmp    $0x5c,%al
  4029af:	0f 84 2b 03 00 00    	je     402ce0 <.text+0xb50>
  4029b5:	8b 45 c0             	mov    -0x40(%ebp),%eax
  4029b8:	80 38 2e             	cmpb   $0x2e,(%eax)
  4029bb:	0f 85 1f 03 00 00    	jne    402ce0 <.text+0xb50>
  4029c1:	80 78 01 00          	cmpb   $0x0,0x1(%eax)
  4029c5:	0f 85 15 03 00 00    	jne    402ce0 <.text+0xb50>
  4029cb:	f6 45 d0 10          	testb  $0x10,-0x30(%ebp)
  4029cf:	0f 85 af 06 00 00    	jne    403084 <.text+0xef4>
  4029d5:	c6 45 9f 5c          	movb   $0x5c,-0x61(%ebp)
  4029d9:	c7 45 c0 00 00 00 00 	movl   $0x0,-0x40(%ebp)
  4029e0:	e9 4e 03 00 00       	jmp    402d33 <.text+0xba3>
  4029e5:	8d 76 00             	lea    0x0(%esi),%esi
  4029e8:	89 65 b8             	mov    %esp,-0x48(%ebp)
  4029eb:	89 c6                	mov    %eax,%esi
  4029ed:	89 04 24             	mov    %eax,(%esp)
  4029f0:	e8 8f 14 00 00       	call   403e84 <_strlen>
  4029f5:	83 c0 10             	add    $0x10,%eax
  4029f8:	c1 e8 04             	shr    $0x4,%eax
  4029fb:	c1 e0 04             	shl    $0x4,%eax
  4029fe:	e8 2d 14 00 00       	call   403e30 <___chkstk_ms>
  402a03:	0f b6 1e             	movzbl (%esi),%ebx
  402a06:	29 c4                	sub    %eax,%esp
  402a08:	8d 7c 24 0c          	lea    0xc(%esp),%edi
  402a0c:	89 7d bc             	mov    %edi,-0x44(%ebp)
  402a0f:	8d 4e 01             	lea    0x1(%esi),%ecx
  402a12:	80 fb 7f             	cmp    $0x7f,%bl
  402a15:	74 22                	je     402a39 <.text+0x8a9>
  402a17:	80 fb 7b             	cmp    $0x7b,%bl
  402a1a:	74 44                	je     402a60 <.text+0x8d0>
  402a1c:	88 1f                	mov    %bl,(%edi)
  402a1e:	8d 47 01             	lea    0x1(%edi),%eax
  402a21:	84 db                	test   %bl,%bl
  402a23:	0f 84 99 02 00 00    	je     402cc2 <.text+0xb32>
  402a29:	0f b6 5e 01          	movzbl 0x1(%esi),%ebx
  402a2d:	89 ce                	mov    %ecx,%esi
  402a2f:	89 c7                	mov    %eax,%edi
  402a31:	8d 4e 01             	lea    0x1(%esi),%ecx
  402a34:	80 fb 7f             	cmp    $0x7f,%bl
  402a37:	75 de                	jne    402a17 <.text+0x887>
  402a39:	0f b6 5e 01          	movzbl 0x1(%esi),%ebx
  402a3d:	c6 07 7f             	movb   $0x7f,(%edi)
  402a40:	84 db                	test   %bl,%bl
  402a42:	75 0c                	jne    402a50 <.text+0x8c0>
  402a44:	8d 46 02             	lea    0x2(%esi),%eax
  402a47:	83 c7 01             	add    $0x1,%edi
  402a4a:	89 ce                	mov    %ecx,%esi
  402a4c:	89 c1                	mov    %eax,%ecx
  402a4e:	eb cc                	jmp    402a1c <.text+0x88c>
  402a50:	88 5f 01             	mov    %bl,0x1(%edi)
  402a53:	83 c6 02             	add    $0x2,%esi
  402a56:	0f b6 1e             	movzbl (%esi),%ebx
  402a59:	83 c7 02             	add    $0x2,%edi
  402a5c:	eb b1                	jmp    402a0f <.text+0x87f>
  402a5e:	66 90                	xchg   %ax,%ax
  402a60:	0f b6 5e 01          	movzbl 0x1(%esi),%ebx
  402a64:	89 f2                	mov    %esi,%edx
  402a66:	89 75 c0             	mov    %esi,-0x40(%ebp)
  402a69:	89 4d d4             	mov    %ecx,-0x2c(%ebp)
  402a6c:	8d 72 01             	lea    0x1(%edx),%esi
  402a6f:	b9 01 00 00 00       	mov    $0x1,%ecx
  402a74:	89 d8                	mov    %ebx,%eax
  402a76:	c7 45 cc 2c 00 00 00 	movl   $0x2c,-0x34(%ebp)
  402a7d:	3c 7b                	cmp    $0x7b,%al
  402a7f:	74 2b                	je     402aac <.text+0x91c>
  402a81:	8d b4 26 00 00 00 00 	lea    0x0(%esi,%eiz,1),%esi
  402a88:	7f 36                	jg     402ac0 <.text+0x930>
  402a8a:	84 c0                	test   %al,%al
  402a8c:	0f 84 1e 01 00 00    	je     402bb0 <.text+0xa20>
  402a92:	3c 2c                	cmp    $0x2c,%al
  402a94:	75 09                	jne    402a9f <.text+0x90f>
  402a96:	83 f9 01             	cmp    $0x1,%ecx
  402a99:	0f 84 11 02 00 00    	je     402cb0 <.text+0xb20>
  402a9f:	0f b6 42 02          	movzbl 0x2(%edx),%eax
  402aa3:	89 f2                	mov    %esi,%edx
  402aa5:	8d 72 01             	lea    0x1(%edx),%esi
  402aa8:	3c 7b                	cmp    $0x7b,%al
  402aaa:	75 dc                	jne    402a88 <.text+0x8f8>
  402aac:	0f b6 42 02          	movzbl 0x2(%edx),%eax
  402ab0:	83 c1 01             	add    $0x1,%ecx
  402ab3:	89 f2                	mov    %esi,%edx
  402ab5:	eb ee                	jmp    402aa5 <.text+0x915>
  402ab7:	8d b4 26 00 00 00 00 	lea    0x0(%esi,%eiz,1),%esi
  402abe:	66 90                	xchg   %ax,%ax
  402ac0:	3c 7d                	cmp    $0x7d,%al
  402ac2:	0f 85 18 01 00 00    	jne    402be0 <.text+0xa50>
  402ac8:	83 e9 01             	sub    $0x1,%ecx
  402acb:	75 d2                	jne    402a9f <.text+0x90f>
  402acd:	83 7d cc 7b          	cmpl   $0x7b,-0x34(%ebp)
  402ad1:	8b 75 c0             	mov    -0x40(%ebp),%esi
  402ad4:	8b 4d d4             	mov    -0x2c(%ebp),%ecx
  402ad7:	0f 85 d6 00 00 00    	jne    402bb3 <.text+0xa23>
  402add:	89 7d d4             	mov    %edi,-0x2c(%ebp)
  402ae0:	8b 7d d0             	mov    -0x30(%ebp),%edi
  402ae3:	8b 45 d4             	mov    -0x2c(%ebp),%eax
  402ae6:	ba 01 00 00 00       	mov    $0x1,%edx
  402aeb:	80 fb 7f             	cmp    $0x7f,%bl
  402aee:	0f 84 98 00 00 00    	je     402b8c <.text+0x9fc>
  402af4:	8d 74 26 00          	lea    0x0(%esi,%eiz,1),%esi
  402af8:	83 c6 01             	add    $0x1,%esi
  402afb:	89 c1                	mov    %eax,%ecx
  402afd:	80 fb 7d             	cmp    $0x7d,%bl
  402b00:	74 6e                	je     402b70 <.text+0x9e0>
  402b02:	80 fb 2c             	cmp    $0x2c,%bl
  402b05:	0f 85 b5 00 00 00    	jne    402bc0 <.text+0xa30>
  402b0b:	83 fa 01             	cmp    $0x1,%edx
  402b0e:	0f 85 ac 00 00 00    	jne    402bc0 <.text+0xa30>
  402b14:	89 f2                	mov    %esi,%edx
  402b16:	bb 01 00 00 00       	mov    $0x1,%ebx
  402b1b:	8d 74 26 00          	lea    0x0(%esi,%eiz,1),%esi
  402b1f:	90                   	nop
  402b20:	8d 42 01             	lea    0x1(%edx),%eax
  402b23:	0f b6 52 01          	movzbl 0x1(%edx),%edx
  402b27:	80 fa 7f             	cmp    $0x7f,%dl
  402b2a:	74 1c                	je     402b48 <.text+0x9b8>
  402b2c:	e9 ef 00 00 00       	jmp    402c20 <.text+0xa90>
  402b31:	8d b4 26 00 00 00 00 	lea    0x0(%esi,%eiz,1),%esi
  402b38:	0f b6 50 02          	movzbl 0x2(%eax),%edx
  402b3c:	83 c0 02             	add    $0x2,%eax
  402b3f:	80 fa 7f             	cmp    $0x7f,%dl
  402b42:	0f 85 d8 00 00 00    	jne    402c20 <.text+0xa90>
  402b48:	80 78 01 00          	cmpb   $0x0,0x1(%eax)
  402b4c:	75 ea                	jne    402b38 <.text+0x9a8>
  402b4e:	c6 01 00             	movb   $0x0,(%ecx)
  402b51:	c7 45 d4 01 00 00 00 	movl   $0x1,-0x2c(%ebp)
  402b58:	8b 65 b8             	mov    -0x48(%ebp),%esp
  402b5b:	8b 45 d4             	mov    -0x2c(%ebp),%eax
  402b5e:	8d 65 f4             	lea    -0xc(%ebp),%esp
  402b61:	5b                   	pop    %ebx
  402b62:	5e                   	pop    %esi
  402b63:	5f                   	pop    %edi
  402b64:	5d                   	pop    %ebp
  402b65:	c3                   	ret    
  402b66:	8d b4 26 00 00 00 00 	lea    0x0(%esi,%eiz,1),%esi
  402b6d:	8d 76 00             	lea    0x0(%esi),%esi
  402b70:	83 ea 01             	sub    $0x1,%edx
  402b73:	0f 84 c7 00 00 00    	je     402c40 <.text+0xab0>
  402b79:	c6 01 7d             	movb   $0x7d,(%ecx)
  402b7c:	8d 41 01             	lea    0x1(%ecx),%eax
  402b7f:	0f b6 5e 01          	movzbl 0x1(%esi),%ebx
  402b83:	80 fb 7f             	cmp    $0x7f,%bl
  402b86:	0f 85 6c ff ff ff    	jne    402af8 <.text+0x968>
  402b8c:	0f b6 5e 02          	movzbl 0x2(%esi),%ebx
  402b90:	c6 00 7f             	movb   $0x7f,(%eax)
  402b93:	8d 48 02             	lea    0x2(%eax),%ecx
  402b96:	88 58 01             	mov    %bl,0x1(%eax)
  402b99:	84 db                	test   %bl,%bl
  402b9b:	74 6b                	je     402c08 <.text+0xa78>
  402b9d:	0f b6 5e 03          	movzbl 0x3(%esi),%ebx
  402ba1:	83 c6 03             	add    $0x3,%esi
  402ba4:	e9 54 ff ff ff       	jmp    402afd <.text+0x96d>
  402ba9:	8d b4 26 00 00 00 00 	lea    0x0(%esi,%eiz,1),%esi
  402bb0:	8b 4d d4             	mov    -0x2c(%ebp),%ecx
  402bb3:	c6 07 7b             	movb   $0x7b,(%edi)
  402bb6:	89 ce                	mov    %ecx,%esi
  402bb8:	83 c7 01             	add    $0x1,%edi
  402bbb:	e9 4f fe ff ff       	jmp    402a0f <.text+0x87f>
  402bc0:	8d 41 01             	lea    0x1(%ecx),%eax
  402bc3:	80 fb 7b             	cmp    $0x7b,%bl
  402bc6:	75 08                	jne    402bd0 <.text+0xa40>
  402bc8:	c6 01 7b             	movb   $0x7b,(%ecx)
  402bcb:	83 c2 01             	add    $0x1,%edx
  402bce:	eb af                	jmp    402b7f <.text+0x9ef>
  402bd0:	88 19                	mov    %bl,(%ecx)
  402bd2:	84 db                	test   %bl,%bl
  402bd4:	75 a9                	jne    402b7f <.text+0x9ef>
  402bd6:	eb 34                	jmp    402c0c <.text+0xa7c>
  402bd8:	8d b4 26 00 00 00 00 	lea    0x0(%esi,%eiz,1),%esi
  402bdf:	90                   	nop
  402be0:	3c 7f                	cmp    $0x7f,%al
  402be2:	0f 85 b7 fe ff ff    	jne    402a9f <.text+0x90f>
  402be8:	0f b6 42 02          	movzbl 0x2(%edx),%eax
  402bec:	84 c0                	test   %al,%al
  402bee:	0f 84 af fe ff ff    	je     402aa3 <.text+0x913>
  402bf4:	8d 72 02             	lea    0x2(%edx),%esi
  402bf7:	0f b6 42 03          	movzbl 0x3(%edx),%eax
  402bfb:	89 f2                	mov    %esi,%edx
  402bfd:	e9 a3 fe ff ff       	jmp    402aa5 <.text+0x915>
  402c02:	8d b6 00 00 00 00    	lea    0x0(%esi),%esi
  402c08:	c6 40 02 00          	movb   $0x0,0x2(%eax)
  402c0c:	c7 45 d4 01 00 00 00 	movl   $0x1,-0x2c(%ebp)
  402c13:	e9 40 ff ff ff       	jmp    402b58 <.text+0x9c8>
  402c18:	8d b4 26 00 00 00 00 	lea    0x0(%esi,%eiz,1),%esi
  402c1f:	90                   	nop
  402c20:	80 fa 7b             	cmp    $0x7b,%dl
  402c23:	74 7b                	je     402ca0 <.text+0xb10>
  402c25:	80 fa 7d             	cmp    $0x7d,%dl
  402c28:	0f 84 a2 00 00 00    	je     402cd0 <.text+0xb40>
  402c2e:	84 d2                	test   %dl,%dl
  402c30:	0f 84 18 ff ff ff    	je     402b4e <.text+0x9be>
  402c36:	89 c2                	mov    %eax,%edx
  402c38:	e9 e3 fe ff ff       	jmp    402b20 <.text+0x990>
  402c3d:	8d 76 00             	lea    0x0(%esi),%esi
  402c40:	89 f0                	mov    %esi,%eax
  402c42:	83 c0 01             	add    $0x1,%eax
  402c45:	8d 76 00             	lea    0x0(%esi),%esi
  402c48:	0f b6 10             	movzbl (%eax),%edx
  402c4b:	83 c1 01             	add    $0x1,%ecx
  402c4e:	83 c0 01             	add    $0x1,%eax
  402c51:	88 51 ff             	mov    %dl,-0x1(%ecx)
  402c54:	84 d2                	test   %dl,%dl
  402c56:	75 f0                	jne    402c48 <.text+0xab8>
  402c58:	8b 45 08             	mov    0x8(%ebp),%eax
  402c5b:	89 fa                	mov    %edi,%edx
  402c5d:	83 cf 01             	or     $0x1,%edi
  402c60:	89 04 24             	mov    %eax,(%esp)
  402c63:	8b 4d c8             	mov    -0x38(%ebp),%ecx
  402c66:	8b 45 bc             	mov    -0x44(%ebp),%eax
  402c69:	e8 22 fc ff ff       	call   402890 <.text+0x700>
  402c6e:	83 f8 01             	cmp    $0x1,%eax
  402c71:	74 99                	je     402c0c <.text+0xa7c>
  402c73:	80 3e 2c             	cmpb   $0x2c,(%esi)
  402c76:	0f 85 92 02 00 00    	jne    402f0e <.text+0xd7e>
  402c7c:	0f b6 5e 01          	movzbl 0x1(%esi),%ebx
  402c80:	e9 5e fe ff ff       	jmp    402ae3 <.text+0x953>
  402c85:	8d 76 00             	lea    0x0(%esi),%esi
  402c88:	8b 45 d4             	mov    -0x2c(%ebp),%eax
  402c8b:	8b 65 bc             	mov    -0x44(%ebp),%esp
  402c8e:	8d 65 f4             	lea    -0xc(%ebp),%esp
  402c91:	5b                   	pop    %ebx
  402c92:	5e                   	pop    %esi
  402c93:	5f                   	pop    %edi
  402c94:	5d                   	pop    %ebp
  402c95:	c3                   	ret    
  402c96:	8d b4 26 00 00 00 00 	lea    0x0(%esi,%eiz,1),%esi
  402c9d:	8d 76 00             	lea    0x0(%esi),%esi
  402ca0:	83 c3 01             	add    $0x1,%ebx
  402ca3:	89 c2                	mov    %eax,%edx
  402ca5:	e9 76 fe ff ff       	jmp    402b20 <.text+0x990>
  402caa:	8d b6 00 00 00 00    	lea    0x0(%esi),%esi
  402cb0:	0f b6 42 02          	movzbl 0x2(%edx),%eax
  402cb4:	c7 45 cc 7b 00 00 00 	movl   $0x7b,-0x34(%ebp)
  402cbb:	89 f2                	mov    %esi,%edx
  402cbd:	e9 e3 fd ff ff       	jmp    402aa5 <.text+0x915>
  402cc2:	8b 65 b8             	mov    -0x48(%ebp),%esp
  402cc5:	e9 e1 fb ff ff       	jmp    4028ab <.text+0x71b>
  402cca:	8d b6 00 00 00 00    	lea    0x0(%esi),%esi
  402cd0:	83 eb 01             	sub    $0x1,%ebx
  402cd3:	0f 84 69 ff ff ff    	je     402c42 <.text+0xab2>
  402cd9:	89 c2                	mov    %eax,%edx
  402cdb:	e9 40 fe ff ff       	jmp    402b20 <.text+0x990>
  402ce0:	8b 45 c0             	mov    -0x40(%ebp),%eax
  402ce3:	89 04 24             	mov    %eax,(%esp)
  402ce6:	e8 99 11 00 00       	call   403e84 <_strlen>
  402ceb:	8b 7d c4             	mov    -0x3c(%ebp),%edi
  402cee:	8b 55 c4             	mov    -0x3c(%ebp),%edx
  402cf1:	8d 1c 07             	lea    (%edi,%eax,1),%ebx
  402cf4:	0f b6 03             	movzbl (%ebx),%eax
  402cf7:	39 df                	cmp    %ebx,%edi
  402cf9:	73 17                	jae    402d12 <.text+0xb82>
  402cfb:	8d 74 26 00          	lea    0x0(%esi,%eiz,1),%esi
  402cff:	90                   	nop
  402d00:	3c 2f                	cmp    $0x2f,%al
  402d02:	74 1c                	je     402d20 <.text+0xb90>
  402d04:	3c 5c                	cmp    $0x5c,%al
  402d06:	74 0a                	je     402d12 <.text+0xb82>
  402d08:	83 eb 01             	sub    $0x1,%ebx
  402d0b:	0f b6 03             	movzbl (%ebx),%eax
  402d0e:	39 da                	cmp    %ebx,%edx
  402d10:	75 ee                	jne    402d00 <.text+0xb70>
  402d12:	3c 2f                	cmp    $0x2f,%al
  402d14:	74 0a                	je     402d20 <.text+0xb90>
  402d16:	3c 5c                	cmp    $0x5c,%al
  402d18:	74 06                	je     402d20 <.text+0xb90>
  402d1a:	c6 45 9f 5c          	movb   $0x5c,-0x61(%ebp)
  402d1e:	eb 13                	jmp    402d33 <.text+0xba3>
  402d20:	83 c3 01             	add    $0x1,%ebx
  402d23:	89 c2                	mov    %eax,%edx
  402d25:	0f b6 03             	movzbl (%ebx),%eax
  402d28:	3c 2f                	cmp    $0x2f,%al
  402d2a:	74 f4                	je     402d20 <.text+0xb90>
  402d2c:	3c 5c                	cmp    $0x5c,%al
  402d2e:	74 f0                	je     402d20 <.text+0xb90>
  402d30:	88 55 9f             	mov    %dl,-0x61(%ebp)
  402d33:	8b 7d e0             	mov    -0x20(%ebp),%edi
  402d36:	c7 45 d4 02 00 00 00 	movl   $0x2,-0x2c(%ebp)
  402d3d:	8b 07                	mov    (%edi),%eax
  402d3f:	85 c0                	test   %eax,%eax
  402d41:	0f 84 36 02 00 00    	je     402f7d <.text+0xded>
  402d47:	8b 4d d0             	mov    -0x30(%ebp),%ecx
  402d4a:	89 5d b8             	mov    %ebx,-0x48(%ebp)
  402d4d:	89 fb                	mov    %edi,%ebx
  402d4f:	81 e1 00 80 00 00    	and    $0x8000,%ecx
  402d55:	89 4d c4             	mov    %ecx,-0x3c(%ebp)
  402d58:	eb 4c                	jmp    402da6 <.text+0xc16>
  402d5a:	8d b6 00 00 00 00    	lea    0x0(%esi),%esi
  402d60:	f6 45 d0 04          	testb  $0x4,-0x30(%ebp)
  402d64:	75 22                	jne    402d88 <.text+0xbf8>
  402d66:	8b 7d c8             	mov    -0x38(%ebp),%edi
  402d69:	85 ff                	test   %edi,%edi
  402d6b:	74 22                	je     402d8f <.text+0xbff>
  402d6d:	e8 92 11 00 00       	call   403f04 <__errno>
  402d72:	8b 00                	mov    (%eax),%eax
  402d74:	89 44 24 04          	mov    %eax,0x4(%esp)
  402d78:	8b 03                	mov    (%ebx),%eax
  402d7a:	89 04 24             	mov    %eax,(%esp)
  402d7d:	ff d7                	call   *%edi
  402d7f:	85 c0                	test   %eax,%eax
  402d81:	74 0c                	je     402d8f <.text+0xbff>
  402d83:	8d 74 26 00          	lea    0x0(%esi,%eiz,1),%esi
  402d87:	90                   	nop
  402d88:	c7 45 d4 01 00 00 00 	movl   $0x1,-0x2c(%ebp)
  402d8f:	8b 03                	mov    (%ebx),%eax
  402d91:	83 c3 04             	add    $0x4,%ebx
  402d94:	89 04 24             	mov    %eax,(%esp)
  402d97:	e8 c4 f3 ff ff       	call   402160 <___mingw_aligned_free>
  402d9c:	8b 03                	mov    (%ebx),%eax
  402d9e:	85 c0                	test   %eax,%eax
  402da0:	0f 84 e7 01 00 00    	je     402f8d <.text+0xdfd>
  402da6:	83 7d d4 01          	cmpl   $0x1,-0x2c(%ebp)
  402daa:	74 dc                	je     402d88 <.text+0xbf8>
  402dac:	89 04 24             	mov    %eax,(%esp)
  402daf:	e8 ac 0a 00 00       	call   403860 <___mingw_opendir>
  402db4:	89 45 cc             	mov    %eax,-0x34(%ebp)
  402db7:	85 c0                	test   %eax,%eax
  402db9:	74 a5                	je     402d60 <.text+0xbd0>
  402dbb:	8b 45 c0             	mov    -0x40(%ebp),%eax
  402dbe:	c7 45 b4 00 00 00 00 	movl   $0x0,-0x4c(%ebp)
  402dc5:	85 c0                	test   %eax,%eax
  402dc7:	74 0d                	je     402dd6 <.text+0xc46>
  402dc9:	8b 03                	mov    (%ebx),%eax
  402dcb:	89 04 24             	mov    %eax,(%esp)
  402dce:	e8 b1 10 00 00       	call   403e84 <_strlen>
  402dd3:	89 45 b4             	mov    %eax,-0x4c(%ebp)
  402dd6:	8b 45 b4             	mov    -0x4c(%ebp),%eax
  402dd9:	c7 45 b0 00 00 00 00 	movl   $0x0,-0x50(%ebp)
  402de0:	83 c0 02             	add    $0x2,%eax
  402de3:	89 45 a0             	mov    %eax,-0x60(%ebp)
  402de6:	8d b4 26 00 00 00 00 	lea    0x0(%esi,%eiz,1),%esi
  402ded:	8d 76 00             	lea    0x0(%esi),%esi
  402df0:	8b 45 cc             	mov    -0x34(%ebp),%eax
  402df3:	89 04 24             	mov    %eax,(%esp)
  402df6:	e8 65 0c 00 00       	call   403a60 <___mingw_readdir>
  402dfb:	89 c6                	mov    %eax,%esi
  402dfd:	85 c0                	test   %eax,%eax
  402dff:	0f 84 30 01 00 00    	je     402f35 <.text+0xda5>
  402e05:	8b 7d c4             	mov    -0x3c(%ebp),%edi
  402e08:	85 ff                	test   %edi,%edi
  402e0a:	74 06                	je     402e12 <.text+0xc82>
  402e0c:	83 7e 08 10          	cmpl   $0x10,0x8(%esi)
  402e10:	75 de                	jne    402df0 <.text+0xc60>
  402e12:	8d 7e 0c             	lea    0xc(%esi),%edi
  402e15:	8b 4d d0             	mov    -0x30(%ebp),%ecx
  402e18:	8b 45 b8             	mov    -0x48(%ebp),%eax
  402e1b:	89 fa                	mov    %edi,%edx
  402e1d:	e8 9e f6 ff ff       	call   4024c0 <.text+0x330>
  402e22:	85 c0                	test   %eax,%eax
  402e24:	75 ca                	jne    402df0 <.text+0xc60>
  402e26:	0f b7 4e 06          	movzwl 0x6(%esi),%ecx
  402e2a:	8b 45 a0             	mov    -0x60(%ebp),%eax
  402e2d:	89 65 ac             	mov    %esp,-0x54(%ebp)
  402e30:	8d 44 01 0f          	lea    0xf(%ecx,%eax,1),%eax
  402e34:	c1 e8 04             	shr    $0x4,%eax
  402e37:	c1 e0 04             	shl    $0x4,%eax
  402e3a:	e8 f1 0f 00 00       	call   403e30 <___chkstk_ms>
  402e3f:	8b 75 b4             	mov    -0x4c(%ebp),%esi
  402e42:	29 c4                	sub    %eax,%esp
  402e44:	8d 54 24 0c          	lea    0xc(%esp),%edx
  402e48:	89 55 a8             	mov    %edx,-0x58(%ebp)
  402e4b:	89 d0                	mov    %edx,%eax
  402e4d:	85 f6                	test   %esi,%esi
  402e4f:	0f 85 3f 01 00 00    	jne    402f94 <.text+0xe04>
  402e55:	83 c1 01             	add    $0x1,%ecx
  402e58:	89 55 a4             	mov    %edx,-0x5c(%ebp)
  402e5b:	89 4c 24 08          	mov    %ecx,0x8(%esp)
  402e5f:	89 7c 24 04          	mov    %edi,0x4(%esp)
  402e63:	89 e7                	mov    %esp,%edi
  402e65:	89 04 24             	mov    %eax,(%esp)
  402e68:	e8 47 10 00 00       	call   403eb4 <_memcpy>
  402e6d:	8b 55 a4             	mov    -0x5c(%ebp),%edx
  402e70:	89 14 24             	mov    %edx,(%esp)
  402e73:	e8 0c 10 00 00       	call   403e84 <_strlen>
  402e78:	83 c0 10             	add    $0x10,%eax
  402e7b:	c1 e8 04             	shr    $0x4,%eax
  402e7e:	c1 e0 04             	shl    $0x4,%eax
  402e81:	e8 aa 0f 00 00       	call   403e30 <___chkstk_ms>
  402e86:	8b 75 a8             	mov    -0x58(%ebp),%esi
  402e89:	29 c4                	sub    %eax,%esp
  402e8b:	8d 44 24 0c          	lea    0xc(%esp),%eax
  402e8f:	89 45 a4             	mov    %eax,-0x5c(%ebp)
  402e92:	89 c2                	mov    %eax,%edx
  402e94:	eb 16                	jmp    402eac <.text+0xd1c>
  402e96:	8d b4 26 00 00 00 00 	lea    0x0(%esi,%eiz,1),%esi
  402e9d:	8d 76 00             	lea    0x0(%esi),%esi
  402ea0:	83 c2 01             	add    $0x1,%edx
  402ea3:	89 ce                	mov    %ecx,%esi
  402ea5:	88 42 ff             	mov    %al,-0x1(%edx)
  402ea8:	84 c0                	test   %al,%al
  402eaa:	74 1b                	je     402ec7 <.text+0xd37>
  402eac:	0f b6 06             	movzbl (%esi),%eax
  402eaf:	8d 4e 01             	lea    0x1(%esi),%ecx
  402eb2:	3c 7f                	cmp    $0x7f,%al
  402eb4:	75 ea                	jne    402ea0 <.text+0xd10>
  402eb6:	0f b6 46 01          	movzbl 0x1(%esi),%eax
  402eba:	83 c2 01             	add    $0x1,%edx
  402ebd:	83 c6 02             	add    $0x2,%esi
  402ec0:	88 42 ff             	mov    %al,-0x1(%edx)
  402ec3:	84 c0                	test   %al,%al
  402ec5:	75 e5                	jne    402eac <.text+0xd1c>
  402ec7:	8b 45 a4             	mov    -0x5c(%ebp),%eax
  402eca:	89 04 24             	mov    %eax,(%esp)
  402ecd:	e8 92 0f 00 00       	call   403e64 <_strdup>
  402ed2:	89 fc                	mov    %edi,%esp
  402ed4:	89 c6                	mov    %eax,%esi
  402ed6:	85 c0                	test   %eax,%eax
  402ed8:	0f 84 38 02 00 00    	je     403116 <.text+0xf86>
  402ede:	8b 7d d4             	mov    -0x2c(%ebp),%edi
  402ee1:	31 c0                	xor    %eax,%eax
  402ee3:	83 ff 02             	cmp    $0x2,%edi
  402ee6:	0f 94 c0             	sete   %al
  402ee9:	83 e8 01             	sub    $0x1,%eax
  402eec:	21 c7                	and    %eax,%edi
  402eee:	89 7d d4             	mov    %edi,-0x2c(%ebp)
  402ef1:	f6 45 d0 40          	testb  $0x40,-0x30(%ebp)
  402ef5:	0f 84 e2 00 00 00    	je     402fdd <.text+0xe4d>
  402efb:	8b 55 08             	mov    0x8(%ebp),%edx
  402efe:	85 d2                	test   %edx,%edx
  402f00:	0f 85 5e 01 00 00    	jne    403064 <.text+0xed4>
  402f06:	8b 65 ac             	mov    -0x54(%ebp),%esp
  402f09:	e9 e2 fe ff ff       	jmp    402df0 <.text+0xc60>
  402f0e:	89 45 d4             	mov    %eax,-0x2c(%ebp)
  402f11:	e9 42 fc ff ff       	jmp    402b58 <.text+0x9c8>
  402f16:	8d 45 d8             	lea    -0x28(%ebp),%eax
  402f19:	8b 55 d0             	mov    -0x30(%ebp),%edx
  402f1c:	89 04 24             	mov    %eax,(%esp)
  402f1f:	8b 4d c8             	mov    -0x38(%ebp),%ecx
  402f22:	8b 45 c0             	mov    -0x40(%ebp),%eax
  402f25:	80 ce 80             	or     $0x80,%dh
  402f28:	e8 63 f9 ff ff       	call   402890 <.text+0x700>
  402f2d:	89 45 d4             	mov    %eax,-0x2c(%ebp)
  402f30:	e9 5e fa ff ff       	jmp    402993 <.text+0x803>
  402f35:	8b 45 cc             	mov    -0x34(%ebp),%eax
  402f38:	89 04 24             	mov    %eax,(%esp)
  402f3b:	e8 70 0b 00 00       	call   403ab0 <___mingw_closedir>
  402f40:	8b 45 b0             	mov    -0x50(%ebp),%eax
  402f43:	85 c0                	test   %eax,%eax
  402f45:	0f 84 44 fe ff ff    	je     402d8f <.text+0xbff>
  402f4b:	8b 55 08             	mov    0x8(%ebp),%edx
  402f4e:	8b 45 b0             	mov    -0x50(%ebp),%eax
  402f51:	e8 9a f8 ff ff       	call   4027f0 <.text+0x660>
  402f56:	e9 34 fe ff ff       	jmp    402d8f <.text+0xbff>
  402f5b:	89 34 24             	mov    %esi,(%esp)
  402f5e:	e8 01 0f 00 00       	call   403e64 <_strdup>
  402f63:	89 dc                	mov    %ebx,%esp
  402f65:	85 c0                	test   %eax,%eax
  402f67:	74 24                	je     402f8d <.text+0xdfd>
  402f69:	8b 55 08             	mov    0x8(%ebp),%edx
  402f6c:	85 d2                	test   %edx,%edx
  402f6e:	74 1d                	je     402f8d <.text+0xdfd>
  402f70:	8b 55 08             	mov    0x8(%ebp),%edx
  402f73:	e8 18 f8 ff ff       	call   402790 <.text+0x600>
  402f78:	8b 45 e0             	mov    -0x20(%ebp),%eax
  402f7b:	89 c7                	mov    %eax,%edi
  402f7d:	89 3c 24             	mov    %edi,(%esp)
  402f80:	e8 db f1 ff ff       	call   402160 <___mingw_aligned_free>
  402f85:	8b 65 bc             	mov    -0x44(%ebp),%esp
  402f88:	e9 ce fb ff ff       	jmp    402b5b <.text+0x9cb>
  402f8d:	8b 45 e0             	mov    -0x20(%ebp),%eax
  402f90:	89 c7                	mov    %eax,%edi
  402f92:	eb e9                	jmp    402f7d <.text+0xded>
  402f94:	8b 75 b4             	mov    -0x4c(%ebp),%esi
  402f97:	8b 03                	mov    (%ebx),%eax
  402f99:	89 4d 98             	mov    %ecx,-0x68(%ebp)
  402f9c:	89 14 24             	mov    %edx,(%esp)
  402f9f:	89 74 24 08          	mov    %esi,0x8(%esp)
  402fa3:	89 44 24 04          	mov    %eax,0x4(%esp)
  402fa7:	89 55 a4             	mov    %edx,-0x5c(%ebp)
  402faa:	e8 05 0f 00 00       	call   403eb4 <_memcpy>
  402faf:	0f b6 44 34 0b       	movzbl 0xb(%esp,%esi,1),%eax
  402fb4:	8b 55 a4             	mov    -0x5c(%ebp),%edx
  402fb7:	8b 4d 98             	mov    -0x68(%ebp),%ecx
  402fba:	3c 2f                	cmp    $0x2f,%al
  402fbc:	0f 84 b1 00 00 00    	je     403073 <.text+0xee3>
  402fc2:	3c 5c                	cmp    $0x5c,%al
  402fc4:	0f 84 a9 00 00 00    	je     403073 <.text+0xee3>
  402fca:	8b 75 b4             	mov    -0x4c(%ebp),%esi
  402fcd:	0f b6 45 9f          	movzbl -0x61(%ebp),%eax
  402fd1:	88 04 32             	mov    %al,(%edx,%esi,1)
  402fd4:	8d 44 32 01          	lea    0x1(%edx,%esi,1),%eax
  402fd8:	e9 78 fe ff ff       	jmp    402e55 <.text+0xcc5>
  402fdd:	8b 7d b0             	mov    -0x50(%ebp),%edi
  402fe0:	85 ff                	test   %edi,%edi
  402fe2:	0f 84 ff 00 00 00    	je     4030e7 <.text+0xf57>
  402fe8:	8b 45 d0             	mov    -0x30(%ebp),%eax
  402feb:	89 5d a8             	mov    %ebx,-0x58(%ebp)
  402fee:	25 00 40 00 00       	and    $0x4000,%eax
  402ff3:	89 c3                	mov    %eax,%ebx
  402ff5:	eb 1f                	jmp    403016 <.text+0xe86>
  402ff7:	8d b4 26 00 00 00 00 	lea    0x0(%esi,%eiz,1),%esi
  402ffe:	66 90                	xchg   %ax,%ax
  403000:	e8 87 0e 00 00       	call   403e8c <_strcoll>
  403005:	8b 0f                	mov    (%edi),%ecx
  403007:	8b 57 04             	mov    0x4(%edi),%edx
  40300a:	85 c0                	test   %eax,%eax
  40300c:	7f 02                	jg     403010 <.text+0xe80>
  40300e:	89 ca                	mov    %ecx,%edx
  403010:	85 d2                	test   %edx,%edx
  403012:	74 17                	je     40302b <.text+0xe9b>
  403014:	89 d7                	mov    %edx,%edi
  403016:	8b 47 08             	mov    0x8(%edi),%eax
  403019:	89 34 24             	mov    %esi,(%esp)
  40301c:	89 44 24 04          	mov    %eax,0x4(%esp)
  403020:	85 db                	test   %ebx,%ebx
  403022:	75 dc                	jne    403000 <.text+0xe70>
  403024:	e8 33 0e 00 00       	call   403e5c <_stricoll>
  403029:	eb da                	jmp    403005 <.text+0xe75>
  40302b:	8b 5d a8             	mov    -0x58(%ebp),%ebx
  40302e:	89 45 a8             	mov    %eax,-0x58(%ebp)
  403031:	c7 04 24 0c 00 00 00 	movl   $0xc,(%esp)
  403038:	e8 87 0e 00 00       	call   403ec4 <_malloc>
  40303d:	8b 55 a8             	mov    -0x58(%ebp),%edx
  403040:	85 c0                	test   %eax,%eax
  403042:	0f 84 be fe ff ff    	je     402f06 <.text+0xd76>
  403048:	89 70 08             	mov    %esi,0x8(%eax)
  40304b:	c7 40 04 00 00 00 00 	movl   $0x0,0x4(%eax)
  403052:	c7 00 00 00 00 00    	movl   $0x0,(%eax)
  403058:	85 d2                	test   %edx,%edx
  40305a:	7e 21                	jle    40307d <.text+0xeed>
  40305c:	89 47 04             	mov    %eax,0x4(%edi)
  40305f:	e9 a2 fe ff ff       	jmp    402f06 <.text+0xd76>
  403064:	8b 55 08             	mov    0x8(%ebp),%edx
  403067:	89 f0                	mov    %esi,%eax
  403069:	e8 22 f7 ff ff       	call   402790 <.text+0x600>
  40306e:	e9 93 fe ff ff       	jmp    402f06 <.text+0xd76>
  403073:	8b 45 b4             	mov    -0x4c(%ebp),%eax
  403076:	01 d0                	add    %edx,%eax
  403078:	e9 d8 fd ff ff       	jmp    402e55 <.text+0xcc5>
  40307d:	89 07                	mov    %eax,(%edi)
  40307f:	e9 82 fe ff ff       	jmp    402f06 <.text+0xd76>
  403084:	8b 7d c4             	mov    -0x3c(%ebp),%edi
  403087:	8b 55 d0             	mov    -0x30(%ebp),%edx
  40308a:	89 f8                	mov    %edi,%eax
  40308c:	e8 5f f6 ff ff       	call   4026f0 <.text+0x560>
  403091:	89 45 d4             	mov    %eax,-0x2c(%ebp)
  403094:	85 c0                	test   %eax,%eax
  403096:	74 08                	je     4030a0 <.text+0xf10>
  403098:	8b 5d c4             	mov    -0x3c(%ebp),%ebx
  40309b:	e9 35 f9 ff ff       	jmp    4029d5 <.text+0x845>
  4030a0:	89 3c 24             	mov    %edi,(%esp)
  4030a3:	89 e3                	mov    %esp,%ebx
  4030a5:	e8 da 0d 00 00       	call   403e84 <_strlen>
  4030aa:	83 c0 10             	add    $0x10,%eax
  4030ad:	c1 e8 04             	shr    $0x4,%eax
  4030b0:	c1 e0 04             	shl    $0x4,%eax
  4030b3:	e8 78 0d 00 00       	call   403e30 <___chkstk_ms>
  4030b8:	29 c4                	sub    %eax,%esp
  4030ba:	89 f9                	mov    %edi,%ecx
  4030bc:	8d 74 24 0c          	lea    0xc(%esp),%esi
  4030c0:	89 f2                	mov    %esi,%edx
  4030c2:	eb 10                	jmp    4030d4 <.text+0xf44>
  4030c4:	89 f9                	mov    %edi,%ecx
  4030c6:	83 c2 01             	add    $0x1,%edx
  4030c9:	88 42 ff             	mov    %al,-0x1(%edx)
  4030cc:	84 c0                	test   %al,%al
  4030ce:	0f 84 87 fe ff ff    	je     402f5b <.text+0xdcb>
  4030d4:	0f b6 01             	movzbl (%ecx),%eax
  4030d7:	8d 79 01             	lea    0x1(%ecx),%edi
  4030da:	3c 7f                	cmp    $0x7f,%al
  4030dc:	75 e6                	jne    4030c4 <.text+0xf34>
  4030de:	0f b6 41 01          	movzbl 0x1(%ecx),%eax
  4030e2:	83 c1 02             	add    $0x2,%ecx
  4030e5:	eb df                	jmp    4030c6 <.text+0xf36>
  4030e7:	c7 04 24 0c 00 00 00 	movl   $0xc,(%esp)
  4030ee:	e8 d1 0d 00 00       	call   403ec4 <_malloc>
  4030f3:	89 45 b0             	mov    %eax,-0x50(%ebp)
  4030f6:	85 c0                	test   %eax,%eax
  4030f8:	0f 84 08 fe ff ff    	je     402f06 <.text+0xd76>
  4030fe:	8b 45 b0             	mov    -0x50(%ebp),%eax
  403101:	89 70 08             	mov    %esi,0x8(%eax)
  403104:	c7 40 04 00 00 00 00 	movl   $0x0,0x4(%eax)
  40310b:	c7 00 00 00 00 00    	movl   $0x0,(%eax)
  403111:	e9 f0 fd ff ff       	jmp    402f06 <.text+0xd76>
  403116:	c7 45 d4 03 00 00 00 	movl   $0x3,-0x2c(%ebp)
  40311d:	e9 e4 fd ff ff       	jmp    402f06 <.text+0xd76>
  403122:	8d b4 26 00 00 00 00 	lea    0x0(%esi,%eiz,1),%esi
  403129:	8d b4 26 00 00 00 00 	lea    0x0(%esi,%eiz,1),%esi

00403130 <___mingw_glob>:
  403130:	55                   	push   %ebp
  403131:	89 e5                	mov    %esp,%ebp
  403133:	57                   	push   %edi
  403134:	56                   	push   %esi
  403135:	53                   	push   %ebx
  403136:	83 ec 2c             	sub    $0x2c,%esp
  403139:	8b 75 14             	mov    0x14(%ebp),%esi
  40313c:	8b 5d 08             	mov    0x8(%ebp),%ebx
  40313f:	8b 7d 0c             	mov    0xc(%ebp),%edi
  403142:	85 f6                	test   %esi,%esi
  403144:	74 08                	je     40314e <___mingw_glob+0x1e>
  403146:	f7 c7 02 00 00 00    	test   $0x2,%edi
  40314c:	74 3a                	je     403188 <___mingw_glob+0x58>
  40314e:	81 3e 0c 52 40 00    	cmpl   $0x40520c,(%esi)
  403154:	74 0d                	je     403163 <___mingw_glob+0x33>
  403156:	89 f0                	mov    %esi,%eax
  403158:	e8 e3 f6 ff ff       	call   402840 <.text+0x6b0>
  40315d:	c7 06 0c 52 40 00    	movl   $0x40520c,(%esi)
  403163:	89 34 24             	mov    %esi,(%esp)
  403166:	8b 4d 10             	mov    0x10(%ebp),%ecx
  403169:	89 fa                	mov    %edi,%edx
  40316b:	89 d8                	mov    %ebx,%eax
  40316d:	e8 1e f7 ff ff       	call   402890 <.text+0x700>
  403172:	89 c1                	mov    %eax,%ecx
  403174:	83 f8 02             	cmp    $0x2,%eax
  403177:	74 1f                	je     403198 <___mingw_glob+0x68>
  403179:	8d 65 f4             	lea    -0xc(%ebp),%esp
  40317c:	89 c8                	mov    %ecx,%eax
  40317e:	5b                   	pop    %ebx
  40317f:	5e                   	pop    %esi
  403180:	5f                   	pop    %edi
  403181:	5d                   	pop    %ebp
  403182:	c3                   	ret    
  403183:	8d 74 26 00          	lea    0x0(%esi,%eiz,1),%esi
  403187:	90                   	nop
  403188:	c7 46 0c 00 00 00 00 	movl   $0x0,0xc(%esi)
  40318f:	eb bd                	jmp    40314e <___mingw_glob+0x1e>
  403191:	8d b4 26 00 00 00 00 	lea    0x0(%esi,%eiz,1),%esi
  403198:	83 e7 10             	and    $0x10,%edi
  40319b:	74 dc                	je     403179 <___mingw_glob+0x49>
  40319d:	89 45 dc             	mov    %eax,-0x24(%ebp)
  4031a0:	89 65 e4             	mov    %esp,-0x1c(%ebp)
  4031a3:	89 1c 24             	mov    %ebx,(%esp)
  4031a6:	e8 d9 0c 00 00       	call   403e84 <_strlen>
  4031ab:	83 c0 10             	add    $0x10,%eax
  4031ae:	c1 e8 04             	shr    $0x4,%eax
  4031b1:	c1 e0 04             	shl    $0x4,%eax
  4031b4:	e8 77 0c 00 00       	call   403e30 <___chkstk_ms>
  4031b9:	8b 4d dc             	mov    -0x24(%ebp),%ecx
  4031bc:	29 c4                	sub    %eax,%esp
  4031be:	8d 44 24 04          	lea    0x4(%esp),%eax
  4031c2:	89 45 e0             	mov    %eax,-0x20(%ebp)
  4031c5:	89 c2                	mov    %eax,%edx
  4031c7:	eb 13                	jmp    4031dc <___mingw_glob+0xac>
  4031c9:	8d b4 26 00 00 00 00 	lea    0x0(%esi,%eiz,1),%esi
  4031d0:	83 c2 01             	add    $0x1,%edx
  4031d3:	89 fb                	mov    %edi,%ebx
  4031d5:	88 42 ff             	mov    %al,-0x1(%edx)
  4031d8:	84 c0                	test   %al,%al
  4031da:	74 1b                	je     4031f7 <___mingw_glob+0xc7>
  4031dc:	0f b6 03             	movzbl (%ebx),%eax
  4031df:	8d 7b 01             	lea    0x1(%ebx),%edi
  4031e2:	3c 7f                	cmp    $0x7f,%al
  4031e4:	75 ea                	jne    4031d0 <___mingw_glob+0xa0>
  4031e6:	0f b6 43 01          	movzbl 0x1(%ebx),%eax
  4031ea:	83 c2 01             	add    $0x1,%edx
  4031ed:	83 c3 02             	add    $0x2,%ebx
  4031f0:	88 42 ff             	mov    %al,-0x1(%edx)
  4031f3:	84 c0                	test   %al,%al
  4031f5:	75 e5                	jne    4031dc <___mingw_glob+0xac>
  4031f7:	8b 45 e0             	mov    -0x20(%ebp),%eax
  4031fa:	89 4d dc             	mov    %ecx,-0x24(%ebp)
  4031fd:	89 04 24             	mov    %eax,(%esp)
  403200:	e8 5f 0c 00 00       	call   403e64 <_strdup>
  403205:	8b 65 e4             	mov    -0x1c(%ebp),%esp
  403208:	8b 4d dc             	mov    -0x24(%ebp),%ecx
  40320b:	85 c0                	test   %eax,%eax
  40320d:	0f 84 66 ff ff ff    	je     403179 <___mingw_glob+0x49>
  403213:	89 f2                	mov    %esi,%edx
  403215:	89 4d e4             	mov    %ecx,-0x1c(%ebp)
  403218:	e8 73 f5 ff ff       	call   402790 <.text+0x600>
  40321d:	8b 4d e4             	mov    -0x1c(%ebp),%ecx
  403220:	e9 54 ff ff ff       	jmp    403179 <___mingw_glob+0x49>
  403225:	8d b4 26 00 00 00 00 	lea    0x0(%esi,%eiz,1),%esi
  40322c:	8d 74 26 00          	lea    0x0(%esi,%eiz,1),%esi

00403230 <___mingw_globfree>:
  403230:	57                   	push   %edi
  403231:	56                   	push   %esi
  403232:	53                   	push   %ebx
  403233:	83 ec 10             	sub    $0x10,%esp
  403236:	8b 74 24 20          	mov    0x20(%esp),%esi
  40323a:	81 3e 0c 52 40 00    	cmpl   $0x40520c,(%esi)
  403240:	74 0e                	je     403250 <___mingw_globfree+0x20>
  403242:	83 c4 10             	add    $0x10,%esp
  403245:	5b                   	pop    %ebx
  403246:	5e                   	pop    %esi
  403247:	5f                   	pop    %edi
  403248:	c3                   	ret    
  403249:	8d b4 26 00 00 00 00 	lea    0x0(%esi,%eiz,1),%esi
  403250:	8b 7e 04             	mov    0x4(%esi),%edi
  403253:	8b 5e 0c             	mov    0xc(%esi),%ebx
  403256:	85 ff                	test   %edi,%edi
  403258:	7e 1b                	jle    403275 <___mingw_globfree+0x45>
  40325a:	01 df                	add    %ebx,%edi
  40325c:	8d 74 26 00          	lea    0x0(%esi,%eiz,1),%esi
  403260:	8b 46 08             	mov    0x8(%esi),%eax
  403263:	8b 04 98             	mov    (%eax,%ebx,4),%eax
  403266:	83 c3 01             	add    $0x1,%ebx
  403269:	89 04 24             	mov    %eax,(%esp)
  40326c:	e8 ef ee ff ff       	call   402160 <___mingw_aligned_free>
  403271:	39 df                	cmp    %ebx,%edi
  403273:	75 eb                	jne    403260 <___mingw_globfree+0x30>
  403275:	8b 46 08             	mov    0x8(%esi),%eax
  403278:	89 44 24 20          	mov    %eax,0x20(%esp)
  40327c:	83 c4 10             	add    $0x10,%esp
  40327f:	5b                   	pop    %ebx
  403280:	5e                   	pop    %esi
  403281:	5f                   	pop    %edi
  403282:	e9 d9 ee ff ff       	jmp    402160 <___mingw_aligned_free>
  403287:	90                   	nop
  403288:	90                   	nop
  403289:	90                   	nop
  40328a:	90                   	nop
  40328b:	90                   	nop
  40328c:	90                   	nop
  40328d:	90                   	nop
  40328e:	90                   	nop
  40328f:	90                   	nop

00403290 <___mingw_dirname>:
  403290:	55                   	push   %ebp
  403291:	89 e5                	mov    %esp,%ebp
  403293:	57                   	push   %edi
  403294:	56                   	push   %esi
  403295:	53                   	push   %ebx
  403296:	83 ec 2c             	sub    $0x2c,%esp
  403299:	c7 44 24 04 00 00 00 	movl   $0x0,0x4(%esp)
  4032a0:	00 
  4032a1:	c7 04 24 02 00 00 00 	movl   $0x2,(%esp)
  4032a8:	e8 ef 0b 00 00       	call   403e9c <_setlocale>
  4032ad:	89 c3                	mov    %eax,%ebx
  4032af:	85 c0                	test   %eax,%eax
  4032b1:	74 0a                	je     4032bd <___mingw_dirname+0x2d>
  4032b3:	89 04 24             	mov    %eax,(%esp)
  4032b6:	e8 a9 0b 00 00       	call   403e64 <_strdup>
  4032bb:	89 c3                	mov    %eax,%ebx
  4032bd:	c7 44 24 04 20 52 40 	movl   $0x405220,0x4(%esp)
  4032c4:	00 
  4032c5:	c7 04 24 02 00 00 00 	movl   $0x2,(%esp)
  4032cc:	e8 cb 0b 00 00       	call   403e9c <_setlocale>
  4032d1:	8b 4d 08             	mov    0x8(%ebp),%ecx
  4032d4:	85 c9                	test   %ecx,%ecx
  4032d6:	74 08                	je     4032e0 <___mingw_dirname+0x50>
  4032d8:	8b 45 08             	mov    0x8(%ebp),%eax
  4032db:	80 38 00             	cmpb   $0x0,(%eax)
  4032de:	75 78                	jne    403358 <___mingw_dirname+0xc8>
  4032e0:	c7 44 24 08 00 00 00 	movl   $0x0,0x8(%esp)
  4032e7:	00 
  4032e8:	c7 44 24 04 22 52 40 	movl   $0x405222,0x4(%esp)
  4032ef:	00 
  4032f0:	c7 04 24 00 00 00 00 	movl   $0x0,(%esp)
  4032f7:	e8 70 0b 00 00       	call   403e6c <_wcstombs>
  4032fc:	8d 70 01             	lea    0x1(%eax),%esi
  4032ff:	89 74 24 04          	mov    %esi,0x4(%esp)
  403303:	a1 68 70 40 00       	mov    0x407068,%eax
  403308:	89 04 24             	mov    %eax,(%esp)
  40330b:	e8 c0 09 00 00       	call   403cd0 <___mingw_realloc>
  403310:	a3 68 70 40 00       	mov    %eax,0x407068
  403315:	89 74 24 08          	mov    %esi,0x8(%esp)
  403319:	c7 44 24 04 22 52 40 	movl   $0x405222,0x4(%esp)
  403320:	00 
  403321:	89 04 24             	mov    %eax,(%esp)
  403324:	e8 43 0b 00 00       	call   403e6c <_wcstombs>
  403329:	89 5c 24 04          	mov    %ebx,0x4(%esp)
  40332d:	c7 04 24 02 00 00 00 	movl   $0x2,(%esp)
  403334:	e8 63 0b 00 00       	call   403e9c <_setlocale>
  403339:	89 1c 24             	mov    %ebx,(%esp)
  40333c:	e8 1f ee ff ff       	call   402160 <___mingw_aligned_free>
  403341:	8b 35 68 70 40 00    	mov    0x407068,%esi
  403347:	8d 65 f4             	lea    -0xc(%ebp),%esp
  40334a:	89 f0                	mov    %esi,%eax
  40334c:	5b                   	pop    %ebx
  40334d:	5e                   	pop    %esi
  40334e:	5f                   	pop    %edi
  40334f:	5d                   	pop    %ebp
  403350:	c3                   	ret    
  403351:	8d b4 26 00 00 00 00 	lea    0x0(%esi,%eiz,1),%esi
  403358:	89 65 dc             	mov    %esp,-0x24(%ebp)
  40335b:	c7 44 24 08 00 00 00 	movl   $0x0,0x8(%esp)
  403362:	00 
  403363:	8b 45 08             	mov    0x8(%ebp),%eax
  403366:	c7 04 24 00 00 00 00 	movl   $0x0,(%esp)
  40336d:	89 44 24 04          	mov    %eax,0x4(%esp)
  403371:	e8 46 0b 00 00       	call   403ebc <_mbstowcs>
  403376:	89 c2                	mov    %eax,%edx
  403378:	8d 44 00 11          	lea    0x11(%eax,%eax,1),%eax
  40337c:	c1 e8 04             	shr    $0x4,%eax
  40337f:	c1 e0 04             	shl    $0x4,%eax
  403382:	e8 a9 0a 00 00       	call   403e30 <___chkstk_ms>
  403387:	29 c4                	sub    %eax,%esp
  403389:	89 54 24 08          	mov    %edx,0x8(%esp)
  40338d:	8b 45 08             	mov    0x8(%ebp),%eax
  403390:	8d 7c 24 0c          	lea    0xc(%esp),%edi
  403394:	89 3c 24             	mov    %edi,(%esp)
  403397:	89 44 24 04          	mov    %eax,0x4(%esp)
  40339b:	e8 1c 0b 00 00       	call   403ebc <_mbstowcs>
  4033a0:	31 d2                	xor    %edx,%edx
  4033a2:	83 f8 01             	cmp    $0x1,%eax
  4033a5:	89 45 d8             	mov    %eax,-0x28(%ebp)
  4033a8:	66 89 14 47          	mov    %dx,(%edi,%eax,2)
  4033ac:	0f b7 07             	movzwl (%edi),%eax
  4033af:	76 3f                	jbe    4033f0 <___mingw_dirname+0x160>
  4033b1:	89 c1                	mov    %eax,%ecx
  4033b3:	66 89 45 e2          	mov    %ax,-0x1e(%ebp)
  4033b7:	0f b7 47 02          	movzwl 0x2(%edi),%eax
  4033bb:	89 7d e4             	mov    %edi,-0x1c(%ebp)
  4033be:	66 83 f9 2f          	cmp    $0x2f,%cx
  4033c2:	0f 84 08 02 00 00    	je     4035d0 <___mingw_dirname+0x340>
  4033c8:	66 83 f9 5c          	cmp    $0x5c,%cx
  4033cc:	0f 84 fe 01 00 00    	je     4035d0 <___mingw_dirname+0x340>
  4033d2:	66 83 f8 3a          	cmp    $0x3a,%ax
  4033d6:	75 1f                	jne    4033f7 <___mingw_dirname+0x167>
  4033d8:	8d 47 04             	lea    0x4(%edi),%eax
  4033db:	89 45 e4             	mov    %eax,-0x1c(%ebp)
  4033de:	0f b7 47 04          	movzwl 0x4(%edi),%eax
  4033e2:	66 89 45 e2          	mov    %ax,-0x1e(%ebp)
  4033e6:	eb 0f                	jmp    4033f7 <___mingw_dirname+0x167>
  4033e8:	8d b4 26 00 00 00 00 	lea    0x0(%esi,%eiz,1),%esi
  4033ef:	90                   	nop
  4033f0:	66 89 45 e2          	mov    %ax,-0x1e(%ebp)
  4033f4:	89 7d e4             	mov    %edi,-0x1c(%ebp)
  4033f7:	66 83 7d e2 00       	cmpw   $0x0,-0x1e(%ebp)
  4033fc:	75 12                	jne    403410 <___mingw_dirname+0x180>
  4033fe:	8b 65 dc             	mov    -0x24(%ebp),%esp
  403401:	e9 da fe ff ff       	jmp    4032e0 <___mingw_dirname+0x50>
  403406:	8d b4 26 00 00 00 00 	lea    0x0(%esi,%eiz,1),%esi
  40340d:	8d 76 00             	lea    0x0(%esi),%esi
  403410:	8b 45 e4             	mov    -0x1c(%ebp),%eax
  403413:	0f b7 55 e2          	movzwl -0x1e(%ebp),%edx
  403417:	89 c1                	mov    %eax,%ecx
  403419:	eb 19                	jmp    403434 <___mingw_dirname+0x1a4>
  40341b:	8d 74 26 00          	lea    0x0(%esi,%eiz,1),%esi
  40341f:	90                   	nop
  403420:	89 c6                	mov    %eax,%esi
  403422:	66 83 fa 5c          	cmp    $0x5c,%dx
  403426:	74 23                	je     40344b <___mingw_dirname+0x1bb>
  403428:	0f b7 56 02          	movzwl 0x2(%esi),%edx
  40342c:	83 c0 02             	add    $0x2,%eax
  40342f:	66 85 d2             	test   %dx,%dx
  403432:	74 34                	je     403468 <___mingw_dirname+0x1d8>
  403434:	66 83 fa 2f          	cmp    $0x2f,%dx
  403438:	75 e6                	jne    403420 <___mingw_dirname+0x190>
  40343a:	0f b7 10             	movzwl (%eax),%edx
  40343d:	66 83 fa 2f          	cmp    $0x2f,%dx
  403441:	75 11                	jne    403454 <___mingw_dirname+0x1c4>
  403443:	8d 74 26 00          	lea    0x0(%esi,%eiz,1),%esi
  403447:	90                   	nop
  403448:	83 c0 02             	add    $0x2,%eax
  40344b:	0f b7 10             	movzwl (%eax),%edx
  40344e:	66 83 fa 2f          	cmp    $0x2f,%dx
  403452:	74 f4                	je     403448 <___mingw_dirname+0x1b8>
  403454:	66 83 fa 5c          	cmp    $0x5c,%dx
  403458:	74 ee                	je     403448 <___mingw_dirname+0x1b8>
  40345a:	89 c6                	mov    %eax,%esi
  40345c:	66 85 d2             	test   %dx,%dx
  40345f:	74 07                	je     403468 <___mingw_dirname+0x1d8>
  403461:	89 c1                	mov    %eax,%ecx
  403463:	eb c3                	jmp    403428 <___mingw_dirname+0x198>
  403465:	8d 76 00             	lea    0x0(%esi),%esi
  403468:	39 4d e4             	cmp    %ecx,-0x1c(%ebp)
  40346b:	0f 82 8f 00 00 00    	jb     403500 <___mingw_dirname+0x270>
  403471:	0f b7 45 e2          	movzwl -0x1e(%ebp),%eax
  403475:	66 83 f8 2f          	cmp    $0x2f,%ax
  403479:	74 11                	je     40348c <___mingw_dirname+0x1fc>
  40347b:	66 83 f8 5c          	cmp    $0x5c,%ax
  40347f:	74 0b                	je     40348c <___mingw_dirname+0x1fc>
  403481:	8b 45 e4             	mov    -0x1c(%ebp),%eax
  403484:	b9 2e 00 00 00       	mov    $0x2e,%ecx
  403489:	66 89 08             	mov    %cx,(%eax)
  40348c:	8b 45 e4             	mov    -0x1c(%ebp),%eax
  40348f:	31 d2                	xor    %edx,%edx
  403491:	66 89 50 02          	mov    %dx,0x2(%eax)
  403495:	c7 44 24 08 00 00 00 	movl   $0x0,0x8(%esp)
  40349c:	00 
  40349d:	89 7c 24 04          	mov    %edi,0x4(%esp)
  4034a1:	c7 04 24 00 00 00 00 	movl   $0x0,(%esp)
  4034a8:	e8 bf 09 00 00       	call   403e6c <_wcstombs>
  4034ad:	8d 50 01             	lea    0x1(%eax),%edx
  4034b0:	89 54 24 04          	mov    %edx,0x4(%esp)
  4034b4:	a1 68 70 40 00       	mov    0x407068,%eax
  4034b9:	89 55 e4             	mov    %edx,-0x1c(%ebp)
  4034bc:	89 04 24             	mov    %eax,(%esp)
  4034bf:	e8 0c 08 00 00       	call   403cd0 <___mingw_realloc>
  4034c4:	8b 55 e4             	mov    -0x1c(%ebp),%edx
  4034c7:	a3 68 70 40 00       	mov    %eax,0x407068
  4034cc:	89 c6                	mov    %eax,%esi
  4034ce:	89 54 24 08          	mov    %edx,0x8(%esp)
  4034d2:	89 7c 24 04          	mov    %edi,0x4(%esp)
  4034d6:	89 04 24             	mov    %eax,(%esp)
  4034d9:	e8 8e 09 00 00       	call   403e6c <_wcstombs>
  4034de:	89 5c 24 04          	mov    %ebx,0x4(%esp)
  4034e2:	c7 04 24 02 00 00 00 	movl   $0x2,(%esp)
  4034e9:	e8 ae 09 00 00       	call   403e9c <_setlocale>
  4034ee:	89 1c 24             	mov    %ebx,(%esp)
  4034f1:	e8 6a ec ff ff       	call   402160 <___mingw_aligned_free>
  4034f6:	8b 65 dc             	mov    -0x24(%ebp),%esp
  4034f9:	e9 49 fe ff ff       	jmp    403347 <___mingw_dirname+0xb7>
  4034fe:	66 90                	xchg   %ax,%ax
  403500:	89 c8                	mov    %ecx,%eax
  403502:	83 e9 02             	sub    $0x2,%ecx
  403505:	39 4d e4             	cmp    %ecx,-0x1c(%ebp)
  403508:	0f 83 4d 01 00 00    	jae    40365b <___mingw_dirname+0x3cb>
  40350e:	0f b7 01             	movzwl (%ecx),%eax
  403511:	66 83 f8 2f          	cmp    $0x2f,%ax
  403515:	74 e9                	je     403500 <___mingw_dirname+0x270>
  403517:	66 83 f8 5c          	cmp    $0x5c,%ax
  40351b:	74 e3                	je     403500 <___mingw_dirname+0x270>
  40351d:	31 c0                	xor    %eax,%eax
  40351f:	66 89 41 02          	mov    %ax,0x2(%ecx)
  403523:	0f b7 07             	movzwl (%edi),%eax
  403526:	89 f9                	mov    %edi,%ecx
  403528:	66 83 f8 2f          	cmp    $0x2f,%ax
  40352c:	74 12                	je     403540 <___mingw_dirname+0x2b0>
  40352e:	66 83 f8 5c          	cmp    $0x5c,%ax
  403532:	0f 85 cd 00 00 00    	jne    403605 <___mingw_dirname+0x375>
  403538:	8d b4 26 00 00 00 00 	lea    0x0(%esi,%eiz,1),%esi
  40353f:	90                   	nop
  403540:	0f b7 51 02          	movzwl 0x2(%ecx),%edx
  403544:	83 c1 02             	add    $0x2,%ecx
  403547:	66 83 fa 2f          	cmp    $0x2f,%dx
  40354b:	74 f3                	je     403540 <___mingw_dirname+0x2b0>
  40354d:	66 83 fa 5c          	cmp    $0x5c,%dx
  403551:	74 ed                	je     403540 <___mingw_dirname+0x2b0>
  403553:	89 ca                	mov    %ecx,%edx
  403555:	29 fa                	sub    %edi,%edx
  403557:	83 fa 04             	cmp    $0x4,%edx
  40355a:	0f 8e a5 00 00 00    	jle    403605 <___mingw_dirname+0x375>
  403560:	89 f9                	mov    %edi,%ecx
  403562:	66 85 c0             	test   %ax,%ax
  403565:	0f 84 c0 00 00 00    	je     40362b <___mingw_dirname+0x39b>
  40356b:	89 5d e4             	mov    %ebx,-0x1c(%ebp)
  40356e:	89 ca                	mov    %ecx,%edx
  403570:	eb 24                	jmp    403596 <___mingw_dirname+0x306>
  403572:	8d b6 00 00 00 00    	lea    0x0(%esi),%esi
  403578:	0f b7 5a 02          	movzwl 0x2(%edx),%ebx
  40357c:	8d 72 02             	lea    0x2(%edx),%esi
  40357f:	66 83 f8 5c          	cmp    $0x5c,%ax
  403583:	0f 84 97 00 00 00    	je     403620 <___mingw_dirname+0x390>
  403589:	89 d8                	mov    %ebx,%eax
  40358b:	89 f2                	mov    %esi,%edx
  40358d:	66 85 c0             	test   %ax,%ax
  403590:	0f 84 92 00 00 00    	je     403628 <___mingw_dirname+0x398>
  403596:	83 c1 02             	add    $0x2,%ecx
  403599:	66 89 41 fe          	mov    %ax,-0x2(%ecx)
  40359d:	66 83 f8 2f          	cmp    $0x2f,%ax
  4035a1:	75 d5                	jne    403578 <___mingw_dirname+0x2e8>
  4035a3:	0f b7 1a             	movzwl (%edx),%ebx
  4035a6:	66 83 fb 5c          	cmp    $0x5c,%bx
  4035aa:	74 0c                	je     4035b8 <___mingw_dirname+0x328>
  4035ac:	89 d8                	mov    %ebx,%eax
  4035ae:	66 83 fb 2f          	cmp    $0x2f,%bx
  4035b2:	75 d9                	jne    40358d <___mingw_dirname+0x2fd>
  4035b4:	8d 74 26 00          	lea    0x0(%esi,%eiz,1),%esi
  4035b8:	0f b7 42 02          	movzwl 0x2(%edx),%eax
  4035bc:	83 c2 02             	add    $0x2,%edx
  4035bf:	66 83 f8 2f          	cmp    $0x2f,%ax
  4035c3:	74 f3                	je     4035b8 <___mingw_dirname+0x328>
  4035c5:	66 83 f8 5c          	cmp    $0x5c,%ax
  4035c9:	74 ed                	je     4035b8 <___mingw_dirname+0x328>
  4035cb:	eb c0                	jmp    40358d <___mingw_dirname+0x2fd>
  4035cd:	8d 76 00             	lea    0x0(%esi),%esi
  4035d0:	66 39 45 e2          	cmp    %ax,-0x1e(%ebp)
  4035d4:	0f 85 1d fe ff ff    	jne    4033f7 <___mingw_dirname+0x167>
  4035da:	66 83 7f 04 00       	cmpw   $0x0,0x4(%edi)
  4035df:	0f 85 12 fe ff ff    	jne    4033f7 <___mingw_dirname+0x167>
  4035e5:	89 5c 24 04          	mov    %ebx,0x4(%esp)
  4035e9:	c7 04 24 02 00 00 00 	movl   $0x2,(%esp)
  4035f0:	e8 a7 08 00 00       	call   403e9c <_setlocale>
  4035f5:	89 1c 24             	mov    %ebx,(%esp)
  4035f8:	e8 63 eb ff ff       	call   402160 <___mingw_aligned_free>
  4035fd:	8b 75 08             	mov    0x8(%ebp),%esi
  403600:	e9 f1 fe ff ff       	jmp    4034f6 <___mingw_dirname+0x266>
  403605:	66 39 47 02          	cmp    %ax,0x2(%edi)
  403609:	0f 85 51 ff ff ff    	jne    403560 <___mingw_dirname+0x2d0>
  40360f:	0f b7 01             	movzwl (%ecx),%eax
  403612:	e9 4b ff ff ff       	jmp    403562 <___mingw_dirname+0x2d2>
  403617:	8d b4 26 00 00 00 00 	lea    0x0(%esi,%eiz,1),%esi
  40361e:	66 90                	xchg   %ax,%ax
  403620:	89 f2                	mov    %esi,%edx
  403622:	eb 82                	jmp    4035a6 <___mingw_dirname+0x316>
  403624:	8d 74 26 00          	lea    0x0(%esi,%eiz,1),%esi
  403628:	8b 5d e4             	mov    -0x1c(%ebp),%ebx
  40362b:	8b 45 d8             	mov    -0x28(%ebp),%eax
  40362e:	31 f6                	xor    %esi,%esi
  403630:	66 89 31             	mov    %si,(%ecx)
  403633:	89 44 24 08          	mov    %eax,0x8(%esp)
  403637:	89 7c 24 04          	mov    %edi,0x4(%esp)
  40363b:	8b 45 08             	mov    0x8(%ebp),%eax
  40363e:	89 04 24             	mov    %eax,(%esp)
  403641:	e8 26 08 00 00       	call   403e6c <_wcstombs>
  403646:	8b 75 08             	mov    0x8(%ebp),%esi
  403649:	83 f8 ff             	cmp    $0xffffffff,%eax
  40364c:	0f 84 8c fe ff ff    	je     4034de <___mingw_dirname+0x24e>
  403652:	c6 04 06 00          	movb   $0x0,(%esi,%eax,1)
  403656:	e9 83 fe ff ff       	jmp    4034de <___mingw_dirname+0x24e>
  40365b:	0f 85 bc fe ff ff    	jne    40351d <___mingw_dirname+0x28d>
  403661:	0f b7 75 e2          	movzwl -0x1e(%ebp),%esi
  403665:	66 83 fe 2f          	cmp    $0x2f,%si
  403669:	74 0a                	je     403675 <___mingw_dirname+0x3e5>
  40366b:	66 83 fe 5c          	cmp    $0x5c,%si
  40366f:	0f 85 a8 fe ff ff    	jne    40351d <___mingw_dirname+0x28d>
  403675:	0f b7 75 e2          	movzwl -0x1e(%ebp),%esi
  403679:	66 39 71 02          	cmp    %si,0x2(%ecx)
  40367d:	0f 85 9a fe ff ff    	jne    40351d <___mingw_dirname+0x28d>
  403683:	0f b7 51 04          	movzwl 0x4(%ecx),%edx
  403687:	66 83 fa 2f          	cmp    $0x2f,%dx
  40368b:	0f 84 8c fe ff ff    	je     40351d <___mingw_dirname+0x28d>
  403691:	66 83 fa 5c          	cmp    $0x5c,%dx
  403695:	0f 84 82 fe ff ff    	je     40351d <___mingw_dirname+0x28d>
  40369b:	89 c1                	mov    %eax,%ecx
  40369d:	e9 7b fe ff ff       	jmp    40351d <___mingw_dirname+0x28d>
  4036a2:	90                   	nop
  4036a3:	90                   	nop
  4036a4:	90                   	nop
  4036a5:	90                   	nop
  4036a6:	90                   	nop
  4036a7:	90                   	nop
  4036a8:	90                   	nop
  4036a9:	90                   	nop
  4036aa:	90                   	nop
  4036ab:	90                   	nop
  4036ac:	90                   	nop
  4036ad:	90                   	nop
  4036ae:	90                   	nop
  4036af:	90                   	nop

004036b0 <.text>:
  4036b0:	56                   	push   %esi
  4036b1:	53                   	push   %ebx
  4036b2:	89 d3                	mov    %edx,%ebx
  4036b4:	81 ec 54 01 00 00    	sub    $0x154,%esp
  4036ba:	8d 54 24 10          	lea    0x10(%esp),%edx
  4036be:	89 04 24             	mov    %eax,(%esp)
  4036c1:	89 54 24 04          	mov    %edx,0x4(%esp)
  4036c5:	e8 da 08 00 00       	call   403fa4 <_FindFirstFileA@8>
  4036ca:	83 ec 08             	sub    $0x8,%esp
  4036cd:	89 c6                	mov    %eax,%esi
  4036cf:	83 f8 ff             	cmp    $0xffffffff,%eax
  4036d2:	74 74                	je     403748 <.text+0x98>
  4036d4:	31 c0                	xor    %eax,%eax
  4036d6:	8d 4b 0c             	lea    0xc(%ebx),%ecx
  4036d9:	66 89 43 06          	mov    %ax,0x6(%ebx)
  4036dd:	0f b6 44 24 3c       	movzbl 0x3c(%esp),%eax
  4036e2:	88 43 0c             	mov    %al,0xc(%ebx)
  4036e5:	84 c0                	test   %al,%al
  4036e7:	74 27                	je     403710 <.text+0x60>
  4036e9:	31 c0                	xor    %eax,%eax
  4036eb:	eb 07                	jmp    4036f4 <.text+0x44>
  4036ed:	8d 76 00             	lea    0x0(%esi),%esi
  4036f0:	0f b7 43 06          	movzwl 0x6(%ebx),%eax
  4036f4:	83 c0 01             	add    $0x1,%eax
  4036f7:	66 89 43 06          	mov    %ax,0x6(%ebx)
  4036fb:	66 3d 04 01          	cmp    $0x104,%ax
  4036ff:	0f b7 c0             	movzwl %ax,%eax
  403702:	0f b6 44 04 3c       	movzbl 0x3c(%esp,%eax,1),%eax
  403707:	83 d1 00             	adc    $0x0,%ecx
  40370a:	88 01                	mov    %al,(%ecx)
  40370c:	84 c0                	test   %al,%al
  40370e:	75 e0                	jne    4036f0 <.text+0x40>
  403710:	8b 44 24 10          	mov    0x10(%esp),%eax
  403714:	24 58                	and    $0x58,%al
  403716:	83 f8 10             	cmp    $0x10,%eax
  403719:	77 15                	ja     403730 <.text+0x80>
  40371b:	89 43 08             	mov    %eax,0x8(%ebx)
  40371e:	81 c4 54 01 00 00    	add    $0x154,%esp
  403724:	89 f0                	mov    %esi,%eax
  403726:	5b                   	pop    %ebx
  403727:	5e                   	pop    %esi
  403728:	c3                   	ret    
  403729:	8d b4 26 00 00 00 00 	lea    0x0(%esi,%eiz,1),%esi
  403730:	c7 43 08 18 00 00 00 	movl   $0x18,0x8(%ebx)
  403737:	81 c4 54 01 00 00    	add    $0x154,%esp
  40373d:	89 f0                	mov    %esi,%eax
  40373f:	5b                   	pop    %ebx
  403740:	5e                   	pop    %esi
  403741:	c3                   	ret    
  403742:	8d b6 00 00 00 00    	lea    0x0(%esi),%esi
  403748:	e8 37 08 00 00       	call   403f84 <_GetLastError@0>
  40374d:	89 c3                	mov    %eax,%ebx
  40374f:	e8 b0 07 00 00       	call   403f04 <__errno>
  403754:	89 18                	mov    %ebx,(%eax)
  403756:	83 fb 03             	cmp    $0x3,%ebx
  403759:	74 24                	je     40377f <.text+0xcf>
  40375b:	e8 a4 07 00 00       	call   403f04 <__errno>
  403760:	81 38 0b 01 00 00    	cmpl   $0x10b,(%eax)
  403766:	74 24                	je     40378c <.text+0xdc>
  403768:	e8 97 07 00 00       	call   403f04 <__errno>
  40376d:	83 38 02             	cmpl   $0x2,(%eax)
  403770:	74 ac                	je     40371e <.text+0x6e>
  403772:	e8 8d 07 00 00       	call   403f04 <__errno>
  403777:	c7 00 16 00 00 00    	movl   $0x16,(%eax)
  40377d:	eb 9f                	jmp    40371e <.text+0x6e>
  40377f:	e8 80 07 00 00       	call   403f04 <__errno>
  403784:	c7 00 02 00 00 00    	movl   $0x2,(%eax)
  40378a:	eb 92                	jmp    40371e <.text+0x6e>
  40378c:	e8 73 07 00 00       	call   403f04 <__errno>
  403791:	c7 00 14 00 00 00    	movl   $0x14,(%eax)
  403797:	eb 85                	jmp    40371e <.text+0x6e>
  403799:	8d b4 26 00 00 00 00 	lea    0x0(%esi,%eiz,1),%esi
  4037a0:	56                   	push   %esi
  4037a1:	53                   	push   %ebx
  4037a2:	89 d3                	mov    %edx,%ebx
  4037a4:	81 ec 54 01 00 00    	sub    $0x154,%esp
  4037aa:	8d 54 24 10          	lea    0x10(%esp),%edx
  4037ae:	89 04 24             	mov    %eax,(%esp)
  4037b1:	89 54 24 04          	mov    %edx,0x4(%esp)
  4037b5:	e8 e2 07 00 00       	call   403f9c <_FindNextFileA@8>
  4037ba:	83 ec 08             	sub    $0x8,%esp
  4037bd:	89 c6                	mov    %eax,%esi
  4037bf:	85 c0                	test   %eax,%eax
  4037c1:	74 75                	je     403838 <.text+0x188>
  4037c3:	31 c0                	xor    %eax,%eax
  4037c5:	8d 4b 0c             	lea    0xc(%ebx),%ecx
  4037c8:	66 89 43 06          	mov    %ax,0x6(%ebx)
  4037cc:	0f b6 44 24 3c       	movzbl 0x3c(%esp),%eax
  4037d1:	88 43 0c             	mov    %al,0xc(%ebx)
  4037d4:	84 c0                	test   %al,%al
  4037d6:	74 28                	je     403800 <.text+0x150>
  4037d8:	31 c0                	xor    %eax,%eax
  4037da:	eb 08                	jmp    4037e4 <.text+0x134>
  4037dc:	8d 74 26 00          	lea    0x0(%esi,%eiz,1),%esi
  4037e0:	0f b7 43 06          	movzwl 0x6(%ebx),%eax
  4037e4:	83 c0 01             	add    $0x1,%eax
  4037e7:	66 89 43 06          	mov    %ax,0x6(%ebx)
  4037eb:	66 3d 04 01          	cmp    $0x104,%ax
  4037ef:	0f b7 c0             	movzwl %ax,%eax
  4037f2:	0f b6 44 04 3c       	movzbl 0x3c(%esp,%eax,1),%eax
  4037f7:	83 d1 00             	adc    $0x0,%ecx
  4037fa:	88 01                	mov    %al,(%ecx)
  4037fc:	84 c0                	test   %al,%al
  4037fe:	75 e0                	jne    4037e0 <.text+0x130>
  403800:	8b 44 24 10          	mov    0x10(%esp),%eax
  403804:	24 58                	and    $0x58,%al
  403806:	83 f8 10             	cmp    $0x10,%eax
  403809:	77 15                	ja     403820 <.text+0x170>
  40380b:	89 43 08             	mov    %eax,0x8(%ebx)
  40380e:	81 c4 54 01 00 00    	add    $0x154,%esp
  403814:	89 f0                	mov    %esi,%eax
  403816:	5b                   	pop    %ebx
  403817:	5e                   	pop    %esi
  403818:	c3                   	ret    
  403819:	8d b4 26 00 00 00 00 	lea    0x0(%esi,%eiz,1),%esi
  403820:	c7 43 08 18 00 00 00 	movl   $0x18,0x8(%ebx)
  403827:	81 c4 54 01 00 00    	add    $0x154,%esp
  40382d:	89 f0                	mov    %esi,%eax
  40382f:	5b                   	pop    %ebx
  403830:	5e                   	pop    %esi
  403831:	c3                   	ret    
  403832:	8d b6 00 00 00 00    	lea    0x0(%esi),%esi
  403838:	e8 47 07 00 00       	call   403f84 <_GetLastError@0>
  40383d:	83 f8 12             	cmp    $0x12,%eax
  403840:	74 cc                	je     40380e <.text+0x15e>
  403842:	e8 bd 06 00 00       	call   403f04 <__errno>
  403847:	c7 00 02 00 00 00    	movl   $0x2,(%eax)
  40384d:	81 c4 54 01 00 00    	add    $0x154,%esp
  403853:	89 f0                	mov    %esi,%eax
  403855:	5b                   	pop    %ebx
  403856:	5e                   	pop    %esi
  403857:	c3                   	ret    
  403858:	8d b4 26 00 00 00 00 	lea    0x0(%esi,%eiz,1),%esi
  40385f:	90                   	nop

00403860 <___mingw_opendir>:
  403860:	55                   	push   %ebp
  403861:	57                   	push   %edi
  403862:	56                   	push   %esi
  403863:	53                   	push   %ebx
  403864:	81 ec 2c 01 00 00    	sub    $0x12c,%esp
  40386a:	8b 84 24 40 01 00 00 	mov    0x140(%esp),%eax
  403871:	85 c0                	test   %eax,%eax
  403873:	0f 84 af 01 00 00    	je     403a28 <___mingw_opendir+0x1c8>
  403879:	80 38 00             	cmpb   $0x0,(%eax)
  40387c:	0f 84 86 01 00 00    	je     403a08 <___mingw_opendir+0x1a8>
  403882:	8d 74 24 1c          	lea    0x1c(%esp),%esi
  403886:	c7 44 24 08 04 01 00 	movl   $0x104,0x8(%esp)
  40388d:	00 
  40388e:	89 44 24 04          	mov    %eax,0x4(%esp)
  403892:	89 34 24             	mov    %esi,(%esp)
  403895:	e8 62 06 00 00       	call   403efc <__fullpath>
  40389a:	80 7c 24 1c 00       	cmpb   $0x0,0x1c(%esp)
  40389f:	89 f2                	mov    %esi,%edx
  4038a1:	74 4d                	je     4038f0 <___mingw_opendir+0x90>
  4038a3:	8b 0a                	mov    (%edx),%ecx
  4038a5:	83 c2 04             	add    $0x4,%edx
  4038a8:	8d 81 ff fe fe fe    	lea    -0x1010101(%ecx),%eax
  4038ae:	f7 d1                	not    %ecx
  4038b0:	21 c8                	and    %ecx,%eax
  4038b2:	25 80 80 80 80       	and    $0x80808080,%eax
  4038b7:	74 ea                	je     4038a3 <___mingw_opendir+0x43>
  4038b9:	a9 80 80 00 00       	test   $0x8080,%eax
  4038be:	0f 84 34 01 00 00    	je     4039f8 <___mingw_opendir+0x198>
  4038c4:	89 c3                	mov    %eax,%ebx
  4038c6:	00 c3                	add    %al,%bl
  4038c8:	83 da 03             	sbb    $0x3,%edx
  4038cb:	29 f2                	sub    %esi,%edx
  4038cd:	0f b6 4c 14 1b       	movzbl 0x1b(%esp,%edx,1),%ecx
  4038d2:	8d 04 16             	lea    (%esi,%edx,1),%eax
  4038d5:	80 f9 2f             	cmp    $0x2f,%cl
  4038d8:	74 40                	je     40391a <___mingw_opendir+0xba>
  4038da:	80 f9 5c             	cmp    $0x5c,%cl
  4038dd:	74 3b                	je     40391a <___mingw_opendir+0xba>
  4038df:	b9 5c 00 00 00       	mov    $0x5c,%ecx
  4038e4:	66 89 08             	mov    %cx,(%eax)
  4038e7:	8d 44 16 01          	lea    0x1(%esi,%edx,1),%eax
  4038eb:	eb 2d                	jmp    40391a <___mingw_opendir+0xba>
  4038ed:	8d 76 00             	lea    0x0(%esi),%esi
  4038f0:	8b 0a                	mov    (%edx),%ecx
  4038f2:	83 c2 04             	add    $0x4,%edx
  4038f5:	8d 81 ff fe fe fe    	lea    -0x1010101(%ecx),%eax
  4038fb:	f7 d1                	not    %ecx
  4038fd:	21 c8                	and    %ecx,%eax
  4038ff:	25 80 80 80 80       	and    $0x80808080,%eax
  403904:	74 ea                	je     4038f0 <___mingw_opendir+0x90>
  403906:	a9 80 80 00 00       	test   $0x8080,%eax
  40390b:	0f 84 d7 00 00 00    	je     4039e8 <___mingw_opendir+0x188>
  403911:	89 c3                	mov    %eax,%ebx
  403913:	00 c3                	add    %al,%bl
  403915:	89 d0                	mov    %edx,%eax
  403917:	83 d8 03             	sbb    $0x3,%eax
  40391a:	ba 2a 00 00 00       	mov    $0x2a,%edx
  40391f:	89 f3                	mov    %esi,%ebx
  403921:	66 89 10             	mov    %dx,(%eax)
  403924:	8b 13                	mov    (%ebx),%edx
  403926:	83 c3 04             	add    $0x4,%ebx
  403929:	8d 82 ff fe fe fe    	lea    -0x1010101(%edx),%eax
  40392f:	f7 d2                	not    %edx
  403931:	21 d0                	and    %edx,%eax
  403933:	25 80 80 80 80       	and    $0x80808080,%eax
  403938:	74 ea                	je     403924 <___mingw_opendir+0xc4>
  40393a:	a9 80 80 00 00       	test   $0x8080,%eax
  40393f:	75 06                	jne    403947 <___mingw_opendir+0xe7>
  403941:	c1 e8 10             	shr    $0x10,%eax
  403944:	83 c3 02             	add    $0x2,%ebx
  403947:	89 c1                	mov    %eax,%ecx
  403949:	00 c1                	add    %al,%cl
  40394b:	83 db 03             	sbb    $0x3,%ebx
  40394e:	29 f3                	sub    %esi,%ebx
  403950:	8d 83 1c 01 00 00    	lea    0x11c(%ebx),%eax
  403956:	89 04 24             	mov    %eax,(%esp)
  403959:	e8 66 05 00 00       	call   403ec4 <_malloc>
  40395e:	89 c5                	mov    %eax,%ebp
  403960:	85 c0                	test   %eax,%eax
  403962:	0f 84 e7 00 00 00    	je     403a4f <___mingw_opendir+0x1ef>
  403968:	8d 4b 01             	lea    0x1(%ebx),%ecx
  40396b:	8d 80 18 01 00 00    	lea    0x118(%eax),%eax
  403971:	83 f9 04             	cmp    $0x4,%ecx
  403974:	72 52                	jb     4039c8 <___mingw_opendir+0x168>
  403976:	8b 54 0c 18          	mov    0x18(%esp,%ecx,1),%edx
  40397a:	c1 eb 02             	shr    $0x2,%ebx
  40397d:	89 c7                	mov    %eax,%edi
  40397f:	89 54 08 fc          	mov    %edx,-0x4(%eax,%ecx,1)
  403983:	89 d9                	mov    %ebx,%ecx
  403985:	f3 a5                	rep movsl %ds:(%esi),%es:(%edi)
  403987:	89 ea                	mov    %ebp,%edx
  403989:	e8 22 fd ff ff       	call   4036b0 <.text>
  40398e:	89 85 10 01 00 00    	mov    %eax,0x110(%ebp)
  403994:	83 f8 ff             	cmp    $0xffffffff,%eax
  403997:	0f 84 a3 00 00 00    	je     403a40 <___mingw_opendir+0x1e0>
  40399d:	b8 10 01 00 00       	mov    $0x110,%eax
  4039a2:	c7 45 00 00 00 00 00 	movl   $0x0,0x0(%ebp)
  4039a9:	c7 85 14 01 00 00 00 	movl   $0x0,0x114(%ebp)
  4039b0:	00 00 00 
  4039b3:	66 89 45 04          	mov    %ax,0x4(%ebp)
  4039b7:	81 c4 2c 01 00 00    	add    $0x12c,%esp
  4039bd:	89 e8                	mov    %ebp,%eax
  4039bf:	5b                   	pop    %ebx
  4039c0:	5e                   	pop    %esi
  4039c1:	5f                   	pop    %edi
  4039c2:	5d                   	pop    %ebp
  4039c3:	c3                   	ret    
  4039c4:	8d 74 26 00          	lea    0x0(%esi,%eiz,1),%esi
  4039c8:	85 c9                	test   %ecx,%ecx
  4039ca:	74 bb                	je     403987 <___mingw_opendir+0x127>
  4039cc:	0f b6 16             	movzbl (%esi),%edx
  4039cf:	88 10                	mov    %dl,(%eax)
  4039d1:	f6 c1 02             	test   $0x2,%cl
  4039d4:	74 b1                	je     403987 <___mingw_opendir+0x127>
  4039d6:	0f b7 54 0e fe       	movzwl -0x2(%esi,%ecx,1),%edx
  4039db:	66 89 54 08 fe       	mov    %dx,-0x2(%eax,%ecx,1)
  4039e0:	eb a5                	jmp    403987 <___mingw_opendir+0x127>
  4039e2:	8d b6 00 00 00 00    	lea    0x0(%esi),%esi
  4039e8:	c1 e8 10             	shr    $0x10,%eax
  4039eb:	83 c2 02             	add    $0x2,%edx
  4039ee:	e9 1e ff ff ff       	jmp    403911 <___mingw_opendir+0xb1>
  4039f3:	8d 74 26 00          	lea    0x0(%esi,%eiz,1),%esi
  4039f7:	90                   	nop
  4039f8:	c1 e8 10             	shr    $0x10,%eax
  4039fb:	83 c2 02             	add    $0x2,%edx
  4039fe:	e9 c1 fe ff ff       	jmp    4038c4 <___mingw_opendir+0x64>
  403a03:	8d 74 26 00          	lea    0x0(%esi,%eiz,1),%esi
  403a07:	90                   	nop
  403a08:	e8 f7 04 00 00       	call   403f04 <__errno>
  403a0d:	31 ed                	xor    %ebp,%ebp
  403a0f:	c7 00 02 00 00 00    	movl   $0x2,(%eax)
  403a15:	81 c4 2c 01 00 00    	add    $0x12c,%esp
  403a1b:	89 e8                	mov    %ebp,%eax
  403a1d:	5b                   	pop    %ebx
  403a1e:	5e                   	pop    %esi
  403a1f:	5f                   	pop    %edi
  403a20:	5d                   	pop    %ebp
  403a21:	c3                   	ret    
  403a22:	8d b6 00 00 00 00    	lea    0x0(%esi),%esi
  403a28:	e8 d7 04 00 00       	call   403f04 <__errno>
  403a2d:	31 ed                	xor    %ebp,%ebp
  403a2f:	c7 00 16 00 00 00    	movl   $0x16,(%eax)
  403a35:	eb 80                	jmp    4039b7 <___mingw_opendir+0x157>
  403a37:	8d b4 26 00 00 00 00 	lea    0x0(%esi,%eiz,1),%esi
  403a3e:	66 90                	xchg   %ax,%ax
  403a40:	89 2c 24             	mov    %ebp,(%esp)
  403a43:	31 ed                	xor    %ebp,%ebp
  403a45:	e8 16 e7 ff ff       	call   402160 <___mingw_aligned_free>
  403a4a:	e9 68 ff ff ff       	jmp    4039b7 <___mingw_opendir+0x157>
  403a4f:	e8 b0 04 00 00       	call   403f04 <__errno>
  403a54:	c7 00 0c 00 00 00    	movl   $0xc,(%eax)
  403a5a:	e9 58 ff ff ff       	jmp    4039b7 <___mingw_opendir+0x157>
  403a5f:	90                   	nop

00403a60 <___mingw_readdir>:
  403a60:	53                   	push   %ebx
  403a61:	83 ec 08             	sub    $0x8,%esp
  403a64:	8b 44 24 10          	mov    0x10(%esp),%eax
  403a68:	85 c0                	test   %eax,%eax
  403a6a:	74 34                	je     403aa0 <___mingw_readdir+0x40>
  403a6c:	8b 90 14 01 00 00    	mov    0x114(%eax),%edx
  403a72:	89 c3                	mov    %eax,%ebx
  403a74:	8d 4a 01             	lea    0x1(%edx),%ecx
  403a77:	89 88 14 01 00 00    	mov    %ecx,0x114(%eax)
  403a7d:	85 d2                	test   %edx,%edx
  403a7f:	7e 16                	jle    403a97 <___mingw_readdir+0x37>
  403a81:	8b 80 10 01 00 00    	mov    0x110(%eax),%eax
  403a87:	89 da                	mov    %ebx,%edx
  403a89:	e8 12 fd ff ff       	call   4037a0 <.text+0xf0>
  403a8e:	83 f8 01             	cmp    $0x1,%eax
  403a91:	19 c0                	sbb    %eax,%eax
  403a93:	f7 d0                	not    %eax
  403a95:	21 c3                	and    %eax,%ebx
  403a97:	83 c4 08             	add    $0x8,%esp
  403a9a:	89 d8                	mov    %ebx,%eax
  403a9c:	5b                   	pop    %ebx
  403a9d:	c3                   	ret    
  403a9e:	66 90                	xchg   %ax,%ax
  403aa0:	e8 5f 04 00 00       	call   403f04 <__errno>
  403aa5:	31 db                	xor    %ebx,%ebx
  403aa7:	c7 00 09 00 00 00    	movl   $0x9,(%eax)
  403aad:	eb e8                	jmp    403a97 <___mingw_readdir+0x37>
  403aaf:	90                   	nop

00403ab0 <___mingw_closedir>:
  403ab0:	53                   	push   %ebx
  403ab1:	83 ec 18             	sub    $0x18,%esp
  403ab4:	8b 5c 24 20          	mov    0x20(%esp),%ebx
  403ab8:	85 db                	test   %ebx,%ebx
  403aba:	74 24                	je     403ae0 <___mingw_closedir+0x30>
  403abc:	8b 83 10 01 00 00    	mov    0x110(%ebx),%eax
  403ac2:	89 04 24             	mov    %eax,(%esp)
  403ac5:	e8 e2 04 00 00       	call   403fac <_FindClose@4>
  403aca:	83 ec 04             	sub    $0x4,%esp
  403acd:	85 c0                	test   %eax,%eax
  403acf:	74 0f                	je     403ae0 <___mingw_closedir+0x30>
  403ad1:	89 1c 24             	mov    %ebx,(%esp)
  403ad4:	e8 87 e6 ff ff       	call   402160 <___mingw_aligned_free>
  403ad9:	31 c0                	xor    %eax,%eax
  403adb:	83 c4 18             	add    $0x18,%esp
  403ade:	5b                   	pop    %ebx
  403adf:	c3                   	ret    
  403ae0:	e8 1f 04 00 00       	call   403f04 <__errno>
  403ae5:	c7 00 09 00 00 00    	movl   $0x9,(%eax)
  403aeb:	b8 ff ff ff ff       	mov    $0xffffffff,%eax
  403af0:	eb e9                	jmp    403adb <___mingw_closedir+0x2b>
  403af2:	8d b4 26 00 00 00 00 	lea    0x0(%esi,%eiz,1),%esi
  403af9:	8d b4 26 00 00 00 00 	lea    0x0(%esi,%eiz,1),%esi

00403b00 <___mingw_rewinddir>:
  403b00:	53                   	push   %ebx
  403b01:	83 ec 18             	sub    $0x18,%esp
  403b04:	8b 5c 24 20          	mov    0x20(%esp),%ebx
  403b08:	85 db                	test   %ebx,%ebx
  403b0a:	74 15                	je     403b21 <___mingw_rewinddir+0x21>
  403b0c:	8b 83 10 01 00 00    	mov    0x110(%ebx),%eax
  403b12:	89 04 24             	mov    %eax,(%esp)
  403b15:	e8 92 04 00 00       	call   403fac <_FindClose@4>
  403b1a:	83 ec 04             	sub    $0x4,%esp
  403b1d:	85 c0                	test   %eax,%eax
  403b1f:	75 17                	jne    403b38 <___mingw_rewinddir+0x38>
  403b21:	e8 de 03 00 00       	call   403f04 <__errno>
  403b26:	c7 00 09 00 00 00    	movl   $0x9,(%eax)
  403b2c:	83 c4 18             	add    $0x18,%esp
  403b2f:	5b                   	pop    %ebx
  403b30:	c3                   	ret    
  403b31:	8d b4 26 00 00 00 00 	lea    0x0(%esi,%eiz,1),%esi
  403b38:	8d 83 18 01 00 00    	lea    0x118(%ebx),%eax
  403b3e:	89 da                	mov    %ebx,%edx
  403b40:	e8 6b fb ff ff       	call   4036b0 <.text>
  403b45:	89 83 10 01 00 00    	mov    %eax,0x110(%ebx)
  403b4b:	83 f8 ff             	cmp    $0xffffffff,%eax
  403b4e:	74 dc                	je     403b2c <___mingw_rewinddir+0x2c>
  403b50:	c7 83 14 01 00 00 00 	movl   $0x0,0x114(%ebx)
  403b57:	00 00 00 
  403b5a:	83 c4 18             	add    $0x18,%esp
  403b5d:	5b                   	pop    %ebx
  403b5e:	c3                   	ret    
  403b5f:	90                   	nop

00403b60 <___mingw_telldir>:
  403b60:	83 ec 0c             	sub    $0xc,%esp
  403b63:	8b 44 24 10          	mov    0x10(%esp),%eax
  403b67:	85 c0                	test   %eax,%eax
  403b69:	74 0a                	je     403b75 <___mingw_telldir+0x15>
  403b6b:	8b 80 14 01 00 00    	mov    0x114(%eax),%eax
  403b71:	83 c4 0c             	add    $0xc,%esp
  403b74:	c3                   	ret    
  403b75:	e8 8a 03 00 00       	call   403f04 <__errno>
  403b7a:	c7 00 09 00 00 00    	movl   $0x9,(%eax)
  403b80:	b8 ff ff ff ff       	mov    $0xffffffff,%eax
  403b85:	eb ea                	jmp    403b71 <___mingw_telldir+0x11>
  403b87:	8d b4 26 00 00 00 00 	lea    0x0(%esi,%eiz,1),%esi
  403b8e:	66 90                	xchg   %ax,%ax

00403b90 <___mingw_seekdir>:
  403b90:	56                   	push   %esi
  403b91:	53                   	push   %ebx
  403b92:	83 ec 14             	sub    $0x14,%esp
  403b95:	8b 74 24 24          	mov    0x24(%esp),%esi
  403b99:	8b 5c 24 20          	mov    0x20(%esp),%ebx
  403b9d:	85 f6                	test   %esi,%esi
  403b9f:	78 4f                	js     403bf0 <___mingw_seekdir+0x60>
  403ba1:	89 1c 24             	mov    %ebx,(%esp)
  403ba4:	e8 57 ff ff ff       	call   403b00 <___mingw_rewinddir>
  403ba9:	85 f6                	test   %esi,%esi
  403bab:	74 37                	je     403be4 <___mingw_seekdir+0x54>
  403bad:	83 bb 10 01 00 00 ff 	cmpl   $0xffffffff,0x110(%ebx)
  403bb4:	75 1b                	jne    403bd1 <___mingw_seekdir+0x41>
  403bb6:	eb 2c                	jmp    403be4 <___mingw_seekdir+0x54>
  403bb8:	8d b4 26 00 00 00 00 	lea    0x0(%esi,%eiz,1),%esi
  403bbf:	90                   	nop
  403bc0:	8b 83 10 01 00 00    	mov    0x110(%ebx),%eax
  403bc6:	89 da                	mov    %ebx,%edx
  403bc8:	e8 d3 fb ff ff       	call   4037a0 <.text+0xf0>
  403bcd:	85 c0                	test   %eax,%eax
  403bcf:	74 13                	je     403be4 <___mingw_seekdir+0x54>
  403bd1:	8b 83 14 01 00 00    	mov    0x114(%ebx),%eax
  403bd7:	83 c0 01             	add    $0x1,%eax
  403bda:	89 83 14 01 00 00    	mov    %eax,0x114(%ebx)
  403be0:	39 f0                	cmp    %esi,%eax
  403be2:	7c dc                	jl     403bc0 <___mingw_seekdir+0x30>
  403be4:	83 c4 14             	add    $0x14,%esp
  403be7:	5b                   	pop    %ebx
  403be8:	5e                   	pop    %esi
  403be9:	c3                   	ret    
  403bea:	8d b6 00 00 00 00    	lea    0x0(%esi),%esi
  403bf0:	e8 0f 03 00 00       	call   403f04 <__errno>
  403bf5:	c7 00 16 00 00 00    	movl   $0x16,(%eax)
  403bfb:	83 c4 14             	add    $0x14,%esp
  403bfe:	5b                   	pop    %ebx
  403bff:	5e                   	pop    %esi
  403c00:	c3                   	ret    
  403c01:	90                   	nop
  403c02:	90                   	nop
  403c03:	90                   	nop
  403c04:	90                   	nop
  403c05:	90                   	nop
  403c06:	90                   	nop
  403c07:	90                   	nop
  403c08:	90                   	nop
  403c09:	90                   	nop
  403c0a:	90                   	nop
  403c0b:	90                   	nop
  403c0c:	90                   	nop
  403c0d:	90                   	nop
  403c0e:	90                   	nop
  403c0f:	90                   	nop

00403c10 <___mingw_memalign_base>:
  403c10:	55                   	push   %ebp
  403c11:	57                   	push   %edi
  403c12:	56                   	push   %esi
  403c13:	53                   	push   %ebx
  403c14:	83 ec 08             	sub    $0x8,%esp
  403c17:	8b 44 24 1c          	mov    0x1c(%esp),%eax
  403c1b:	85 c0                	test   %eax,%eax
  403c1d:	0f 84 83 00 00 00    	je     403ca6 <___mingw_memalign_base+0x96>
  403c23:	8b 35 6c 70 40 00    	mov    0x40706c,%esi
  403c29:	85 f6                	test   %esi,%esi
  403c2b:	74 79                	je     403ca6 <___mingw_memalign_base+0x96>
  403c2d:	8d 56 08             	lea    0x8(%esi),%edx
  403c30:	39 c2                	cmp    %eax,%edx
  403c32:	77 72                	ja     403ca6 <___mingw_memalign_base+0x96>
  403c34:	8d 50 fc             	lea    -0x4(%eax),%edx
  403c37:	8b 7c 24 20          	mov    0x20(%esp),%edi
  403c3b:	83 e2 fc             	and    $0xfffffffc,%edx
  403c3e:	8b 12                	mov    (%edx),%edx
  403c40:	89 d3                	mov    %edx,%ebx
  403c42:	89 d1                	mov    %edx,%ecx
  403c44:	83 e3 03             	and    $0x3,%ebx
  403c47:	83 e1 fc             	and    $0xfffffffc,%ecx
  403c4a:	89 5f 04             	mov    %ebx,0x4(%edi)
  403c4d:	89 0f                	mov    %ecx,(%edi)
  403c4f:	39 ce                	cmp    %ecx,%esi
  403c51:	77 53                	ja     403ca6 <___mingw_memalign_base+0x96>
  403c53:	8d 70 f8             	lea    -0x8(%eax),%esi
  403c56:	39 f1                	cmp    %esi,%ecx
  403c58:	77 4c                	ja     403ca6 <___mingw_memalign_base+0x96>
  403c5a:	89 4c 24 04          	mov    %ecx,0x4(%esp)
  403c5e:	f6 c2 01             	test   $0x1,%dl
  403c61:	74 4d                	je     403cb0 <___mingw_memalign_base+0xa0>
  403c63:	8b 39                	mov    (%ecx),%edi
  403c65:	89 fd                	mov    %edi,%ebp
  403c67:	8d 77 07             	lea    0x7(%edi),%esi
  403c6a:	f7 dd                	neg    %ebp
  403c6c:	89 2c 24             	mov    %ebp,(%esp)
  403c6f:	8b 6c 24 20          	mov    0x20(%esp),%ebp
  403c73:	89 7d 08             	mov    %edi,0x8(%ebp)
  403c76:	83 e2 02             	and    $0x2,%edx
  403c79:	74 0b                	je     403c86 <___mingw_memalign_base+0x76>
  403c7b:	8d 53 01             	lea    0x1(%ebx),%edx
  403c7e:	c1 ea 02             	shr    $0x2,%edx
  403c81:	8b 14 91             	mov    (%ecx,%edx,4),%edx
  403c84:	01 d1                	add    %edx,%ecx
  403c86:	8b 6c 24 20          	mov    0x20(%esp),%ebp
  403c8a:	89 55 0c             	mov    %edx,0xc(%ebp)
  403c8d:	83 fb 03             	cmp    $0x3,%ebx
  403c90:	75 03                	jne    403c95 <___mingw_memalign_base+0x85>
  403c92:	8d 77 0b             	lea    0xb(%edi),%esi
  403c95:	8b 2c 24             	mov    (%esp),%ebp
  403c98:	01 f1                	add    %esi,%ecx
  403c9a:	21 cd                	and    %ecx,%ebp
  403c9c:	29 d5                	sub    %edx,%ebp
  403c9e:	39 e8                	cmp    %ebp,%eax
  403ca0:	75 04                	jne    403ca6 <___mingw_memalign_base+0x96>
  403ca2:	8b 44 24 04          	mov    0x4(%esp),%eax
  403ca6:	83 c4 08             	add    $0x8,%esp
  403ca9:	5b                   	pop    %ebx
  403caa:	5e                   	pop    %esi
  403cab:	5f                   	pop    %edi
  403cac:	5d                   	pop    %ebp
  403cad:	c3                   	ret    
  403cae:	66 90                	xchg   %ax,%ax
  403cb0:	c7 04 24 f8 ff ff ff 	movl   $0xfffffff8,(%esp)
  403cb7:	be 0f 00 00 00       	mov    $0xf,%esi
  403cbc:	bf 08 00 00 00       	mov    $0x8,%edi
  403cc1:	eb ac                	jmp    403c6f <___mingw_memalign_base+0x5f>
  403cc3:	90                   	nop
  403cc4:	90                   	nop
  403cc5:	90                   	nop
  403cc6:	90                   	nop
  403cc7:	90                   	nop
  403cc8:	90                   	nop
  403cc9:	90                   	nop
  403cca:	90                   	nop
  403ccb:	90                   	nop
  403ccc:	90                   	nop
  403ccd:	90                   	nop
  403cce:	90                   	nop
  403ccf:	90                   	nop

00403cd0 <___mingw_realloc>:
  403cd0:	57                   	push   %edi
  403cd1:	56                   	push   %esi
  403cd2:	53                   	push   %ebx
  403cd3:	83 ec 20             	sub    $0x20,%esp
  403cd6:	8b 5c 24 30          	mov    0x30(%esp),%ebx
  403cda:	8b 74 24 34          	mov    0x34(%esp),%esi
  403cde:	85 db                	test   %ebx,%ebx
  403ce0:	74 3a                	je     403d1c <___mingw_realloc+0x4c>
  403ce2:	8d 7c 24 10          	lea    0x10(%esp),%edi
  403ce6:	89 1c 24             	mov    %ebx,(%esp)
  403ce9:	89 7c 24 04          	mov    %edi,0x4(%esp)
  403ced:	e8 1e ff ff ff       	call   403c10 <___mingw_memalign_base>
  403cf2:	39 c3                	cmp    %eax,%ebx
  403cf4:	74 26                	je     403d1c <___mingw_realloc+0x4c>
  403cf6:	85 f6                	test   %esi,%esi
  403cf8:	74 1e                	je     403d18 <___mingw_realloc+0x48>
  403cfa:	39 74 24 1c          	cmp    %esi,0x1c(%esp)
  403cfe:	72 30                	jb     403d30 <___mingw_realloc+0x60>
  403d00:	e8 ff 01 00 00       	call   403f04 <__errno>
  403d05:	c7 00 16 00 00 00    	movl   $0x16,(%eax)
  403d0b:	83 c4 20             	add    $0x20,%esp
  403d0e:	31 c0                	xor    %eax,%eax
  403d10:	5b                   	pop    %ebx
  403d11:	5e                   	pop    %esi
  403d12:	5f                   	pop    %edi
  403d13:	c3                   	ret    
  403d14:	8d 74 26 00          	lea    0x0(%esi,%eiz,1),%esi
  403d18:	8b 5c 24 10          	mov    0x10(%esp),%ebx
  403d1c:	89 74 24 04          	mov    %esi,0x4(%esp)
  403d20:	89 1c 24             	mov    %ebx,(%esp)
  403d23:	ff 15 18 82 40 00    	call   *0x408218
  403d29:	83 c4 20             	add    $0x20,%esp
  403d2c:	5b                   	pop    %ebx
  403d2d:	5e                   	pop    %esi
  403d2e:	5f                   	pop    %edi
  403d2f:	c3                   	ret    
  403d30:	89 74 24 08          	mov    %esi,0x8(%esp)
  403d34:	89 7c 24 04          	mov    %edi,0x4(%esp)
  403d38:	89 1c 24             	mov    %ebx,(%esp)
  403d3b:	e8 10 00 00 00       	call   403d50 <___mingw_memalign_realloc>
  403d40:	83 c4 20             	add    $0x20,%esp
  403d43:	5b                   	pop    %ebx
  403d44:	5e                   	pop    %esi
  403d45:	5f                   	pop    %edi
  403d46:	c3                   	ret    
  403d47:	90                   	nop
  403d48:	90                   	nop
  403d49:	90                   	nop
  403d4a:	90                   	nop
  403d4b:	90                   	nop
  403d4c:	90                   	nop
  403d4d:	90                   	nop
  403d4e:	90                   	nop
  403d4f:	90                   	nop

00403d50 <___mingw_memalign_realloc>:
  403d50:	55                   	push   %ebp
  403d51:	57                   	push   %edi
  403d52:	56                   	push   %esi
  403d53:	53                   	push   %ebx
  403d54:	83 ec 1c             	sub    $0x1c,%esp
  403d57:	8b 74 24 34          	mov    0x34(%esp),%esi
  403d5b:	8b 06                	mov    (%esi),%eax
  403d5d:	89 04 24             	mov    %eax,(%esp)
  403d60:	e8 87 01 00 00       	call   403eec <__msize>
  403d65:	8b 56 08             	mov    0x8(%esi),%edx
  403d68:	89 c7                	mov    %eax,%edi
  403d6a:	8b 46 04             	mov    0x4(%esi),%eax
  403d6d:	8d 5a 07             	lea    0x7(%edx),%ebx
  403d70:	83 e0 03             	and    $0x3,%eax
  403d73:	83 f8 03             	cmp    $0x3,%eax
  403d76:	75 03                	jne    403d7b <___mingw_memalign_realloc+0x2b>
  403d78:	8d 5a 0b             	lea    0xb(%edx),%ebx
  403d7b:	8b 44 24 38          	mov    0x38(%esp),%eax
  403d7f:	01 d8                	add    %ebx,%eax
  403d81:	89 44 24 04          	mov    %eax,0x4(%esp)
  403d85:	8b 06                	mov    (%esi),%eax
  403d87:	89 04 24             	mov    %eax,(%esp)
  403d8a:	ff 15 18 82 40 00    	call   *0x408218
  403d90:	8b 16                	mov    (%esi),%edx
  403d92:	39 c2                	cmp    %eax,%edx
  403d94:	0f 84 86 00 00 00    	je     403e20 <___mingw_memalign_realloc+0xd0>
  403d9a:	31 ed                	xor    %ebp,%ebp
  403d9c:	85 c0                	test   %eax,%eax
  403d9e:	74 59                	je     403df9 <___mingw_memalign_realloc+0xa9>
  403da0:	8b 4c 24 30          	mov    0x30(%esp),%ecx
  403da4:	8b 2d 6c 70 40 00    	mov    0x40706c,%ebp
  403daa:	29 d1                	sub    %edx,%ecx
  403dac:	85 ed                	test   %ebp,%ebp
  403dae:	75 58                	jne    403e08 <___mingw_memalign_realloc+0xb8>
  403db0:	a3 6c 70 40 00       	mov    %eax,0x40706c
  403db5:	8b 6e 04             	mov    0x4(%esi),%ebp
  403db8:	03 5e 0c             	add    0xc(%esi),%ebx
  403dbb:	01 c3                	add    %eax,%ebx
  403dbd:	09 c5                	or     %eax,%ebp
  403dbf:	01 c8                	add    %ecx,%eax
  403dc1:	89 2e                	mov    %ebp,(%esi)
  403dc3:	8b 6e 08             	mov    0x8(%esi),%ebp
  403dc6:	f7 dd                	neg    %ebp
  403dc8:	21 eb                	and    %ebp,%ebx
  403dca:	2b 5e 0c             	sub    0xc(%esi),%ebx
  403dcd:	89 dd                	mov    %ebx,%ebp
  403dcf:	39 c3                	cmp    %eax,%ebx
  403dd1:	74 1c                	je     403def <___mingw_memalign_realloc+0x9f>
  403dd3:	2b 54 24 30          	sub    0x30(%esp),%edx
  403dd7:	01 d7                	add    %edx,%edi
  403dd9:	3b 7c 24 38          	cmp    0x38(%esp),%edi
  403ddd:	77 31                	ja     403e10 <___mingw_memalign_realloc+0xc0>
  403ddf:	89 7c 24 08          	mov    %edi,0x8(%esp)
  403de3:	89 44 24 04          	mov    %eax,0x4(%esp)
  403de7:	89 1c 24             	mov    %ebx,(%esp)
  403dea:	e8 bd 00 00 00       	call   403eac <_memmove>
  403def:	8b 06                	mov    (%esi),%eax
  403df1:	83 eb 04             	sub    $0x4,%ebx
  403df4:	83 e3 fc             	and    $0xfffffffc,%ebx
  403df7:	89 03                	mov    %eax,(%ebx)
  403df9:	83 c4 1c             	add    $0x1c,%esp
  403dfc:	89 e8                	mov    %ebp,%eax
  403dfe:	5b                   	pop    %ebx
  403dff:	5e                   	pop    %esi
  403e00:	5f                   	pop    %edi
  403e01:	5d                   	pop    %ebp
  403e02:	c3                   	ret    
  403e03:	8d 74 26 00          	lea    0x0(%esi,%eiz,1),%esi
  403e07:	90                   	nop
  403e08:	39 c5                	cmp    %eax,%ebp
  403e0a:	76 a9                	jbe    403db5 <___mingw_memalign_realloc+0x65>
  403e0c:	eb a2                	jmp    403db0 <___mingw_memalign_realloc+0x60>
  403e0e:	66 90                	xchg   %ax,%ax
  403e10:	8b 7c 24 38          	mov    0x38(%esp),%edi
  403e14:	eb c9                	jmp    403ddf <___mingw_memalign_realloc+0x8f>
  403e16:	8d b4 26 00 00 00 00 	lea    0x0(%esi,%eiz,1),%esi
  403e1d:	8d 76 00             	lea    0x0(%esi),%esi
  403e20:	8b 6c 24 30          	mov    0x30(%esp),%ebp
  403e24:	83 c4 1c             	add    $0x1c,%esp
  403e27:	5b                   	pop    %ebx
  403e28:	5e                   	pop    %esi
  403e29:	89 e8                	mov    %ebp,%eax
  403e2b:	5f                   	pop    %edi
  403e2c:	5d                   	pop    %ebp
  403e2d:	c3                   	ret    
  403e2e:	90                   	nop
  403e2f:	90                   	nop

00403e30 <___chkstk_ms>:
  403e30:	51                   	push   %ecx
  403e31:	50                   	push   %eax
  403e32:	3d 00 10 00 00       	cmp    $0x1000,%eax
  403e37:	8d 4c 24 0c          	lea    0xc(%esp),%ecx
  403e3b:	72 15                	jb     403e52 <___chkstk_ms+0x22>
  403e3d:	81 e9 00 10 00 00    	sub    $0x1000,%ecx
  403e43:	83 09 00             	orl    $0x0,(%ecx)
  403e46:	2d 00 10 00 00       	sub    $0x1000,%eax
  403e4b:	3d 00 10 00 00       	cmp    $0x1000,%eax
  403e50:	77 eb                	ja     403e3d <___chkstk_ms+0xd>
  403e52:	29 c1                	sub    %eax,%ecx
  403e54:	83 09 00             	orl    $0x0,(%ecx)
  403e57:	58                   	pop    %eax
  403e58:	59                   	pop    %ecx
  403e59:	c3                   	ret    
  403e5a:	90                   	nop
  403e5b:	90                   	nop

00403e5c <_stricoll>:
  403e5c:	ff 25 8c 81 40 00    	jmp    *0x40818c
  403e62:	90                   	nop
  403e63:	90                   	nop

00403e64 <_strdup>:
  403e64:	ff 25 88 81 40 00    	jmp    *0x408188
  403e6a:	90                   	nop
  403e6b:	90                   	nop

00403e6c <_wcstombs>:
  403e6c:	ff 25 10 82 40 00    	jmp    *0x408210
  403e72:	90                   	nop
  403e73:	90                   	nop

00403e74 <_vfprintf>:
  403e74:	ff 25 0c 82 40 00    	jmp    *0x40820c
  403e7a:	90                   	nop
  403e7b:	90                   	nop

00403e7c <_tolower>:
  403e7c:	ff 25 08 82 40 00    	jmp    *0x408208
  403e82:	90                   	nop
  403e83:	90                   	nop

00403e84 <_strlen>:
  403e84:	ff 25 04 82 40 00    	jmp    *0x408204
  403e8a:	90                   	nop
  403e8b:	90                   	nop

00403e8c <_strcoll>:
  403e8c:	ff 25 00 82 40 00    	jmp    *0x408200
  403e92:	90                   	nop
  403e93:	90                   	nop

00403e94 <_signal>:
  403e94:	ff 25 fc 81 40 00    	jmp    *0x4081fc
  403e9a:	90                   	nop
  403e9b:	90                   	nop

00403e9c <_setlocale>:
  403e9c:	ff 25 f8 81 40 00    	jmp    *0x4081f8
  403ea2:	90                   	nop
  403ea3:	90                   	nop

00403ea4 <_printf>:
  403ea4:	ff 25 f4 81 40 00    	jmp    *0x4081f4
  403eaa:	90                   	nop
  403eab:	90                   	nop

00403eac <_memmove>:
  403eac:	ff 25 f0 81 40 00    	jmp    *0x4081f0
  403eb2:	90                   	nop
  403eb3:	90                   	nop

00403eb4 <_memcpy>:
  403eb4:	ff 25 ec 81 40 00    	jmp    *0x4081ec
  403eba:	90                   	nop
  403ebb:	90                   	nop

00403ebc <_mbstowcs>:
  403ebc:	ff 25 e8 81 40 00    	jmp    *0x4081e8
  403ec2:	90                   	nop
  403ec3:	90                   	nop

00403ec4 <_malloc>:
  403ec4:	ff 25 e4 81 40 00    	jmp    *0x4081e4
  403eca:	90                   	nop
  403ecb:	90                   	nop

00403ecc <_fwrite>:
  403ecc:	ff 25 e0 81 40 00    	jmp    *0x4081e0
  403ed2:	90                   	nop
  403ed3:	90                   	nop

00403ed4 <_calloc>:
  403ed4:	ff 25 dc 81 40 00    	jmp    *0x4081dc
  403eda:	90                   	nop
  403edb:	90                   	nop

00403edc <_abort>:
  403edc:	ff 25 d4 81 40 00    	jmp    *0x4081d4
  403ee2:	90                   	nop
  403ee3:	90                   	nop

00403ee4 <__setmode>:
  403ee4:	ff 25 d0 81 40 00    	jmp    *0x4081d0
  403eea:	90                   	nop
  403eeb:	90                   	nop

00403eec <__msize>:
  403eec:	ff 25 c4 81 40 00    	jmp    *0x4081c4
  403ef2:	90                   	nop
  403ef3:	90                   	nop

00403ef4 <__isctype>:
  403ef4:	ff 25 c0 81 40 00    	jmp    *0x4081c0
  403efa:	90                   	nop
  403efb:	90                   	nop

00403efc <__fullpath>:
  403efc:	ff 25 b8 81 40 00    	jmp    *0x4081b8
  403f02:	90                   	nop
  403f03:	90                   	nop

00403f04 <__errno>:
  403f04:	ff 25 b0 81 40 00    	jmp    *0x4081b0
  403f0a:	90                   	nop
  403f0b:	90                   	nop

00403f0c <__cexit>:
  403f0c:	ff 25 ac 81 40 00    	jmp    *0x4081ac
  403f12:	90                   	nop
  403f13:	90                   	nop

00403f14 <___p__pgmptr>:
  403f14:	ff 25 a4 81 40 00    	jmp    *0x4081a4
  403f1a:	90                   	nop
  403f1b:	90                   	nop

00403f1c <___p__fmode>:
  403f1c:	ff 25 a0 81 40 00    	jmp    *0x4081a0
  403f22:	90                   	nop
  403f23:	90                   	nop

00403f24 <___p__environ>:
  403f24:	ff 25 9c 81 40 00    	jmp    *0x40819c
  403f2a:	90                   	nop
  403f2b:	90                   	nop

00403f2c <___getmainargs>:
  403f2c:	ff 25 94 81 40 00    	jmp    *0x408194
  403f32:	90                   	nop
  403f33:	90                   	nop

00403f34 <_VirtualQuery@12>:
  403f34:	ff 25 80 81 40 00    	jmp    *0x408180
  403f3a:	90                   	nop
  403f3b:	90                   	nop

00403f3c <_VirtualProtect@16>:
  403f3c:	ff 25 7c 81 40 00    	jmp    *0x40817c
  403f42:	90                   	nop
  403f43:	90                   	nop

00403f44 <_TlsGetValue@4>:
  403f44:	ff 25 78 81 40 00    	jmp    *0x408178
  403f4a:	90                   	nop
  403f4b:	90                   	nop

00403f4c <_SetUnhandledExceptionFilter@4>:
  403f4c:	ff 25 74 81 40 00    	jmp    *0x408174
  403f52:	90                   	nop
  403f53:	90                   	nop

00403f54 <_LoadLibraryA@4>:
  403f54:	ff 25 70 81 40 00    	jmp    *0x408170
  403f5a:	90                   	nop
  403f5b:	90                   	nop

00403f5c <_LeaveCriticalSection@4>:
  403f5c:	ff 25 6c 81 40 00    	jmp    *0x40816c
  403f62:	90                   	nop
  403f63:	90                   	nop

00403f64 <_InitializeCriticalSection@4>:
  403f64:	ff 25 68 81 40 00    	jmp    *0x408168
  403f6a:	90                   	nop
  403f6b:	90                   	nop

00403f6c <_GetProcAddress@8>:
  403f6c:	ff 25 64 81 40 00    	jmp    *0x408164
  403f72:	90                   	nop
  403f73:	90                   	nop

00403f74 <_GetModuleHandleA@4>:
  403f74:	ff 25 60 81 40 00    	jmp    *0x408160
  403f7a:	90                   	nop
  403f7b:	90                   	nop

00403f7c <_GetModuleFileNameA@12>:
  403f7c:	ff 25 5c 81 40 00    	jmp    *0x40815c
  403f82:	90                   	nop
  403f83:	90                   	nop

00403f84 <_GetLastError@0>:
  403f84:	ff 25 58 81 40 00    	jmp    *0x408158
  403f8a:	90                   	nop
  403f8b:	90                   	nop

00403f8c <_GetCommandLineA@0>:
  403f8c:	ff 25 54 81 40 00    	jmp    *0x408154
  403f92:	90                   	nop
  403f93:	90                   	nop

00403f94 <_FreeLibrary@4>:
  403f94:	ff 25 50 81 40 00    	jmp    *0x408150
  403f9a:	90                   	nop
  403f9b:	90                   	nop

00403f9c <_FindNextFileA@8>:
  403f9c:	ff 25 4c 81 40 00    	jmp    *0x40814c
  403fa2:	90                   	nop
  403fa3:	90                   	nop

00403fa4 <_FindFirstFileA@8>:
  403fa4:	ff 25 48 81 40 00    	jmp    *0x408148
  403faa:	90                   	nop
  403fab:	90                   	nop

00403fac <_FindClose@4>:
  403fac:	ff 25 44 81 40 00    	jmp    *0x408144
  403fb2:	90                   	nop
  403fb3:	90                   	nop

00403fb4 <_ExitProcess@4>:
  403fb4:	ff 25 40 81 40 00    	jmp    *0x408140
  403fba:	90                   	nop
  403fbb:	90                   	nop

00403fbc <_EnterCriticalSection@4>:
  403fbc:	ff 25 3c 81 40 00    	jmp    *0x40813c
  403fc2:	90                   	nop
  403fc3:	90                   	nop

00403fc4 <_DeleteCriticalSection@4>:
  403fc4:	ff 25 38 81 40 00    	jmp    *0x408138
  403fca:	90                   	nop
  403fcb:	90                   	nop

00403fcc <.text>:
  403fcc:	66 90                	xchg   %ax,%ax
  403fce:	66 90                	xchg   %ax,%ax

00403fd0 <_register_frame_ctor>:
  403fd0:	e9 5b d3 ff ff       	jmp    401330 <___gcc_register_frame>
  403fd5:	90                   	nop
  403fd6:	90                   	nop
  403fd7:	90                   	nop
  403fd8:	90                   	nop
  403fd9:	90                   	nop
  403fda:	90                   	nop
  403fdb:	90                   	nop
  403fdc:	90                   	nop
  403fdd:	90                   	nop
  403fde:	90                   	nop
  403fdf:	90                   	nop

00403fe0 <__CTOR_LIST__>:
  403fe0:	ff                   	(bad)  
  403fe1:	ff                   	(bad)  
  403fe2:	ff                   	(bad)  
  403fe3:	ff                 	call   *%eax

00403fe4 <.ctors.65535>:
  403fe4:	d0 3f                	sarb   (%edi)
  403fe6:	40                   	inc    %eax
  403fe7:	00 00                	add    %al,(%eax)
  403fe9:	00 00                	add    %al,(%eax)
	...

00403fec <__DTOR_LIST__>:
  403fec:	ff                   	(bad)  
  403fed:	ff                   	(bad)  
  403fee:	ff                   	(bad)  
  403fef:	ff 00                	incl   (%eax)
  403ff1:	00 00                	add    %al,(%eax)
	...

Disassembly of section .data:

00404000 <__data_start__>:
  404000:	00 00                	add    %al,(%eax)
	...

00404004 <__CRT_glob>:
  404004:	02 00                	add    (%eax),%al
	...

00404008 <__CRT_fenv>:
  404008:	fd                   	std    
  404009:	ff                   	(bad)  
  40400a:	ff                   	(bad)  
  40400b:	ff                 	incl   (%eax)

0040400c <__fmode>:
  40400c:	00 40 00             	add    %al,0x0(%eax)
	...

00404010 <.data>:
  404010:	f0 3f                	lock aas 
  404012:	40                   	inc    %eax
	...

00404014 <.data>:
  404014:	ff                   	(bad)  
  404015:	ff                   	(bad)  
  404016:	ff                   	(bad)  
  404017:	ff                   	.byte 0xff

Disassembly of section .rdata:

00405000 <.rdata>:
  405000:	6c                   	insb   (%dx),%es:(%edi)
  405001:	69 62 67 63 63 5f 73 	imul   $0x735f6363,0x67(%edx),%esp
  405008:	5f                   	pop    %edi
  405009:	64 77 32             	fs ja  40503e <.rdata+0x3e>
  40500c:	2d 31 2e 64 6c       	sub    $0x6c642e31,%eax
  405011:	6c                   	insb   (%dx),%es:(%edi)
  405012:	00 5f 5f             	add    %bl,0x5f(%edi)
  405015:	72 65                	jb     40507c <.rdata+0x2c>
  405017:	67 69 73 74 65 72 5f 	imul   $0x665f7265,0x74(%bp,%di),%esi
  40501e:	66 
  40501f:	72 61                	jb     405082 <.rdata+0x32>
  405021:	6d                   	insl   (%dx),%es:(%edi)
  405022:	65 5f                	gs pop %edi
  405024:	69 6e 66 6f 00 5f 5f 	imul   $0x5f5f006f,0x66(%esi),%ebp
  40502b:	64 65 72 65          	fs gs jb 405094 <.rdata+0x44>
  40502f:	67 69 73 74 65 72 5f 	imul   $0x665f7265,0x74(%bp,%di),%esi
  405036:	66 
  405037:	72 61                	jb     40509a <.rdata+0x4a>
  405039:	6d                   	insl   (%dx),%es:(%edi)
  40503a:	65 5f                	gs pop %edi
  40503c:	69 6e 66 6f 00 00 00 	imul   $0x6f,0x66(%esi),%ebp
	...

00405044 <.rdata>:
  405044:	48                   	dec    %eax
  405045:	6f                   	outsl  %ds:(%esi),(%dx)
  405046:	6c                   	insb   (%dx),%es:(%edi)
  405047:	61                   	popa   
  405048:	20 6d 75             	and    %ch,0x75(%ebp)
  40504b:	6e                   	outsb  %ds:(%esi),(%dx)
  40504c:	64 6f                	outsl  %fs:(%esi),(%dx)
	...

00405050 <.rdata>:
  405050:	94                   	xchg   %eax,%esp
  405051:	17                   	pop    %ss
  405052:	40                   	inc    %eax
  405053:	00 fa                	add    %bh,%dl
  405055:	14 40                	adc    $0x40,%al
  405057:	00 fa                	add    %bh,%dl
  405059:	14 40                	adc    $0x40,%al
  40505b:	00 fa                	add    %bh,%dl
  40505d:	14 40                	adc    $0x40,%al
  40505f:	00 fa                	add    %bh,%dl
  405061:	14 40                	adc    $0x40,%al
  405063:	00 40 17             	add    %al,0x17(%eax)
  405066:	40                   	inc    %eax
  405067:	00 fa                	add    %bh,%dl
  405069:	14 40                	adc    $0x40,%al
  40506b:	00 fa                	add    %bh,%dl
  40506d:	14 40                	adc    $0x40,%al
  40506f:	00 f6                	add    %dh,%dh
  405071:	16                   	push   %ss
  405072:	40                   	inc    %eax
  405073:	00 fa                	add    %bh,%dl
  405075:	14 40                	adc    $0x40,%al
  405077:	00 f6                	add    %dh,%dh
  405079:	16                   	push   %ss
  40507a:	40                   	inc    %eax
  40507b:	00 fa                	add    %bh,%dl
  40507d:	14 40                	adc    $0x40,%al
  40507f:	00 fa                	add    %bh,%dl
  405081:	14 40                	adc    $0x40,%al
  405083:	00 fa                	add    %bh,%dl
  405085:	14 40                	adc    $0x40,%al
  405087:	00 fa                	add    %bh,%dl
  405089:	14 40                	adc    $0x40,%al
  40508b:	00 fa                	add    %bh,%dl
  40508d:	14 40                	adc    $0x40,%al
  40508f:	00 fa                	add    %bh,%dl
  405091:	14 40                	adc    $0x40,%al
  405093:	00 fa                	add    %bh,%dl
  405095:	14 40                	adc    $0x40,%al
  405097:	00 fa                	add    %bh,%dl
  405099:	14 40                	adc    $0x40,%al
  40509b:	00 fa                	add    %bh,%dl
  40509d:	14 40                	adc    $0x40,%al
  40509f:	00 fa                	add    %bh,%dl
  4050a1:	14 40                	adc    $0x40,%al
  4050a3:	00 fa                	add    %bh,%dl
  4050a5:	14 40                	adc    $0x40,%al
  4050a7:	00 fa                	add    %bh,%dl
  4050a9:	14 40                	adc    $0x40,%al
  4050ab:	00 fa                	add    %bh,%dl
  4050ad:	14 40                	adc    $0x40,%al
  4050af:	00 fa                	add    %bh,%dl
  4050b1:	14 40                	adc    $0x40,%al
  4050b3:	00 fa                	add    %bh,%dl
  4050b5:	14 40                	adc    $0x40,%al
  4050b7:	00 fa                	add    %bh,%dl
  4050b9:	14 40                	adc    $0x40,%al
  4050bb:	00 fa                	add    %bh,%dl
  4050bd:	14 40                	adc    $0x40,%al
  4050bf:	00 fa                	add    %bh,%dl
  4050c1:	14 40                	adc    $0x40,%al
  4050c3:	00 f6                	add    %dh,%dh
  4050c5:	16                   	push   %ss
  4050c6:	40                   	inc    %eax
  4050c7:	00 08                	add    %cl,(%eax)
  4050c9:	18 40 00             	sbb    %al,0x0(%eax)
  4050cc:	f7 17                	notl   (%edi)
  4050ce:	40                   	inc    %eax
  4050cf:	00 fa                	add    %bh,%dl
  4050d1:	14 40                	adc    $0x40,%al
  4050d3:	00 fa                	add    %bh,%dl
  4050d5:	14 40                	adc    $0x40,%al
  4050d7:	00 fa                	add    %bh,%dl
  4050d9:	14 40                	adc    $0x40,%al
  4050db:	00 fa                	add    %bh,%dl
  4050dd:	14 40                	adc    $0x40,%al
  4050df:	00 fa                	add    %bh,%dl
  4050e1:	14 40                	adc    $0x40,%al
  4050e3:	00 fa                	add    %bh,%dl
  4050e5:	14 40                	adc    $0x40,%al
  4050e7:	00 fa                	add    %bh,%dl
  4050e9:	14 40                	adc    $0x40,%al
  4050eb:	00 fa                	add    %bh,%dl
  4050ed:	14 40                	adc    $0x40,%al
  4050ef:	00 fa                	add    %bh,%dl
  4050f1:	14 40                	adc    $0x40,%al
  4050f3:	00 fa                	add    %bh,%dl
  4050f5:	14 40                	adc    $0x40,%al
  4050f7:	00 fa                	add    %bh,%dl
  4050f9:	14 40                	adc    $0x40,%al
  4050fb:	00 fa                	add    %bh,%dl
  4050fd:	14 40                	adc    $0x40,%al
  4050ff:	00 fa                	add    %bh,%dl
  405101:	14 40                	adc    $0x40,%al
  405103:	00 fa                	add    %bh,%dl
  405105:	14 40                	adc    $0x40,%al
  405107:	00 fa                	add    %bh,%dl
  405109:	14 40                	adc    $0x40,%al
  40510b:	00 fa                	add    %bh,%dl
  40510d:	14 40                	adc    $0x40,%al
  40510f:	00 fa                	add    %bh,%dl
  405111:	14 40                	adc    $0x40,%al
  405113:	00 fa                	add    %bh,%dl
  405115:	14 40                	adc    $0x40,%al
  405117:	00 fa                	add    %bh,%dl
  405119:	14 40                	adc    $0x40,%al
  40511b:	00 fa                	add    %bh,%dl
  40511d:	14 40                	adc    $0x40,%al
  40511f:	00 fa                	add    %bh,%dl
  405121:	14 40                	adc    $0x40,%al
  405123:	00 fa                	add    %bh,%dl
  405125:	14 40                	adc    $0x40,%al
  405127:	00 fa                	add    %bh,%dl
  405129:	14 40                	adc    $0x40,%al
  40512b:	00 fa                	add    %bh,%dl
  40512d:	14 40                	adc    $0x40,%al
  40512f:	00 fa                	add    %bh,%dl
  405131:	14 40                	adc    $0x40,%al
  405133:	00 fa                	add    %bh,%dl
  405135:	14 40                	adc    $0x40,%al
  405137:	00 fa                	add    %bh,%dl
  405139:	14 40                	adc    $0x40,%al
  40513b:	00 fa                	add    %bh,%dl
  40513d:	14 40                	adc    $0x40,%al
  40513f:	00 fa                	add    %bh,%dl
  405141:	14 40                	adc    $0x40,%al
  405143:	00 fa                	add    %bh,%dl
  405145:	14 40                	adc    $0x40,%al
  405147:	00 f6                	add    %dh,%dh
  405149:	16                   	push   %ss
  40514a:	40                   	inc    %eax
  40514b:	00 fa                	add    %bh,%dl
  40514d:	14 40                	adc    $0x40,%al
  40514f:	00 f6                	add    %dh,%dh
  405151:	16                   	push   %ss
  405152:	40                   	inc    %eax
  405153:	00 fa                	add    %bh,%dl
  405155:	14 40                	adc    $0x40,%al
  405157:	00 f6                	add    %dh,%dh
  405159:	16                   	push   %ss
  40515a:	40                   	inc    %eax
	...

0040515c <___dyn_tls_init_callback>:
  40515c:	c0 1a 40             	rcrb   $0x40,(%edx)
	...

00405160 <.rdata>:
  405160:	4d                   	dec    %ebp
  405161:	69 6e 67 77 20 72 75 	imul   $0x75722077,0x67(%esi),%ebp
  405168:	6e                   	outsb  %ds:(%esi),(%dx)
  405169:	74 69                	je     4051d4 <.rdata+0x74>
  40516b:	6d                   	insl   (%dx),%es:(%edi)
  40516c:	65 20 66 61          	and    %ah,%gs:0x61(%esi)
  405170:	69 6c 75 72 65 3a 0a 	imul   $0xa3a65,0x72(%ebp,%esi,2),%ebp
  405177:	00 
  405178:	20 20                	and    %ah,(%eax)
  40517a:	56                   	push   %esi
  40517b:	69 72 74 75 61 6c 51 	imul   $0x516c6175,0x74(%edx),%esi
  405182:	75 65                	jne    4051e9 <.rdata+0x89>
  405184:	72 79                	jb     4051ff <.rdata+0x9f>
  405186:	20 66 61             	and    %ah,0x61(%esi)
  405189:	69 6c 65 64 20 66 6f 	imul   $0x726f6620,0x64(%ebp,%eiz,2),%ebp
  405190:	72 
  405191:	20 25 64 20 62 79    	and    %ah,0x79622064
  405197:	74 65                	je     4051fe <.rdata+0x9e>
  405199:	73 20                	jae    4051bb <.rdata+0x5b>
  40519b:	61                   	popa   
  40519c:	74 20                	je     4051be <.rdata+0x5e>
  40519e:	61                   	popa   
  40519f:	64 64 72 65          	fs fs jb 405208 <.rdata+0xa8>
  4051a3:	73 73                	jae    405218 <.rdata+0xc>
  4051a5:	20 25 70 00 00 00    	and    %ah,0x70
  4051ab:	00 20                	add    %ah,(%eax)
  4051ad:	20 55 6e             	and    %dl,0x6e(%ebp)
  4051b0:	6b 6e 6f 77          	imul   $0x77,0x6f(%esi),%ebp
  4051b4:	6e                   	outsb  %ds:(%esi),(%dx)
  4051b5:	20 70 73             	and    %dh,0x73(%eax)
  4051b8:	65 75 64             	gs jne 40521f <.rdata+0x13>
  4051bb:	6f                   	outsl  %ds:(%esi),(%dx)
  4051bc:	20 72 65             	and    %dh,0x65(%edx)
  4051bf:	6c                   	insb   (%dx),%es:(%edi)
  4051c0:	6f                   	outsl  %ds:(%esi),(%dx)
  4051c1:	63 61 74             	arpl   %sp,0x74(%ecx)
  4051c4:	69 6f 6e 20 70 72 6f 	imul   $0x6f727020,0x6e(%edi),%ebp
  4051cb:	74 6f                	je     40523c <.rdata+0x1c>
  4051cd:	63 6f 6c             	arpl   %bp,0x6c(%edi)
  4051d0:	20 76 65             	and    %dh,0x65(%esi)
  4051d3:	72 73                	jb     405248 <.rdata+0x28>
  4051d5:	69 6f 6e 20 25 64 2e 	imul   $0x2e642520,0x6e(%edi),%ebp
  4051dc:	0a 00                	or     (%eax),%al
  4051de:	00 00                	add    %al,(%eax)
  4051e0:	20 20                	and    %ah,(%eax)
  4051e2:	55                   	push   %ebp
  4051e3:	6e                   	outsb  %ds:(%esi),(%dx)
  4051e4:	6b 6e 6f 77          	imul   $0x77,0x6f(%esi),%ebp
  4051e8:	6e                   	outsb  %ds:(%esi),(%dx)
  4051e9:	20 70 73             	and    %dh,0x73(%eax)
  4051ec:	65 75 64             	gs jne 405253 <.rdata+0x33>
  4051ef:	6f                   	outsl  %ds:(%esi),(%dx)
  4051f0:	20 72 65             	and    %dh,0x65(%edx)
  4051f3:	6c                   	insb   (%dx),%es:(%edi)
  4051f4:	6f                   	outsl  %ds:(%esi),(%dx)
  4051f5:	63 61 74             	arpl   %sp,0x74(%ecx)
  4051f8:	69 6f 6e 20 62 69 74 	imul   $0x74696220,0x6e(%edi),%ebp
  4051ff:	20 73 69             	and    %dh,0x69(%ebx)
  405202:	7a 65                	jp     405269 <.rdata$zzz+0xd>
  405204:	20 25 64 2e 0a 00    	and    %ah,0xa2e64
	...

0040520c <.rdata>:
  40520c:	67 6c                	insb   (%dx),%es:(%di)
  40520e:	6f                   	outsl  %ds:(%esi),(%dx)
  40520f:	62 2d 31 2e 30 2d    	bound  %ebp,0x2d302e31
  405215:	6d                   	insl   (%dx),%es:(%edi)
  405216:	69 6e 67 77 33 32 00 	imul   $0x323377,0x67(%esi),%ebp
  40521d:	00 00                	add    %al,(%eax)
	...

00405220 <.rdata>:
  405220:	00 00                	add    %al,(%eax)
  405222:	2e 00 00             	add    %al,%cs:(%eax)
  405225:	00 00                	add    %al,(%eax)
  405227:	00 47 43             	add    %al,0x43(%edi)
  40522a:	43                   	inc    %ebx
  40522b:	3a 20                	cmp    (%eax),%ah
  40522d:	28 4d 69             	sub    %cl,0x69(%ebp)
  405230:	6e                   	outsb  %ds:(%esi),(%dx)
  405231:	47                   	inc    %edi
  405232:	57                   	push   %edi
  405233:	2e 6f                	outsl  %cs:(%esi),(%dx)
  405235:	72 67                	jb     40529e <.rdata$zzz+0xe>
  405237:	20 43 72             	and    %al,0x72(%ebx)
  40523a:	6f                   	outsl  %ds:(%esi),(%dx)
  40523b:	73 73                	jae    4052b0 <.rdata$zzz+0x20>
  40523d:	2d 47 43 43 20       	sub    $0x20434347,%eax
  405242:	42                   	inc    %edx
  405243:	75 69                	jne    4052ae <.rdata$zzz+0x1e>
  405245:	6c                   	insb   (%dx),%es:(%edi)
  405246:	64 2d 32 30 32 30    	fs sub $0x30323032,%eax
  40524c:	30 35 33 31 2d 31    	xor    %dh,0x312d3133
  405252:	29 20                	sub    %esp,(%eax)
  405254:	39 2e                	cmp    %ebp,(%esi)
  405256:	32 2e                	xor    (%esi),%ch
  405258:	30 00                	xor    %al,(%eax)
	...

0040525c <.rdata$zzz>:
  40525c:	47                   	inc    %edi
  40525d:	43                   	inc    %ebx
  40525e:	43                   	inc    %ebx
  40525f:	3a 20                	cmp    (%eax),%ah
  405261:	28 4d 69             	sub    %cl,0x69(%ebp)
  405264:	6e                   	outsb  %ds:(%esi),(%dx)
  405265:	47                   	inc    %edi
  405266:	57                   	push   %edi
  405267:	2e 6f                	outsl  %cs:(%esi),(%dx)
  405269:	72 67                	jb     4052d2 <.rdata$zzz+0x42>
  40526b:	20 43 72             	and    %al,0x72(%ebx)
  40526e:	6f                   	outsl  %ds:(%esi),(%dx)
  40526f:	73 73                	jae    4052e4 <.rdata$zzz+0x54>
  405271:	2d 47 43 43 20       	sub    $0x20434347,%eax
  405276:	42                   	inc    %edx
  405277:	75 69                	jne    4052e2 <.rdata$zzz+0x52>
  405279:	6c                   	insb   (%dx),%es:(%edi)
  40527a:	64 2d 32 30 32 30    	fs sub $0x30323032,%eax
  405280:	30 35 33 31 2d 31    	xor    %dh,0x312d3133
  405286:	29 20                	sub    %esp,(%eax)
  405288:	39 2e                	cmp    %ebp,(%esi)
  40528a:	32 2e                	xor    (%esi),%ch
  40528c:	30 00                	xor    %al,(%eax)
	...

00405290 <.rdata$zzz>:
  405290:	47                   	inc    %edi
  405291:	43                   	inc    %ebx
  405292:	43                   	inc    %ebx
  405293:	3a 20                	cmp    (%eax),%ah
  405295:	28 4d 69             	sub    %cl,0x69(%ebp)
  405298:	6e                   	outsb  %ds:(%esi),(%dx)
  405299:	47                   	inc    %edi
  40529a:	57                   	push   %edi
  40529b:	2e 6f                	outsl  %cs:(%esi),(%dx)
  40529d:	72 67                	jb     405306 <.rdata$zzz+0x76>
  40529f:	20 47 43             	and    %al,0x43(%edi)
  4052a2:	43                   	inc    %ebx
  4052a3:	20 42 75             	and    %al,0x75(%edx)
  4052a6:	69 6c 64 2d 32 29 20 	imul   $0x39202932,0x2d(%esp,%eiz,2),%ebp
  4052ad:	39 
  4052ae:	2e 32 2e             	xor    %cs:(%esi),%ch
  4052b1:	30 00                	xor    %al,(%eax)
  4052b3:	00 47 43             	add    %al,0x43(%edi)
  4052b6:	43                   	inc    %ebx
  4052b7:	3a 20                	cmp    (%eax),%ah
  4052b9:	28 4d 69             	sub    %cl,0x69(%ebp)
  4052bc:	6e                   	outsb  %ds:(%esi),(%dx)
  4052bd:	47                   	inc    %edi
  4052be:	57                   	push   %edi
  4052bf:	2e 6f                	outsl  %cs:(%esi),(%dx)
  4052c1:	72 67                	jb     40532a <.rdata$zzz+0x9a>
  4052c3:	20 43 72             	and    %al,0x72(%ebx)
  4052c6:	6f                   	outsl  %ds:(%esi),(%dx)
  4052c7:	73 73                	jae    40533c <.rdata$zzz+0xac>
  4052c9:	2d 47 43 43 20       	sub    $0x20434347,%eax
  4052ce:	42                   	inc    %edx
  4052cf:	75 69                	jne    40533a <.rdata$zzz+0xaa>
  4052d1:	6c                   	insb   (%dx),%es:(%edi)
  4052d2:	64 2d 32 30 32 30    	fs sub $0x30323032,%eax
  4052d8:	30 35 33 31 2d 31    	xor    %dh,0x312d3133
  4052de:	29 20                	sub    %esp,(%eax)
  4052e0:	39 2e                	cmp    %ebp,(%esi)
  4052e2:	32 2e                	xor    (%esi),%ch
  4052e4:	30 00                	xor    %al,(%eax)
  4052e6:	00 00                	add    %al,(%eax)
  4052e8:	47                   	inc    %edi
  4052e9:	43                   	inc    %ebx
  4052ea:	43                   	inc    %ebx
  4052eb:	3a 20                	cmp    (%eax),%ah
  4052ed:	28 4d 69             	sub    %cl,0x69(%ebp)
  4052f0:	6e                   	outsb  %ds:(%esi),(%dx)
  4052f1:	47                   	inc    %edi
  4052f2:	57                   	push   %edi
  4052f3:	2e 6f                	outsl  %cs:(%esi),(%dx)
  4052f5:	72 67                	jb     40535e <.rdata$zzz+0xce>
  4052f7:	20 43 72             	and    %al,0x72(%ebx)
  4052fa:	6f                   	outsl  %ds:(%esi),(%dx)
  4052fb:	73 73                	jae    405370 <.rdata$zzz+0xe0>
  4052fd:	2d 47 43 43 20       	sub    $0x20434347,%eax
  405302:	42                   	inc    %edx
  405303:	75 69                	jne    40536e <.rdata$zzz+0xde>
  405305:	6c                   	insb   (%dx),%es:(%edi)
  405306:	64 2d 32 30 32 30    	fs sub $0x30323032,%eax
  40530c:	30 35 33 31 2d 31    	xor    %dh,0x312d3133
  405312:	29 20                	sub    %esp,(%eax)
  405314:	39 2e                	cmp    %ebp,(%esi)
  405316:	32 2e                	xor    (%esi),%ch
  405318:	30 00                	xor    %al,(%eax)
  40531a:	00 00                	add    %al,(%eax)
  40531c:	47                   	inc    %edi
  40531d:	43                   	inc    %ebx
  40531e:	43                   	inc    %ebx
  40531f:	3a 20                	cmp    (%eax),%ah
  405321:	28 4d 69             	sub    %cl,0x69(%ebp)
  405324:	6e                   	outsb  %ds:(%esi),(%dx)
  405325:	47                   	inc    %edi
  405326:	57                   	push   %edi
  405327:	2e 6f                	outsl  %cs:(%esi),(%dx)
  405329:	72 67                	jb     405392 <.rdata$zzz+0x102>
  40532b:	20 43 72             	and    %al,0x72(%ebx)
  40532e:	6f                   	outsl  %ds:(%esi),(%dx)
  40532f:	73 73                	jae    4053a4 <.rdata$zzz+0x114>
  405331:	2d 47 43 43 20       	sub    $0x20434347,%eax
  405336:	42                   	inc    %edx
  405337:	75 69                	jne    4053a2 <.rdata$zzz+0x112>
  405339:	6c                   	insb   (%dx),%es:(%edi)
  40533a:	64 2d 32 30 32 30    	fs sub $0x30323032,%eax
  405340:	30 35 33 31 2d 31    	xor    %dh,0x312d3133
  405346:	29 20                	sub    %esp,(%eax)
  405348:	39 2e                	cmp    %ebp,(%esi)
  40534a:	32 2e                	xor    (%esi),%ch
  40534c:	30 00                	xor    %al,(%eax)
  40534e:	00 00                	add    %al,(%eax)
  405350:	47                   	inc    %edi
  405351:	43                   	inc    %ebx
  405352:	43                   	inc    %ebx
  405353:	3a 20                	cmp    (%eax),%ah
  405355:	28 4d 69             	sub    %cl,0x69(%ebp)
  405358:	6e                   	outsb  %ds:(%esi),(%dx)
  405359:	47                   	inc    %edi
  40535a:	57                   	push   %edi
  40535b:	2e 6f                	outsl  %cs:(%esi),(%dx)
  40535d:	72 67                	jb     4053c6 <.rdata$zzz+0x136>
  40535f:	20 43 72             	and    %al,0x72(%ebx)
  405362:	6f                   	outsl  %ds:(%esi),(%dx)
  405363:	73 73                	jae    4053d8 <.rdata$zzz+0x148>
  405365:	2d 47 43 43 20       	sub    $0x20434347,%eax
  40536a:	42                   	inc    %edx
  40536b:	75 69                	jne    4053d6 <.rdata$zzz+0x146>
  40536d:	6c                   	insb   (%dx),%es:(%edi)
  40536e:	64 2d 32 30 32 30    	fs sub $0x30323032,%eax
  405374:	30 35 33 31 2d 31    	xor    %dh,0x312d3133
  40537a:	29 20                	sub    %esp,(%eax)
  40537c:	39 2e                	cmp    %ebp,(%esi)
  40537e:	32 2e                	xor    (%esi),%ch
  405380:	30 00                	xor    %al,(%eax)
  405382:	00 00                	add    %al,(%eax)
  405384:	47                   	inc    %edi
  405385:	43                   	inc    %ebx
  405386:	43                   	inc    %ebx
  405387:	3a 20                	cmp    (%eax),%ah
  405389:	28 4d 69             	sub    %cl,0x69(%ebp)
  40538c:	6e                   	outsb  %ds:(%esi),(%dx)
  40538d:	47                   	inc    %edi
  40538e:	57                   	push   %edi
  40538f:	2e 6f                	outsl  %cs:(%esi),(%dx)
  405391:	72 67                	jb     4053fa <.rdata$zzz+0x16a>
  405393:	20 43 72             	and    %al,0x72(%ebx)
  405396:	6f                   	outsl  %ds:(%esi),(%dx)
  405397:	73 73                	jae    40540c <.rdata$zzz+0x17c>
  405399:	2d 47 43 43 20       	sub    $0x20434347,%eax
  40539e:	42                   	inc    %edx
  40539f:	75 69                	jne    40540a <.rdata$zzz+0x17a>
  4053a1:	6c                   	insb   (%dx),%es:(%edi)
  4053a2:	64 2d 32 30 32 30    	fs sub $0x30323032,%eax
  4053a8:	30 35 33 31 2d 31    	xor    %dh,0x312d3133
  4053ae:	29 20                	sub    %esp,(%eax)
  4053b0:	39 2e                	cmp    %ebp,(%esi)
  4053b2:	32 2e                	xor    (%esi),%ch
  4053b4:	30 00                	xor    %al,(%eax)
  4053b6:	00 00                	add    %al,(%eax)
  4053b8:	47                   	inc    %edi
  4053b9:	43                   	inc    %ebx
  4053ba:	43                   	inc    %ebx
  4053bb:	3a 20                	cmp    (%eax),%ah
  4053bd:	28 4d 69             	sub    %cl,0x69(%ebp)
  4053c0:	6e                   	outsb  %ds:(%esi),(%dx)
  4053c1:	47                   	inc    %edi
  4053c2:	57                   	push   %edi
  4053c3:	2e 6f                	outsl  %cs:(%esi),(%dx)
  4053c5:	72 67                	jb     40542e <.rdata$zzz+0x19e>
  4053c7:	20 43 72             	and    %al,0x72(%ebx)
  4053ca:	6f                   	outsl  %ds:(%esi),(%dx)
  4053cb:	73 73                	jae    405440 <.rdata$zzz+0x1b0>
  4053cd:	2d 47 43 43 20       	sub    $0x20434347,%eax
  4053d2:	42                   	inc    %edx
  4053d3:	75 69                	jne    40543e <.rdata$zzz+0x1ae>
  4053d5:	6c                   	insb   (%dx),%es:(%edi)
  4053d6:	64 2d 32 30 32 30    	fs sub $0x30323032,%eax
  4053dc:	30 35 33 31 2d 31    	xor    %dh,0x312d3133
  4053e2:	29 20                	sub    %esp,(%eax)
  4053e4:	39 2e                	cmp    %ebp,(%esi)
  4053e6:	32 2e                	xor    (%esi),%ch
  4053e8:	30 00                	xor    %al,(%eax)
  4053ea:	00 00                	add    %al,(%eax)
  4053ec:	47                   	inc    %edi
  4053ed:	43                   	inc    %ebx
  4053ee:	43                   	inc    %ebx
  4053ef:	3a 20                	cmp    (%eax),%ah
  4053f1:	28 4d 69             	sub    %cl,0x69(%ebp)
  4053f4:	6e                   	outsb  %ds:(%esi),(%dx)
  4053f5:	47                   	inc    %edi
  4053f6:	57                   	push   %edi
  4053f7:	2e 6f                	outsl  %cs:(%esi),(%dx)
  4053f9:	72 67                	jb     405462 <.rdata$zzz+0x1d2>
  4053fb:	20 43 72             	and    %al,0x72(%ebx)
  4053fe:	6f                   	outsl  %ds:(%esi),(%dx)
  4053ff:	73 73                	jae    405474 <.rdata$zzz+0x1e4>
  405401:	2d 47 43 43 20       	sub    $0x20434347,%eax
  405406:	42                   	inc    %edx
  405407:	75 69                	jne    405472 <.rdata$zzz+0x1e2>
  405409:	6c                   	insb   (%dx),%es:(%edi)
  40540a:	64 2d 32 30 32 30    	fs sub $0x30323032,%eax
  405410:	30 35 33 31 2d 31    	xor    %dh,0x312d3133
  405416:	29 20                	sub    %esp,(%eax)
  405418:	39 2e                	cmp    %ebp,(%esi)
  40541a:	32 2e                	xor    (%esi),%ch
  40541c:	30 00                	xor    %al,(%eax)
  40541e:	00 00                	add    %al,(%eax)
  405420:	47                   	inc    %edi
  405421:	43                   	inc    %ebx
  405422:	43                   	inc    %ebx
  405423:	3a 20                	cmp    (%eax),%ah
  405425:	28 4d 69             	sub    %cl,0x69(%ebp)
  405428:	6e                   	outsb  %ds:(%esi),(%dx)
  405429:	47                   	inc    %edi
  40542a:	57                   	push   %edi
  40542b:	2e 6f                	outsl  %cs:(%esi),(%dx)
  40542d:	72 67                	jb     405496 <.rdata$zzz+0x206>
  40542f:	20 43 72             	and    %al,0x72(%ebx)
  405432:	6f                   	outsl  %ds:(%esi),(%dx)
  405433:	73 73                	jae    4054a8 <.rdata$zzz+0x218>
  405435:	2d 47 43 43 20       	sub    $0x20434347,%eax
  40543a:	42                   	inc    %edx
  40543b:	75 69                	jne    4054a6 <.rdata$zzz+0x216>
  40543d:	6c                   	insb   (%dx),%es:(%edi)
  40543e:	64 2d 32 30 32 30    	fs sub $0x30323032,%eax
  405444:	30 35 33 31 2d 31    	xor    %dh,0x312d3133
  40544a:	29 20                	sub    %esp,(%eax)
  40544c:	39 2e                	cmp    %ebp,(%esi)
  40544e:	32 2e                	xor    (%esi),%ch
  405450:	30 00                	xor    %al,(%eax)
  405452:	00 00                	add    %al,(%eax)
  405454:	47                   	inc    %edi
  405455:	43                   	inc    %ebx
  405456:	43                   	inc    %ebx
  405457:	3a 20                	cmp    (%eax),%ah
  405459:	28 4d 69             	sub    %cl,0x69(%ebp)
  40545c:	6e                   	outsb  %ds:(%esi),(%dx)
  40545d:	47                   	inc    %edi
  40545e:	57                   	push   %edi
  40545f:	2e 6f                	outsl  %cs:(%esi),(%dx)
  405461:	72 67                	jb     4054ca <.rdata$zzz+0x23a>
  405463:	20 43 72             	and    %al,0x72(%ebx)
  405466:	6f                   	outsl  %ds:(%esi),(%dx)
  405467:	73 73                	jae    4054dc <.rdata$zzz+0x24c>
  405469:	2d 47 43 43 20       	sub    $0x20434347,%eax
  40546e:	42                   	inc    %edx
  40546f:	75 69                	jne    4054da <.rdata$zzz+0x24a>
  405471:	6c                   	insb   (%dx),%es:(%edi)
  405472:	64 2d 32 30 32 30    	fs sub $0x30323032,%eax
  405478:	30 35 33 31 2d 31    	xor    %dh,0x312d3133
  40547e:	29 20                	sub    %esp,(%eax)
  405480:	39 2e                	cmp    %ebp,(%esi)
  405482:	32 2e                	xor    (%esi),%ch
  405484:	30 00                	xor    %al,(%eax)
  405486:	00 00                	add    %al,(%eax)
  405488:	47                   	inc    %edi
  405489:	43                   	inc    %ebx
  40548a:	43                   	inc    %ebx
  40548b:	3a 20                	cmp    (%eax),%ah
  40548d:	28 4d 69             	sub    %cl,0x69(%ebp)
  405490:	6e                   	outsb  %ds:(%esi),(%dx)
  405491:	47                   	inc    %edi
  405492:	57                   	push   %edi
  405493:	2e 6f                	outsl  %cs:(%esi),(%dx)
  405495:	72 67                	jb     4054fe <.rdata$zzz+0x26e>
  405497:	20 43 72             	and    %al,0x72(%ebx)
  40549a:	6f                   	outsl  %ds:(%esi),(%dx)
  40549b:	73 73                	jae    405510 <.rdata$zzz+0x280>
  40549d:	2d 47 43 43 20       	sub    $0x20434347,%eax
  4054a2:	42                   	inc    %edx
  4054a3:	75 69                	jne    40550e <.rdata$zzz+0x27e>
  4054a5:	6c                   	insb   (%dx),%es:(%edi)
  4054a6:	64 2d 32 30 32 30    	fs sub $0x30323032,%eax
  4054ac:	30 35 33 31 2d 31    	xor    %dh,0x312d3133
  4054b2:	29 20                	sub    %esp,(%eax)
  4054b4:	39 2e                	cmp    %ebp,(%esi)
  4054b6:	32 2e                	xor    (%esi),%ch
  4054b8:	30 00                	xor    %al,(%eax)
  4054ba:	00 00                	add    %al,(%eax)
  4054bc:	47                   	inc    %edi
  4054bd:	43                   	inc    %ebx
  4054be:	43                   	inc    %ebx
  4054bf:	3a 20                	cmp    (%eax),%ah
  4054c1:	28 4d 69             	sub    %cl,0x69(%ebp)
  4054c4:	6e                   	outsb  %ds:(%esi),(%dx)
  4054c5:	47                   	inc    %edi
  4054c6:	57                   	push   %edi
  4054c7:	2e 6f                	outsl  %cs:(%esi),(%dx)
  4054c9:	72 67                	jb     405532 <.rdata$zzz+0x2a2>
  4054cb:	20 43 72             	and    %al,0x72(%ebx)
  4054ce:	6f                   	outsl  %ds:(%esi),(%dx)
  4054cf:	73 73                	jae    405544 <.rdata$zzz+0x2b4>
  4054d1:	2d 47 43 43 20       	sub    $0x20434347,%eax
  4054d6:	42                   	inc    %edx
  4054d7:	75 69                	jne    405542 <.rdata$zzz+0x2b2>
  4054d9:	6c                   	insb   (%dx),%es:(%edi)
  4054da:	64 2d 32 30 32 30    	fs sub $0x30323032,%eax
  4054e0:	30 35 33 31 2d 31    	xor    %dh,0x312d3133
  4054e6:	29 20                	sub    %esp,(%eax)
  4054e8:	39 2e                	cmp    %ebp,(%esi)
  4054ea:	32 2e                	xor    (%esi),%ch
  4054ec:	30 00                	xor    %al,(%eax)
  4054ee:	00 00                	add    %al,(%eax)
  4054f0:	47                   	inc    %edi
  4054f1:	43                   	inc    %ebx
  4054f2:	43                   	inc    %ebx
  4054f3:	3a 20                	cmp    (%eax),%ah
  4054f5:	28 4d 69             	sub    %cl,0x69(%ebp)
  4054f8:	6e                   	outsb  %ds:(%esi),(%dx)
  4054f9:	47                   	inc    %edi
  4054fa:	57                   	push   %edi
  4054fb:	2e 6f                	outsl  %cs:(%esi),(%dx)
  4054fd:	72 67                	jb     405566 <.rdata$zzz+0x2d6>
  4054ff:	20 43 72             	and    %al,0x72(%ebx)
  405502:	6f                   	outsl  %ds:(%esi),(%dx)
  405503:	73 73                	jae    405578 <.rdata$zzz+0x2e8>
  405505:	2d 47 43 43 20       	sub    $0x20434347,%eax
  40550a:	42                   	inc    %edx
  40550b:	75 69                	jne    405576 <.rdata$zzz+0x2e6>
  40550d:	6c                   	insb   (%dx),%es:(%edi)
  40550e:	64 2d 32 30 32 30    	fs sub $0x30323032,%eax
  405514:	30 35 33 31 2d 31    	xor    %dh,0x312d3133
  40551a:	29 20                	sub    %esp,(%eax)
  40551c:	39 2e                	cmp    %ebp,(%esi)
  40551e:	32 2e                	xor    (%esi),%ch
  405520:	30 00                	xor    %al,(%eax)
  405522:	00 00                	add    %al,(%eax)
  405524:	47                   	inc    %edi
  405525:	43                   	inc    %ebx
  405526:	43                   	inc    %ebx
  405527:	3a 20                	cmp    (%eax),%ah
  405529:	28 4d 69             	sub    %cl,0x69(%ebp)
  40552c:	6e                   	outsb  %ds:(%esi),(%dx)
  40552d:	47                   	inc    %edi
  40552e:	57                   	push   %edi
  40552f:	2e 6f                	outsl  %cs:(%esi),(%dx)
  405531:	72 67                	jb     40559a <.rdata$zzz+0x30a>
  405533:	20 43 72             	and    %al,0x72(%ebx)
  405536:	6f                   	outsl  %ds:(%esi),(%dx)
  405537:	73 73                	jae    4055ac <.rdata$zzz+0x31c>
  405539:	2d 47 43 43 20       	sub    $0x20434347,%eax
  40553e:	42                   	inc    %edx
  40553f:	75 69                	jne    4055aa <.rdata$zzz+0x31a>
  405541:	6c                   	insb   (%dx),%es:(%edi)
  405542:	64 2d 32 30 32 30    	fs sub $0x30323032,%eax
  405548:	30 35 33 31 2d 31    	xor    %dh,0x312d3133
  40554e:	29 20                	sub    %esp,(%eax)
  405550:	39 2e                	cmp    %ebp,(%esi)
  405552:	32 2e                	xor    (%esi),%ch
  405554:	30 00                	xor    %al,(%eax)
  405556:	00 00                	add    %al,(%eax)
  405558:	47                   	inc    %edi
  405559:	43                   	inc    %ebx
  40555a:	43                   	inc    %ebx
  40555b:	3a 20                	cmp    (%eax),%ah
  40555d:	28 4d 69             	sub    %cl,0x69(%ebp)
  405560:	6e                   	outsb  %ds:(%esi),(%dx)
  405561:	47                   	inc    %edi
  405562:	57                   	push   %edi
  405563:	2e 6f                	outsl  %cs:(%esi),(%dx)
  405565:	72 67                	jb     4055ce <.rdata$zzz+0x33e>
  405567:	20 43 72             	and    %al,0x72(%ebx)
  40556a:	6f                   	outsl  %ds:(%esi),(%dx)
  40556b:	73 73                	jae    4055e0 <.rdata$zzz+0x350>
  40556d:	2d 47 43 43 20       	sub    $0x20434347,%eax
  405572:	42                   	inc    %edx
  405573:	75 69                	jne    4055de <.rdata$zzz+0x34e>
  405575:	6c                   	insb   (%dx),%es:(%edi)
  405576:	64 2d 32 30 32 30    	fs sub $0x30323032,%eax
  40557c:	30 35 33 31 2d 31    	xor    %dh,0x312d3133
  405582:	29 20                	sub    %esp,(%eax)
  405584:	39 2e                	cmp    %ebp,(%esi)
  405586:	32 2e                	xor    (%esi),%ch
  405588:	30 00                	xor    %al,(%eax)
  40558a:	00 00                	add    %al,(%eax)
  40558c:	47                   	inc    %edi
  40558d:	43                   	inc    %ebx
  40558e:	43                   	inc    %ebx
  40558f:	3a 20                	cmp    (%eax),%ah
  405591:	28 4d 69             	sub    %cl,0x69(%ebp)
  405594:	6e                   	outsb  %ds:(%esi),(%dx)
  405595:	47                   	inc    %edi
  405596:	57                   	push   %edi
  405597:	2e 6f                	outsl  %cs:(%esi),(%dx)
  405599:	72 67                	jb     405602 <.rdata$zzz+0x372>
  40559b:	20 43 72             	and    %al,0x72(%ebx)
  40559e:	6f                   	outsl  %ds:(%esi),(%dx)
  40559f:	73 73                	jae    405614 <.rdata$zzz+0x384>
  4055a1:	2d 47 43 43 20       	sub    $0x20434347,%eax
  4055a6:	42                   	inc    %edx
  4055a7:	75 69                	jne    405612 <.rdata$zzz+0x382>
  4055a9:	6c                   	insb   (%dx),%es:(%edi)
  4055aa:	64 2d 32 30 32 30    	fs sub $0x30323032,%eax
  4055b0:	30 35 33 31 2d 31    	xor    %dh,0x312d3133
  4055b6:	29 20                	sub    %esp,(%eax)
  4055b8:	39 2e                	cmp    %ebp,(%esi)
  4055ba:	32 2e                	xor    (%esi),%ch
  4055bc:	30 00                	xor    %al,(%eax)
  4055be:	00 00                	add    %al,(%eax)
  4055c0:	47                   	inc    %edi
  4055c1:	43                   	inc    %ebx
  4055c2:	43                   	inc    %ebx
  4055c3:	3a 20                	cmp    (%eax),%ah
  4055c5:	28 4d 69             	sub    %cl,0x69(%ebp)
  4055c8:	6e                   	outsb  %ds:(%esi),(%dx)
  4055c9:	47                   	inc    %edi
  4055ca:	57                   	push   %edi
  4055cb:	2e 6f                	outsl  %cs:(%esi),(%dx)
  4055cd:	72 67                	jb     405636 <.rdata$zzz+0x3a6>
  4055cf:	20 43 72             	and    %al,0x72(%ebx)
  4055d2:	6f                   	outsl  %ds:(%esi),(%dx)
  4055d3:	73 73                	jae    405648 <.rdata$zzz+0x3b8>
  4055d5:	2d 47 43 43 20       	sub    $0x20434347,%eax
  4055da:	42                   	inc    %edx
  4055db:	75 69                	jne    405646 <.rdata$zzz+0x3b6>
  4055dd:	6c                   	insb   (%dx),%es:(%edi)
  4055de:	64 2d 32 30 32 30    	fs sub $0x30323032,%eax
  4055e4:	30 35 33 31 2d 31    	xor    %dh,0x312d3133
  4055ea:	29 20                	sub    %esp,(%eax)
  4055ec:	39 2e                	cmp    %ebp,(%esi)
  4055ee:	32 2e                	xor    (%esi),%ch
  4055f0:	30 00                	xor    %al,(%eax)
  4055f2:	00 00                	add    %al,(%eax)
  4055f4:	47                   	inc    %edi
  4055f5:	43                   	inc    %ebx
  4055f6:	43                   	inc    %ebx
  4055f7:	3a 20                	cmp    (%eax),%ah
  4055f9:	28 4d 69             	sub    %cl,0x69(%ebp)
  4055fc:	6e                   	outsb  %ds:(%esi),(%dx)
  4055fd:	47                   	inc    %edi
  4055fe:	57                   	push   %edi
  4055ff:	2e 6f                	outsl  %cs:(%esi),(%dx)
  405601:	72 67                	jb     40566a <.rdata$zzz+0x3da>
  405603:	20 43 72             	and    %al,0x72(%ebx)
  405606:	6f                   	outsl  %ds:(%esi),(%dx)
  405607:	73 73                	jae    40567c <.rdata$zzz+0x3ec>
  405609:	2d 47 43 43 20       	sub    $0x20434347,%eax
  40560e:	42                   	inc    %edx
  40560f:	75 69                	jne    40567a <.rdata$zzz+0x3ea>
  405611:	6c                   	insb   (%dx),%es:(%edi)
  405612:	64 2d 32 30 32 30    	fs sub $0x30323032,%eax
  405618:	30 35 33 31 2d 31    	xor    %dh,0x312d3133
  40561e:	29 20                	sub    %esp,(%eax)
  405620:	39 2e                	cmp    %ebp,(%esi)
  405622:	32 2e                	xor    (%esi),%ch
  405624:	30 00                	xor    %al,(%eax)
  405626:	00 00                	add    %al,(%eax)
  405628:	47                   	inc    %edi
  405629:	43                   	inc    %ebx
  40562a:	43                   	inc    %ebx
  40562b:	3a 20                	cmp    (%eax),%ah
  40562d:	28 4d 69             	sub    %cl,0x69(%ebp)
  405630:	6e                   	outsb  %ds:(%esi),(%dx)
  405631:	47                   	inc    %edi
  405632:	57                   	push   %edi
  405633:	2e 6f                	outsl  %cs:(%esi),(%dx)
  405635:	72 67                	jb     40569e <.rdata$zzz+0x40e>
  405637:	20 43 72             	and    %al,0x72(%ebx)
  40563a:	6f                   	outsl  %ds:(%esi),(%dx)
  40563b:	73 73                	jae    4056b0 <.rdata$zzz+0x420>
  40563d:	2d 47 43 43 20       	sub    $0x20434347,%eax
  405642:	42                   	inc    %edx
  405643:	75 69                	jne    4056ae <.rdata$zzz+0x41e>
  405645:	6c                   	insb   (%dx),%es:(%edi)
  405646:	64 2d 32 30 32 30    	fs sub $0x30323032,%eax
  40564c:	30 35 33 31 2d 31    	xor    %dh,0x312d3133
  405652:	29 20                	sub    %esp,(%eax)
  405654:	39 2e                	cmp    %ebp,(%esi)
  405656:	32 2e                	xor    (%esi),%ch
  405658:	30 00                	xor    %al,(%eax)
  40565a:	00 00                	add    %al,(%eax)
  40565c:	47                   	inc    %edi
  40565d:	43                   	inc    %ebx
  40565e:	43                   	inc    %ebx
  40565f:	3a 20                	cmp    (%eax),%ah
  405661:	28 4d 69             	sub    %cl,0x69(%ebp)
  405664:	6e                   	outsb  %ds:(%esi),(%dx)
  405665:	47                   	inc    %edi
  405666:	57                   	push   %edi
  405667:	2e 6f                	outsl  %cs:(%esi),(%dx)
  405669:	72 67                	jb     4056d2 <.rdata$zzz+0xe>
  40566b:	20 43 72             	and    %al,0x72(%ebx)
  40566e:	6f                   	outsl  %ds:(%esi),(%dx)
  40566f:	73 73                	jae    4056e4 <.rdata$zzz+0x20>
  405671:	2d 47 43 43 20       	sub    $0x20434347,%eax
  405676:	42                   	inc    %edx
  405677:	75 69                	jne    4056e2 <.rdata$zzz+0x1e>
  405679:	6c                   	insb   (%dx),%es:(%edi)
  40567a:	64 2d 32 30 32 30    	fs sub $0x30323032,%eax
  405680:	30 35 33 31 2d 31    	xor    %dh,0x312d3133
  405686:	29 20                	sub    %esp,(%eax)
  405688:	39 2e                	cmp    %ebp,(%esi)
  40568a:	32 2e                	xor    (%esi),%ch
  40568c:	30 00                	xor    %al,(%eax)
  40568e:	00 00                	add    %al,(%eax)
  405690:	47                   	inc    %edi
  405691:	43                   	inc    %ebx
  405692:	43                   	inc    %ebx
  405693:	3a 20                	cmp    (%eax),%ah
  405695:	28 4d 69             	sub    %cl,0x69(%ebp)
  405698:	6e                   	outsb  %ds:(%esi),(%dx)
  405699:	47                   	inc    %edi
  40569a:	57                   	push   %edi
  40569b:	2e 6f                	outsl  %cs:(%esi),(%dx)
  40569d:	72 67                	jb     405706 <.rdata$zzz+0xe>
  40569f:	20 43 72             	and    %al,0x72(%ebx)
  4056a2:	6f                   	outsl  %ds:(%esi),(%dx)
  4056a3:	73 73                	jae    405718 <.rdata$zzz+0x20>
  4056a5:	2d 47 43 43 20       	sub    $0x20434347,%eax
  4056aa:	42                   	inc    %edx
  4056ab:	75 69                	jne    405716 <.rdata$zzz+0x1e>
  4056ad:	6c                   	insb   (%dx),%es:(%edi)
  4056ae:	64 2d 32 30 32 30    	fs sub $0x30323032,%eax
  4056b4:	30 35 33 31 2d 31    	xor    %dh,0x312d3133
  4056ba:	29 20                	sub    %esp,(%eax)
  4056bc:	39 2e                	cmp    %ebp,(%esi)
  4056be:	32 2e                	xor    (%esi),%ch
  4056c0:	30 00                	xor    %al,(%eax)
	...

004056c4 <.rdata$zzz>:
  4056c4:	47                   	inc    %edi
  4056c5:	43                   	inc    %ebx
  4056c6:	43                   	inc    %ebx
  4056c7:	3a 20                	cmp    (%eax),%ah
  4056c9:	28 4d 69             	sub    %cl,0x69(%ebp)
  4056cc:	6e                   	outsb  %ds:(%esi),(%dx)
  4056cd:	47                   	inc    %edi
  4056ce:	57                   	push   %edi
  4056cf:	2e 6f                	outsl  %cs:(%esi),(%dx)
  4056d1:	72 67                	jb     40573a <__RUNTIME_PSEUDO_RELOC_LIST_END__+0xe>
  4056d3:	20 43 72             	and    %al,0x72(%ebx)
  4056d6:	6f                   	outsl  %ds:(%esi),(%dx)
  4056d7:	73 73                	jae    40574c <__RUNTIME_PSEUDO_RELOC_LIST_END__+0x20>
  4056d9:	2d 47 43 43 20       	sub    $0x20434347,%eax
  4056de:	42                   	inc    %edx
  4056df:	75 69                	jne    40574a <__RUNTIME_PSEUDO_RELOC_LIST_END__+0x1e>
  4056e1:	6c                   	insb   (%dx),%es:(%edi)
  4056e2:	64 2d 32 30 32 30    	fs sub $0x30323032,%eax
  4056e8:	30 35 33 31 2d 31    	xor    %dh,0x312d3133
  4056ee:	29 20                	sub    %esp,(%eax)
  4056f0:	39 2e                	cmp    %ebp,(%esi)
  4056f2:	32 2e                	xor    (%esi),%ch
  4056f4:	30 00                	xor    %al,(%eax)
	...

004056f8 <.rdata$zzz>:
  4056f8:	47                   	inc    %edi
  4056f9:	43                   	inc    %ebx
  4056fa:	43                   	inc    %ebx
  4056fb:	3a 20                	cmp    (%eax),%ah
  4056fd:	28 4d 69             	sub    %cl,0x69(%ebp)
  405700:	6e                   	outsb  %ds:(%esi),(%dx)
  405701:	47                   	inc    %edi
  405702:	57                   	push   %edi
  405703:	2e 6f                	outsl  %cs:(%esi),(%dx)
  405705:	72 67                	jb     40576e <__RUNTIME_PSEUDO_RELOC_LIST_END__+0x42>
  405707:	20 43 72             	and    %al,0x72(%ebx)
  40570a:	6f                   	outsl  %ds:(%esi),(%dx)
  40570b:	73 73                	jae    405780 <__RUNTIME_PSEUDO_RELOC_LIST_END__+0x54>
  40570d:	2d 47 43 43 20       	sub    $0x20434347,%eax
  405712:	42                   	inc    %edx
  405713:	75 69                	jne    40577e <__RUNTIME_PSEUDO_RELOC_LIST_END__+0x52>
  405715:	6c                   	insb   (%dx),%es:(%edi)
  405716:	64 2d 32 30 32 30    	fs sub $0x30323032,%eax
  40571c:	30 35 33 31 2d 31    	xor    %dh,0x312d3133
  405722:	29 20                	sub    %esp,(%eax)
  405724:	39 2e                	cmp    %ebp,(%esi)
  405726:	32 2e                	xor    (%esi),%ch
  405728:	30 00                	xor    %al,(%eax)
	...

Disassembly of section .eh_frame:

00406000 <___EH_FRAME_BEGIN__-0xc8>:
  406000:	14 00                	adc    $0x0,%al
  406002:	00 00                	add    %al,(%eax)
  406004:	00 00                	add    %al,(%eax)
  406006:	00 00                	add    %al,(%eax)
  406008:	01 7a 52             	add    %edi,0x52(%edx)
  40600b:	00 01                	add    %al,(%ecx)
  40600d:	7c 08                	jl     406017 <__RUNTIME_PSEUDO_RELOC_LIST_END__+0x8eb>
  40600f:	01 1b                	add    %ebx,(%ebx)
  406011:	0c 04                	or     $0x4,%al
  406013:	04 88                	add    $0x88,%al
  406015:	01 00                	add    %eax,(%eax)
  406017:	00 18                	add    %bl,(%eax)
  406019:	00 00                	add    %al,(%eax)
  40601b:	00 1c 00             	add    %bl,(%eax,%eax,1)
  40601e:	00 00                	add    %al,(%eax)
  406020:	e0 af                	loopne 405fd1 <__RUNTIME_PSEUDO_RELOC_LIST_END__+0x8a5>
  406022:	ff                   	(bad)  
  406023:	ff 9b 01 00 00 00    	lcall  *0x1(%ebx)
  406029:	43                   	inc    %ebx
  40602a:	0e                   	push   %cs
  40602b:	20 02                	and    %al,(%edx)
  40602d:	56                   	push   %esi
  40602e:	0a 0e                	or     (%esi),%cl
  406030:	04 47                	add    $0x47,%al
  406032:	0b 00                	or     (%eax),%eax
  406034:	28 00                	sub    %al,(%eax)
  406036:	00 00                	add    %al,(%eax)
  406038:	38 00                	cmp    %al,(%eax)
  40603a:	00 00                	add    %al,(%eax)
  40603c:	64 b1 ff             	fs mov $0xff,%cl
  40603f:	ff                   	(bad)  
  406040:	e9 00 00 00 00       	jmp    406045 <__RUNTIME_PSEUDO_RELOC_LIST_END__+0x919>
  406045:	41                   	inc    %ecx
  406046:	0e                   	push   %cs
  406047:	08 83 02 43 0e 20    	or     %al,0x200e4302(%ebx)
  40604d:	62 0e                	bound  %ecx,(%esi)
  40604f:	14 43                	adc    $0x43,%al
  406051:	0e                   	push   %cs
  406052:	20 4c 0e 1c          	and    %cl,0x1c(%esi,%ecx,1)
  406056:	43                   	inc    %ebx
  406057:	0e                   	push   %cs
  406058:	20 02                	and    %al,(%edx)
  40605a:	6a 0a                	push   $0xa
  40605c:	0e                   	push   %cs
  40605d:	1c 0b                	sbb    $0xb,%al
  40605f:	00 14 00             	add    %dl,(%eax,%eax,1)
  406062:	00 00                	add    %al,(%eax)
  406064:	64 00 00             	add    %al,%fs:(%eax)
  406067:	00 28                	add    %ch,(%eax)
  406069:	b2 ff                	mov    $0xff,%dl
  40606b:	ff                   	(bad)  
  40606c:	3f                   	aas    
  40606d:	00 00                	add    %al,(%eax)
  40606f:	00 00                	add    %al,(%eax)
  406071:	43                   	inc    %ebx
  406072:	0e                   	push   %cs
  406073:	40                   	inc    %eax
  406074:	7b 0e                	jnp    406084 <__RUNTIME_PSEUDO_RELOC_LIST_END__+0x958>
  406076:	04 00                	add    $0x0,%al
  406078:	10 00                	adc    %al,(%eax)
  40607a:	00 00                	add    %al,(%eax)
  40607c:	7c 00                	jl     40607e <__RUNTIME_PSEUDO_RELOC_LIST_END__+0x952>
  40607e:	00 00                	add    %al,(%eax)
  406080:	50                   	push   %eax
  406081:	b2 ff                	mov    $0xff,%dl
  406083:	ff 15 00 00 00 00    	call   *0x0
  406089:	43                   	inc    %ebx
  40608a:	0e                   	push   %cs
  40608b:	20 10                	and    %dl,(%eax)
  40608d:	00 00                	add    %al,(%eax)
  40608f:	00 90 00 00 00 5c    	add    %dl,0x5c000000(%eax)
  406095:	b2 ff                	mov    $0xff,%dl
  406097:	ff 15 00 00 00 00    	call   *0x0
  40609d:	43                   	inc    %ebx
  40609e:	0e                   	push   %cs
  40609f:	20 10                	and    %dl,(%eax)
  4060a1:	00 00                	add    %al,(%eax)
  4060a3:	00 a4 00 00 00 68 b2 	add    %ah,-0x4d980000(%eax,%eax,1)
  4060aa:	ff                   	(bad)  
  4060ab:	ff 06                	incl   (%esi)
  4060ad:	00 00                	add    %al,(%eax)
  4060af:	00 00                	add    %al,(%eax)
  4060b1:	00 00                	add    %al,(%eax)
  4060b3:	00 10                	add    %dl,(%eax)
  4060b5:	00 00                	add    %al,(%eax)
  4060b7:	00 b8 00 00 00 64    	add    %bh,0x64000000(%eax)
  4060bd:	b2 ff                	mov    $0xff,%dl
  4060bf:	ff 06                	incl   (%esi)
  4060c1:	00 00                	add    %al,(%eax)
  4060c3:	00 00                	add    %al,(%eax)
  4060c5:	00 00                	add    %al,(%eax)
	...

004060c8 <___EH_FRAME_BEGIN__>:
  4060c8:	14 00                	adc    $0x0,%al
  4060ca:	00 00                	add    %al,(%eax)
  4060cc:	00 00                	add    %al,(%eax)
  4060ce:	00 00                	add    %al,(%eax)
  4060d0:	01 7a 52             	add    %edi,0x52(%edx)
  4060d3:	00 01                	add    %al,(%ecx)
  4060d5:	7c 08                	jl     4060df <___EH_FRAME_BEGIN__+0x17>
  4060d7:	01 1b                	add    %ebx,(%ebx)
  4060d9:	0c 04                	or     $0x4,%al
  4060db:	04 88                	add    $0x88,%al
  4060dd:	01 00                	add    %eax,(%eax)
  4060df:	00 28                	add    %ch,(%eax)
  4060e1:	00 00                	add    %al,(%eax)
  4060e3:	00 1c 00             	add    %bl,(%eax,%eax,1)
  4060e6:	00 00                	add    %al,(%eax)
  4060e8:	48                   	dec    %eax
  4060e9:	b2 ff                	mov    $0xff,%dl
  4060eb:	ff a1 00 00 00 00    	jmp    *0x0(%ecx)
  4060f1:	41                   	inc    %ecx
  4060f2:	0e                   	push   %cs
  4060f3:	08 85 02 42 0d 05    	or     %al,0x50d4202(%ebp)
  4060f9:	45                   	inc    %ebp
  4060fa:	86 03                	xchg   %al,(%ebx)
  4060fc:	83 04 02 7b          	addl   $0x7b,(%edx,%eax,1)
  406100:	0a c3                	or     %bl,%al
  406102:	41                   	inc    %ecx
  406103:	c6 41 c5 0c          	movb   $0xc,-0x3b(%ecx)
  406107:	04 04                	add    $0x4,%al
  406109:	4b                   	dec    %ebx
  40610a:	0b 00                	or     (%eax),%eax
  40610c:	1c 00                	sbb    $0x0,%al
  40610e:	00 00                	add    %al,(%eax)
  406110:	48                   	dec    %eax
  406111:	00 00                	add    %al,(%eax)
  406113:	00 cc                	add    %cl,%ah
  406115:	b2 ff                	mov    $0xff,%dl
  406117:	ff 2e                	ljmp   *(%esi)
  406119:	00 00                	add    %al,(%eax)
  40611b:	00 00                	add    %al,(%eax)
  40611d:	41                   	inc    %ecx
  40611e:	0e                   	push   %cs
  40611f:	08 85 02 42 0d 05    	or     %al,0x50d4202(%ebp)
  406125:	6a c5                	push   $0xffffffc5
  406127:	0c 04                	or     $0x4,%al
  406129:	04 00                	add    $0x0,%al
	...

0040612c <.eh_frame>:
  40612c:	14 00                	adc    $0x0,%al
  40612e:	00 00                	add    %al,(%eax)
  406130:	00 00                	add    %al,(%eax)
  406132:	00 00                	add    %al,(%eax)
  406134:	01 7a 52             	add    %edi,0x52(%edx)
  406137:	00 01                	add    %al,(%ecx)
  406139:	7c 08                	jl     406143 <.eh_frame+0x17>
  40613b:	01 1b                	add    %ebx,(%ebx)
  40613d:	0c 04                	or     $0x4,%al
  40613f:	04 88                	add    $0x88,%al
  406141:	01 00                	add    %eax,(%eax)
  406143:	00 1c 00             	add    %bl,(%eax,%eax,1)
  406146:	00 00                	add    %al,(%eax)
  406148:	1c 00                	sbb    $0x0,%al
  40614a:	00 00                	add    %al,(%eax)
  40614c:	c4 b2 ff ff 21 00    	les    0x21ffff(%edx),%esi
  406152:	00 00                	add    %al,(%eax)
  406154:	00 41 0e             	add    %al,0xe(%ecx)
  406157:	08 85 02 42 0d 05    	or     %al,0x50d4202(%ebp)
  40615d:	5d                   	pop    %ebp
  40615e:	c5 0c 04             	lds    (%esp,%eax,1),%ecx
  406161:	04 00                	add    $0x0,%al
  406163:	00 14 00             	add    %dl,(%eax,%eax,1)
  406166:	00 00                	add    %al,(%eax)
  406168:	00 00                	add    %al,(%eax)
  40616a:	00 00                	add    %al,(%eax)
  40616c:	01 7a 52             	add    %edi,0x52(%edx)
  40616f:	00 01                	add    %al,(%ecx)
  406171:	7c 08                	jl     40617b <.eh_frame+0x4f>
  406173:	01 1b                	add    %ebx,(%ebx)
  406175:	0c 04                	or     $0x4,%al
  406177:	04 88                	add    $0x88,%al
  406179:	01 00                	add    %eax,(%eax)
  40617b:	00 2c 00             	add    %ch,(%eax,%eax,1)
  40617e:	00 00                	add    %al,(%eax)
  406180:	1c 00                	sbb    $0x0,%al
  406182:	00 00                	add    %al,(%eax)
  406184:	bc b2 ff ff 51       	mov    $0x51ffffb2,%esp
  406189:	04 00                	add    $0x0,%al
  40618b:	00 00                	add    %al,(%eax)
  40618d:	41                   	inc    %ecx
  40618e:	0e                   	push   %cs
  40618f:	08 85 02 42 0d 05    	or     %al,0x50d4202(%ebp)
  406195:	49                   	dec    %ecx
  406196:	87 03                	xchg   %eax,(%ebx)
  406198:	86 04 83             	xchg   %al,(%ebx,%eax,4)
  40619b:	05 52 0a c3 41       	add    $0x41c30a52,%eax
  4061a0:	c6 41 c7 41          	movb   $0x41,-0x39(%ecx)
  4061a4:	c5 0c 04             	lds    (%esp,%eax,1),%ecx
  4061a7:	04 47                	add    $0x47,%al
  4061a9:	0b 00                	or     (%eax),%eax
  4061ab:	00 14 00             	add    %dl,(%eax,%eax,1)
  4061ae:	00 00                	add    %al,(%eax)
  4061b0:	00 00                	add    %al,(%eax)
  4061b2:	00 00                	add    %al,(%eax)
  4061b4:	01 7a 52             	add    %edi,0x52(%edx)
  4061b7:	00 01                	add    %al,(%ecx)
  4061b9:	7c 08                	jl     4061c3 <.eh_frame+0x97>
  4061bb:	01 1b                	add    %ebx,(%ebx)
  4061bd:	0c 04                	or     $0x4,%al
  4061bf:	04 88                	add    $0x88,%al
  4061c1:	01 00                	add    %eax,(%eax)
  4061c3:	00 24 00             	add    %ah,(%eax,%eax,1)
  4061c6:	00 00                	add    %al,(%eax)
  4061c8:	1c 00                	sbb    $0x0,%al
  4061ca:	00 00                	add    %al,(%eax)
  4061cc:	d4 b6                	aam    $0xb6
  4061ce:	ff                   	(bad)  
  4061cf:	ff 07                	incl   (%edi)
  4061d1:	01 00                	add    %eax,(%eax)
  4061d3:	00 00                	add    %al,(%eax)
  4061d5:	5d                   	pop    %ebp
  4061d6:	0e                   	push   %cs
  4061d7:	08 83 02 02 48 0c    	or     %al,0xc480202(%ebx)
  4061dd:	05 0c 85 03 02       	add    $0x203850c,%eax
  4061e2:	41                   	inc    %ecx
  4061e3:	c5 0c 04             	lds    (%esp,%eax,1),%ecx
  4061e6:	08 02                	or     %al,(%edx)
  4061e8:	5f                   	pop    %edi
  4061e9:	c3                   	ret    
  4061ea:	0e                   	push   %cs
  4061eb:	04 14                	add    $0x14,%al
  4061ed:	00 00                	add    %al,(%eax)
  4061ef:	00 00                	add    %al,(%eax)
  4061f1:	00 00                	add    %al,(%eax)
  4061f3:	00 01                	add    %al,(%ecx)
  4061f5:	7a 52                	jp     406249 <.eh_frame+0x11d>
  4061f7:	00 01                	add    %al,(%ecx)
  4061f9:	7c 08                	jl     406203 <.eh_frame+0xd7>
  4061fb:	01 1b                	add    %ebx,(%ebx)
  4061fd:	0c 04                	or     $0x4,%al
  4061ff:	04 88                	add    $0x88,%al
  406201:	01 00                	add    %eax,(%eax)
  406203:	00 14 00             	add    %dl,(%eax,%eax,1)
  406206:	00 00                	add    %al,(%eax)
  406208:	1c 00                	sbb    $0x0,%al
  40620a:	00 00                	add    %al,(%eax)
  40620c:	a4                   	movsb  %ds:(%esi),%es:(%edi)
  40620d:	b7 ff                	mov    $0xff,%bh
  40620f:	ff 31                	pushl  (%ecx)
  406211:	00 00                	add    %al,(%eax)
  406213:	00 00                	add    %al,(%eax)
  406215:	4e                   	dec    %esi
  406216:	0e                   	push   %cs
  406217:	10 5c 0e 04          	adc    %bl,0x4(%esi,%ecx,1)
  40621b:	00 20                	add    %ah,(%eax)
  40621d:	00 00                	add    %al,(%eax)
  40621f:	00 34 00             	add    %dh,(%eax,%eax,1)
  406222:	00 00                	add    %al,(%eax)
  406224:	cc                   	int3   
  406225:	b7 ff                	mov    $0xff,%bh
  406227:	ff 52 00             	call   *0x0(%edx)
  40622a:	00 00                	add    %al,(%eax)
  40622c:	00 41 0e             	add    %al,0xe(%ecx)
  40622f:	08 83 02 43 0e 20    	or     %al,0x200e4302(%ebx)
  406235:	6f                   	outsl  %ds:(%esi),(%dx)
  406236:	0a 0e                	or     (%esi),%cl
  406238:	08 41 c3             	or     %al,-0x3d(%ecx)
  40623b:	0e                   	push   %cs
  40623c:	04 44                	add    $0x44,%al
  40623e:	0b 00                	or     (%eax),%eax
  406240:	10 00                	adc    %al,(%eax)
  406242:	00 00                	add    %al,(%eax)
  406244:	58                   	pop    %eax
  406245:	00 00                	add    %al,(%eax)
  406247:	00 08                	add    %cl,(%eax)
  406249:	b8 ff ff 1c 00       	mov    $0x1cffff,%eax
  40624e:	00 00                	add    %al,(%eax)
  406250:	00 00                	add    %al,(%eax)
  406252:	00 00                	add    %al,(%eax)
  406254:	14 00                	adc    $0x0,%al
  406256:	00 00                	add    %al,(%eax)
  406258:	00 00                	add    %al,(%eax)
  40625a:	00 00                	add    %al,(%eax)
  40625c:	01 7a 52             	add    %edi,0x52(%edx)
  40625f:	00 01                	add    %al,(%ecx)
  406261:	7c 08                	jl     40626b <.eh_frame+0x13f>
  406263:	01 1b                	add    %ebx,(%ebx)
  406265:	0c 04                	or     $0x4,%al
  406267:	04 88                	add    $0x88,%al
  406269:	01 00                	add    %eax,(%eax)
  40626b:	00 1c 00             	add    %bl,(%eax,%eax,1)
  40626e:	00 00                	add    %al,(%eax)
  406270:	1c 00                	sbb    $0x0,%al
  406272:	00 00                	add    %al,(%eax)
  406274:	fc                   	cld    
  406275:	b7 ff                	mov    $0xff,%bh
  406277:	ff 43 00             	incl   0x0(%ebx)
  40627a:	00 00                	add    %al,(%eax)
  40627c:	00 43 0e             	add    %al,0xe(%ebx)
  40627f:	20 55 0a             	and    %dl,0xa(%ebp)
  406282:	0e                   	push   %cs
  406283:	04 48                	add    $0x48,%al
  406285:	0b 60 0e             	or     0xe(%eax),%esp
  406288:	04 00                	add    $0x0,%al
  40628a:	00 00                	add    %al,(%eax)
  40628c:	44                   	inc    %esp
  40628d:	00 00                	add    %al,(%eax)
  40628f:	00 3c 00             	add    %bh,(%eax,%eax,1)
  406292:	00 00                	add    %al,(%eax)
  406294:	2c b8                	sub    $0xb8,%al
  406296:	ff                   	(bad)  
  406297:	ff a1 00 00 00 00    	jmp    *0x0(%ecx)
  40629d:	41                   	inc    %ecx
  40629e:	0e                   	push   %cs
  40629f:	08 86 02 41 0e 0c    	or     %al,0xc0e4102(%esi)
  4062a5:	83 03 43             	addl   $0x43,(%ebx)
  4062a8:	0e                   	push   %cs
  4062a9:	20 64 0a 0e          	and    %ah,0xe(%edx,%ecx,1)
  4062ad:	0c 46                	or     $0x46,%al
  4062af:	c3                   	ret    
  4062b0:	0e                   	push   %cs
  4062b1:	08 41 c6             	or     %al,-0x3a(%ecx)
  4062b4:	0e                   	push   %cs
  4062b5:	04 48                	add    $0x48,%al
  4062b7:	0b 6f 0a             	or     0xa(%edi),%ebp
  4062ba:	0e                   	push   %cs
  4062bb:	0c 46                	or     $0x46,%al
  4062bd:	c3                   	ret    
  4062be:	0e                   	push   %cs
  4062bf:	08 41 c6             	or     %al,-0x3a(%ecx)
  4062c2:	0e                   	push   %cs
  4062c3:	04 4a                	add    $0x4a,%al
  4062c5:	0b 5f 0e             	or     0xe(%edi),%ebx
  4062c8:	0c 46                	or     $0x46,%al
  4062ca:	c3                   	ret    
  4062cb:	0e                   	push   %cs
  4062cc:	08 41 c6             	or     %al,-0x3a(%ecx)
  4062cf:	0e                   	push   %cs
  4062d0:	04 00                	add    $0x0,%al
  4062d2:	00 00                	add    %al,(%eax)
  4062d4:	10 00                	adc    %al,(%eax)
  4062d6:	00 00                	add    %al,(%eax)
  4062d8:	84 00                	test   %al,(%eax)
  4062da:	00 00                	add    %al,(%eax)
  4062dc:	94                   	xchg   %eax,%esp
  4062dd:	b8 ff ff 03 00       	mov    $0x3ffff,%eax
  4062e2:	00 00                	add    %al,(%eax)
  4062e4:	00 00                	add    %al,(%eax)
  4062e6:	00 00                	add    %al,(%eax)
  4062e8:	14 00                	adc    $0x0,%al
  4062ea:	00 00                	add    %al,(%eax)
  4062ec:	00 00                	add    %al,(%eax)
  4062ee:	00 00                	add    %al,(%eax)
  4062f0:	01 7a 52             	add    %edi,0x52(%edx)
  4062f3:	00 01                	add    %al,(%ecx)
  4062f5:	7c 08                	jl     4062ff <.eh_frame+0x1d3>
  4062f7:	01 1b                	add    %ebx,(%ebx)
  4062f9:	0c 04                	or     $0x4,%al
  4062fb:	04 88                	add    $0x88,%al
  4062fd:	01 00                	add    %eax,(%eax)
  4062ff:	00 38                	add    %bh,(%eax)
  406301:	00 00                	add    %al,(%eax)
  406303:	00 1c 00             	add    %bl,(%eax,%eax,1)
  406306:	00 00                	add    %al,(%eax)
  406308:	78 b8                	js     4062c2 <.eh_frame+0x196>
  40630a:	ff                   	(bad)  
  40630b:	ff 60 00             	jmp    *0x0(%eax)
  40630e:	00 00                	add    %al,(%eax)
  406310:	00 41 0e             	add    %al,0xe(%ecx)
  406313:	08 86 02 41 0e 0c    	or     %al,0xc0e4102(%esi)
  406319:	83 03 43             	addl   $0x43,(%ebx)
  40631c:	0e                   	push   %cs
  40631d:	20 4c 0e 1c          	and    %cl,0x1c(%esi,%ecx,1)
  406321:	49                   	dec    %ecx
  406322:	0e                   	push   %cs
  406323:	20 50 0e             	and    %dl,0xe(%eax)
  406326:	1c 43                	sbb    $0x43,%al
  406328:	0e                   	push   %cs
  406329:	20 6a 0e             	and    %ch,0xe(%edx)
  40632c:	1c 43                	sbb    $0x43,%al
  40632e:	0e                   	push   %cs
  40632f:	20 43 0e             	and    %al,0xe(%ebx)
  406332:	0c 41                	or     $0x41,%al
  406334:	c3                   	ret    
  406335:	0e                   	push   %cs
  406336:	08 41 c6             	or     %al,-0x3a(%ecx)
  406339:	0e                   	push   %cs
  40633a:	04 00                	add    $0x0,%al
  40633c:	2c 00                	sub    $0x0,%al
  40633e:	00 00                	add    %al,(%eax)
  406340:	58                   	pop    %eax
  406341:	00 00                	add    %al,(%eax)
  406343:	00 9c b8 ff ff 73 00 	add    %bl,0x73ffff(%eax,%edi,4)
  40634a:	00 00                	add    %al,(%eax)
  40634c:	00 51 0e             	add    %dl,0xe(%ecx)
  40634f:	08 83 02 43 0e 20    	or     %al,0x200e4302(%ebx)
  406355:	73 0e                	jae    406365 <.eh_frame+0x239>
  406357:	1c 4e                	sbb    $0x4e,%al
  406359:	0e                   	push   %cs
  40635a:	20 4f 0e             	and    %cl,0xe(%edi)
  40635d:	1c 45                	sbb    $0x45,%al
  40635f:	0e                   	push   %cs
  406360:	20 43 0a             	and    %al,0xa(%ebx)
  406363:	0e                   	push   %cs
  406364:	08 41 c3             	or     %al,-0x3d(%ecx)
  406367:	0e                   	push   %cs
  406368:	04 41                	add    $0x41,%al
  40636a:	0b 00                	or     (%eax),%eax
  40636c:	38 00                	cmp    %al,(%eax)
  40636e:	00 00                	add    %al,(%eax)
  406370:	88 00                	mov    %al,(%eax)
  406372:	00 00                	add    %al,(%eax)
  406374:	ec                   	in     (%dx),%al
  406375:	b8 ff ff 88 00       	mov    $0x88ffff,%eax
  40637a:	00 00                	add    %al,(%eax)
  40637c:	00 41 0e             	add    %al,0xe(%ecx)
  40637f:	08 83 02 43 0e 20    	or     %al,0x200e4302(%ebx)
  406385:	50                   	push   %eax
  406386:	0a 0e                	or     (%esi),%cl
  406388:	08 43 c3             	or     %al,-0x3d(%ebx)
  40638b:	0e                   	push   %cs
  40638c:	04 49                	add    $0x49,%al
  40638e:	0b 4c 0e 1c          	or     0x1c(%esi,%ecx,1),%ecx
  406392:	48                   	dec    %eax
  406393:	0e                   	push   %cs
  406394:	20 78 0e             	and    %bh,0xe(%eax)
  406397:	1c 45                	sbb    $0x45,%al
  406399:	0e                   	push   %cs
  40639a:	20 43 0a             	and    %al,0xa(%ebx)
  40639d:	0e                   	push   %cs
  40639e:	08 41 c3             	or     %al,-0x3d(%ecx)
  4063a1:	0e                   	push   %cs
  4063a2:	04 4b                	add    $0x4b,%al
  4063a4:	0b 00                	or     (%eax),%eax
  4063a6:	00 00                	add    %al,(%eax)
  4063a8:	30 00                	xor    %al,(%eax)
  4063aa:	00 00                	add    %al,(%eax)
  4063ac:	c4 00                	les    (%eax),%eax
  4063ae:	00 00                	add    %al,(%eax)
  4063b0:	40                   	inc    %eax
  4063b1:	b9 ff ff bc 00       	mov    $0xbcffff,%ecx
  4063b6:	00 00                	add    %al,(%eax)
  4063b8:	00 43 0e             	add    %al,0xe(%ebx)
  4063bb:	20 5a 0a             	and    %bl,0xa(%edx)
  4063be:	0e                   	push   %cs
  4063bf:	04 43                	add    $0x43,%al
  4063c1:	0b 5b 0a             	or     0xa(%ebx),%ebx
  4063c4:	0e                   	push   %cs
  4063c5:	04 45                	add    $0x45,%al
  4063c7:	0b 69 0e             	or     0xe(%ecx),%ebp
  4063ca:	1c 43                	sbb    $0x43,%al
  4063cc:	0e                   	push   %cs
  4063cd:	20 5a 0a             	and    %bl,0xa(%edx)
  4063d0:	0e                   	push   %cs
  4063d1:	04 4a                	add    $0x4a,%al
  4063d3:	0b 64 0e 1c          	or     0x1c(%esi,%ecx,1),%esp
  4063d7:	43                   	inc    %ebx
  4063d8:	0e                   	push   %cs
  4063d9:	20 00                	and    %al,(%eax)
  4063db:	00 14 00             	add    %dl,(%eax,%eax,1)
  4063de:	00 00                	add    %al,(%eax)
  4063e0:	00 00                	add    %al,(%eax)
  4063e2:	00 00                	add    %al,(%eax)
  4063e4:	01 7a 52             	add    %edi,0x52(%edx)
  4063e7:	00 01                	add    %al,(%ecx)
  4063e9:	7c 08                	jl     4063f3 <.eh_frame+0x2c7>
  4063eb:	01 1b                	add    %ebx,(%ebx)
  4063ed:	0c 04                	or     $0x4,%al
  4063ef:	04 88                	add    $0x88,%al
  4063f1:	01 00                	add    %eax,(%eax)
  4063f3:	00 1c 00             	add    %bl,(%eax,%eax,1)
  4063f6:	00 00                	add    %al,(%eax)
  4063f8:	1c 00                	sbb    $0x0,%al
  4063fa:	00 00                	add    %al,(%eax)
  4063fc:	b4 b9                	mov    $0xb9,%ah
  4063fe:	ff                   	(bad)  
  4063ff:	ff 4a 00             	decl   0x0(%edx)
  406402:	00 00                	add    %al,(%eax)
  406404:	00 41 0e             	add    %al,0xe(%ecx)
  406407:	08 86 02 41 0e 0c    	or     %al,0xc0e4102(%esi)
  40640d:	83 03 43             	addl   $0x43,(%ebx)
  406410:	0e                   	push   %cs
  406411:	20 00                	and    %al,(%eax)
  406413:	00 64 00 00          	add    %ah,0x0(%eax,%eax,1)
  406417:	00 3c 00             	add    %bh,(%eax,%eax,1)
  40641a:	00 00                	add    %al,(%eax)
  40641c:	e4 b9                	in     $0xb9,%al
  40641e:	ff                   	(bad)  
  40641f:	ff                   	(bad)  
  406420:	ec                   	in     (%dx),%al
  406421:	00 00                	add    %al,(%eax)
  406423:	00 00                	add    %al,(%eax)
  406425:	41                   	inc    %ecx
  406426:	0e                   	push   %cs
  406427:	08 85 02 41 0e 0c    	or     %al,0xc0e4102(%ebp)
  40642d:	87 03                	xchg   %eax,(%ebx)
  40642f:	43                   	inc    %ebx
  406430:	0e                   	push   %cs
  406431:	10 86 04 43 0e 14    	adc    %al,0x140e4304(%esi)
  406437:	83 05 45 0e 50 58 0e 	addl   $0xe,0x58500e45
  40643e:	44                   	inc    %esp
  40643f:	43                   	inc    %ebx
  406440:	0e                   	push   %cs
  406441:	50                   	push   %eax
  406442:	6d                   	insl   (%dx),%es:(%edi)
  406443:	0a 0e                	or     (%esi),%cl
  406445:	14 41                	adc    $0x41,%al
  406447:	c3                   	ret    
  406448:	0e                   	push   %cs
  406449:	10 41 c6             	adc    %al,-0x3a(%ecx)
  40644c:	0e                   	push   %cs
  40644d:	0c 41                	or     $0x41,%al
  40644f:	c7                   	(bad)  
  406450:	0e                   	push   %cs
  406451:	08 41 c5             	or     %al,-0x3b(%ecx)
  406454:	0e                   	push   %cs
  406455:	04 47                	add    $0x47,%al
  406457:	0b 64 0e 40          	or     0x40(%esi,%ecx,1),%esp
  40645b:	43                   	inc    %ebx
  40645c:	0e                   	push   %cs
  40645d:	50                   	push   %eax
  40645e:	02 42 0e             	add    0xe(%edx),%al
  406461:	40                   	inc    %eax
  406462:	43                   	inc    %ebx
  406463:	0e                   	push   %cs
  406464:	50                   	push   %eax
  406465:	43                   	inc    %ebx
  406466:	0a 0e                	or     (%esi),%cl
  406468:	14 41                	adc    $0x41,%al
  40646a:	c3                   	ret    
  40646b:	0e                   	push   %cs
  40646c:	10 41 c6             	adc    %al,-0x3a(%ecx)
  40646f:	0e                   	push   %cs
  406470:	0c 41                	or     $0x41,%al
  406472:	c7                   	(bad)  
  406473:	0e                   	push   %cs
  406474:	08 41 c5             	or     %al,-0x3b(%ecx)
  406477:	0e                   	push   %cs
  406478:	04 41                	add    $0x41,%al
  40647a:	0b 00                	or     (%eax),%eax
  40647c:	48                   	dec    %eax
  40647d:	00 00                	add    %al,(%eax)
  40647f:	00 a4 00 00 00 6c ba 	add    %ah,-0x45940000(%eax,%eax,1)
  406486:	ff                   	(bad)  
  406487:	ff                   	(bad)  
  406488:	ea 01 00 00 00 6a 0e 	ljmp   $0xe6a,$0x1
  40648f:	08 87 02 41 0e 0c    	or     %al,0xc0e4102(%edi)
  406495:	86 03                	xchg   %al,(%ebx)
  406497:	41                   	inc    %ecx
  406498:	0e                   	push   %cs
  406499:	10 83 04 43 0e 30    	adc    %al,0x300e4304(%ebx)
  40649f:	02 93 0a 0e 10 41    	add    0x41100e0a(%ebx),%dl
  4064a5:	c3                   	ret    
  4064a6:	0e                   	push   %cs
  4064a7:	0c 41                	or     $0x41,%al
  4064a9:	c6                   	(bad)  
  4064aa:	0e                   	push   %cs
  4064ab:	08 41 c7             	or     %al,-0x39(%ecx)
  4064ae:	0e                   	push   %cs
  4064af:	04 4b                	add    $0x4b,%al
  4064b1:	0b 02                	or     (%edx),%eax
  4064b3:	fb                   	sti    
  4064b4:	0a 0e                	or     (%esi),%cl
  4064b6:	10 41 c3             	adc    %al,-0x3d(%ecx)
  4064b9:	0e                   	push   %cs
  4064ba:	0c 41                	or     $0x41,%al
  4064bc:	c6                   	(bad)  
  4064bd:	0e                   	push   %cs
  4064be:	08 41 c7             	or     %al,-0x39(%ecx)
  4064c1:	0e                   	push   %cs
  4064c2:	04 42                	add    $0x42,%al
  4064c4:	0b 00                	or     (%eax),%eax
  4064c6:	00 00                	add    %al,(%eax)
  4064c8:	14 00                	adc    $0x0,%al
  4064ca:	00 00                	add    %al,(%eax)
  4064cc:	00 00                	add    %al,(%eax)
  4064ce:	00 00                	add    %al,(%eax)
  4064d0:	01 7a 52             	add    %edi,0x52(%edx)
  4064d3:	00 01                	add    %al,(%ecx)
  4064d5:	7c 08                	jl     4064df <.eh_frame+0x3b3>
  4064d7:	01 1b                	add    %ebx,(%ebx)
  4064d9:	0c 04                	or     $0x4,%al
  4064db:	04 88                	add    $0x88,%al
  4064dd:	01 00                	add    %eax,(%eax)
  4064df:	00 18                	add    %bl,(%eax)
  4064e1:	00 00                	add    %al,(%eax)
  4064e3:	00 1c 00             	add    %bl,(%eax,%eax,1)
  4064e6:	00 00                	add    %al,(%eax)
  4064e8:	f8                   	clc    
  4064e9:	bb ff ff 77 00       	mov    $0x77ffff,%ebx
  4064ee:	00 00                	add    %al,(%eax)
  4064f0:	00 43 0e             	add    %al,0xe(%ebx)
  4064f3:	20 02                	and    %al,(%edx)
  4064f5:	41                   	inc    %ecx
  4064f6:	0a 0e                	or     (%esi),%cl
  4064f8:	04 44                	add    $0x44,%al
  4064fa:	0b 00                	or     (%eax),%eax
  4064fc:	14 00                	adc    $0x0,%al
  4064fe:	00 00                	add    %al,(%eax)
  406500:	00 00                	add    %al,(%eax)
  406502:	00 00                	add    %al,(%eax)
  406504:	01 7a 52             	add    %edi,0x52(%edx)
  406507:	00 01                	add    %al,(%ecx)
  406509:	7c 08                	jl     406513 <.eh_frame+0x3e7>
  40650b:	01 1b                	add    %ebx,(%ebx)
  40650d:	0c 04                	or     $0x4,%al
  40650f:	04 88                	add    $0x88,%al
  406511:	01 00                	add    %eax,(%eax)
  406513:	00 14 00             	add    %dl,(%eax,%eax,1)
  406516:	00 00                	add    %al,(%eax)
  406518:	1c 00                	sbb    $0x0,%al
  40651a:	00 00                	add    %al,(%eax)
  40651c:	44                   	inc    %esp
  40651d:	bc ff ff 24 00       	mov    $0x24ffff,%esp
  406522:	00 00                	add    %al,(%eax)
  406524:	00 43 0e             	add    %al,0xe(%ebx)
  406527:	30 60 0e             	xor    %ah,0xe(%eax)
  40652a:	04 00                	add    $0x0,%al
  40652c:	14 00                	adc    $0x0,%al
  40652e:	00 00                	add    %al,(%eax)
  406530:	00 00                	add    %al,(%eax)
  406532:	00 00                	add    %al,(%eax)
  406534:	01 7a 52             	add    %edi,0x52(%edx)
  406537:	00 01                	add    %al,(%ecx)
  406539:	7c 08                	jl     406543 <.eh_frame+0x417>
  40653b:	01 1b                	add    %ebx,(%ebx)
  40653d:	0c 04                	or     $0x4,%al
  40653f:	04 88                	add    $0x88,%al
  406541:	01 00                	add    %eax,(%eax)
  406543:	00 3c 00             	add    %bh,(%eax,%eax,1)
  406546:	00 00                	add    %al,(%eax)
  406548:	1c 00                	sbb    $0x0,%al
  40654a:	00 00                	add    %al,(%eax)
  40654c:	44                   	inc    %esp
  40654d:	bc ff ff 27 03       	mov    $0x327ffff,%esp
  406552:	00 00                	add    %al,(%eax)
  406554:	00 41 0e             	add    %al,0xe(%ecx)
  406557:	08 85 02 41 0e 0c    	or     %al,0xc0e4102(%ebp)
  40655d:	87 03                	xchg   %eax,(%ebx)
  40655f:	41                   	inc    %ecx
  406560:	0e                   	push   %cs
  406561:	10 86 04 41 0e 14    	adc    %al,0x140e4104(%esi)
  406567:	83 05 43 0e 50 03 26 	addl   $0x26,0x3500e43
  40656e:	01 0a                	add    %ecx,(%edx)
  406570:	0e                   	push   %cs
  406571:	14 41                	adc    $0x41,%al
  406573:	c3                   	ret    
  406574:	0e                   	push   %cs
  406575:	10 41 c6             	adc    %al,-0x3a(%ecx)
  406578:	0e                   	push   %cs
  406579:	0c 41                	or     $0x41,%al
  40657b:	c7                   	(bad)  
  40657c:	0e                   	push   %cs
  40657d:	08 41 c5             	or     %al,-0x3b(%ecx)
  406580:	0e                   	push   %cs
  406581:	04 47                	add    $0x47,%al
  406583:	0b 3c 00             	or     (%eax,%eax,1),%edi
  406586:	00 00                	add    %al,(%eax)
  406588:	5c                   	pop    %esp
  406589:	00 00                	add    %al,(%eax)
  40658b:	00 34 bf             	add    %dh,(%edi,%edi,4)
  40658e:	ff                   	(bad)  
  40658f:	ff 27                	jmp    *(%edi)
  406591:	02 00                	add    (%eax),%al
  406593:	00 00                	add    %al,(%eax)
  406595:	41                   	inc    %ecx
  406596:	0e                   	push   %cs
  406597:	08 85 02 43 0e 0c    	or     %al,0xc0e4302(%ebp)
  40659d:	87 03                	xchg   %eax,(%ebx)
  40659f:	41                   	inc    %ecx
  4065a0:	0e                   	push   %cs
  4065a1:	10 86 04 43 0e 14    	adc    %al,0x140e4304(%esi)
  4065a7:	83 05 43 0e 40 02 ca 	addl   $0xffffffca,0x2400e43
  4065ae:	0a 0e                	or     (%esi),%cl
  4065b0:	14 43                	adc    $0x43,%al
  4065b2:	c3                   	ret    
  4065b3:	0e                   	push   %cs
  4065b4:	10 41 c6             	adc    %al,-0x3a(%ecx)
  4065b7:	0e                   	push   %cs
  4065b8:	0c 41                	or     $0x41,%al
  4065ba:	c7                   	(bad)  
  4065bb:	0e                   	push   %cs
  4065bc:	08 41 c5             	or     %al,-0x3b(%ecx)
  4065bf:	0e                   	push   %cs
  4065c0:	04 45                	add    $0x45,%al
  4065c2:	0b 00                	or     (%eax),%eax
  4065c4:	3c 00                	cmp    $0x0,%al
  4065c6:	00 00                	add    %al,(%eax)
  4065c8:	9c                   	pushf  
  4065c9:	00 00                	add    %al,(%eax)
  4065cb:	00 24 c1             	add    %ah,(%ecx,%eax,8)
  4065ce:	ff                   	(bad)  
  4065cf:	ff 9d 00 00 00 00    	lcall  *0x0(%ebp)
  4065d5:	41                   	inc    %ecx
  4065d6:	0e                   	push   %cs
  4065d7:	08 87 02 44 0e 0c    	or     %al,0xc0e4402(%edi)
  4065dd:	86 03                	xchg   %al,(%ebx)
  4065df:	41                   	inc    %ecx
  4065e0:	0e                   	push   %cs
  4065e1:	10 83 04 02 6b 0a    	adc    %al,0xa6b0204(%ebx)
  4065e7:	c3                   	ret    
  4065e8:	0e                   	push   %cs
  4065e9:	0c 41                	or     $0x41,%al
  4065eb:	c6                   	(bad)  
  4065ec:	0e                   	push   %cs
  4065ed:	08 41 c7             	or     %al,-0x39(%ecx)
  4065f0:	0e                   	push   %cs
  4065f1:	04 45                	add    $0x45,%al
  4065f3:	0b 59 0a             	or     0xa(%ecx),%ebx
  4065f6:	c3                   	ret    
  4065f7:	0e                   	push   %cs
  4065f8:	0c 46                	or     $0x46,%al
  4065fa:	c6                   	(bad)  
  4065fb:	0e                   	push   %cs
  4065fc:	08 41 c7             	or     %al,-0x39(%ecx)
  4065ff:	0e                   	push   %cs
  406600:	04 41                	add    $0x41,%al
  406602:	0b 00                	or     (%eax),%eax
  406604:	44                   	inc    %esp
  406605:	00 00                	add    %al,(%eax)
  406607:	00 dc                	add    %bl,%ah
  406609:	00 00                	add    %al,(%eax)
  40660b:	00 84 c1 ff ff 5c 00 	add    %al,0x5cffff(%ecx,%eax,8)
  406612:	00 00                	add    %al,(%eax)
  406614:	00 41 0e             	add    %al,0xe(%ecx)
  406617:	08 87 02 41 0e 0c    	or     %al,0xc0e4102(%edi)
  40661d:	86 03                	xchg   %al,(%ebx)
  40661f:	43                   	inc    %ebx
  406620:	0e                   	push   %cs
  406621:	10 83 04 45 0e 20    	adc    %al,0x200e4504(%ebx)
  406627:	02 40 0a             	add    0xa(%eax),%al
  40662a:	0e                   	push   %cs
  40662b:	10 43 c3             	adc    %al,-0x3d(%ebx)
  40662e:	0e                   	push   %cs
  40662f:	0c 41                	or     $0x41,%al
  406631:	c6                   	(bad)  
  406632:	0e                   	push   %cs
  406633:	08 41 c7             	or     %al,-0x39(%ecx)
  406636:	0e                   	push   %cs
  406637:	04 41                	add    $0x41,%al
  406639:	0b 43 0e             	or     0xe(%ebx),%eax
  40663c:	10 46 c3             	adc    %al,-0x3d(%esi)
  40663f:	0e                   	push   %cs
  406640:	0c 41                	or     $0x41,%al
  406642:	c6                   	(bad)  
  406643:	0e                   	push   %cs
  406644:	08 41 c7             	or     %al,-0x39(%ecx)
  406647:	0e                   	push   %cs
  406648:	04 00                	add    $0x0,%al
  40664a:	00 00                	add    %al,(%eax)
  40664c:	28 00                	sub    %al,(%eax)
  40664e:	00 00                	add    %al,(%eax)
  406650:	24 01                	and    $0x1,%al
  406652:	00 00                	add    %al,(%eax)
  406654:	9c                   	pushf  
  406655:	c1 ff ff             	sar    $0xff,%edi
  406658:	49                   	dec    %ecx
  406659:	00 00                	add    %al,(%eax)
  40665b:	00 00                	add    %al,(%eax)
  40665d:	41                   	inc    %ecx
  40665e:	0e                   	push   %cs
  40665f:	08 86 02 43 0e 0c    	or     %al,0xc0e4302(%esi)
  406665:	83 03 45             	addl   $0x45,(%ebx)
  406668:	0e                   	push   %cs
  406669:	20 6f 0a             	and    %ch,0xa(%edi)
  40666c:	0e                   	push   %cs
  40666d:	0c 41                	or     $0x41,%al
  40666f:	c3                   	ret    
  406670:	0e                   	push   %cs
  406671:	08 41 c6             	or     %al,-0x3a(%ecx)
  406674:	0e                   	push   %cs
  406675:	04 46                	add    $0x46,%al
  406677:	0b 28                	or     (%eax),%ebp
  406679:	00 00                	add    %al,(%eax)
  40667b:	00 50 01             	add    %dl,0x1(%eax)
  40667e:	00 00                	add    %al,(%eax)
  406680:	c0 c1 ff             	rol    $0xff,%cl
  406683:	ff 4b 00             	decl   0x0(%ebx)
  406686:	00 00                	add    %al,(%eax)
  406688:	00 41 0e             	add    %al,0xe(%ecx)
  40668b:	08 86 02 43 0e 0c    	or     %al,0xc0e4302(%esi)
  406691:	83 03 43             	addl   $0x43,(%ebx)
  406694:	0e                   	push   %cs
  406695:	20 7a 0a             	and    %bh,0xa(%edx)
  406698:	0e                   	push   %cs
  406699:	0c 41                	or     $0x41,%al
  40669b:	c3                   	ret    
  40669c:	0e                   	push   %cs
  40669d:	08 41 c6             	or     %al,-0x3a(%ecx)
  4066a0:	0e                   	push   %cs
  4066a1:	04 41                	add    $0x41,%al
  4066a3:	0b 3c 00             	or     (%eax,%eax,1),%edi
  4066a6:	00 00                	add    %al,(%eax)
  4066a8:	7c 01                	jl     4066ab <.eh_frame+0x57f>
  4066aa:	00 00                	add    %al,(%eax)
  4066ac:	e4 c1                	in     $0xc1,%al
  4066ae:	ff                   	(bad)  
  4066af:	ff 92 08 00 00 00    	call   *0x8(%edx)
  4066b5:	41                   	inc    %ecx
  4066b6:	0e                   	push   %cs
  4066b7:	08 85 02 42 0d 05    	or     %al,0x50d4202(%ebp)
  4066bd:	46                   	inc    %esi
  4066be:	87 03                	xchg   %eax,(%ebx)
  4066c0:	86 04 83             	xchg   %al,(%ebx,%eax,4)
  4066c3:	05 03 c9 02 0a       	add    $0xa02c903,%eax
  4066c8:	c3                   	ret    
  4066c9:	41                   	inc    %ecx
  4066ca:	c6 41 c7 41          	movb   $0x41,-0x39(%ecx)
  4066ce:	c5 0c 04             	lds    (%esp,%eax,1),%ecx
  4066d1:	04 4b                	add    $0x4b,%al
  4066d3:	0b 03                	or     (%ebx),%eax
  4066d5:	22 01                	and    (%ecx),%al
  4066d7:	0a c3                	or     %bl,%al
  4066d9:	41                   	inc    %ecx
  4066da:	c6 41 c7 41          	movb   $0x41,-0x39(%ecx)
  4066de:	c5 0c 04             	lds    (%esp,%eax,1),%ecx
  4066e1:	04 4b                	add    $0x4b,%al
  4066e3:	0b 2c 00             	or     (%eax,%eax,1),%ebp
  4066e6:	00 00                	add    %al,(%eax)
  4066e8:	bc 01 00 00 44       	mov    $0x44000001,%esp
  4066ed:	ca ff ff             	lret   $0xffff
  4066f0:	f5                   	cmc    
  4066f1:	00 00                	add    %al,(%eax)
  4066f3:	00 00                	add    %al,(%eax)
  4066f5:	41                   	inc    %ecx
  4066f6:	0e                   	push   %cs
  4066f7:	08 85 02 42 0d 05    	or     %al,0x50d4202(%ebp)
  4066fd:	46                   	inc    %esi
  4066fe:	87 03                	xchg   %eax,(%ebx)
  406700:	86 04 83             	xchg   %al,(%ebx,%eax,4)
  406703:	05 02 46 0a c3       	add    $0xc30a4602,%eax
  406708:	41                   	inc    %ecx
  406709:	c6 41 c7 41          	movb   $0x41,-0x39(%ecx)
  40670d:	c5 0c 04             	lds    (%esp,%eax,1),%ecx
  406710:	04 46                	add    $0x46,%al
  406712:	0b 00                	or     (%eax),%eax
  406714:	40                   	inc    %eax
  406715:	00 00                	add    %al,(%eax)
  406717:	00 ec                	add    %ch,%ah
  406719:	01 00                	add    %eax,(%eax)
  40671b:	00 14 cb             	add    %dl,(%ebx,%ecx,8)
  40671e:	ff                   	(bad)  
  40671f:	ff 57 00             	call   *0x0(%edi)
  406722:	00 00                	add    %al,(%eax)
  406724:	00 41 0e             	add    %al,0xe(%ecx)
  406727:	08 87 02 41 0e 0c    	or     %al,0xc0e4102(%edi)
  40672d:	86 03                	xchg   %al,(%ebx)
  40672f:	41                   	inc    %ecx
  406730:	0e                   	push   %cs
  406731:	10 83 04 43 0e 20    	adc    %al,0x200e4304(%ebx)
  406737:	4f                   	dec    %edi
  406738:	0a 0e                	or     (%esi),%cl
  40673a:	10 41 c3             	adc    %al,-0x3d(%ecx)
  40673d:	0e                   	push   %cs
  40673e:	0c 41                	or     $0x41,%al
  406740:	c6                   	(bad)  
  406741:	0e                   	push   %cs
  406742:	08 41 c7             	or     %al,-0x39(%ecx)
  406745:	0e                   	push   %cs
  406746:	04 48                	add    $0x48,%al
  406748:	0b 6f 0e             	or     0xe(%edi),%ebp
  40674b:	10 41 c3             	adc    %al,-0x3d(%ecx)
  40674e:	0e                   	push   %cs
  40674f:	0c 41                	or     $0x41,%al
  406751:	c6                   	(bad)  
  406752:	0e                   	push   %cs
  406753:	08 41 c7             	or     %al,-0x39(%ecx)
  406756:	0e                   	push   %cs
  406757:	04 14                	add    $0x14,%al
  406759:	00 00                	add    %al,(%eax)
  40675b:	00 00                	add    %al,(%eax)
  40675d:	00 00                	add    %al,(%eax)
  40675f:	00 01                	add    %al,(%ecx)
  406761:	7a 52                	jp     4067b5 <.eh_frame+0x689>
  406763:	00 01                	add    %al,(%ecx)
  406765:	7c 08                	jl     40676f <.eh_frame+0x643>
  406767:	01 1b                	add    %ebx,(%ebx)
  406769:	0c 04                	or     $0x4,%al
  40676b:	04 88                	add    $0x88,%al
  40676d:	01 00                	add    %eax,(%eax)
  40676f:	00 2c 00             	add    %ch,(%eax,%eax,1)
  406772:	00 00                	add    %al,(%eax)
  406774:	1c 00                	sbb    $0x0,%al
  406776:	00 00                	add    %al,(%eax)
  406778:	18 cb                	sbb    %cl,%bl
  40677a:	ff                   	(bad)  
  40677b:	ff 12                	call   *(%edx)
  40677d:	04 00                	add    $0x0,%al
  40677f:	00 00                	add    %al,(%eax)
  406781:	41                   	inc    %ecx
  406782:	0e                   	push   %cs
  406783:	08 85 02 42 0d 05    	or     %al,0x50d4202(%ebp)
  406789:	46                   	inc    %esi
  40678a:	87 03                	xchg   %eax,(%ebx)
  40678c:	86 04 83             	xchg   %al,(%ebx,%eax,4)
  40678f:	05 02 b4 0a c3       	add    $0xc30ab402,%eax
  406794:	41                   	inc    %ecx
  406795:	c6 41 c7 41          	movb   $0x41,-0x39(%ecx)
  406799:	c5 0c 04             	lds    (%esp,%eax,1),%ecx
  40679c:	04 48                	add    $0x48,%al
  40679e:	0b 00                	or     (%eax),%eax
  4067a0:	14 00                	adc    $0x0,%al
  4067a2:	00 00                	add    %al,(%eax)
  4067a4:	00 00                	add    %al,(%eax)
  4067a6:	00 00                	add    %al,(%eax)
  4067a8:	01 7a 52             	add    %edi,0x52(%edx)
  4067ab:	00 01                	add    %al,(%ecx)
  4067ad:	7c 08                	jl     4067b7 <.eh_frame+0x68b>
  4067af:	01 1b                	add    %ebx,(%ebx)
  4067b1:	0c 04                	or     $0x4,%al
  4067b3:	04 88                	add    $0x88,%al
  4067b5:	01 00                	add    %eax,(%eax)
  4067b7:	00 40 00             	add    %al,0x0(%eax)
  4067ba:	00 00                	add    %al,(%eax)
  4067bc:	1c 00                	sbb    $0x0,%al
  4067be:	00 00                	add    %al,(%eax)
  4067c0:	f0 ce                	lock into 
  4067c2:	ff                   	(bad)  
  4067c3:	ff                   	(bad)  
  4067c4:	e9 00 00 00 00       	jmp    4067c9 <.eh_frame+0x69d>
  4067c9:	41                   	inc    %ecx
  4067ca:	0e                   	push   %cs
  4067cb:	08 86 02 41 0e 0c    	or     %al,0xc0e4102(%esi)
  4067d1:	83 03 48             	addl   $0x48,(%ebx)
  4067d4:	0e                   	push   %cs
  4067d5:	e0 02                	loopne 4067d9 <.eh_frame+0x6ad>
  4067d7:	50                   	push   %eax
  4067d8:	0e                   	push   %cs
  4067d9:	d8 02                	fadds  (%edx)
  4067db:	43                   	inc    %ebx
  4067dc:	0e                   	push   %cs
  4067dd:	e0 02                	loopne 4067e1 <.eh_frame+0x6b5>
  4067df:	02 57 0a             	add    0xa(%edi),%dl
  4067e2:	0e                   	push   %cs
  4067e3:	0c 43                	or     $0x43,%al
  4067e5:	c3                   	ret    
  4067e6:	0e                   	push   %cs
  4067e7:	08 41 c6             	or     %al,-0x3a(%ecx)
  4067ea:	0e                   	push   %cs
  4067eb:	04 48                	add    $0x48,%al
  4067ed:	0b 4d 0a             	or     0xa(%ebp),%ecx
  4067f0:	0e                   	push   %cs
  4067f1:	0c 43                	or     $0x43,%al
  4067f3:	c3                   	ret    
  4067f4:	0e                   	push   %cs
  4067f5:	08 41 c6             	or     %al,-0x3a(%ecx)
  4067f8:	0e                   	push   %cs
  4067f9:	04 47                	add    $0x47,%al
  4067fb:	0b 4c 00 00          	or     0x0(%eax,%eax,1),%ecx
  4067ff:	00 60 00             	add    %ah,0x0(%eax)
  406802:	00 00                	add    %al,(%eax)
  406804:	9c                   	pushf  
  406805:	cf                   	iret   
  406806:	ff                   	(bad)  
  406807:	ff                   	(bad)  
  406808:	b8 00 00 00 00       	mov    $0x0,%eax
  40680d:	41                   	inc    %ecx
  40680e:	0e                   	push   %cs
  40680f:	08 86 02 41 0e 0c    	or     %al,0xc0e4102(%esi)
  406815:	83 03 48             	addl   $0x48,(%ebx)
  406818:	0e                   	push   %cs
  406819:	e0 02                	loopne 40681d <.eh_frame+0x6f1>
  40681b:	50                   	push   %eax
  40681c:	0e                   	push   %cs
  40681d:	d8 02                	fadds  (%edx)
  40681f:	43                   	inc    %ebx
  406820:	0e                   	push   %cs
  406821:	e0 02                	loopne 406825 <.eh_frame+0x6f9>
  406823:	02 57 0a             	add    0xa(%edi),%dl
  406826:	0e                   	push   %cs
  406827:	0c 43                	or     $0x43,%al
  406829:	c3                   	ret    
  40682a:	0e                   	push   %cs
  40682b:	08 41 c6             	or     %al,-0x3a(%ecx)
  40682e:	0e                   	push   %cs
  40682f:	04 48                	add    $0x48,%al
  406831:	0b 4d 0a             	or     0xa(%ebp),%ecx
  406834:	0e                   	push   %cs
  406835:	0c 43                	or     $0x43,%al
  406837:	c3                   	ret    
  406838:	0e                   	push   %cs
  406839:	08 41 c6             	or     %al,-0x3a(%ecx)
  40683c:	0e                   	push   %cs
  40683d:	04 47                	add    $0x47,%al
  40683f:	0b 5b 0e             	or     0xe(%ebx),%ebx
  406842:	0c 43                	or     $0x43,%al
  406844:	c3                   	ret    
  406845:	0e                   	push   %cs
  406846:	08 41 c6             	or     %al,-0x3a(%ecx)
  406849:	0e                   	push   %cs
  40684a:	04 00                	add    $0x0,%al
  40684c:	54                   	push   %esp
  40684d:	00 00                	add    %al,(%eax)
  40684f:	00 b0 00 00 00 0c    	add    %dh,0xc000000(%eax)
  406855:	d0 ff                	sar    %bh
  406857:	ff                   	(bad)  
  406858:	ff 01                	incl   (%ecx)
  40685a:	00 00                	add    %al,(%eax)
  40685c:	00 41 0e             	add    %al,0xe(%ecx)
  40685f:	08 85 02 41 0e 0c    	or     %al,0xc0e4102(%ebp)
  406865:	87 03                	xchg   %eax,(%ebx)
  406867:	41                   	inc    %ecx
  406868:	0e                   	push   %cs
  406869:	10 86 04 41 0e 14    	adc    %al,0x140e4104(%esi)
  40686f:	83 05 46 0e c0 02 03 	addl   $0x3,0x2c00e46
  406876:	53                   	push   %ebx
  406877:	01 0a                	add    %ecx,(%edx)
  406879:	0e                   	push   %cs
  40687a:	14 43                	adc    $0x43,%al
  40687c:	c3                   	ret    
  40687d:	0e                   	push   %cs
  40687e:	10 41 c6             	adc    %al,-0x3a(%ecx)
  406881:	0e                   	push   %cs
  406882:	0c 41                	or     $0x41,%al
  406884:	c7                   	(bad)  
  406885:	0e                   	push   %cs
  406886:	08 41 c5             	or     %al,-0x3b(%ecx)
  406889:	0e                   	push   %cs
  40688a:	04 45                	add    $0x45,%al
  40688c:	0b 02                	or     (%edx),%eax
  40688e:	53                   	push   %ebx
  40688f:	0a 0e                	or     (%esi),%cl
  406891:	14 43                	adc    $0x43,%al
  406893:	c3                   	ret    
  406894:	0e                   	push   %cs
  406895:	10 41 c6             	adc    %al,-0x3a(%ecx)
  406898:	0e                   	push   %cs
  406899:	0c 41                	or     $0x41,%al
  40689b:	c7                   	(bad)  
  40689c:	0e                   	push   %cs
  40689d:	08 41 c5             	or     %al,-0x3b(%ecx)
  4068a0:	0e                   	push   %cs
  4068a1:	04 47                	add    $0x47,%al
  4068a3:	0b 20                	or     (%eax),%esp
  4068a5:	00 00                	add    %al,(%eax)
  4068a7:	00 08                	add    %cl,(%eax)
  4068a9:	01 00                	add    %eax,(%eax)
  4068ab:	00 b4 d1 ff ff 4f 00 	add    %dh,0x4fffff(%ecx,%edx,8)
  4068b2:	00 00                	add    %al,(%eax)
  4068b4:	00 41 0e             	add    %al,0xe(%ecx)
  4068b7:	08 83 02 43 0e 10    	or     %al,0x100e4302(%ebx)
  4068bd:	76 0a                	jbe    4068c9 <.eh_frame+0x79d>
  4068bf:	0e                   	push   %cs
  4068c0:	08 43 c3             	or     %al,-0x3d(%ebx)
  4068c3:	0e                   	push   %cs
  4068c4:	04 43                	add    $0x43,%al
  4068c6:	0b 00                	or     (%eax),%eax
  4068c8:	28 00                	sub    %al,(%eax)
  4068ca:	00 00                	add    %al,(%eax)
  4068cc:	2c 01                	sub    $0x1,%al
  4068ce:	00 00                	add    %al,(%eax)
  4068d0:	e0 d1                	loopne 4068a3 <.eh_frame+0x777>
  4068d2:	ff                   	(bad)  
  4068d3:	ff 42 00             	incl   0x0(%edx)
  4068d6:	00 00                	add    %al,(%eax)
  4068d8:	00 41 0e             	add    %al,0xe(%ecx)
  4068db:	08 83 02 43 0e 20    	or     %al,0x200e4302(%ebx)
  4068e1:	56                   	push   %esi
  4068e2:	0e                   	push   %cs
  4068e3:	1c 43                	sbb    $0x43,%al
  4068e5:	0e                   	push   %cs
  4068e6:	20 51 0a             	and    %dl,0xa(%ecx)
  4068e9:	0e                   	push   %cs
  4068ea:	08 41 c3             	or     %al,-0x3d(%ecx)
  4068ed:	0e                   	push   %cs
  4068ee:	04 41                	add    $0x41,%al
  4068f0:	0b 00                	or     (%eax),%eax
  4068f2:	00 00                	add    %al,(%eax)
  4068f4:	2c 00                	sub    $0x0,%al
  4068f6:	00 00                	add    %al,(%eax)
  4068f8:	58                   	pop    %eax
  4068f9:	01 00                	add    %eax,(%eax)
  4068fb:	00 04 d2             	add    %al,(%edx,%edx,8)
  4068fe:	ff                   	(bad)  
  4068ff:	ff 5f 00             	lcall  *0x0(%edi)
  406902:	00 00                	add    %al,(%eax)
  406904:	00 41 0e             	add    %al,0xe(%ecx)
  406907:	08 83 02 43 0e 20    	or     %al,0x200e4302(%ebx)
  40690d:	56                   	push   %esi
  40690e:	0e                   	push   %cs
  40690f:	1c 43                	sbb    $0x43,%al
  406911:	0e                   	push   %cs
  406912:	20 52 0a             	and    %dl,0xa(%edx)
  406915:	0e                   	push   %cs
  406916:	08 41 c3             	or     %al,-0x3d(%ecx)
  406919:	0e                   	push   %cs
  40691a:	04 48                	add    $0x48,%al
  40691c:	0b 65 0e             	or     0xe(%ebp),%esp
  40691f:	08 41 c3             	or     %al,-0x3d(%ecx)
  406922:	0e                   	push   %cs
  406923:	04 18                	add    $0x18,%al
  406925:	00 00                	add    %al,(%eax)
  406927:	00 88 01 00 00 34    	add    %cl,0x34000001(%eax)
  40692d:	d2 ff                	sar    %cl,%bh
  40692f:	ff 27                	jmp    *(%edi)
  406931:	00 00                	add    %al,(%eax)
  406933:	00 00                	add    %al,(%eax)
  406935:	43                   	inc    %ebx
  406936:	0e                   	push   %cs
  406937:	10 51 0a             	adc    %dl,0xa(%ecx)
  40693a:	0e                   	push   %cs
  40693b:	04 41                	add    $0x41,%al
  40693d:	0b 00                	or     (%eax),%eax
  40693f:	00 34 00             	add    %dh,(%eax,%eax,1)
  406942:	00 00                	add    %al,(%eax)
  406944:	a4                   	movsb  %ds:(%esi),%es:(%edi)
  406945:	01 00                	add    %eax,(%eax)
  406947:	00 48 d2             	add    %cl,-0x2e(%eax)
  40694a:	ff                   	(bad)  
  40694b:	ff 71 00             	pushl  0x0(%ecx)
  40694e:	00 00                	add    %al,(%eax)
  406950:	00 41 0e             	add    %al,0xe(%ecx)
  406953:	08 86 02 41 0e 0c    	or     %al,0xc0e4102(%esi)
  406959:	83 03 43             	addl   $0x43,(%ebx)
  40695c:	0e                   	push   %cs
  40695d:	20 02                	and    %al,(%edx)
  40695f:	52                   	push   %edx
  406960:	0a 0e                	or     (%esi),%cl
  406962:	0c 41                	or     $0x41,%al
  406964:	c3                   	ret    
  406965:	0e                   	push   %cs
  406966:	08 41 c6             	or     %al,-0x3a(%ecx)
  406969:	0e                   	push   %cs
  40696a:	04 47                	add    $0x47,%al
  40696c:	0b 4e 0e             	or     0xe(%esi),%ecx
  40696f:	0c 41                	or     $0x41,%al
  406971:	c3                   	ret    
  406972:	0e                   	push   %cs
  406973:	08 41 c6             	or     %al,-0x3a(%ecx)
  406976:	0e                   	push   %cs
  406977:	04 14                	add    $0x14,%al
  406979:	00 00                	add    %al,(%eax)
  40697b:	00 00                	add    %al,(%eax)
  40697d:	00 00                	add    %al,(%eax)
  40697f:	00 01                	add    %al,(%ecx)
  406981:	7a 52                	jp     4069d5 <.eh_frame+0x8a9>
  406983:	00 01                	add    %al,(%ecx)
  406985:	7c 08                	jl     40698f <.eh_frame+0x863>
  406987:	01 1b                	add    %ebx,(%ebx)
  406989:	0c 04                	or     $0x4,%al
  40698b:	04 88                	add    $0x88,%al
  40698d:	01 00                	add    %eax,(%eax)
  40698f:	00 3c 00             	add    %bh,(%eax,%eax,1)
  406992:	00 00                	add    %al,(%eax)
  406994:	1c 00                	sbb    $0x0,%al
  406996:	00 00                	add    %al,(%eax)
  406998:	78 d2                	js     40696c <.eh_frame+0x840>
  40699a:	ff                   	(bad)  
  40699b:	ff b3 00 00 00 00    	pushl  0x0(%ebx)
  4069a1:	41                   	inc    %ecx
  4069a2:	0e                   	push   %cs
  4069a3:	08 85 02 41 0e 0c    	or     %al,0xc0e4102(%ebp)
  4069a9:	87 03                	xchg   %eax,(%ebx)
  4069ab:	41                   	inc    %ecx
  4069ac:	0e                   	push   %cs
  4069ad:	10 86 04 41 0e 14    	adc    %al,0x140e4104(%esi)
  4069b3:	83 05 43 0e 1c 02 92 	addl   $0xffffff92,0x21c0e43
  4069ba:	0a 0e                	or     (%esi),%cl
  4069bc:	14 41                	adc    $0x41,%al
  4069be:	c3                   	ret    
  4069bf:	0e                   	push   %cs
  4069c0:	10 41 c6             	adc    %al,-0x3a(%ecx)
  4069c3:	0e                   	push   %cs
  4069c4:	0c 41                	or     $0x41,%al
  4069c6:	c7                   	(bad)  
  4069c7:	0e                   	push   %cs
  4069c8:	08 41 c5             	or     %al,-0x3b(%ecx)
  4069cb:	0e                   	push   %cs
  4069cc:	04 43                	add    $0x43,%al
  4069ce:	0b 00                	or     (%eax),%eax
  4069d0:	14 00                	adc    $0x0,%al
  4069d2:	00 00                	add    %al,(%eax)
  4069d4:	00 00                	add    %al,(%eax)
  4069d6:	00 00                	add    %al,(%eax)
  4069d8:	01 7a 52             	add    %edi,0x52(%edx)
  4069db:	00 01                	add    %al,(%ecx)
  4069dd:	7c 08                	jl     4069e7 <.eh_frame+0x8bb>
  4069df:	01 1b                	add    %ebx,(%ebx)
  4069e1:	0c 04                	or     $0x4,%al
  4069e3:	04 88                	add    $0x88,%al
  4069e5:	01 00                	add    %eax,(%eax)
  4069e7:	00 54 00 00          	add    %dl,0x0(%eax,%eax,1)
  4069eb:	00 1c 00             	add    %bl,(%eax,%eax,1)
  4069ee:	00 00                	add    %al,(%eax)
  4069f0:	e0 d2                	loopne 4069c4 <.eh_frame+0x898>
  4069f2:	ff                   	(bad)  
  4069f3:	ff 77 00             	pushl  0x0(%edi)
  4069f6:	00 00                	add    %al,(%eax)
  4069f8:	00 41 0e             	add    %al,0xe(%ecx)
  4069fb:	08 87 02 41 0e 0c    	or     %al,0xc0e4102(%edi)
  406a01:	86 03                	xchg   %al,(%ebx)
  406a03:	41                   	inc    %ecx
  406a04:	0e                   	push   %cs
  406a05:	10 83 04 43 0e 30    	adc    %al,0x300e4304(%ebx)
  406a0b:	78 0a                	js     406a17 <.eh_frame+0x8eb>
  406a0d:	0e                   	push   %cs
  406a0e:	10 43 c3             	adc    %al,-0x3d(%ebx)
  406a11:	0e                   	push   %cs
  406a12:	0c 41                	or     $0x41,%al
  406a14:	c6                   	(bad)  
  406a15:	0e                   	push   %cs
  406a16:	08 41 c7             	or     %al,-0x39(%ecx)
  406a19:	0e                   	push   %cs
  406a1a:	04 45                	add    $0x45,%al
  406a1c:	0b 54 0a 0e          	or     0xe(%edx,%ecx,1),%edx
  406a20:	10 41 c3             	adc    %al,-0x3d(%ecx)
  406a23:	0e                   	push   %cs
  406a24:	0c 41                	or     $0x41,%al
  406a26:	c6                   	(bad)  
  406a27:	0e                   	push   %cs
  406a28:	08 41 c7             	or     %al,-0x39(%ecx)
  406a2b:	0e                   	push   %cs
  406a2c:	04 41                	add    $0x41,%al
  406a2e:	0b 53 0e             	or     0xe(%ebx),%edx
  406a31:	10 41 c3             	adc    %al,-0x3d(%ecx)
  406a34:	0e                   	push   %cs
  406a35:	0c 41                	or     $0x41,%al
  406a37:	c6                   	(bad)  
  406a38:	0e                   	push   %cs
  406a39:	08 41 c7             	or     %al,-0x39(%ecx)
  406a3c:	0e                   	push   %cs
  406a3d:	04 00                	add    $0x0,%al
  406a3f:	00 14 00             	add    %dl,(%eax,%eax,1)
  406a42:	00 00                	add    %al,(%eax)
  406a44:	00 00                	add    %al,(%eax)
  406a46:	00 00                	add    %al,(%eax)
  406a48:	01 7a 52             	add    %edi,0x52(%edx)
  406a4b:	00 01                	add    %al,(%ecx)
  406a4d:	7c 08                	jl     406a57 <.eh_frame+0x92b>
  406a4f:	01 1b                	add    %ebx,(%ebx)
  406a51:	0c 04                	or     $0x4,%al
  406a53:	04 88                	add    $0x88,%al
  406a55:	01 00                	add    %eax,(%eax)
  406a57:	00 50 00             	add    %dl,0x0(%eax)
  406a5a:	00 00                	add    %al,(%eax)
  406a5c:	1c 00                	sbb    $0x0,%al
  406a5e:	00 00                	add    %al,(%eax)
  406a60:	f0 d2 ff             	lock sar %cl,%bh
  406a63:	ff                   	(bad)  
  406a64:	de 00                	fiadds (%eax)
  406a66:	00 00                	add    %al,(%eax)
  406a68:	00 41 0e             	add    %al,0xe(%ecx)
  406a6b:	08 85 02 41 0e 0c    	or     %al,0xc0e4102(%ebp)
  406a71:	87 03                	xchg   %eax,(%ebx)
  406a73:	41                   	inc    %ecx
  406a74:	0e                   	push   %cs
  406a75:	10 86 04 41 0e 14    	adc    %al,0x140e4104(%esi)
  406a7b:	83 05 43 0e 30 02 a5 	addl   $0xffffffa5,0x2300e43
  406a82:	0a 0e                	or     (%esi),%cl
  406a84:	14 43                	adc    $0x43,%al
  406a86:	c3                   	ret    
  406a87:	0e                   	push   %cs
  406a88:	10 41 c6             	adc    %al,-0x3a(%ecx)
  406a8b:	0e                   	push   %cs
  406a8c:	0c 41                	or     $0x41,%al
  406a8e:	c7                   	(bad)  
  406a8f:	0e                   	push   %cs
  406a90:	08 41 c5             	or     %al,-0x3b(%ecx)
  406a93:	0e                   	push   %cs
  406a94:	04 46                	add    $0x46,%al
  406a96:	0b 5f 0e             	or     0xe(%edi),%ebx
  406a99:	14 41                	adc    $0x41,%al
  406a9b:	c3                   	ret    
  406a9c:	0e                   	push   %cs
  406a9d:	10 41 c6             	adc    %al,-0x3a(%ecx)
  406aa0:	0e                   	push   %cs
  406aa1:	0c 43                	or     $0x43,%al
  406aa3:	c7                   	(bad)  
  406aa4:	0e                   	push   %cs
  406aa5:	08 41 c5             	or     %al,-0x3b(%ecx)
  406aa8:	0e                   	push   %cs
  406aa9:	04 00                	add    $0x0,%al
	...

00406aac <___FRAME_END__>:
  406aac:	00 00                	add    %al,(%eax)
  406aae:	00 00                	add    %al,(%eax)
  406ab0:	14 00                	adc    $0x0,%al
  406ab2:	00 00                	add    %al,(%eax)
  406ab4:	00 00                	add    %al,(%eax)
  406ab6:	00 00                	add    %al,(%eax)
  406ab8:	01 7a 52             	add    %edi,0x52(%edx)
  406abb:	00 01                	add    %al,(%ecx)
  406abd:	7c 08                	jl     406ac7 <___FRAME_END__+0x1b>
  406abf:	01 1b                	add    %ebx,(%ebx)
  406ac1:	0c 04                	or     $0x4,%al
  406ac3:	04 88                	add    $0x88,%al
  406ac5:	01 00                	add    %eax,(%eax)
  406ac7:	00 10                	add    %dl,(%eax)
  406ac9:	00 00                	add    %al,(%eax)
  406acb:	00 1c 00             	add    %bl,(%eax,%eax,1)
  406ace:	00 00                	add    %al,(%eax)
  406ad0:	00 d5                	add    %dl,%ch
  406ad2:	ff                   	(bad)  
  406ad3:	ff 05 00 00 00 00    	incl   0x0
  406ad9:	00 00                	add    %al,(%eax)
	...

Disassembly of section .bss:

00407000 <__argv>:
  407000:	00 00                	add    %al,(%eax)
	...

00407004 <__argc>:
  407004:	00 00                	add    %al,(%eax)
	...

00407008 <_obj>:
	...

00407020 <__CRT_fmode>:
  407020:	00 00                	add    %al,(%eax)
	...

00407024 <___cpu_features>:
  407024:	00 00                	add    %al,(%eax)
	...

00407028 <.bss>:
  407028:	00 00                	add    %al,(%eax)
	...

0040702c <_mingw_initltssuo_force>:
  40702c:	00 00                	add    %al,(%eax)
	...

00407030 <_mingw_initltsdyn_force>:
  407030:	00 00                	add    %al,(%eax)
	...

00407034 <_mingw_initltsdrot_force>:
  407034:	00 00                	add    %al,(%eax)
	...

00407038 <__tls_index>:
  407038:	00 00                	add    %al,(%eax)
	...

0040703c <.bss>:
	...

0040705c <.bss>:
	...

00407064 <__CRT_MT>:
  407064:	00 00                	add    %al,(%eax)
	...

00407068 <.bss>:
  407068:	00 00                	add    %al,(%eax)
	...

0040706c <___mingw_memalign_lwm>:
  40706c:	00 00                	add    %al,(%eax)
	...

00407070 <_hmod_libgcc>:
  407070:	00 00                	add    %al,(%eax)
	...

Disassembly of section .idata:

00408000 <__head_libkernel32_a>:
  408000:	50                   	push   %eax
  408001:	80 00 00             	addb   $0x0,(%eax)
	...
  40800c:	6c                   	insb   (%dx),%es:(%edi)
  40800d:	85 00                	test   %eax,(%eax)
  40800f:	00 38                	add    %bh,(%eax)
  408011:	81 00 00       	addl   $0x80a000,(%eax)

00408014 <__head_libmoldname_a>:
  408014:	a0 80 00 00 00       	mov    0x80,%al
  408019:	00 00                	add    %al,(%eax)
  40801b:	00 00                	add    %al,(%eax)
  40801d:	00 00                	add    %al,(%eax)
  40801f:	00 84 85 00 00 88 81 	add    %al,-0x7e780000(%ebp,%eax,4)
	...

00408028 <__head_libmsvcrt_a>:
  408028:	ac                   	lods   %ds:(%esi),%al
  408029:	80 00 00             	addb   $0x0,(%eax)
	...
  408034:	18 86 00 00 94 81    	sbb    %al,-0x7e6c0000(%esi)
	...

00408050 <.idata$4>:
  408050:	20 82 00 00 38 82    	and    %al,-0x7dc80000(%edx)
  408056:	00 00                	add    %al,(%eax)
  408058:	50                   	push   %eax
  408059:	82 00 00             	addb   $0x0,(%eax)
  40805c:	5e                   	pop    %esi
  40805d:	82 00 00             	addb   $0x0,(%eax)
  408060:	6a 82                	push   $0xffffff82
  408062:	00 00                	add    %al,(%eax)
  408064:	7c 82                	jl     407fe8 <__bss_end__+0xf74>
  408066:	00 00                	add    %al,(%eax)
  408068:	8c 82 00 00 9a 82    	mov    %es,-0x7d660000(%edx)
  40806e:	00 00                	add    %al,(%eax)
  408070:	ac                   	lods   %ds:(%esi),%al
  408071:	82 00 00             	addb   $0x0,(%eax)
  408074:	bc 82 00 00 d2       	mov    $0xd2000082,%esp
  408079:	82 00 00             	addb   $0x0,(%eax)
  40807c:	e6 82                	out    %al,$0x82
  40807e:	00 00                	add    %al,(%eax)
  408080:	f8                   	clc    
  408081:	82 00 00             	addb   $0x0,(%eax)
  408084:	14 83                	adc    $0x83,%al
  408086:	00 00                	add    %al,(%eax)
  408088:	2c 83                	sub    $0x83,%al
  40808a:	00 00                	add    %al,(%eax)
  40808c:	3c 83                	cmp    $0x83,%al
  40808e:	00 00                	add    %al,(%eax)
  408090:	5a                   	pop    %edx
  408091:	83 00 00             	addl   $0x0,(%eax)
  408094:	68 83 00 00 7a       	push   $0x7a000083
  408099:	83 00 00             	addl   $0x0,(%eax)
  40809c:	00 00                	add    %al,(%eax)
	...

004080a0 <.idata$4>:
  4080a0:	8a 83 00 00 94 83    	mov    -0x7c6c0000(%ebx),%al
  4080a6:	00 00                	add    %al,(%eax)
  4080a8:	00 00                	add    %al,(%eax)
	...

004080ac <.idata$4>:
  4080ac:	a0 83 00 00 b0       	mov    0xb0000083,%al
  4080b1:	83 00 00             	addl   $0x0,(%eax)
  4080b4:	c0 83 00 00 d0 83 00 	rolb   $0x0,-0x7c300000(%ebx)
  4080bb:	00 de                	add    %bl,%dh
  4080bd:	83 00 00             	addl   $0x0,(%eax)
  4080c0:	ec                   	in     (%dx),%al
  4080c1:	83 00 00             	addl   $0x0,(%eax)
  4080c4:	fe 83 00 00 08 84    	incb   -0x7bf80000(%ebx)
  4080ca:	00 00                	add    %al,(%eax)
  4080cc:	12 84 00 00 1e 84 00 	adc    0x841e00(%eax,%eax,1),%al
  4080d3:	00 2a                	add    %ch,(%edx)
  4080d5:	84 00                	test   %al,(%eax)
  4080d7:	00 32                	add    %dh,(%edx)
  4080d9:	84 00                	test   %al,(%eax)
  4080db:	00 3e                	add    %bh,(%esi)
  4080dd:	84 00                	test   %al,(%eax)
  4080df:	00 48 84             	add    %cl,-0x7c(%eax)
  4080e2:	00 00                	add    %al,(%eax)
  4080e4:	52                   	push   %edx
  4080e5:	84 00                	test   %al,(%eax)
  4080e7:	00 5c 84 00          	add    %bl,0x0(%esp,%eax,4)
  4080eb:	00 68 84             	add    %ch,-0x7c(%eax)
  4080ee:	00 00                	add    %al,(%eax)
  4080f0:	70 84                	jo     408076 <.idata$4+0x26>
  4080f2:	00 00                	add    %al,(%eax)
  4080f4:	7a 84                	jp     40807a <.idata$4+0x2a>
  4080f6:	00 00                	add    %al,(%eax)
  4080f8:	84 84 00 00 8e 84 00 	test   %al,0x848e00(%eax,%eax,1)
  4080ff:	00 98 84 00 00 a4    	add    %bl,-0x5bffff7c(%eax)
  408105:	84 00                	test   %al,(%eax)
  408107:	00 ae 84 00 00 b8    	add    %ch,-0x47ffff7c(%esi)
  40810d:	84 00                	test   %al,(%eax)
  40810f:	00 c2                	add    %al,%dl
  408111:	84 00                	test   %al,(%eax)
  408113:	00 ce                	add    %cl,%dh
  408115:	84 00                	test   %al,(%eax)
  408117:	00 d8                	add    %bl,%al
  408119:	84 00                	test   %al,(%eax)
  40811b:	00 e2                	add    %ah,%dl
  40811d:	84 00                	test   %al,(%eax)
  40811f:	00 ec                	add    %ch,%ah
  408121:	84 00                	test   %al,(%eax)
  408123:	00 f6                	add    %dh,%dh
  408125:	84 00                	test   %al,(%eax)
  408127:	00 02                	add    %al,(%edx)
  408129:	85 00                	test   %eax,(%eax)
  40812b:	00 0e                	add    %cl,(%esi)
  40812d:	85 00                	test   %eax,(%eax)
  40812f:	00 16                	add    %dl,(%esi)
  408131:	85 00                	test   %eax,(%eax)
  408133:	00 00                	add    %al,(%eax)
  408135:	00 00                	add    %al,(%eax)
	...

00408138 <__IAT_start__>:
  408138:	20 82 00 00      	and    %al,-0x7dc80000(%edx)

0040813c <__imp__EnterCriticalSection@4>:
  40813c:	38 82 00 00      	cmp    %al,-0x7db00000(%edx)

00408140 <__imp__ExitProcess@4>:
  408140:	50                   	push   %eax
  408141:	82 00 00             	addb   $0x0,(%eax)

00408144 <__imp__FindClose@4>:
  408144:	5e                   	pop    %esi
  408145:	82 00 00             	addb   $0x0,(%eax)

00408148 <__imp__FindFirstFileA@8>:
  408148:	6a 82                	push   $0xffffff82
	...

0040814c <__imp__FindNextFileA@8>:
  40814c:	7c 82                	jl     4080d0 <.idata$4+0x24>
	...

00408150 <__imp__FreeLibrary@4>:
  408150:	8c 82 00 00      	mov    %es,-0x7d660000(%edx)

00408154 <__imp__GetCommandLineA@0>:
  408154:	9a 82 00 00    	lcall  $0x82,$0xac000082

00408158 <__imp__GetLastError@0>:
  408158:	ac                   	lods   %ds:(%esi),%al
  408159:	82 00 00             	addb   $0x0,(%eax)

0040815c <__imp__GetModuleFileNameA@12>:
  40815c:	bc 82 00 00        	mov    $0xd2000082,%esp

00408160 <__imp__GetModuleHandleA@4>:
  408160:	d2 82 00 00      	rolb   %cl,-0x7d1a0000(%edx)

00408164 <__imp__GetProcAddress@8>:
  408164:	e6 82                	out    %al,$0x82
	...

00408168 <__imp__InitializeCriticalSection@4>:
  408168:	f8                   	clc    
  408169:	82 00 00             	addb   $0x0,(%eax)

0040816c <__imp__LeaveCriticalSection@4>:
  40816c:	14 83                	adc    $0x83,%al
	...

00408170 <__imp__LoadLibraryA@4>:
  408170:	2c 83                	sub    $0x83,%al
	...

00408174 <__imp__SetUnhandledExceptionFilter@4>:
  408174:	3c 83                	cmp    $0x83,%al
	...

00408178 <__imp__TlsGetValue@4>:
  408178:	5a                   	pop    %edx
  408179:	83 00 00             	addl   $0x0,(%eax)

0040817c <__imp__VirtualProtect@16>:
  40817c:	68 83 00 00        	push   $0x7a000083

00408180 <__imp__VirtualQuery@12>:
  408180:	7a 83                	jp     408105 <.idata$4+0x59>
  408182:	00 00                	add    %al,(%eax)
  408184:	00 00                	add    %al,(%eax)
	...

00408188 <__imp__strdup>:
  408188:	8a 83 00 00      	mov    -0x7c6c0000(%ebx),%al

0040818c <__imp__stricoll>:
  40818c:	94                   	xchg   %eax,%esp
  40818d:	83 00 00             	addl   $0x0,(%eax)
  408190:	00 00                	add    %al,(%eax)
	...

00408194 <__imp____getmainargs>:
  408194:	a0 83 00 00        	mov    0xb0000083,%al

00408198 <__imp____mb_cur_max>:
  408198:	b0 83                	mov    $0x83,%al
	...

0040819c <__imp____p__environ>:
  40819c:	c0 83 00 00    	rolb   $0x0,-0x7c300000(%ebx)

004081a0 <__imp____p__fmode>:
  4081a0:	d0 83 00 00      	rolb   -0x7c220000(%ebx)

004081a4 <__imp____p__pgmptr>:
  4081a4:	de 83 00 00      	fiadds -0x7c140000(%ebx)

004081a8 <__imp____set_app_type>:
  4081a8:	ec                   	in     (%dx),%al
  4081a9:	83 00 00             	addl   $0x0,(%eax)

004081ac <__imp___cexit>:
  4081ac:	fe 83 00 00      	incb   -0x7bf80000(%ebx)

004081b0 <__imp___errno>:
  4081b0:	08 84 00 00    	or     %al,0x841200(%eax,%eax,1)

004081b4 <__imp___fpreset>:
  4081b4:	12 84 00 00    	adc    0x841e00(%eax,%eax,1),%al

004081b8 <__imp___fullpath>:
  4081b8:	1e                   	push   %ds
  4081b9:	84 00                	test   %al,(%eax)
	...

004081bc <__imp___iob>:
  4081bc:	2a 84 00 00    	sub    0x843200(%eax,%eax,1),%al

004081c0 <__imp___isctype>:
  4081c0:	32 84 00 00    	xor    0x843e00(%eax,%eax,1),%al

004081c4 <__imp___msize>:
  4081c4:	3e 84 00             	test   %al,%ds:(%eax)
	...

004081c8 <__imp___onexit>:
  4081c8:	48                   	dec    %eax
  4081c9:	84 00                	test   %al,(%eax)
	...

004081cc <__imp___pctype>:
  4081cc:	52                   	push   %edx
  4081cd:	84 00                	test   %al,(%eax)
	...

004081d0 <__imp___setmode>:
  4081d0:	5c                   	pop    %esp
  4081d1:	84 00                	test   %al,(%eax)
	...

004081d4 <__imp__abort>:
  4081d4:	68 84 00 00        	push   $0x70000084

004081d8 <__imp__atexit>:
  4081d8:	70 84                	jo     40815e <__imp__GetModuleFileNameA@12+0x2>
	...

004081dc <__imp__calloc>:
  4081dc:	7a 84                	jp     408162 <__imp__GetModuleHandleA@4+0x2>
	...

004081e0 <__imp__fwrite>:
  4081e0:	84 84 00 00    	test   %al,0x848e00(%eax,%eax,1)

004081e4 <__imp__malloc>:
  4081e4:	8e 84 00 00    	mov    0x849800(%eax,%eax,1),%es

004081e8 <__imp__mbstowcs>:
  4081e8:	98                   	cwtl   
  4081e9:	84 00                	test   %al,(%eax)
	...

004081ec <__imp__memcpy>:
  4081ec:	a4                   	movsb  %ds:(%esi),%es:(%edi)
  4081ed:	84 00                	test   %al,(%eax)
	...

004081f0 <__imp__memmove>:
  4081f0:	ae                   	scas   %es:(%edi),%al
  4081f1:	84 00                	test   %al,(%eax)
	...

004081f4 <__imp__printf>:
  4081f4:	b8 84 00 00        	mov    $0xc2000084,%eax

004081f8 <__imp__setlocale>:
  4081f8:	c2 84 00             	ret    $0x84
	...

004081fc <__imp__signal>:
  4081fc:	ce                   	into   
  4081fd:	84 00                	test   %al,(%eax)
	...

00408200 <__imp__strcoll>:
  408200:	d8 84 00 00    	fadds  0x84e200(%eax,%eax,1)

00408204 <__imp__strlen>:
  408204:	e2 84                	loop   40818a <__imp__strdup+0x2>
	...

00408208 <__imp__tolower>:
  408208:	ec                   	in     (%dx),%al
  408209:	84 00                	test   %al,(%eax)
	...

0040820c <__imp__vfprintf>:
  40820c:	f6 84 00 00    	testb  $0x0,0x850200(%eax,%eax,1)
  408213:	 

00408210 <__imp__wcstombs>:
  408210:	02 85 00 00      	add    -0x7af20000(%ebp),%al

00408214 <__imp____msvcrt_free>:
  408214:	0e                   	push   %cs
  408215:	85 00                	test   %eax,(%eax)
	...

00408218 <__imp____msvcrt_realloc>:
  408218:	16                   	push   %ss
  408219:	85 00                	test   %eax,(%eax)
  40821b:	00 00                	add    %al,(%eax)
  40821d:	00 00                	add    %al,(%eax)
	...

00408220 <__IAT_end__>:
  408220:	d0 00                	rolb   (%eax)
  408222:	44                   	inc    %esp
  408223:	65 6c                	gs insb (%dx),%es:(%edi)
  408225:	65 74 65             	gs je  40828d <.idata$6+0x1>
  408228:	43                   	inc    %ebx
  408229:	72 69                	jb     408294 <.idata$6+0x8>
  40822b:	74 69                	je     408296 <.idata$6+0xa>
  40822d:	63 61 6c             	arpl   %sp,0x6c(%ecx)
  408230:	53                   	push   %ebx
  408231:	65 63 74 69 6f       	arpl   %si,%gs:0x6f(%ecx,%ebp,2)
  408236:	6e                   	outsb  %ds:(%esi),(%dx)
	...

00408238 <.idata$6>:
  408238:	ed                   	in     (%dx),%eax
  408239:	00 45 6e             	add    %al,0x6e(%ebp)
  40823c:	74 65                	je     4082a3 <.idata$6+0x9>
  40823e:	72 43                	jb     408283 <.idata$6+0x7>
  408240:	72 69                	jb     4082ab <.idata$6+0x11>
  408242:	74 69                	je     4082ad <.idata$6+0x1>
  408244:	63 61 6c             	arpl   %sp,0x6c(%ecx)
  408247:	53                   	push   %ebx
  408248:	65 63 74 69 6f       	arpl   %si,%gs:0x6f(%ecx,%ebp,2)
  40824d:	6e                   	outsb  %ds:(%esi),(%dx)
	...

00408250 <.idata$6>:
  408250:	18 01                	sbb    %al,(%ecx)
  408252:	45                   	inc    %ebp
  408253:	78 69                	js     4082be <.idata$6+0x2>
  408255:	74 50                	je     4082a7 <.idata$6+0xd>
  408257:	72 6f                	jb     4082c8 <.idata$6+0xc>
  408259:	63 65 73             	arpl   %sp,0x73(%ebp)
  40825c:	73 00                	jae    40825e <.idata$6>

0040825e <.idata$6>:
  40825e:	2d 01 46 69 6e       	sub    $0x6e694601,%eax
  408263:	64 43                	fs inc %ebx
  408265:	6c                   	insb   (%dx),%es:(%edi)
  408266:	6f                   	outsl  %ds:(%esi),(%dx)
  408267:	73 65                	jae    4082ce <.idata$6+0x12>
	...

0040826a <.idata$6>:
  40826a:	31 01                	xor    %eax,(%ecx)
  40826c:	46                   	inc    %esi
  40826d:	69 6e 64 46 69 72 73 	imul   $0x73726946,0x64(%esi),%ebp
  408274:	74 46                	je     4082bc <.idata$6>
  408276:	69 6c 65 41 00 00  	imul   $0x1420000,0x41(%ebp,%eiz,2),%ebp
  40827d:	 

0040827c <.idata$6>:
  40827c:	42                   	inc    %edx
  40827d:	01 46 69             	add    %eax,0x69(%esi)
  408280:	6e                   	outsb  %ds:(%esi),(%dx)
  408281:	64 4e                	fs dec %esi
  408283:	65 78 74             	gs js  4082fa <.idata$6+0x2>
  408286:	46                   	inc    %esi
  408287:	69 6c 65 41 00   	imul   $0x46016100,0x41(%ebp,%eiz,2),%ebp
  40828e:	 

0040828c <.idata$6>:
  40828c:	61                   	popa   
  40828d:	01 46 72             	add    %eax,0x72(%esi)
  408290:	65 65 4c             	gs gs dec %esp
  408293:	69 62 72 61 72 79 00 	imul   $0x797261,0x72(%edx),%esp

0040829a <.idata$6>:
  40829a:	85 01                	test   %eax,(%ecx)
  40829c:	47                   	inc    %edi
  40829d:	65 74 43             	gs je  4082e3 <.idata$6+0x11>
  4082a0:	6f                   	outsl  %ds:(%esi),(%dx)
  4082a1:	6d                   	insl   (%dx),%es:(%edi)
  4082a2:	6d                   	insl   (%dx),%es:(%edi)
  4082a3:	61                   	popa   
  4082a4:	6e                   	outsb  %ds:(%esi),(%dx)
  4082a5:	64 4c                	fs dec %esp
  4082a7:	69 6e 65 41 00   	imul   $0x1ff0041,0x65(%esi),%ebp

004082ac <.idata$6>:
  4082ac:	ff 01                	incl   (%ecx)
  4082ae:	47                   	inc    %edi
  4082af:	65 74 4c             	gs je  4082fe <.idata$6+0x6>
  4082b2:	61                   	popa   
  4082b3:	73 74                	jae    408329 <.idata$6+0x15>
  4082b5:	45                   	inc    %ebp
  4082b6:	72 72                	jb     40832a <.idata$6+0x16>
  4082b8:	6f                   	outsl  %ds:(%esi),(%dx)
  4082b9:	72 00                	jb     4082bb <.idata$6+0xf>
	...

004082bc <.idata$6>:
  4082bc:	10 02                	adc    %al,(%edx)
  4082be:	47                   	inc    %edi
  4082bf:	65 74 4d             	gs je  40830f <.idata$6+0x17>
  4082c2:	6f                   	outsl  %ds:(%esi),(%dx)
  4082c3:	64 75 6c             	fs jne 408332 <.idata$6+0x6>
  4082c6:	65 46                	gs inc %esi
  4082c8:	69 6c 65 4e 61 6d 65 	imul   $0x41656d61,0x4e(%ebp,%eiz,2),%ebp
  4082cf:	41 
	...

004082d2 <.idata$6>:
  4082d2:	12 02                	adc    (%edx),%al
  4082d4:	47                   	inc    %edi
  4082d5:	65 74 4d             	gs je  408325 <.idata$6+0x11>
  4082d8:	6f                   	outsl  %ds:(%esi),(%dx)
  4082d9:	64 75 6c             	fs jne 408348 <.idata$6+0xc>
  4082dc:	65 48                	gs dec %eax
  4082de:	61                   	popa   
  4082df:	6e                   	outsb  %ds:(%esi),(%dx)
  4082e0:	64 6c                	fs insb (%dx),%es:(%edi)
  4082e2:	65 41                	gs inc %ecx
	...

004082e6 <.idata$6>:
  4082e6:	42                   	inc    %edx
  4082e7:	02 47 65             	add    0x65(%edi),%al
  4082ea:	74 50                	je     40833c <.idata$6>
  4082ec:	72 6f                	jb     40835d <.idata$6+0x3>
  4082ee:	63 41 64             	arpl   %ax,0x64(%ecx)
  4082f1:	64 72 65             	fs jb  408359 <.idata$6+0x1d>
  4082f4:	73 73                	jae    408369 <.idata$6+0x1>
	...

004082f8 <.idata$6>:
  4082f8:	df 02                	filds  (%edx)
  4082fa:	49                   	dec    %ecx
  4082fb:	6e                   	outsb  %ds:(%esi),(%dx)
  4082fc:	69 74 69 61 6c 69 7a 	imul   $0x657a696c,0x61(%ecx,%ebp,2),%esi
  408303:	65 
  408304:	43                   	inc    %ebx
  408305:	72 69                	jb     408370 <.idata$6+0x8>
  408307:	74 69                	je     408372 <.idata$6+0xa>
  408309:	63 61 6c             	arpl   %sp,0x6c(%ecx)
  40830c:	53                   	push   %ebx
  40830d:	65 63 74 69 6f       	arpl   %si,%gs:0x6f(%ecx,%ebp,2)
  408312:	6e                   	outsb  %ds:(%esi),(%dx)
	...

00408314 <.idata$6>:
  408314:	2f                   	das    
  408315:	03 4c 65 61          	add    0x61(%ebp,%eiz,2),%ecx
  408319:	76 65                	jbe    408380 <.idata$6+0x6>
  40831b:	43                   	inc    %ebx
  40831c:	72 69                	jb     408387 <.idata$6+0xd>
  40831e:	74 69                	je     408389 <.idata$6+0xf>
  408320:	63 61 6c             	arpl   %sp,0x6c(%ecx)
  408323:	53                   	push   %ebx
  408324:	65 63 74 69 6f       	arpl   %si,%gs:0x6f(%ecx,%ebp,2)
  408329:	6e                   	outsb  %ds:(%esi),(%dx)
	...

0040832c <.idata$6>:
  40832c:	32 03                	xor    (%ebx),%al
  40832e:	4c                   	dec    %esp
  40832f:	6f                   	outsl  %ds:(%esi),(%dx)
  408330:	61                   	popa   
  408331:	64 4c                	fs dec %esp
  408333:	69 62 72 61 72 79 41 	imul   $0x41797261,0x72(%edx),%esp
	...

0040833c <.idata$6>:
  40833c:	6c                   	insb   (%dx),%es:(%edi)
  40833d:	04 53                	add    $0x53,%al
  40833f:	65 74 55             	gs je  408397 <.idata$6+0x3>
  408342:	6e                   	outsb  %ds:(%esi),(%dx)
  408343:	68 61 6e 64 6c       	push   $0x6c646e61
  408348:	65 64 45             	gs fs inc %ebp
  40834b:	78 63                	js     4083b0 <.idata$6>
  40834d:	65 70 74             	gs jo  4083c4 <.idata$6+0x4>
  408350:	69 6f 6e 46 69 6c 74 	imul   $0x746c6946,0x6e(%edi),%ebp
  408357:	65 72 00             	gs jb  40835a <.idata$6>

0040835a <.idata$6>:
  40835a:	8d 04 54             	lea    (%esp,%edx,2),%eax
  40835d:	6c                   	insb   (%dx),%es:(%edi)
  40835e:	73 47                	jae    4083a7 <.idata$6+0x7>
  408360:	65 74 56             	gs je  4083b9 <.idata$6+0x9>
  408363:	61                   	popa   
  408364:	6c                   	insb   (%dx),%es:(%edi)
  408365:	75 65                	jne    4083cc <.idata$6+0xc>
	...

00408368 <.idata$6>:
  408368:	b5 04                	mov    $0x4,%ch
  40836a:	56                   	push   %esi
  40836b:	69 72 74 75 61 6c 50 	imul   $0x506c6175,0x74(%edx),%esi
  408372:	72 6f                	jb     4083e3 <.idata$6+0x5>
  408374:	74 65                	je     4083db <.idata$6+0xb>
  408376:	63 74 00 00          	arpl   %si,0x0(%eax,%eax,1)

0040837a <.idata$6>:
  40837a:	b7 04                	mov    $0x4,%bh
  40837c:	56                   	push   %esi
  40837d:	69 72 74 75 61 6c 51 	imul   $0x516c6175,0x74(%edx),%esi
  408384:	75 65                	jne    4083eb <.idata$6+0xd>
  408386:	72 79                	jb     408401 <.idata$6+0x3>
	...

0040838a <.idata$6>:
  40838a:	51                   	push   %ecx
  40838b:	00 5f 73             	add    %bl,0x73(%edi)
  40838e:	74 72                	je     408402 <.idata$6+0x4>
  408390:	64 75 70             	fs jne 408403 <.idata$6+0x5>
	...

00408394 <.idata$6>:
  408394:	53                   	push   %ebx
  408395:	00 5f 73             	add    %bl,0x73(%edi)
  408398:	74 72                	je     40840c <.idata$6+0x4>
  40839a:	69 63 6f 6c 6c 00  	imul   $0x59006c6c,0x6f(%ebx),%esp

004083a0 <.idata$6>:
  4083a0:	59                   	pop    %ecx
  4083a1:	00 5f 5f             	add    %bl,0x5f(%edi)
  4083a4:	67 65 74 6d          	addr16 gs je 408415 <.idata$6+0x3>
  4083a8:	61                   	popa   
  4083a9:	69 6e 61 72 67 73 00 	imul   $0x736772,0x61(%esi),%ebp

004083b0 <.idata$6>:
  4083b0:	78 00                	js     4083b2 <.idata$6+0x2>
  4083b2:	5f                   	pop    %edi
  4083b3:	5f                   	pop    %edi
  4083b4:	6d                   	insl   (%dx),%es:(%edi)
  4083b5:	62 5f 63             	bound  %ebx,0x63(%edi)
  4083b8:	75 72                	jne    40842c <.idata$6+0x2>
  4083ba:	5f                   	pop    %edi
  4083bb:	6d                   	insl   (%dx),%es:(%edi)
  4083bc:	61                   	popa   
  4083bd:	78 00                	js     4083bf <.idata$6+0xf>
	...

004083c0 <.idata$6>:
  4083c0:	84 00                	test   %al,(%eax)
  4083c2:	5f                   	pop    %edi
  4083c3:	5f                   	pop    %edi
  4083c4:	70 5f                	jo     408425 <.idata$6+0x7>
  4083c6:	5f                   	pop    %edi
  4083c7:	65 6e                	outsb  %gs:(%esi),(%dx)
  4083c9:	76 69                	jbe    408434 <.idata$6+0x2>
  4083cb:	72 6f                	jb     40843c <.idata$6+0xa>
  4083cd:	6e                   	outsb  %ds:(%esi),(%dx)
	...

004083d0 <.idata$6>:
  4083d0:	86 00                	xchg   %al,(%eax)
  4083d2:	5f                   	pop    %edi
  4083d3:	5f                   	pop    %edi
  4083d4:	70 5f                	jo     408435 <.idata$6+0x3>
  4083d6:	5f                   	pop    %edi
  4083d7:	66 6d                	insw   (%dx),%es:(%edi)
  4083d9:	6f                   	outsl  %ds:(%esi),(%dx)
  4083da:	64 65 00 00          	fs add %al,%gs:(%eax)

004083de <.idata$6>:
  4083de:	8c 00                	mov    %es,(%eax)
  4083e0:	5f                   	pop    %edi
  4083e1:	5f                   	pop    %edi
  4083e2:	70 5f                	jo     408443 <.idata$6+0x5>
  4083e4:	5f                   	pop    %edi
  4083e5:	70 67                	jo     40844e <.idata$6+0x6>
  4083e7:	6d                   	insl   (%dx),%es:(%edi)
  4083e8:	70 74                	jo     40845e <.idata$6+0x2>
  4083ea:	72 00                	jb     4083ec <.idata$6>

004083ec <.idata$6>:
  4083ec:	9a 00 5f 5f 73 65 74 	lcall  $0x7465,$0x735f5f00
  4083f3:	5f                   	pop    %edi
  4083f4:	61                   	popa   
  4083f5:	70 70                	jo     408467 <.idata$6+0xb>
  4083f7:	5f                   	pop    %edi
  4083f8:	74 79                	je     408473 <.idata$6+0x3>
  4083fa:	70 65                	jo     408461 <.idata$6+0x5>
	...

004083fe <.idata$6>:
  4083fe:	d7                   	xlat   %ds:(%ebx)
  4083ff:	00 5f 63             	add    %bl,0x63(%edi)
  408402:	65 78 69             	gs js  40846e <.idata$6+0x6>
  408405:	74 00                	je     408407 <.idata$6+0x9>
	...

00408408 <.idata$6>:
  408408:	18 01                	sbb    %al,(%ecx)
  40840a:	5f                   	pop    %edi
  40840b:	65 72 72             	gs jb  408480 <.idata$6+0x6>
  40840e:	6e                   	outsb  %ds:(%esi),(%dx)
  40840f:	6f                   	outsl  %ds:(%esi),(%dx)
	...

00408412 <.idata$6>:
  408412:	3f                   	aas    
  408413:	01 5f 66             	add    %ebx,0x66(%edi)
  408416:	70 72                	jo     40848a <.idata$6+0x6>
  408418:	65 73 65             	gs jae 408480 <.idata$6+0x6>
  40841b:	74 00                	je     40841d <.idata$6+0xb>
	...

0040841e <.idata$6>:
  40841e:	59                   	pop    %ecx
  40841f:	01 5f 66             	add    %ebx,0x66(%edi)
  408422:	75 6c                	jne    408490 <.idata$6+0x2>
  408424:	6c                   	insb   (%dx),%es:(%edi)
  408425:	70 61                	jo     408488 <.idata$6+0x4>
  408427:	74 68                	je     408491 <.idata$6+0x3>
	...

0040842a <.idata$6>:
  40842a:	9c                   	pushf  
  40842b:	01 5f 69             	add    %ebx,0x69(%edi)
  40842e:	6f                   	outsl  %ds:(%esi),(%dx)
  40842f:	62 00                	bound  %eax,(%eax)
	...

00408432 <.idata$6>:
  408432:	a1 01 5f 69 73       	mov    0x73695f01,%eax
  408437:	63 74 79 70          	arpl   %si,0x70(%ecx,%edi,2)
  40843b:	65 00 00             	add    %al,%gs:(%eax)

0040843e <.idata$6>:
  40843e:	a9 02 5f 6d 73       	test   $0x736d5f02,%eax
  408443:	69 7a 65 00 00   	imul   $0x2ac0000,0x65(%edx),%edi

00408448 <.idata$6>:
  408448:	ac                   	lods   %ds:(%esi),%al
  408449:	02 5f 6f             	add    0x6f(%edi),%bl
  40844c:	6e                   	outsb  %ds:(%esi),(%dx)
  40844d:	65 78 69             	gs js  4084b9 <.idata$6+0x1>
  408450:	74 00                	je     408452 <.idata$6>

00408452 <.idata$6>:
  408452:	b5 02                	mov    $0x2,%ch
  408454:	5f                   	pop    %edi
  408455:	70 63                	jo     4084ba <.idata$6+0x2>
  408457:	74 79                	je     4084d2 <.idata$6+0x4>
  408459:	70 65                	jo     4084c0 <.idata$6+0x8>
	...

0040845c <.idata$6>:
  40845c:	ec                   	in     (%dx),%al
  40845d:	02 5f 73             	add    0x73(%edi),%bl
  408460:	65 74 6d             	gs je  4084d0 <.idata$6+0x2>
  408463:	6f                   	outsl  %ds:(%esi),(%dx)
  408464:	64 65 00 00          	fs add %al,%gs:(%eax)

00408468 <.idata$6>:
  408468:	36 04 61             	ss add $0x61,%al
  40846b:	62 6f 72             	bound  %ebp,0x72(%edi)
  40846e:	74 00                	je     408470 <.idata$6>

00408470 <.idata$6>:
  408470:	3e 04 61             	ds add $0x61,%al
  408473:	74 65                	je     4084da <.idata$6+0x2>
  408475:	78 69                	js     4084e0 <.idata$6+0x8>
  408477:	74 00                	je     408479 <.idata$6+0x9>
	...

0040847a <.idata$6>:
  40847a:	45                   	inc    %ebp
  40847b:	04 63                	add    $0x63,%al
  40847d:	61                   	popa   
  40847e:	6c                   	insb   (%dx),%es:(%edi)
  40847f:	6c                   	insb   (%dx),%es:(%edi)
  408480:	6f                   	outsl  %ds:(%esi),(%dx)
  408481:	63 00                	arpl   %ax,(%eax)
	...

00408484 <.idata$6>:
  408484:	71 04                	jno    40848a <.idata$6+0x6>
  408486:	66 77 72             	data16 ja 4084fb <.idata$6+0x5>
  408489:	69 74 65 00 00   	imul   $0x6d049e00,0x0(%ebp,%eiz,2),%esi
  408490:	 

0040848e <.idata$6>:
  40848e:	9e                   	sahf   
  40848f:	04 6d                	add    $0x6d,%al
  408491:	61                   	popa   
  408492:	6c                   	insb   (%dx),%es:(%edi)
  408493:	6c                   	insb   (%dx),%es:(%edi)
  408494:	6f                   	outsl  %ds:(%esi),(%dx)
  408495:	63 00                	arpl   %ax,(%eax)
	...

00408498 <.idata$6>:
  408498:	a5                   	movsl  %ds:(%esi),%es:(%edi)
  408499:	04 6d                	add    $0x6d,%al
  40849b:	62 73 74             	bound  %esi,0x74(%ebx)
  40849e:	6f                   	outsl  %ds:(%esi),(%dx)
  40849f:	77 63                	ja     408504 <.idata$6+0x2>
  4084a1:	73 00                	jae    4084a3 <.idata$6+0xb>
	...

004084a4 <.idata$6>:
  4084a4:	aa                   	stos   %al,%es:(%edi)
  4084a5:	04 6d                	add    $0x6d,%al
  4084a7:	65 6d                	gs insl (%dx),%es:(%edi)
  4084a9:	63 70 79             	arpl   %si,0x79(%eax)
	...

004084ae <.idata$6>:
  4084ae:	ac                   	lods   %ds:(%esi),%al
  4084af:	04 6d                	add    $0x6d,%al
  4084b1:	65 6d                	gs insl (%dx),%es:(%edi)
  4084b3:	6d                   	insl   (%dx),%es:(%edi)
  4084b4:	6f                   	outsl  %ds:(%esi),(%dx)
  4084b5:	76 65                	jbe    40851c <.idata$6+0x6>
	...

004084b8 <.idata$6>:
  4084b8:	b3 04                	mov    $0x4,%bl
  4084ba:	70 72                	jo     40852e <.idata$6+0x18>
  4084bc:	69 6e 74 66 00 00  	imul   $0xc6000066,0x74(%esi),%ebp

004084c2 <.idata$6>:
  4084c2:	c6 04 73 65          	movb   $0x65,(%ebx,%esi,2)
  4084c6:	74 6c                	je     408534 <.idata$6+0x1e>
  4084c8:	6f                   	outsl  %ds:(%esi),(%dx)
  4084c9:	63 61 6c             	arpl   %sp,0x6c(%ecx)
  4084cc:	65 00              	gs add %cl,%al

004084ce <.idata$6>:
  4084ce:	c8 04 73 69          	enter  $0x7304,$0x69
  4084d2:	67 6e                	outsb  %ds:(%si),(%dx)
  4084d4:	61                   	popa   
  4084d5:	6c                   	insb   (%dx),%es:(%edi)
	...

004084d8 <.idata$6>:
  4084d8:	d5 04                	aad    $0x4
  4084da:	73 74                	jae    408550 <.idata$6+0x3a>
  4084dc:	72 63                	jb     408541 <.idata$6+0x2b>
  4084de:	6f                   	outsl  %ds:(%esi),(%dx)
  4084df:	6c                   	insb   (%dx),%es:(%edi)
  4084e0:	6c                   	insb   (%dx),%es:(%edi)
	...

004084e2 <.idata$6>:
  4084e2:	dc 04 73             	faddl  (%ebx,%esi,2)
  4084e5:	74 72                	je     408559 <.idata$6+0x43>
  4084e7:	6c                   	insb   (%dx),%es:(%edi)
  4084e8:	65 6e                	outsb  %gs:(%esi),(%dx)
	...

004084ec <.idata$6>:
  4084ec:	f8                   	clc    
  4084ed:	04 74                	add    $0x74,%al
  4084ef:	6f                   	outsl  %ds:(%esi),(%dx)
  4084f0:	6c                   	insb   (%dx),%es:(%edi)
  4084f1:	6f                   	outsl  %ds:(%esi),(%dx)
  4084f2:	77 65                	ja     408559 <.idata$6+0x43>
  4084f4:	72 00                	jb     4084f6 <.idata$6>

004084f6 <.idata$6>:
  4084f6:	ff 04 76             	incl   (%esi,%esi,2)
  4084f9:	66 70 72             	data16 jo 40856e <__libkernel32_a_iname+0x2>
  4084fc:	69 6e 74 66 00 00  	imul   $0x28000066,0x74(%esi),%ebp

00408502 <.idata$6>:
  408502:	28 05 77 63 73 74    	sub    %al,0x74736377
  408508:	6f                   	outsl  %ds:(%esi),(%dx)
  408509:	6d                   	insl   (%dx),%es:(%edi)
  40850a:	62 73 00             	bound  %esi,0x0(%ebx)
	...

0040850e <.idata$6>:
  40850e:	66 04 66             	data16 add $0x66,%al
  408511:	72 65                	jb     408578 <__libkernel32_a_iname+0xc>
  408513:	65 00 00             	add    %al,%gs:(%eax)

00408516 <.idata$6>:
  408516:	bf 04 72 65 61       	mov    $0x61657204,%edi
  40851b:	6c                   	insb   (%dx),%es:(%edi)
  40851c:	6c                   	insb   (%dx),%es:(%edi)
  40851d:	6f                   	outsl  %ds:(%esi),(%dx)
  40851e:	63 00                	arpl   %ax,(%eax)
  408520:	00 80 00 00 00 80    	add    %al,-0x80000000(%eax)
  408526:	00 00                	add    %al,(%eax)
  408528:	00 80 00 00 00 80    	add    %al,-0x80000000(%eax)
  40852e:	00 00                	add    %al,(%eax)
  408530:	00 80 00 00 00 80    	add    %al,-0x80000000(%eax)
  408536:	00 00                	add    %al,(%eax)
  408538:	00 80 00 00 00 80    	add    %al,-0x80000000(%eax)
  40853e:	00 00                	add    %al,(%eax)
  408540:	00 80 00 00 00 80    	add    %al,-0x80000000(%eax)
  408546:	00 00                	add    %al,(%eax)
  408548:	00 80 00 00 00 80    	add    %al,-0x80000000(%eax)
  40854e:	00 00                	add    %al,(%eax)
  408550:	00 80 00 00 00 80    	add    %al,-0x80000000(%eax)
  408556:	00 00                	add    %al,(%eax)
  408558:	00 80 00 00 00 80    	add    %al,-0x80000000(%eax)
  40855e:	00 00                	add    %al,(%eax)
  408560:	00 80 00 00 00 80    	add    %al,-0x80000000(%eax)
  408566:	00 00                	add    %al,(%eax)
  408568:	00 80 00 00      	add    %al,0x454b0000(%eax)

0040856c <__libkernel32_a_iname>:
  40856c:	4b                   	dec    %ebx
  40856d:	45                   	inc    %ebp
  40856e:	52                   	push   %edx
  40856f:	4e                   	dec    %esi
  408570:	45                   	inc    %ebp
  408571:	4c                   	dec    %esp
  408572:	33 32                	xor    (%edx),%esi
  408574:	2e 64 6c             	cs fs insb (%dx),%es:(%edi)
  408577:	6c                   	insb   (%dx),%es:(%edi)
  408578:	00 00                	add    %al,(%eax)
  40857a:	00 00                	add    %al,(%eax)
  40857c:	14 80                	adc    $0x80,%al
  40857e:	00 00                	add    %al,(%eax)
  408580:	14 80                	adc    $0x80,%al
	...

00408584 <__libmoldname_a_iname>:
  408584:	6d                   	insl   (%dx),%es:(%edi)
  408585:	73 76                	jae    4085fd <__libmoldname_a_iname+0x79>
  408587:	63 72 74             	arpl   %si,0x74(%edx)
  40858a:	2e 64 6c             	cs fs insb (%dx),%es:(%edi)
  40858d:	6c                   	insb   (%dx),%es:(%edi)
  40858e:	00 00                	add    %al,(%eax)
  408590:	28 80 00 00 28 80    	sub    %al,-0x7fd80000(%eax)
  408596:	00 00                	add    %al,(%eax)
  408598:	28 80 00 00 28 80    	sub    %al,-0x7fd80000(%eax)
  40859e:	00 00                	add    %al,(%eax)
  4085a0:	28 80 00 00 28 80    	sub    %al,-0x7fd80000(%eax)
  4085a6:	00 00                	add    %al,(%eax)
  4085a8:	28 80 00 00 28 80    	sub    %al,-0x7fd80000(%eax)
  4085ae:	00 00                	add    %al,(%eax)
  4085b0:	28 80 00 00 28 80    	sub    %al,-0x7fd80000(%eax)
  4085b6:	00 00                	add    %al,(%eax)
  4085b8:	28 80 00 00 28 80    	sub    %al,-0x7fd80000(%eax)
  4085be:	00 00                	add    %al,(%eax)
  4085c0:	28 80 00 00 28 80    	sub    %al,-0x7fd80000(%eax)
  4085c6:	00 00                	add    %al,(%eax)
  4085c8:	28 80 00 00 28 80    	sub    %al,-0x7fd80000(%eax)
  4085ce:	00 00                	add    %al,(%eax)
  4085d0:	28 80 00 00 28 80    	sub    %al,-0x7fd80000(%eax)
  4085d6:	00 00                	add    %al,(%eax)
  4085d8:	28 80 00 00 28 80    	sub    %al,-0x7fd80000(%eax)
  4085de:	00 00                	add    %al,(%eax)
  4085e0:	28 80 00 00 28 80    	sub    %al,-0x7fd80000(%eax)
  4085e6:	00 00                	add    %al,(%eax)
  4085e8:	28 80 00 00 28 80    	sub    %al,-0x7fd80000(%eax)
  4085ee:	00 00                	add    %al,(%eax)
  4085f0:	28 80 00 00 28 80    	sub    %al,-0x7fd80000(%eax)
  4085f6:	00 00                	add    %al,(%eax)
  4085f8:	28 80 00 00 28 80    	sub    %al,-0x7fd80000(%eax)
  4085fe:	00 00                	add    %al,(%eax)
  408600:	28 80 00 00 28 80    	sub    %al,-0x7fd80000(%eax)
  408606:	00 00                	add    %al,(%eax)
  408608:	28 80 00 00 28 80    	sub    %al,-0x7fd80000(%eax)
  40860e:	00 00                	add    %al,(%eax)
  408610:	28 80 00 00 28 80    	sub    %al,-0x7fd80000(%eax)
	...

00408618 <__libmsvcrt_a_iname>:
  408618:	6d                   	insl   (%dx),%es:(%edi)
  408619:	73 76                	jae    408691 <__libmsvcrt_a_iname+0x79>
  40861b:	63 72 74             	arpl   %si,0x74(%edx)
  40861e:	2e 64 6c             	cs fs insb (%dx),%es:(%edi)
  408621:	6c                   	insb   (%dx),%es:(%edi)
	...

Disassembly of section .CRT:

00409000 <___crt_xc_end__>:
  409000:	00 00                	add    %al,(%eax)
	...

00409004 <___xl_c>:
  409004:	c0 1a 40             	rcrb   $0x40,(%edx)
	...

00409008 <___xl_d>:
  409008:	70 1a                	jo     409024 <.CRT$XDZ+0x10>
  40900a:	40                   	inc    %eax
	...

0040900c <___xl_z>:
  40900c:	00 00                	add    %al,(%eax)
	...

00409010 <___crt_xp_end__>:
  409010:	00 00                	add    %al,(%eax)
	...

00409014 <.CRT$XDZ>:
  409014:	00 00                	add    %al,(%eax)
	...

Disassembly of section .tls:

0040a000 <___tls_start__>:
  40a000:	00 00                	add    %al,(%eax)
	...

0040a004 <__tls_used>:
  40a004:	01 a0 40 00 1c a0    	add    %esp,-0x5fe3ffc0(%eax)
  40a00a:	40                   	inc    %eax
  40a00b:	00 38                	add    %bh,(%eax)
  40a00d:	70 40                	jo     40a04f <___tls_end__+0x2f>
  40a00f:	00 04 90             	add    %al,(%eax,%edx,4)
  40a012:	40                   	inc    %eax
	...

0040a01c <__tls_end>:
  40a01c:	00 00                	add    %al,(%eax)
	...

Disassembly of section .debug_aranges:

0040b000 <.debug_aranges>:
  40b000:	1c 00                	sbb    $0x0,%al
  40b002:	00 00                	add    %al,(%eax)
  40b004:	02 00                	add    (%eax),%al
  40b006:	00 00                	add    %al,(%eax)
  40b008:	00 00                	add    %al,(%eax)
  40b00a:	04 00                	add    $0x0,%al
  40b00c:	00 00                	add    %al,(%eax)
  40b00e:	00 00                	add    %al,(%eax)
  40b010:	30 3e                	xor    %bh,(%esi)
  40b012:	40                   	inc    %eax
  40b013:	00 2a                	add    %ch,(%edx)
	...

0040b020 <.debug_aranges>:
  40b020:	14 00                	adc    $0x0,%al
  40b022:	00 00                	add    %al,(%eax)
  40b024:	02 00                	add    (%eax),%al
  40b026:	26 00 00             	add    %al,%es:(%eax)
  40b029:	00 04 00             	add    %al,(%eax,%eax,1)
	...

Disassembly of section .debug_info:

0040c000 <.debug_info>:
  40c000:	22 00                	and    (%eax),%al
  40c002:	00 00                	add    %al,(%eax)
  40c004:	02 00                	add    (%eax),%al
  40c006:	00 00                	add    %al,(%eax)
  40c008:	00 00                	add    %al,(%eax)
  40c00a:	04 01                	add    $0x1,%al
  40c00c:	00 00                	add    %al,(%eax)
  40c00e:	00 00                	add    %al,(%eax)
  40c010:	30 3e                	xor    %bh,(%esi)
  40c012:	40                   	inc    %eax
  40c013:	00 5a 3e             	add    %bl,0x3e(%edx)
  40c016:	40                   	inc    %eax
  40c017:	00 00                	add    %al,(%eax)
  40c019:	00 00                	add    %al,(%eax)
  40c01b:	00 33                	add    %dh,(%ebx)
  40c01d:	00 00                	add    %al,(%eax)
  40c01f:	00 7a 00             	add    %bh,0x0(%edx)
  40c022:	00 00                	add    %al,(%eax)
  40c024:	01 80        	add    %eax,0x1ea2(%eax)

0040c026 <.debug_info>:
  40c026:	a2 1e 00 00 04       	mov    %al,0x400001e
  40c02b:	00 14 00             	add    %dl,(%eax,%eax,1)
  40c02e:	00 00                	add    %al,(%eax)
  40c030:	04 01                	add    $0x1,%al
  40c032:	47                   	inc    %edi
  40c033:	4e                   	dec    %esi
  40c034:	55                   	push   %ebp
  40c035:	20 43 31             	and    %al,0x31(%ebx)
  40c038:	37                   	aaa    
  40c039:	20 39                	and    %bh,(%ecx)
  40c03b:	2e 32 2e             	xor    %cs:(%esi),%ch
  40c03e:	30 20                	xor    %ah,(%eax)
  40c040:	2d 6d 74 75 6e       	sub    $0x6e75746d,%eax
  40c045:	65 3d 67 65 6e 65    	gs cmp $0x656e6567,%eax
  40c04b:	72 69                	jb     40c0b6 <.debug_info+0x90>
  40c04d:	63 20                	arpl   %sp,(%eax)
  40c04f:	2d 6d 61 72 63       	sub    $0x6372616d,%eax
  40c054:	68 3d 69 35 38       	push   $0x3835693d
  40c059:	36 20 2d 67 20 2d 67 	and    %ch,%ss:0x672d2067
  40c060:	20 2d 67 20 2d 4f    	and    %ch,0x4f2d2067
  40c066:	32 20                	xor    (%eax),%ah
  40c068:	2d 4f 32 20 2d       	sub    $0x2d20324f,%eax
  40c06d:	4f                   	dec    %edi
  40c06e:	32 20                	xor    (%eax),%ah
  40c070:	2d 66 62 75 69       	sub    $0x69756266,%eax
  40c075:	6c                   	insb   (%dx),%es:(%edi)
  40c076:	64 69 6e 67 2d 6c 69 	imul   $0x62696c2d,%fs:0x67(%esi),%ebp
  40c07d:	62 
  40c07e:	67 63 63 20          	arpl   %sp,0x20(%bp,%di)
  40c082:	2d 66 6e 6f 2d       	sub    $0x2d6f6e66,%eax
  40c087:	73 74                	jae    40c0fd <.debug_info+0xd7>
  40c089:	61                   	popa   
  40c08a:	63 6b 2d             	arpl   %bp,0x2d(%ebx)
  40c08d:	70 72                	jo     40c101 <.debug_info+0xdb>
  40c08f:	6f                   	outsl  %ds:(%esi),(%dx)
  40c090:	74 65                	je     40c0f7 <.debug_info+0xd1>
  40c092:	63 74 6f 72          	arpl   %si,0x72(%edi,%ebp,2)
  40c096:	00 0c 2e             	add    %cl,(%esi,%ebp,1)
  40c099:	2e 2f                	cs das 
  40c09b:	2e 2e 2f             	cs cs das 
  40c09e:	2e 2e 2f             	cs cs das 
  40c0a1:	73 72                	jae    40c115 <.debug_info+0xef>
  40c0a3:	63 2f                	arpl   %bp,(%edi)
  40c0a5:	67 63 63 2d          	arpl   %sp,0x2d(%bp,%di)
  40c0a9:	39 2e                	cmp    %ebp,(%esi)
  40c0ab:	32 2e                	xor    (%esi),%ch
  40c0ad:	30 2f                	xor    %ch,(%edi)
  40c0af:	6c                   	insb   (%dx),%es:(%edi)
  40c0b0:	69 62 67 63 63 2f 6c 	imul   $0x6c2f6363,0x67(%edx),%esp
  40c0b7:	69 62 67 63 63 32 2e 	imul   $0x2e326363,0x67(%edx),%esp
  40c0be:	63 00                	arpl   %ax,(%eax)
  40c0c0:	2f                   	das    
  40c0c1:	68 6f 6d 65 2f       	push   $0x2f656d6f
  40c0c6:	6b 65 69 74          	imul   $0x74,0x69(%ebp),%esp
  40c0ca:	68 2f 62 75 69       	push   $0x6975622f
  40c0cf:	6c                   	insb   (%dx),%es:(%edi)
  40c0d0:	64 73 2f             	fs jae 40c102 <.debug_info+0xdc>
  40c0d3:	6d                   	insl   (%dx),%es:(%edi)
  40c0d4:	69 6e 67 77 2f 67 63 	imul   $0x63672f77,0x67(%esi),%ebp
  40c0db:	63 2d 39 2e 32 2e    	arpl   %bp,0x2e322e39
  40c0e1:	30 2d 6d 69 6e 67    	xor    %ch,0x676e696d
  40c0e7:	77 33                	ja     40c11c <.debug_info+0xf6>
  40c0e9:	32 2d 63 72 6f 73    	xor    0x736f7263,%ch
  40c0ef:	73 2d                	jae    40c11e <.debug_info+0xf8>
  40c0f1:	6e                   	outsb  %ds:(%esi),(%dx)
  40c0f2:	61                   	popa   
  40c0f3:	74 69                	je     40c15e <.debug_info+0x138>
  40c0f5:	76 65                	jbe    40c15c <.debug_info+0x136>
  40c0f7:	2f                   	das    
  40c0f8:	6d                   	insl   (%dx),%es:(%edi)
  40c0f9:	69 6e 67 77 33 32 2f 	imul   $0x2f323377,0x67(%esi),%ebp
  40c100:	6c                   	insb   (%dx),%es:(%edi)
  40c101:	69 62 67 63 63 00 71 	imul   $0x71006363,0x67(%edx),%esp
  40c108:	00 00                	add    %al,(%eax)
  40c10a:	00 02                	add    %al,(%edx)
  40c10c:	04 05                	add    $0x5,%al
  40c10e:	69 6e 74 00 03 e5 00 	imul   $0xe50300,0x74(%esi),%ebp
  40c115:	00 00                	add    %al,(%eax)
  40c117:	02 04 07             	add    (%edi,%eax,1),%al
  40c11a:	75 6e                	jne    40c18a <.debug_info+0x164>
  40c11c:	73 69                	jae    40c187 <.debug_info+0x161>
  40c11e:	67 6e                	outsb  %ds:(%si),(%dx)
  40c120:	65 64 20 69 6e       	gs and %ch,%fs:0x6e(%ecx)
  40c125:	74 00                	je     40c127 <.debug_info+0x101>
  40c127:	02 02                	add    (%edx),%al
  40c129:	07                   	pop    %es
  40c12a:	73 68                	jae    40c194 <.debug_info+0x16e>
  40c12c:	6f                   	outsl  %ds:(%esi),(%dx)
  40c12d:	72 74                	jb     40c1a3 <.debug_info+0x17d>
  40c12f:	20 75 6e             	and    %dh,0x6e(%ebp)
  40c132:	73 69                	jae    40c19d <.debug_info+0x177>
  40c134:	67 6e                	outsb  %ds:(%si),(%dx)
  40c136:	65 64 20 69 6e       	gs and %ch,%fs:0x6e(%ecx)
  40c13b:	74 00                	je     40c13d <.debug_info+0x117>
  40c13d:	02 08                	add    (%eax),%cl
  40c13f:	05 6c 6f 6e 67       	add    $0x676e6f6c,%eax
  40c144:	20 6c 6f 6e          	and    %ch,0x6e(%edi,%ebp,2)
  40c148:	67 20 69 6e          	and    %ch,0x6e(%bx,%di)
  40c14c:	74 00                	je     40c14e <.debug_info+0x128>
  40c14e:	02 0c 04             	add    (%esp,%eax,1),%cl
  40c151:	6c                   	insb   (%dx),%es:(%edi)
  40c152:	6f                   	outsl  %ds:(%esi),(%dx)
  40c153:	6e                   	outsb  %ds:(%esi),(%dx)
  40c154:	67 20 64 6f          	and    %ah,0x6f(%si)
  40c158:	75 62                	jne    40c1bc <.debug_info+0x196>
  40c15a:	6c                   	insb   (%dx),%es:(%edi)
  40c15b:	65 00 02             	add    %al,%gs:(%edx)
  40c15e:	10 04 5f             	adc    %al,(%edi,%ebx,2)
  40c161:	46                   	inc    %esi
  40c162:	6c                   	insb   (%dx),%es:(%edi)
  40c163:	6f                   	outsl  %ds:(%esi),(%dx)
  40c164:	61                   	popa   
  40c165:	74 31                	je     40c198 <.debug_info+0x172>
  40c167:	32 38                	xor    (%eax),%bh
  40c169:	00 02                	add    %al,(%edx)
  40c16b:	01 06                	add    %eax,(%esi)
  40c16d:	63 68 61             	arpl   %bp,0x61(%eax)
  40c170:	72 00                	jb     40c172 <.debug_info+0x14c>
  40c172:	03 44 01 00          	add    0x0(%ecx,%eax,1),%eax
  40c176:	00 02                	add    %al,(%edx)
  40c178:	04 05                	add    $0x5,%al
  40c17a:	6c                   	insb   (%dx),%es:(%edi)
  40c17b:	6f                   	outsl  %ds:(%esi),(%dx)
  40c17c:	6e                   	outsb  %ds:(%esi),(%dx)
  40c17d:	67 20 69 6e          	and    %ch,0x6e(%bx,%di)
  40c181:	74 00                	je     40c183 <.debug_info+0x15d>
  40c183:	04 5f                	add    $0x5f,%al
  40c185:	69 6f 62 75 66 00 20 	imul   $0x20006675,0x62(%edi),%ebp
  40c18c:	01 d2                	add    %edx,%edx
  40c18e:	10 ed                	adc    %ch,%ch
  40c190:	01 00                	add    %eax,(%eax)
  40c192:	00 05 5f 70 74 72    	add    %al,0x7274705f
  40c198:	00 01                	add    %al,(%ecx)
  40c19a:	d4 09                	aam    $0x9
  40c19c:	ed                   	in     (%dx),%eax
  40c19d:	01 00                	add    %eax,(%eax)
  40c19f:	00 00                	add    %al,(%eax)
  40c1a1:	05 5f 63 6e 74       	add    $0x746e635f,%eax
  40c1a6:	00 01                	add    %al,(%ecx)
  40c1a8:	d5 08                	aad    $0x8
  40c1aa:	e5 00                	in     $0x0,%eax
  40c1ac:	00 00                	add    %al,(%eax)
  40c1ae:	04 05                	add    $0x5,%al
  40c1b0:	5f                   	pop    %edi
  40c1b1:	62 61 73             	bound  %esp,0x73(%ecx)
  40c1b4:	65 00 01             	add    %al,%gs:(%ecx)
  40c1b7:	d6                   	(bad)  
  40c1b8:	09 ed                	or     %ebp,%ebp
  40c1ba:	01 00                	add    %eax,(%eax)
  40c1bc:	00 08                	add    %cl,(%eax)
  40c1be:	05 5f 66 6c 61       	add    $0x616c665f,%eax
  40c1c3:	67 00 01             	add    %al,(%bx,%di)
  40c1c6:	d7                   	xlat   %ds:(%ebx)
  40c1c7:	08 e5                	or     %ah,%ch
  40c1c9:	00 00                	add    %al,(%eax)
  40c1cb:	00 0c 05 5f 66 69 6c 	add    %cl,0x6c69665f(,%eax,1)
  40c1d2:	65 00 01             	add    %al,%gs:(%ecx)
  40c1d5:	d8 08                	fmuls  (%eax)
  40c1d7:	e5 00                	in     $0x0,%eax
  40c1d9:	00 00                	add    %al,(%eax)
  40c1db:	10 05 5f 63 68 61    	adc    %al,0x6168635f
  40c1e1:	72 62                	jb     40c245 <.debug_info+0x21f>
  40c1e3:	75 66                	jne    40c24b <.debug_info+0x225>
  40c1e5:	00 01                	add    %al,(%ecx)
  40c1e7:	d9 08                	(bad)  (%eax)
  40c1e9:	e5 00                	in     $0x0,%eax
  40c1eb:	00 00                	add    %al,(%eax)
  40c1ed:	14 05                	adc    $0x5,%al
  40c1ef:	5f                   	pop    %edi
  40c1f0:	62 75 66             	bound  %esi,0x66(%ebp)
  40c1f3:	73 69                	jae    40c25e <.debug_info+0x238>
  40c1f5:	7a 00                	jp     40c1f7 <.debug_info+0x1d1>
  40c1f7:	01 da                	add    %ebx,%edx
  40c1f9:	08 e5                	or     %ah,%ch
  40c1fb:	00 00                	add    %al,(%eax)
  40c1fd:	00 18                	add    %bl,(%eax)
  40c1ff:	05 5f 74 6d 70       	add    $0x706d745f,%eax
  40c204:	66 6e                	data16 outsb %ds:(%esi),(%dx)
  40c206:	61                   	popa   
  40c207:	6d                   	insl   (%dx),%es:(%edi)
  40c208:	65 00 01             	add    %al,%gs:(%ecx)
  40c20b:	db 09                	fisttpl (%ecx)
  40c20d:	ed                   	in     (%dx),%eax
  40c20e:	01 00                	add    %eax,(%eax)
  40c210:	00 1c 00             	add    %bl,(%eax,%eax,1)
  40c213:	06                   	push   %es
  40c214:	04 44                	add    $0x44,%al
  40c216:	01 00                	add    %eax,(%eax)
  40c218:	00 07                	add    %al,(%edi)
  40c21a:	46                   	inc    %esi
  40c21b:	49                   	dec    %ecx
  40c21c:	4c                   	dec    %esp
  40c21d:	45                   	inc    %ebp
  40c21e:	00 01                	add    %al,(%ecx)
  40c220:	dc 03                	faddl  (%ebx)
  40c222:	5d                   	pop    %ebp
  40c223:	01 00                	add    %eax,(%eax)
  40c225:	00 08                	add    %cl,(%eax)
  40c227:	f3 01 00             	repz add %eax,(%eax)
  40c22a:	00 0b                	add    %cl,(%ebx)
  40c22c:	02 00                	add    (%eax),%al
  40c22e:	00 09                	add    %cl,(%ecx)
  40c230:	00 0a                	add    %cl,(%edx)
  40c232:	5f                   	pop    %edi
  40c233:	69 6f 62 00 01 ef 15 	imul   $0x15ef0100,0x62(%edi),%ebp
  40c23a:	00 02                	add    %al,(%edx)
  40c23c:	00 00                	add    %al,(%eax)
  40c23e:	02 02                	add    (%edx),%al
  40c240:	05 73 68 6f 72       	add    $0x726f6873,%eax
  40c245:	74 20                	je     40c267 <.debug_info+0x241>
  40c247:	69 6e 74 00 02 04 07 	imul   $0x7040200,0x74(%esi),%ebp
  40c24e:	6c                   	insb   (%dx),%es:(%edi)
  40c24f:	6f                   	outsl  %ds:(%esi),(%dx)
  40c250:	6e                   	outsb  %ds:(%esi),(%dx)
  40c251:	67 20 75 6e          	and    %dh,0x6e(%di)
  40c255:	73 69                	jae    40c2c0 <.debug_info+0x29a>
  40c257:	67 6e                	outsb  %ds:(%si),(%dx)
  40c259:	65 64 20 69 6e       	gs and %ch,%fs:0x6e(%ecx)
  40c25e:	74 00                	je     40c260 <.debug_info+0x23a>
  40c260:	0a 5f 61             	or     0x61(%edi),%bl
  40c263:	72 67                	jb     40c2cc <.debug_info+0x2a6>
  40c265:	63 00                	arpl   %ax,(%eax)
  40c267:	02 63 10             	add    0x10(%ebx),%ah
  40c26a:	e5 00                	in     $0x0,%eax
  40c26c:	00 00                	add    %al,(%eax)
  40c26e:	0a 5f 61             	or     0x61(%edi),%bl
  40c271:	72 67                	jb     40c2da <.debug_info+0x2b4>
  40c273:	76 00                	jbe    40c275 <.debug_info+0x24f>
  40c275:	02 64 10 56          	add    0x56(%eax,%edx,1),%ah
  40c279:	02 00                	add    (%eax),%al
  40c27b:	00 06                	add    %al,(%esi)
  40c27d:	04 ed                	add    $0xed,%al
  40c27f:	01 00                	add    %eax,(%eax)
  40c281:	00 0a                	add    %cl,(%edx)
  40c283:	5f                   	pop    %edi
  40c284:	5f                   	pop    %edi
  40c285:	6d                   	insl   (%dx),%es:(%edi)
  40c286:	62 5f 63             	bound  %ebx,0x63(%edi)
  40c289:	75 72                	jne    40c2fd <.debug_info+0x2d7>
  40c28b:	5f                   	pop    %edi
  40c28c:	6d                   	insl   (%dx),%es:(%edi)
  40c28d:	61                   	popa   
  40c28e:	78 00                	js     40c290 <.debug_info+0x26a>
  40c290:	02 8e 17 e5 00 00    	add    0xe517(%esi),%cl
  40c296:	00 0a                	add    %cl,(%edx)
  40c298:	5f                   	pop    %edi
  40c299:	73 79                	jae    40c314 <.debug_info+0x2ee>
  40c29b:	73 5f                	jae    40c2fc <.debug_info+0x2d6>
  40c29d:	6e                   	outsb  %ds:(%esi),(%dx)
  40c29e:	65 72 72             	gs jb  40c313 <.debug_info+0x2ed>
  40c2a1:	00 02                	add    %al,(%edx)
  40c2a3:	e5 14                	in     $0x14,%eax
  40c2a5:	e5 00                	in     $0x0,%eax
  40c2a7:	00 00                	add    %al,(%eax)
  40c2a9:	08 ed                	or     %ch,%ch
  40c2ab:	01 00                	add    %eax,(%eax)
  40c2ad:	00 8e 02 00 00 09    	add    %cl,0x9000002(%esi)
  40c2b3:	00 0a                	add    %cl,(%edx)
  40c2b5:	5f                   	pop    %edi
  40c2b6:	73 79                	jae    40c331 <.debug_info+0x30b>
  40c2b8:	73 5f                	jae    40c319 <.debug_info+0x2f3>
  40c2ba:	65 72 72             	gs jb  40c32f <.debug_info+0x309>
  40c2bd:	6c                   	insb   (%dx),%es:(%edi)
  40c2be:	69 73 74 00 02 fe 16 	imul   $0x16fe0200,0x74(%ebx),%esi
  40c2c5:	83 02 00             	addl   $0x0,(%edx)
  40c2c8:	00 0b                	add    %cl,(%ebx)
  40c2ca:	5f                   	pop    %edi
  40c2cb:	6f                   	outsl  %ds:(%esi),(%dx)
  40c2cc:	73 76                	jae    40c344 <.debug_info+0x31e>
  40c2ce:	65 72 00             	gs jb  40c2d1 <.debug_info+0x2ab>
  40c2d1:	02 15 01 1e f1 00    	add    0xf11e01,%dl
  40c2d7:	00 00                	add    %al,(%eax)
  40c2d9:	0b 5f 77             	or     0x77(%edi),%ebx
  40c2dc:	69 6e 76 65 72 00 02 	imul   $0x2007265,0x76(%esi),%ebp
  40c2e3:	16                   	push   %ss
  40c2e4:	01 1e                	add    %ebx,(%esi)
  40c2e6:	f1                   	icebp  
  40c2e7:	00 00                	add    %al,(%eax)
  40c2e9:	00 0b                	add    %cl,(%ebx)
  40c2eb:	5f                   	pop    %edi
  40c2ec:	77 69                	ja     40c357 <.debug_info+0x331>
  40c2ee:	6e                   	outsb  %ds:(%esi),(%dx)
  40c2ef:	6d                   	insl   (%dx),%es:(%edi)
  40c2f0:	61                   	popa   
  40c2f1:	6a 6f                	push   $0x6f
  40c2f3:	72 00                	jb     40c2f5 <.debug_info+0x2cf>
  40c2f5:	02 17                	add    (%edi),%dl
  40c2f7:	01 1e                	add    %ebx,(%esi)
  40c2f9:	f1                   	icebp  
  40c2fa:	00 00                	add    %al,(%eax)
  40c2fc:	00 0b                	add    %cl,(%ebx)
  40c2fe:	5f                   	pop    %edi
  40c2ff:	77 69                	ja     40c36a <.debug_info+0x344>
  40c301:	6e                   	outsb  %ds:(%esi),(%dx)
  40c302:	6d                   	insl   (%dx),%es:(%edi)
  40c303:	69 6e 6f 72 00 02 18 	imul   $0x18020072,0x6f(%esi),%ebp
  40c30a:	01 1e                	add    %ebx,(%esi)
  40c30c:	f1                   	icebp  
  40c30d:	00 00                	add    %al,(%eax)
  40c30f:	00 0b                	add    %cl,(%ebx)
  40c311:	5f                   	pop    %edi
  40c312:	66 6d                	insw   (%dx),%es:(%edi)
  40c314:	6f                   	outsl  %ds:(%esi),(%dx)
  40c315:	64 65 00 02          	fs add %al,%gs:(%edx)
  40c319:	60                   	pusha  
  40c31a:	01 15 e5 00 00 00    	add    %edx,0xe5
  40c320:	0a 6f 70             	or     0x70(%edi),%ch
  40c323:	74 69                	je     40c38e <.debug_info+0x368>
  40c325:	6e                   	outsb  %ds:(%esi),(%dx)
  40c326:	64 00 03             	add    %al,%fs:(%ebx)
  40c329:	3c 0c                	cmp    $0xc,%al
  40c32b:	e5 00                	in     $0x0,%eax
  40c32d:	00 00                	add    %al,(%eax)
  40c32f:	0a 6f 70             	or     0x70(%edi),%ch
  40c332:	74 6f                	je     40c3a3 <.debug_info+0x37d>
  40c334:	70 74                	jo     40c3aa <.debug_info+0x384>
  40c336:	00 03                	add    %al,(%ebx)
  40c338:	3d 0c e5 00 00       	cmp    $0xe50c,%eax
  40c33d:	00 0a                	add    %cl,(%edx)
  40c33f:	6f                   	outsl  %ds:(%esi),(%dx)
  40c340:	70 74                	jo     40c3b6 <.debug_info+0x390>
  40c342:	65 72 72             	gs jb  40c3b7 <.debug_info+0x391>
  40c345:	00 03                	add    %al,(%ebx)
  40c347:	3e 0c e5             	ds or  $0xe5,%al
  40c34a:	00 00                	add    %al,(%eax)
  40c34c:	00 0a                	add    %cl,(%edx)
  40c34e:	6f                   	outsl  %ds:(%esi),(%dx)
  40c34f:	70 74                	jo     40c3c5 <.debug_info+0x39f>
  40c351:	61                   	popa   
  40c352:	72 67                	jb     40c3bb <.debug_info+0x395>
  40c354:	00 03                	add    %al,(%ebx)
  40c356:	41                   	inc    %ecx
  40c357:	0e                   	push   %cs
  40c358:	ed                   	in     (%dx),%eax
  40c359:	01 00                	add    %eax,(%eax)
  40c35b:	00 0b                	add    %cl,(%ebx)
  40c35d:	5f                   	pop    %edi
  40c35e:	64 61                	fs popa 
  40c360:	79 6c                	jns    40c3ce <.debug_info+0x3a8>
  40c362:	69 67 68 74 00 04 5c 	imul   $0x5c040074,0x68(%edi),%esp
  40c369:	01 16                	add    %edx,(%esi)
  40c36b:	e5 00                	in     $0x0,%eax
  40c36d:	00 00                	add    %al,(%eax)
  40c36f:	0b 5f 74             	or     0x74(%edi),%ebx
  40c372:	69 6d 65 7a 6f 6e 65 	imul   $0x656e6f7a,0x65(%ebp),%ebp
  40c379:	00 04 5d 01 16 51 01 	add    %al,0x1511601(,%ebx,2)
  40c380:	00 00                	add    %al,(%eax)
  40c382:	08 ed                	or     %ch,%ch
  40c384:	01 00                	add    %eax,(%eax)
  40c386:	00 6c 03 00          	add    %ch,0x0(%ebx,%eax,1)
  40c38a:	00 0c f1             	add    %cl,(%ecx,%esi,8)
  40c38d:	00 00                	add    %al,(%eax)
  40c38f:	00 01                	add    %al,(%ecx)
  40c391:	00 0b                	add    %cl,(%ebx)
  40c393:	5f                   	pop    %edi
  40c394:	74 7a                	je     40c410 <.debug_info+0x3ea>
  40c396:	6e                   	outsb  %ds:(%esi),(%dx)
  40c397:	61                   	popa   
  40c398:	6d                   	insl   (%dx),%es:(%edi)
  40c399:	65 00 04 5e          	add    %al,%gs:(%esi,%ebx,2)
  40c39d:	01 16                	add    %edx,(%esi)
  40c39f:	5c                   	pop    %esp
  40c3a0:	03 00                	add    (%eax),%eax
  40c3a2:	00 0b                	add    %cl,(%ebx)
  40c3a4:	64 61                	fs popa 
  40c3a6:	79 6c                	jns    40c414 <.debug_info+0x3ee>
  40c3a8:	69 67 68 74 00 04 7d 	imul   $0x7d040074,0x68(%edi),%esp
  40c3af:	01 16                	add    %edx,(%esi)
  40c3b1:	e5 00                	in     $0x0,%eax
  40c3b3:	00 00                	add    %al,(%eax)
  40c3b5:	0b 74 69 6d          	or     0x6d(%ecx,%ebp,2),%esi
  40c3b9:	65 7a 6f             	gs jp  40c42b <.debug_info+0x405>
  40c3bc:	6e                   	outsb  %ds:(%esi),(%dx)
  40c3bd:	65 00 04 7e          	add    %al,%gs:(%esi,%edi,2)
  40c3c1:	01 16                	add    %edx,(%esi)
  40c3c3:	51                   	push   %ecx
  40c3c4:	01 00                	add    %eax,(%eax)
  40c3c6:	00 0b                	add    %cl,(%ebx)
  40c3c8:	74 7a                	je     40c444 <.debug_info+0x41e>
  40c3ca:	6e                   	outsb  %ds:(%esi),(%dx)
  40c3cb:	61                   	popa   
  40c3cc:	6d                   	insl   (%dx),%es:(%edi)
  40c3cd:	65 00 04 7f          	add    %al,%gs:(%edi,%edi,2)
  40c3d1:	01 16                	add    %edx,(%esi)
  40c3d3:	5c                   	pop    %esp
  40c3d4:	03 00                	add    (%eax),%eax
  40c3d6:	00 07                	add    %al,(%edi)
  40c3d8:	68 61 73 68 76       	push   $0x76687361
  40c3dd:	61                   	popa   
  40c3de:	6c                   	insb   (%dx),%es:(%edi)
  40c3df:	5f                   	pop    %edi
  40c3e0:	74 00                	je     40c3e2 <.debug_info+0x3bc>
  40c3e2:	05 2a 16 f1 00       	add    $0xf1162a,%eax
  40c3e7:	00 00                	add    %al,(%eax)
  40c3e9:	07                   	pop    %es
  40c3ea:	68 74 61 62 5f       	push   $0x5f626174
  40c3ef:	68 61 73 68 00       	push   $0x687361
  40c3f4:	05 2f 15 d5 03       	add    $0x3d5152f,%eax
  40c3f9:	00 00                	add    %al,(%eax)
  40c3fb:	06                   	push   %es
  40c3fc:	04 db                	add    $0xdb,%al
  40c3fe:	03 00                	add    (%eax),%eax
  40c400:	00 0d b1 03 00 00    	add    %cl,0x3b1
  40c406:	ea 03 00 00 0e ea 03 	ljmp   $0x3ea,$0xe000003
  40c40d:	00 00                	add    %al,(%eax)
  40c40f:	00 06                	add    %al,(%esi)
  40c411:	04 f0                	add    $0xf0,%al
  40c413:	03 00                	add    (%eax),%eax
  40c415:	00 0f                	add    %cl,(%edi)
  40c417:	07                   	pop    %es
  40c418:	68 74 61 62 5f       	push   $0x5f626174
  40c41d:	65 71 00             	gs jno 40c420 <.debug_info+0x3fa>
  40c420:	05 36 0f 01 04       	add    $0x4010f36,%eax
  40c425:	00 00                	add    %al,(%eax)
  40c427:	06                   	push   %es
  40c428:	04 07                	add    $0x7,%al
  40c42a:	04 00                	add    $0x0,%al
  40c42c:	00 0d e5 00 00 00    	add    %cl,0xe5
  40c432:	1b 04 00             	sbb    (%eax,%eax,1),%eax
  40c435:	00 0e                	add    %cl,(%esi)
  40c437:	ea 03 00 00 0e ea 03 	ljmp   $0x3ea,$0xe000003
  40c43e:	00 00                	add    %al,(%eax)
  40c440:	00 0a                	add    %cl,(%edx)
  40c442:	68 74 61 62 5f       	push   $0x5f626174
  40c447:	68 61 73 68 5f       	push   $0x5f687361
  40c44c:	70 6f                	jo     40c4bd <.debug_info+0x497>
  40c44e:	69 6e 74 65 72 00 05 	imul   $0x5007265,0x74(%esi),%ebp
  40c455:	bb 12 c3 03 00       	mov    $0x3c312,%ebx
  40c45a:	00 0a                	add    %cl,(%edx)
  40c45c:	68 74 61 62 5f       	push   $0x5f626174
  40c461:	65 71 5f             	gs jno 40c4c3 <.debug_info+0x49d>
  40c464:	70 6f                	jo     40c4d5 <.debug_info+0x4af>
  40c466:	69 6e 74 65 72 00 05 	imul   $0x5007265,0x74(%esi),%ebp
  40c46d:	be 10 f1 03 00       	mov    $0x3f110,%esi
  40c472:	00 02                	add    %al,(%edx)
  40c474:	01 08                	add    %ecx,(%eax)
  40c476:	75 6e                	jne    40c4e6 <.debug_info+0x4c0>
  40c478:	73 69                	jae    40c4e3 <.debug_info+0x4bd>
  40c47a:	67 6e                	outsb  %ds:(%si),(%dx)
  40c47c:	65 64 20 63 68       	gs and %ah,%fs:0x68(%ebx)
  40c481:	61                   	popa   
  40c482:	72 00                	jb     40c484 <.debug_info+0x45e>
  40c484:	10 73 74             	adc    %dh,0x74(%ebx)
  40c487:	72 69                	jb     40c4f2 <.debug_info+0x4cc>
  40c489:	6e                   	outsb  %ds:(%esi),(%dx)
  40c48a:	67 6f                	outsl  %ds:(%si),(%dx)
  40c48c:	70 5f                	jo     40c4ed <.debug_info+0x4c7>
  40c48e:	61                   	popa   
  40c48f:	6c                   	insb   (%dx),%es:(%edi)
  40c490:	67 00 07             	add    %al,(%bx)
  40c493:	04 f1                	add    $0xf1,%al
  40c495:	00 00                	add    %al,(%eax)
  40c497:	00 08                	add    %cl,(%eax)
  40c499:	1d 06 0c 05 00       	sbb    $0x50c06,%eax
  40c49e:	00 11                	add    %dl,(%ecx)
  40c4a0:	6e                   	outsb  %ds:(%esi),(%dx)
  40c4a1:	6f                   	outsl  %ds:(%esi),(%dx)
  40c4a2:	5f                   	pop    %edi
  40c4a3:	73 74                	jae    40c519 <.debug_info+0x4f3>
  40c4a5:	72 69                	jb     40c510 <.debug_info+0x4ea>
  40c4a7:	6e                   	outsb  %ds:(%esi),(%dx)
  40c4a8:	67 6f                	outsl  %ds:(%si),(%dx)
  40c4aa:	70 00                	jo     40c4ac <.debug_info+0x486>
  40c4ac:	00 11                	add    %dl,(%ecx)
  40c4ae:	6c                   	insb   (%dx),%es:(%edi)
  40c4af:	69 62 63 61 6c 6c 00 	imul   $0x6c6c61,0x63(%edx),%esp
  40c4b6:	01 11                	add    %edx,(%ecx)
  40c4b8:	72 65                	jb     40c51f <.debug_info+0x4f9>
  40c4ba:	70 5f                	jo     40c51b <.debug_info+0x4f5>
  40c4bc:	70 72                	jo     40c530 <.debug_info+0x50a>
  40c4be:	65 66 69 78 5f 31 5f 	imul   $0x5f31,%gs:0x5f(%eax),%di
  40c4c5:	62 79 74             	bound  %edi,0x74(%ecx)
  40c4c8:	65 00 02             	add    %al,%gs:(%edx)
  40c4cb:	11 72 65             	adc    %esi,0x65(%edx)
  40c4ce:	70 5f                	jo     40c52f <.debug_info+0x509>
  40c4d0:	70 72                	jo     40c544 <.debug_info+0x51e>
  40c4d2:	65 66 69 78 5f 34 5f 	imul   $0x5f34,%gs:0x5f(%eax),%di
  40c4d9:	62 79 74             	bound  %edi,0x74(%ecx)
  40c4dc:	65 00 03             	add    %al,%gs:(%ebx)
  40c4df:	11 72 65             	adc    %esi,0x65(%edx)
  40c4e2:	70 5f                	jo     40c543 <.debug_info+0x51d>
  40c4e4:	70 72                	jo     40c558 <.debug_info+0x532>
  40c4e6:	65 66 69 78 5f 38 5f 	imul   $0x5f38,%gs:0x5f(%eax),%di
  40c4ed:	62 79 74             	bound  %edi,0x74(%ecx)
  40c4f0:	65 00 04 11          	add    %al,%gs:(%ecx,%edx,1)
  40c4f4:	6c                   	insb   (%dx),%es:(%edi)
  40c4f5:	6f                   	outsl  %ds:(%esi),(%dx)
  40c4f6:	6f                   	outsl  %ds:(%esi),(%dx)
  40c4f7:	70 5f                	jo     40c558 <.debug_info+0x532>
  40c4f9:	31 5f 62             	xor    %ebx,0x62(%edi)
  40c4fc:	79 74                	jns    40c572 <.debug_info+0x54c>
  40c4fe:	65 00 05 11 6c 6f 6f 	add    %al,%gs:0x6f6f6c11
  40c505:	70 00                	jo     40c507 <.debug_info+0x4e1>
  40c507:	06                   	push   %es
  40c508:	11 75 6e             	adc    %esi,0x6e(%ebp)
  40c50b:	72 6f                	jb     40c57c <.debug_info+0x556>
  40c50d:	6c                   	insb   (%dx),%es:(%edi)
  40c50e:	6c                   	insb   (%dx),%es:(%edi)
  40c50f:	65 64 5f             	gs fs pop %edi
  40c512:	6c                   	insb   (%dx),%es:(%edi)
  40c513:	6f                   	outsl  %ds:(%esi),(%dx)
  40c514:	6f                   	outsl  %ds:(%esi),(%dx)
  40c515:	70 00                	jo     40c517 <.debug_info+0x4f1>
  40c517:	07                   	pop    %es
  40c518:	11 76 65             	adc    %esi,0x65(%esi)
  40c51b:	63 74 6f 72          	arpl   %si,0x72(%edi,%ebp,2)
  40c51f:	5f                   	pop    %edi
  40c520:	6c                   	insb   (%dx),%es:(%edi)
  40c521:	6f                   	outsl  %ds:(%esi),(%dx)
  40c522:	6f                   	outsl  %ds:(%esi),(%dx)
  40c523:	70 00                	jo     40c525 <.debug_info+0x4ff>
  40c525:	08 11                	or     %dl,(%ecx)
  40c527:	6c                   	insb   (%dx),%es:(%edi)
  40c528:	61                   	popa   
  40c529:	73 74                	jae    40c59f <.debug_info+0x579>
  40c52b:	5f                   	pop    %edi
  40c52c:	61                   	popa   
  40c52d:	6c                   	insb   (%dx),%es:(%edi)
  40c52e:	67 00 09             	add    %cl,(%bx,%di)
  40c531:	00 03                	add    %al,(%ebx)
  40c533:	5e                   	pop    %esi
  40c534:	04 00                	add    $0x0,%al
  40c536:	00 08                	add    %cl,(%eax)
  40c538:	27                   	daa    
  40c539:	05 00 00 1c 05       	add    $0x51c0000,%eax
  40c53e:	00 00                	add    %al,(%eax)
  40c540:	09 00                	or     %eax,(%eax)
  40c542:	03 11                	add    (%ecx),%edx
  40c544:	05 00 00 06 04       	add    $0x4060000,%eax
  40c549:	4c                   	dec    %esp
  40c54a:	01 00                	add    %eax,(%eax)
  40c54c:	00 03                	add    %al,(%ebx)
  40c54e:	21 05 00 00 0b 75    	and    %eax,0x750b0000
  40c554:	6e                   	outsb  %ds:(%esi),(%dx)
  40c555:	73 70                	jae    40c5c7 <.debug_info+0x5a1>
  40c557:	65 63 5f 73          	arpl   %bx,%gs:0x73(%edi)
  40c55b:	74 72                	je     40c5cf <.debug_info+0x5a9>
  40c55d:	69 6e 67 73 00 06 4a 	imul   $0x4a060073,0x67(%esi),%ebp
  40c564:	01 1a                	add    %ebx,(%edx)
  40c566:	1c 05                	sbb    $0x5,%al
  40c568:	00 00                	add    %al,(%eax)
  40c56a:	0b 75 6e             	or     0x6e(%ebp),%esi
  40c56d:	73 70                	jae    40c5df <.debug_info+0x5b9>
  40c56f:	65 63 76 5f          	arpl   %si,%gs:0x5f(%esi)
  40c573:	73 74                	jae    40c5e9 <.debug_info+0x5c3>
  40c575:	72 69                	jb     40c5e0 <.debug_info+0x5ba>
  40c577:	6e                   	outsb  %ds:(%esi),(%dx)
  40c578:	67 73 00             	addr16 jae 40c57b <.debug_info+0x555>
  40c57b:	06                   	push   %es
  40c57c:	a6                   	cmpsb  %es:(%edi),%ds:(%esi)
  40c57d:	01 1a                	add    %ebx,(%edx)
  40c57f:	1c 05                	sbb    $0x5,%al
  40c581:	00 00                	add    %al,(%eax)
  40c583:	04 73                	add    $0x73,%al
  40c585:	74 72                	je     40c5f9 <.debug_info+0x5d3>
  40c587:	69 6e 67 6f 70 5f 73 	imul   $0x735f706f,0x67(%esi),%ebp
  40c58e:	74 72                	je     40c602 <.debug_info+0x5dc>
  40c590:	61                   	popa   
  40c591:	74 65                	je     40c5f8 <.debug_info+0x5d2>
  40c593:	67 79 00             	addr16 jns 40c596 <.debug_info+0x570>
  40c596:	0c 07                	or     $0x7,%al
  40c598:	e1 10                	loope  40c5aa <.debug_info+0x584>
  40c59a:	a4                   	movsb  %ds:(%esi),%es:(%edi)
  40c59b:	05 00 00 05 6d       	add    $0x6d050000,%eax
  40c5a0:	61                   	popa   
  40c5a1:	78 00                	js     40c5a3 <.debug_info+0x57d>
  40c5a3:	07                   	pop    %es
  40c5a4:	e2 0f                	loop   40c5b5 <.debug_info+0x58f>
  40c5a6:	ec                   	in     (%dx),%al
  40c5a7:	00 00                	add    %al,(%eax)
  40c5a9:	00 00                	add    %al,(%eax)
  40c5ab:	05 61 6c 67 00       	add    $0x676c61,%eax
  40c5b0:	07                   	pop    %es
  40c5b1:	e3 1d                	jecxz  40c5d0 <.debug_info+0x5aa>
  40c5b3:	0c 05                	or     $0x5,%al
  40c5b5:	00 00                	add    %al,(%eax)
  40c5b7:	04 05                	add    $0x5,%al
  40c5b9:	6e                   	outsb  %ds:(%esi),(%dx)
  40c5ba:	6f                   	outsl  %ds:(%esi),(%dx)
  40c5bb:	61                   	popa   
  40c5bc:	6c                   	insb   (%dx),%es:(%edi)
  40c5bd:	69 67 6e 00 07 e4 09 	imul   $0x9e40700,0x6e(%edi),%esp
  40c5c4:	e5 00                	in     $0x0,%eax
  40c5c6:	00 00                	add    %al,(%eax)
  40c5c8:	08 00                	or     %al,(%eax)
  40c5ca:	03 5d 05             	add    0x5(%ebp),%ebx
  40c5cd:	00 00                	add    %al,(%eax)
  40c5cf:	04 73                	add    $0x73,%al
  40c5d1:	74 72                	je     40c645 <.debug_info+0x61f>
  40c5d3:	69 6e 67 6f 70 5f 61 	imul   $0x615f706f,0x67(%esi),%ebp
  40c5da:	6c                   	insb   (%dx),%es:(%edi)
  40c5db:	67 73 00             	addr16 jae 40c5de <.debug_info+0x5b8>
  40c5de:	34 07                	xor    $0x7,%al
  40c5e0:	de 08                	fimuls (%eax)
  40c5e2:	e5 05                	in     $0x5,%eax
  40c5e4:	00 00                	add    %al,(%eax)
  40c5e6:	05 75 6e 6b 6e       	add    $0x6e6b6e75,%eax
  40c5eb:	6f                   	outsl  %ds:(%esi),(%dx)
  40c5ec:	77 6e                	ja     40c65c <.debug_info+0x636>
  40c5ee:	5f                   	pop    %edi
  40c5ef:	73 69                	jae    40c65a <.debug_info+0x634>
  40c5f1:	7a 65                	jp     40c658 <.debug_info+0x632>
  40c5f3:	00 07                	add    %al,(%edi)
  40c5f5:	e0 1b                	loopne 40c612 <.debug_info+0x5ec>
  40c5f7:	0c 05                	or     $0x5,%al
  40c5f9:	00 00                	add    %al,(%eax)
  40c5fb:	00 05 73 69 7a 65    	add    %al,0x657a6973
  40c601:	00 07                	add    %al,(%edi)
  40c603:	e5 05                	in     $0x5,%eax
  40c605:	f5                   	cmc    
  40c606:	05 00 00 04 00       	add    $0x40000,%eax
  40c60b:	08 a4 05 00 00 f5 05 	or     %ah,0x5f50000(%ebp,%eax,1)
  40c612:	00 00                	add    %al,(%eax)
  40c614:	0c f1                	or     $0xf1,%al
  40c616:	00 00                	add    %al,(%eax)
  40c618:	00 03                	add    %al,(%ebx)
  40c61a:	00 03                	add    %al,(%ebx)
  40c61c:	e5 05                	in     $0x5,%eax
  40c61e:	00 00                	add    %al,(%eax)
  40c620:	12 70 72             	adc    0x72(%eax),%dh
  40c623:	6f                   	outsl  %ds:(%esi),(%dx)
  40c624:	63 65 73             	arpl   %sp,0x73(%ebp)
  40c627:	73 6f                	jae    40c698 <.debug_info+0x672>
  40c629:	72 5f                	jb     40c68a <.debug_info+0x664>
  40c62b:	63 6f 73             	arpl   %bp,0x73(%edi)
  40c62e:	74 73                	je     40c6a3 <.debug_info+0x67d>
  40c630:	00 90 01 07 ea 08    	add    %dl,0x8ea0701(%eax)
  40c636:	71 0b                	jno    40c643 <.debug_info+0x61d>
  40c638:	00 00                	add    %al,(%eax)
  40c63a:	05 61 64 64 00       	add    $0x646461,%eax
  40c63f:	07                   	pop    %es
  40c640:	eb 0d                	jmp    40c64f <.debug_info+0x629>
  40c642:	ec                   	in     (%dx),%al
  40c643:	00 00                	add    %al,(%eax)
  40c645:	00 00                	add    %al,(%eax)
  40c647:	05 6c 65 61 00       	add    $0x61656c,%eax
  40c64c:	07                   	pop    %es
  40c64d:	ec                   	in     (%dx),%al
  40c64e:	0d ec 00 00 00       	or     $0xec,%eax
  40c653:	04 05                	add    $0x5,%al
  40c655:	73 68                	jae    40c6bf <.debug_info+0x699>
  40c657:	69 66 74 5f 76 61 72 	imul   $0x7261765f,0x74(%esi),%esp
  40c65e:	00 07                	add    %al,(%edi)
  40c660:	ed                   	in     (%dx),%eax
  40c661:	0d ec 00 00 00       	or     $0xec,%eax
  40c666:	08 05 73 68 69 66    	or     %al,0x66696873
  40c66c:	74 5f                	je     40c6cd <.debug_info+0x6a7>
  40c66e:	63 6f 6e             	arpl   %bp,0x6e(%edi)
  40c671:	73 74                	jae    40c6e7 <.debug_info+0x6c1>
  40c673:	00 07                	add    %al,(%edi)
  40c675:	ee                   	out    %al,(%dx)
  40c676:	0d ec 00 00 00       	or     $0xec,%eax
  40c67b:	0c 05                	or     $0x5,%al
  40c67d:	6d                   	insl   (%dx),%es:(%edi)
  40c67e:	75 6c                	jne    40c6ec <.debug_info+0x6c6>
  40c680:	74 5f                	je     40c6e1 <.debug_info+0x6bb>
  40c682:	69 6e 69 74 00 07 ef 	imul   $0xef070074,0x69(%esi),%ebp
  40c689:	0d 86 0b 00 00       	or     $0xb86,%eax
  40c68e:	10 05 6d 75 6c 74    	adc    %al,0x746c756d
  40c694:	5f                   	pop    %edi
  40c695:	62 69 74             	bound  %ebp,0x74(%ecx)
  40c698:	00 07                	add    %al,(%edi)
  40c69a:	f1                   	icebp  
  40c69b:	0d ec 00 00 00       	or     $0xec,%eax
  40c6a0:	24 05                	and    $0x5,%al
  40c6a2:	64 69 76 69 64 65 00 	imul   $0x7006564,%fs:0x69(%esi),%esi
  40c6a9:	07 
  40c6aa:	f2 0d 86 0b 00 00    	repnz or $0xb86,%eax
  40c6b0:	28 05 6d 6f 76 73    	sub    %al,0x73766f6d
  40c6b6:	78 00                	js     40c6b8 <.debug_info+0x692>
  40c6b8:	07                   	pop    %es
  40c6b9:	f4                   	hlt    
  40c6ba:	07                   	pop    %es
  40c6bb:	e5 00                	in     $0x0,%eax
  40c6bd:	00 00                	add    %al,(%eax)
  40c6bf:	3c 05                	cmp    $0x5,%al
  40c6c1:	6d                   	insl   (%dx),%es:(%edi)
  40c6c2:	6f                   	outsl  %ds:(%esi),(%dx)
  40c6c3:	76 7a                	jbe    40c73f <.debug_info+0x719>
  40c6c5:	78 00                	js     40c6c7 <.debug_info+0x6a1>
  40c6c7:	07                   	pop    %es
  40c6c8:	f5                   	cmc    
  40c6c9:	07                   	pop    %es
  40c6ca:	e5 00                	in     $0x0,%eax
  40c6cc:	00 00                	add    %al,(%eax)
  40c6ce:	40                   	inc    %eax
  40c6cf:	05 6c 61 72 67       	add    $0x6772616c,%eax
  40c6d4:	65 5f                	gs pop %edi
  40c6d6:	69 6e 73 6e 00 07 f6 	imul   $0xf607006e,0x73(%esi),%ebp
  40c6dd:	0d ec 00 00 00       	or     $0xec,%eax
  40c6e2:	44                   	inc    %esp
  40c6e3:	05 6d 6f 76 65       	add    $0x65766f6d,%eax
  40c6e8:	5f                   	pop    %edi
  40c6e9:	72 61                	jb     40c74c <.debug_info+0x726>
  40c6eb:	74 69                	je     40c756 <.debug_info+0x730>
  40c6ed:	6f                   	outsl  %ds:(%esi),(%dx)
  40c6ee:	00 07                	add    %al,(%edi)
  40c6f0:	f7 0d ec 00 00 00 48 	testl  $0x6f6d0548,0xec
  40c6f7:	05 6d 6f 
  40c6fa:	76 7a                	jbe    40c776 <.debug_info+0x750>
  40c6fc:	62 6c 5f 6c          	bound  %ebp,0x6c(%edi,%ebx,2)
  40c700:	6f                   	outsl  %ds:(%esi),(%dx)
  40c701:	61                   	popa   
  40c702:	64 00 07             	add    %al,%fs:(%edi)
  40c705:	f9                   	stc    
  40c706:	0d ec 00 00 00       	or     $0xec,%eax
  40c70b:	4c                   	dec    %esp
  40c70c:	05 69 6e 74 5f       	add    $0x5f746e69,%eax
  40c711:	6c                   	insb   (%dx),%es:(%edi)
  40c712:	6f                   	outsl  %ds:(%esi),(%dx)
  40c713:	61                   	popa   
  40c714:	64 00 07             	add    %al,%fs:(%edi)
  40c717:	fa                   	cli    
  40c718:	0d 9b 0b 00 00       	or     $0xb9b,%eax
  40c71d:	50                   	push   %eax
  40c71e:	05 69 6e 74 5f       	add    $0x5f746e69,%eax
  40c723:	73 74                	jae    40c799 <.debug_info+0x773>
  40c725:	6f                   	outsl  %ds:(%esi),(%dx)
  40c726:	72 65                	jb     40c78d <.debug_info+0x767>
  40c728:	00 07                	add    %al,(%edi)
  40c72a:	fd                   	std    
  40c72b:	0d 9b 0b 00 00       	or     $0xb9b,%eax
  40c730:	5c                   	pop    %esp
  40c731:	05 66 70 5f 6d       	add    $0x6d5f7066,%eax
  40c736:	6f                   	outsl  %ds:(%esi),(%dx)
  40c737:	76 65                	jbe    40c79e <.debug_info+0x778>
  40c739:	00 07                	add    %al,(%edi)
  40c73b:	ff 0d ec 00 00 00    	decl   0xec
  40c741:	68 13 66 70 5f       	push   $0x5f706613
  40c746:	6c                   	insb   (%dx),%es:(%edi)
  40c747:	6f                   	outsl  %ds:(%esi),(%dx)
  40c748:	61                   	popa   
  40c749:	64 00 07             	add    %al,%fs:(%edi)
  40c74c:	00 01                	add    %al,(%ecx)
  40c74e:	0d 9b 0b 00 00       	or     $0xb9b,%eax
  40c753:	6c                   	insb   (%dx),%es:(%edi)
  40c754:	13 66 70             	adc    0x70(%esi),%esp
  40c757:	5f                   	pop    %edi
  40c758:	73 74                	jae    40c7ce <.debug_info+0x7a8>
  40c75a:	6f                   	outsl  %ds:(%esi),(%dx)
  40c75b:	72 65                	jb     40c7c2 <.debug_info+0x79c>
  40c75d:	00 07                	add    %al,(%edi)
  40c75f:	02 01                	add    (%ecx),%al
  40c761:	0d 9b 0b 00 00       	or     $0xb9b,%eax
  40c766:	78 13                	js     40c77b <.debug_info+0x755>
  40c768:	6d                   	insl   (%dx),%es:(%edi)
  40c769:	6d                   	insl   (%dx),%es:(%edi)
  40c76a:	78 5f                	js     40c7cb <.debug_info+0x7a5>
  40c76c:	6d                   	insl   (%dx),%es:(%edi)
  40c76d:	6f                   	outsl  %ds:(%esi),(%dx)
  40c76e:	76 65                	jbe    40c7d5 <.debug_info+0x7af>
  40c770:	00 07                	add    %al,(%edi)
  40c772:	04 01                	add    $0x1,%al
  40c774:	0d ec 00 00 00       	or     $0xec,%eax
  40c779:	84 13                	test   %dl,(%ebx)
  40c77b:	6d                   	insl   (%dx),%es:(%edi)
  40c77c:	6d                   	insl   (%dx),%es:(%edi)
  40c77d:	78 5f                	js     40c7de <.debug_info+0x7b8>
  40c77f:	6c                   	insb   (%dx),%es:(%edi)
  40c780:	6f                   	outsl  %ds:(%esi),(%dx)
  40c781:	61                   	popa   
  40c782:	64 00 07             	add    %al,%fs:(%edi)
  40c785:	05 01 0d b0 0b       	add    $0xbb00d01,%eax
  40c78a:	00 00                	add    %al,(%eax)
  40c78c:	88 13                	mov    %dl,(%ebx)
  40c78e:	6d                   	insl   (%dx),%es:(%edi)
  40c78f:	6d                   	insl   (%dx),%es:(%edi)
  40c790:	78 5f                	js     40c7f1 <.debug_info+0x7cb>
  40c792:	73 74                	jae    40c808 <.debug_info+0x7e2>
  40c794:	6f                   	outsl  %ds:(%esi),(%dx)
  40c795:	72 65                	jb     40c7fc <.debug_info+0x7d6>
  40c797:	00 07                	add    %al,(%edi)
  40c799:	07                   	pop    %es
  40c79a:	01 0d b0 0b 00 00    	add    %ecx,0xbb0
  40c7a0:	90                   	nop
  40c7a1:	13 78 6d             	adc    0x6d(%eax),%edi
  40c7a4:	6d                   	insl   (%dx),%es:(%edi)
  40c7a5:	5f                   	pop    %edi
  40c7a6:	6d                   	insl   (%dx),%es:(%edi)
  40c7a7:	6f                   	outsl  %ds:(%esi),(%dx)
  40c7a8:	76 65                	jbe    40c80f <.debug_info+0x7e9>
  40c7aa:	00 07                	add    %al,(%edi)
  40c7ac:	09 01                	or     %eax,(%ecx)
  40c7ae:	0d ec 00 00 00       	or     $0xec,%eax
  40c7b3:	98                   	cwtl   
  40c7b4:	13 79 6d             	adc    0x6d(%ecx),%edi
  40c7b7:	6d                   	insl   (%dx),%es:(%edi)
  40c7b8:	5f                   	pop    %edi
  40c7b9:	6d                   	insl   (%dx),%es:(%edi)
  40c7ba:	6f                   	outsl  %ds:(%esi),(%dx)
  40c7bb:	76 65                	jbe    40c822 <.debug_info+0x7fc>
  40c7bd:	00 07                	add    %al,(%edi)
  40c7bf:	09 01                	or     %eax,(%ecx)
  40c7c1:	17                   	pop    %ss
  40c7c2:	ec                   	in     (%dx),%al
  40c7c3:	00 00                	add    %al,(%eax)
  40c7c5:	00 9c 13 7a 6d 6d 5f 	add    %bl,0x5f6d6d7a(%ebx,%edx,1)
  40c7cc:	6d                   	insl   (%dx),%es:(%edi)
  40c7cd:	6f                   	outsl  %ds:(%esi),(%dx)
  40c7ce:	76 65                	jbe    40c835 <.debug_info+0x80f>
  40c7d0:	00 07                	add    %al,(%edi)
  40c7d2:	0a 01                	or     (%ecx),%al
  40c7d4:	06                   	push   %es
  40c7d5:	ec                   	in     (%dx),%al
  40c7d6:	00 00                	add    %al,(%eax)
  40c7d8:	00 a0 13 73 73 65    	add    %ah,0x65737313(%eax)
  40c7de:	5f                   	pop    %edi
  40c7df:	6c                   	insb   (%dx),%es:(%edi)
  40c7e0:	6f                   	outsl  %ds:(%esi),(%dx)
  40c7e1:	61                   	popa   
  40c7e2:	64 00 07             	add    %al,%fs:(%edi)
  40c7e5:	0b 01                	or     (%ecx),%eax
  40c7e7:	0d 86 0b 00 00       	or     $0xb86,%eax
  40c7ec:	a4                   	movsb  %ds:(%esi),%es:(%edi)
  40c7ed:	13 73 73             	adc    0x73(%ebx),%esi
  40c7f0:	65 5f                	gs pop %edi
  40c7f2:	75 6e                	jne    40c862 <.debug_info+0x83c>
  40c7f4:	61                   	popa   
  40c7f5:	6c                   	insb   (%dx),%es:(%edi)
  40c7f6:	69 67 6e 65 64 5f 6c 	imul   $0x6c5f6465,0x6e(%edi),%esp
  40c7fd:	6f                   	outsl  %ds:(%esi),(%dx)
  40c7fe:	61                   	popa   
  40c7ff:	64 00 07             	add    %al,%fs:(%edi)
  40c802:	0d 01 0d 86 0b       	or     $0xb860d01,%eax
  40c807:	00 00                	add    %al,(%eax)
  40c809:	b8 13 73 73 65       	mov    $0x65737313,%eax
  40c80e:	5f                   	pop    %edi
  40c80f:	73 74                	jae    40c885 <.debug_info+0x85f>
  40c811:	6f                   	outsl  %ds:(%esi),(%dx)
  40c812:	72 65                	jb     40c879 <.debug_info+0x853>
  40c814:	00 07                	add    %al,(%edi)
  40c816:	0e                   	push   %cs
  40c817:	01 0d 86 0b 00 00    	add    %ecx,0xb86
  40c81d:	cc                   	int3   
  40c81e:	13 73 73             	adc    0x73(%ebx),%esi
  40c821:	65 5f                	gs pop %edi
  40c823:	75 6e                	jne    40c893 <.debug_info+0x86d>
  40c825:	61                   	popa   
  40c826:	6c                   	insb   (%dx),%es:(%edi)
  40c827:	69 67 6e 65 64 5f 73 	imul   $0x735f6465,0x6e(%edi),%esp
  40c82e:	74 6f                	je     40c89f <.debug_info+0x879>
  40c830:	72 65                	jb     40c897 <.debug_info+0x871>
  40c832:	00 07                	add    %al,(%edi)
  40c834:	10 01                	adc    %al,(%ecx)
  40c836:	0d 86 0b 00 00       	or     $0xb86,%eax
  40c83b:	e0 13                	loopne 40c850 <.debug_info+0x82a>
  40c83d:	6d                   	insl   (%dx),%es:(%edi)
  40c83e:	6d                   	insl   (%dx),%es:(%edi)
  40c83f:	78 73                	js     40c8b4 <.debug_info+0x88e>
  40c841:	73 65                	jae    40c8a8 <.debug_info+0x882>
  40c843:	5f                   	pop    %edi
  40c844:	74 6f                	je     40c8b5 <.debug_info+0x88f>
  40c846:	5f                   	pop    %edi
  40c847:	69 6e 74 65 67 65 72 	imul   $0x72656765,0x74(%esi),%ebp
  40c84e:	00 07                	add    %al,(%edi)
  40c850:	11 01                	adc    %eax,(%ecx)
  40c852:	0d ec 00 00 00       	or     $0xec,%eax
  40c857:	f4                   	hlt    
  40c858:	13 73 73             	adc    0x73(%ebx),%esi
  40c85b:	65 6d                	gs insl (%dx),%es:(%edi)
  40c85d:	6d                   	insl   (%dx),%es:(%edi)
  40c85e:	78 5f                	js     40c8bf <.debug_info+0x899>
  40c860:	74 6f                	je     40c8d1 <.debug_info+0x8ab>
  40c862:	5f                   	pop    %edi
  40c863:	69 6e 74 65 67 65 72 	imul   $0x72656765,0x74(%esi),%ebp
  40c86a:	00 07                	add    %al,(%edi)
  40c86c:	13 01                	adc    (%ecx),%eax
  40c86e:	0d ec 00 00 00       	or     $0xec,%eax
  40c873:	f8                   	clc    
  40c874:	13 67 61             	adc    0x61(%edi),%esp
  40c877:	74 68                	je     40c8e1 <.debug_info+0x8bb>
  40c879:	65 72 5f             	gs jb  40c8db <.debug_info+0x8b5>
  40c87c:	73 74                	jae    40c8f2 <.debug_info+0x8cc>
  40c87e:	61                   	popa   
  40c87f:	74 69                	je     40c8ea <.debug_info+0x8c4>
  40c881:	63 00                	arpl   %ax,(%eax)
  40c883:	07                   	pop    %es
  40c884:	14 01                	adc    $0x1,%al
  40c886:	0d ec 00 00 00       	or     $0xec,%eax
  40c88b:	fc                   	cld    
  40c88c:	14 67                	adc    $0x67,%al
  40c88e:	61                   	popa   
  40c88f:	74 68                	je     40c8f9 <.debug_info+0x8d3>
  40c891:	65 72 5f             	gs jb  40c8f3 <.debug_info+0x8cd>
  40c894:	70 65                	jo     40c8fb <.debug_info+0x8d5>
  40c896:	72 5f                	jb     40c8f7 <.debug_info+0x8d1>
  40c898:	65 6c                	gs insb (%dx),%es:(%edi)
  40c89a:	74 00                	je     40c89c <.debug_info+0x876>
  40c89c:	07                   	pop    %es
  40c89d:	14 01                	adc    $0x1,%al
  40c89f:	1c ec                	sbb    $0xec,%al
  40c8a1:	00 00                	add    %al,(%eax)
  40c8a3:	00 00                	add    %al,(%eax)
  40c8a5:	01 14 73             	add    %edx,(%ebx,%esi,2)
  40c8a8:	63 61 74             	arpl   %sp,0x74(%ecx)
  40c8ab:	74 65                	je     40c912 <.debug_info+0x8ec>
  40c8ad:	72 5f                	jb     40c90e <.debug_info+0x8e8>
  40c8af:	73 74                	jae    40c925 <.debug_info+0x8ff>
  40c8b1:	61                   	popa   
  40c8b2:	74 69                	je     40c91d <.debug_info+0x8f7>
  40c8b4:	63 00                	arpl   %ax,(%eax)
  40c8b6:	07                   	pop    %es
  40c8b7:	16                   	push   %ss
  40c8b8:	01 0d ec 00 00 00    	add    %ecx,0xec
  40c8be:	04 01                	add    $0x1,%al
  40c8c0:	14 73                	adc    $0x73,%al
  40c8c2:	63 61 74             	arpl   %sp,0x74(%ecx)
  40c8c5:	74 65                	je     40c92c <.debug_info+0x906>
  40c8c7:	72 5f                	jb     40c928 <.debug_info+0x902>
  40c8c9:	70 65                	jo     40c930 <.debug_info+0x90a>
  40c8cb:	72 5f                	jb     40c92c <.debug_info+0x906>
  40c8cd:	65 6c                	gs insb (%dx),%es:(%edi)
  40c8cf:	74 00                	je     40c8d1 <.debug_info+0x8ab>
  40c8d1:	07                   	pop    %es
  40c8d2:	16                   	push   %ss
  40c8d3:	01 1d ec 00 00 00    	add    %ebx,0xec
  40c8d9:	08 01                	or     %al,(%ecx)
  40c8db:	14 6c                	adc    $0x6c,%al
  40c8dd:	31 5f 63             	xor    %ebx,0x63(%edi)
  40c8e0:	61                   	popa   
  40c8e1:	63 68 65             	arpl   %bp,0x65(%eax)
  40c8e4:	5f                   	pop    %edi
  40c8e5:	73 69                	jae    40c950 <.debug_info+0x92a>
  40c8e7:	7a 65                	jp     40c94e <.debug_info+0x928>
  40c8e9:	00 07                	add    %al,(%edi)
  40c8eb:	18 01                	sbb    %al,(%ecx)
  40c8ed:	0d ec 00 00 00       	or     $0xec,%eax
  40c8f2:	0c 01                	or     $0x1,%al
  40c8f4:	14 6c                	adc    $0x6c,%al
  40c8f6:	32 5f 63             	xor    0x63(%edi),%bl
  40c8f9:	61                   	popa   
  40c8fa:	63 68 65             	arpl   %bp,0x65(%eax)
  40c8fd:	5f                   	pop    %edi
  40c8fe:	73 69                	jae    40c969 <.debug_info+0x943>
  40c900:	7a 65                	jp     40c967 <.debug_info+0x941>
  40c902:	00 07                	add    %al,(%edi)
  40c904:	19 01                	sbb    %eax,(%ecx)
  40c906:	0d ec 00 00 00       	or     $0xec,%eax
  40c90b:	10 01                	adc    %al,(%ecx)
  40c90d:	14 70                	adc    $0x70,%al
  40c90f:	72 65                	jb     40c976 <.debug_info+0x950>
  40c911:	66 65 74 63          	data16 gs je 40c978 <.debug_info+0x952>
  40c915:	68 5f 62 6c 6f       	push   $0x6f6c625f
  40c91a:	63 6b 00             	arpl   %bp,0x0(%ebx)
  40c91d:	07                   	pop    %es
  40c91e:	1a 01                	sbb    (%ecx),%al
  40c920:	0d ec 00 00 00       	or     $0xec,%eax
  40c925:	14 01                	adc    $0x1,%al
  40c927:	14 73                	adc    $0x73,%al
  40c929:	69 6d 75 6c 74 61 6e 	imul   $0x6e61746c,0x75(%ebp),%ebp
  40c930:	65 6f                	outsl  %gs:(%esi),(%dx)
  40c932:	75 73                	jne    40c9a7 <.debug_info+0x981>
  40c934:	5f                   	pop    %edi
  40c935:	70 72                	jo     40c9a9 <.debug_info+0x983>
  40c937:	65 66 65 74 63       	gs data16 gs je 40c99f <.debug_info+0x979>
  40c93c:	68 65 73 00 07       	push   $0x7007365
  40c941:	1b 01                	sbb    (%ecx),%eax
  40c943:	0d ec 00 00 00       	or     $0xec,%eax
  40c948:	18 01                	sbb    %al,(%ecx)
  40c94a:	14 62                	adc    $0x62,%al
  40c94c:	72 61                	jb     40c9af <.debug_info+0x989>
  40c94e:	6e                   	outsb  %ds:(%esi),(%dx)
  40c94f:	63 68 5f             	arpl   %bp,0x5f(%eax)
  40c952:	63 6f 73             	arpl   %bp,0x73(%edi)
  40c955:	74 00                	je     40c957 <.debug_info+0x931>
  40c957:	07                   	pop    %es
  40c958:	1d 01 0d ec 00       	sbb    $0xec0d01,%eax
  40c95d:	00 00                	add    %al,(%eax)
  40c95f:	1c 01                	sbb    $0x1,%al
  40c961:	14 66                	adc    $0x66,%al
  40c963:	61                   	popa   
  40c964:	64 64 00 07          	fs add %al,%fs:(%edi)
  40c968:	1e                   	push   %ds
  40c969:	01 0d ec 00 00 00    	add    %ecx,0xec
  40c96f:	20 01                	and    %al,(%ecx)
  40c971:	14 66                	adc    $0x66,%al
  40c973:	6d                   	insl   (%dx),%es:(%edi)
  40c974:	75 6c                	jne    40c9e2 <.debug_info+0x9bc>
  40c976:	00 07                	add    %al,(%edi)
  40c978:	1f                   	pop    %ds
  40c979:	01 0d ec 00 00 00    	add    %ecx,0xec
  40c97f:	24 01                	and    $0x1,%al
  40c981:	14 66                	adc    $0x66,%al
  40c983:	64 69 76 00 07 20 01 	imul   $0xd012007,%fs:0x0(%esi),%esi
  40c98a:	0d 
  40c98b:	ec                   	in     (%dx),%al
  40c98c:	00 00                	add    %al,(%eax)
  40c98e:	00 28                	add    %ch,(%eax)
  40c990:	01 14 66             	add    %edx,(%esi,%eiz,2)
  40c993:	61                   	popa   
  40c994:	62 73 00             	bound  %esi,0x0(%ebx)
  40c997:	07                   	pop    %es
  40c998:	21 01                	and    %eax,(%ecx)
  40c99a:	0d ec 00 00 00       	or     $0xec,%eax
  40c99f:	2c 01                	sub    $0x1,%al
  40c9a1:	14 66                	adc    $0x66,%al
  40c9a3:	63 68 73             	arpl   %bp,0x73(%eax)
  40c9a6:	00 07                	add    %al,(%edi)
  40c9a8:	22 01                	and    (%ecx),%al
  40c9aa:	0d ec 00 00 00       	or     $0xec,%eax
  40c9af:	30 01                	xor    %al,(%ecx)
  40c9b1:	14 66                	adc    $0x66,%al
  40c9b3:	73 71                	jae    40ca26 <.debug_info+0xa00>
  40c9b5:	72 74                	jb     40ca2b <.debug_info+0xa05>
  40c9b7:	00 07                	add    %al,(%edi)
  40c9b9:	23 01                	and    (%ecx),%eax
  40c9bb:	0d ec 00 00 00       	or     $0xec,%eax
  40c9c0:	34 01                	xor    $0x1,%al
  40c9c2:	14 73                	adc    $0x73,%al
  40c9c4:	73 65                	jae    40ca2b <.debug_info+0xa05>
  40c9c6:	5f                   	pop    %edi
  40c9c7:	6f                   	outsl  %ds:(%esi),(%dx)
  40c9c8:	70 00                	jo     40c9ca <.debug_info+0x9a4>
  40c9ca:	07                   	pop    %es
  40c9cb:	26 01 0d ec 00 00 00 	add    %ecx,%es:0xec
  40c9d2:	38 01                	cmp    %al,(%ecx)
  40c9d4:	14 61                	adc    $0x61,%al
  40c9d6:	64 64 73 73          	fs fs jae 40ca4d <.debug_info+0xa27>
  40c9da:	00 07                	add    %al,(%edi)
  40c9dc:	27                   	daa    
  40c9dd:	01 0d ec 00 00 00    	add    %ecx,0xec
  40c9e3:	3c 01                	cmp    $0x1,%al
  40c9e5:	14 6d                	adc    $0x6d,%al
  40c9e7:	75 6c                	jne    40ca55 <.debug_info+0xa2f>
  40c9e9:	73 73                	jae    40ca5e <.debug_info+0xa38>
  40c9eb:	00 07                	add    %al,(%edi)
  40c9ed:	28 01                	sub    %al,(%ecx)
  40c9ef:	0d ec 00 00 00       	or     $0xec,%eax
  40c9f4:	40                   	inc    %eax
  40c9f5:	01 14 6d 75 6c 73 64 	add    %edx,0x64736c75(,%ebp,2)
  40c9fc:	00 07                	add    %al,(%edi)
  40c9fe:	29 01                	sub    %eax,(%ecx)
  40ca00:	0d ec 00 00 00       	or     $0xec,%eax
  40ca05:	44                   	inc    %esp
  40ca06:	01 14 66             	add    %edx,(%esi,%eiz,2)
  40ca09:	6d                   	insl   (%dx),%es:(%edi)
  40ca0a:	61                   	popa   
  40ca0b:	73 73                	jae    40ca80 <.debug_info+0xa5a>
  40ca0d:	00 07                	add    %al,(%edi)
  40ca0f:	2a 01                	sub    (%ecx),%al
  40ca11:	0d ec 00 00 00       	or     $0xec,%eax
  40ca16:	48                   	dec    %eax
  40ca17:	01 14 66             	add    %edx,(%esi,%eiz,2)
  40ca1a:	6d                   	insl   (%dx),%es:(%edi)
  40ca1b:	61                   	popa   
  40ca1c:	73 64                	jae    40ca82 <.debug_info+0xa5c>
  40ca1e:	00 07                	add    %al,(%edi)
  40ca20:	2b 01                	sub    (%ecx),%eax
  40ca22:	0d ec 00 00 00       	or     $0xec,%eax
  40ca27:	4c                   	dec    %esp
  40ca28:	01 14 64             	add    %edx,(%esp,%eiz,2)
  40ca2b:	69 76 73 73 00 07 2c 	imul   $0x2c070073,0x73(%esi),%esi
  40ca32:	01 0d ec 00 00 00    	add    %ecx,0xec
  40ca38:	50                   	push   %eax
  40ca39:	01 14 64             	add    %edx,(%esp,%eiz,2)
  40ca3c:	69 76 73 64 00 07 2d 	imul   $0x2d070064,0x73(%esi),%esi
  40ca43:	01 0d ec 00 00 00    	add    %ecx,0xec
  40ca49:	54                   	push   %esp
  40ca4a:	01 14 73             	add    %edx,(%ebx,%esi,2)
  40ca4d:	71 72                	jno    40cac1 <.debug_info+0xa9b>
  40ca4f:	74 73                	je     40cac4 <.debug_info+0xa9e>
  40ca51:	73 00                	jae    40ca53 <.debug_info+0xa2d>
  40ca53:	07                   	pop    %es
  40ca54:	2e 01 0d ec 00 00 00 	add    %ecx,%cs:0xec
  40ca5b:	58                   	pop    %eax
  40ca5c:	01 14 73             	add    %edx,(%ebx,%esi,2)
  40ca5f:	71 72                	jno    40cad3 <.debug_info+0xaad>
  40ca61:	74 73                	je     40cad6 <.debug_info+0xab0>
  40ca63:	64 00 07             	add    %al,%fs:(%edi)
  40ca66:	2f                   	das    
  40ca67:	01 0d ec 00 00 00    	add    %ecx,0xec
  40ca6d:	5c                   	pop    %esp
  40ca6e:	01 14 72             	add    %edx,(%edx,%esi,2)
  40ca71:	65 61                	gs popa 
  40ca73:	73 73                	jae    40cae8 <.debug_info+0xac2>
  40ca75:	6f                   	outsl  %ds:(%esi),(%dx)
  40ca76:	63 5f 69             	arpl   %bx,0x69(%edi)
  40ca79:	6e                   	outsb  %ds:(%esi),(%dx)
  40ca7a:	74 00                	je     40ca7c <.debug_info+0xa56>
  40ca7c:	07                   	pop    %es
  40ca7d:	30 01                	xor    %al,(%ecx)
  40ca7f:	0d ec 00 00 00       	or     $0xec,%eax
  40ca84:	60                   	pusha  
  40ca85:	01 14 72             	add    %edx,(%edx,%esi,2)
  40ca88:	65 61                	gs popa 
  40ca8a:	73 73                	jae    40caff <.debug_info+0xad9>
  40ca8c:	6f                   	outsl  %ds:(%esi),(%dx)
  40ca8d:	63 5f 66             	arpl   %bx,0x66(%edi)
  40ca90:	70 00                	jo     40ca92 <.debug_info+0xa6c>
  40ca92:	07                   	pop    %es
  40ca93:	30 01                	xor    %al,(%ecx)
  40ca95:	1a ec                	sbb    %ah,%ch
  40ca97:	00 00                	add    %al,(%eax)
  40ca99:	00 64 01 14          	add    %ah,0x14(%ecx,%eax,1)
  40ca9d:	72 65                	jb     40cb04 <.debug_info+0xade>
  40ca9f:	61                   	popa   
  40caa0:	73 73                	jae    40cb15 <.debug_info+0xaef>
  40caa2:	6f                   	outsl  %ds:(%esi),(%dx)
  40caa3:	63 5f 76             	arpl   %bx,0x76(%edi)
  40caa6:	65 63 5f 69          	arpl   %bx,%gs:0x69(%edi)
  40caaa:	6e                   	outsb  %ds:(%esi),(%dx)
  40caab:	74 00                	je     40caad <.debug_info+0xa87>
  40caad:	07                   	pop    %es
  40caae:	30 01                	xor    %al,(%ecx)
  40cab0:	26 ec                	es in  (%dx),%al
  40cab2:	00 00                	add    %al,(%eax)
  40cab4:	00 68 01             	add    %ch,0x1(%eax)
  40cab7:	14 72                	adc    $0x72,%al
  40cab9:	65 61                	gs popa 
  40cabb:	73 73                	jae    40cb30 <.debug_info+0xb0a>
  40cabd:	6f                   	outsl  %ds:(%esi),(%dx)
  40cabe:	63 5f 76             	arpl   %bx,0x76(%edi)
  40cac1:	65 63 5f 66          	arpl   %bx,%gs:0x66(%edi)
  40cac5:	70 00                	jo     40cac7 <.debug_info+0xaa1>
  40cac7:	07                   	pop    %es
  40cac8:	30 01                	xor    %al,(%ecx)
  40caca:	37                   	aaa    
  40cacb:	ec                   	in     (%dx),%al
  40cacc:	00 00                	add    %al,(%eax)
  40cace:	00 6c 01 14          	add    %ch,0x14(%ecx,%eax,1)
  40cad2:	6d                   	insl   (%dx),%es:(%edi)
  40cad3:	65 6d                	gs insl (%dx),%es:(%edi)
  40cad5:	63 70 79             	arpl   %si,0x79(%eax)
  40cad8:	00 07                	add    %al,(%edi)
  40cada:	37                   	aaa    
  40cadb:	01 19                	add    %ebx,(%ecx)
  40cadd:	b5 0b                	mov    $0xb,%ch
  40cadf:	00 00                	add    %al,(%eax)
  40cae1:	70 01                	jo     40cae4 <.debug_info+0xabe>
  40cae3:	14 6d                	adc    $0x6d,%al
  40cae5:	65 6d                	gs insl (%dx),%es:(%edi)
  40cae7:	73 65                	jae    40cb4e <.debug_info+0xb28>
  40cae9:	74 00                	je     40caeb <.debug_info+0xac5>
  40caeb:	07                   	pop    %es
  40caec:	37                   	aaa    
  40caed:	01 22                	add    %esp,(%edx)
  40caef:	b5 0b                	mov    $0xb,%ch
  40caf1:	00 00                	add    %al,(%eax)
  40caf3:	74 01                	je     40caf6 <.debug_info+0xad0>
  40caf5:	14 63                	adc    $0x63,%al
  40caf7:	6f                   	outsl  %ds:(%esi),(%dx)
  40caf8:	6e                   	outsb  %ds:(%esi),(%dx)
  40caf9:	64 5f                	fs pop %edi
  40cafb:	74 61                	je     40cb5e <.debug_info+0xb38>
  40cafd:	6b 65 6e 5f          	imul   $0x5f,0x6e(%ebp),%esp
  40cb01:	62 72 61             	bound  %esi,0x61(%edx)
  40cb04:	6e                   	outsb  %ds:(%esi),(%dx)
  40cb05:	63 68 5f             	arpl   %bp,0x5f(%eax)
  40cb08:	63 6f 73             	arpl   %bp,0x73(%edi)
  40cb0b:	74 00                	je     40cb0d <.debug_info+0xae7>
  40cb0d:	07                   	pop    %es
  40cb0e:	38 01                	cmp    %al,(%ecx)
  40cb10:	0d ec 00 00 00       	or     $0xec,%eax
  40cb15:	78 01                	js     40cb18 <.debug_info+0xaf2>
  40cb17:	14 63                	adc    $0x63,%al
  40cb19:	6f                   	outsl  %ds:(%esi),(%dx)
  40cb1a:	6e                   	outsb  %ds:(%esi),(%dx)
  40cb1b:	64 5f                	fs pop %edi
  40cb1d:	6e                   	outsb  %ds:(%esi),(%dx)
  40cb1e:	6f                   	outsl  %ds:(%esi),(%dx)
  40cb1f:	74 5f                	je     40cb80 <.debug_info+0xb5a>
  40cb21:	74 61                	je     40cb84 <.debug_info+0xb5e>
  40cb23:	6b 65 6e 5f          	imul   $0x5f,0x6e(%ebp),%esp
  40cb27:	62 72 61             	bound  %esi,0x61(%edx)
  40cb2a:	6e                   	outsb  %ds:(%esi),(%dx)
  40cb2b:	63 68 5f             	arpl   %bp,0x5f(%eax)
  40cb2e:	63 6f 73             	arpl   %bp,0x73(%edi)
  40cb31:	74 00                	je     40cb33 <.debug_info+0xb0d>
  40cb33:	07                   	pop    %es
  40cb34:	3a 01                	cmp    (%ecx),%al
  40cb36:	0d ec 00 00 00       	or     $0xec,%eax
  40cb3b:	7c 01                	jl     40cb3e <.debug_info+0xb18>
  40cb3d:	14 61                	adc    $0x61,%al
  40cb3f:	6c                   	insb   (%dx),%es:(%edi)
  40cb40:	69 67 6e 5f 6c 6f 6f 	imul   $0x6f6f6c5f,0x6e(%edi),%esp
  40cb47:	70 00                	jo     40cb49 <.debug_info+0xb23>
  40cb49:	07                   	pop    %es
  40cb4a:	40                   	inc    %eax
  40cb4b:	01 15 27 05 00 00    	add    %edx,0x527
  40cb51:	80 01 14             	addb   $0x14,(%ecx)
  40cb54:	61                   	popa   
  40cb55:	6c                   	insb   (%dx),%es:(%edi)
  40cb56:	69 67 6e 5f 6a 75 6d 	imul   $0x6d756a5f,0x6e(%edi),%esp
  40cb5d:	70 00                	jo     40cb5f <.debug_info+0xb39>
  40cb5f:	07                   	pop    %es
  40cb60:	41                   	inc    %ecx
  40cb61:	01 15 27 05 00 00    	add    %edx,0x527
  40cb67:	84 01                	test   %al,(%ecx)
  40cb69:	14 61                	adc    $0x61,%al
  40cb6b:	6c                   	insb   (%dx),%es:(%edi)
  40cb6c:	69 67 6e 5f 6c 61 62 	imul   $0x62616c5f,0x6e(%edi),%esp
  40cb73:	65 6c                	gs insb (%dx),%es:(%edi)
  40cb75:	00 07                	add    %al,(%edi)
  40cb77:	42                   	inc    %edx
  40cb78:	01 15 27 05 00 00    	add    %edx,0x527
  40cb7e:	88 01                	mov    %al,(%ecx)
  40cb80:	14 61                	adc    $0x61,%al
  40cb82:	6c                   	insb   (%dx),%es:(%edi)
  40cb83:	69 67 6e 5f 66 75 6e 	imul   $0x6e75665f,0x6e(%edi),%esp
  40cb8a:	63 00                	arpl   %ax,(%eax)
  40cb8c:	07                   	pop    %es
  40cb8d:	43                   	inc    %ebx
  40cb8e:	01 15 27 05 00 00    	add    %edx,0x527
  40cb94:	8c 01                	mov    %es,(%ecx)
  40cb96:	00 03                	add    %al,(%ebx)
  40cb98:	fa                   	cli    
  40cb99:	05 00 00 08 ec       	add    $0xec080000,%eax
  40cb9e:	00 00                	add    %al,(%eax)
  40cba0:	00 86 0b 00 00 0c    	add    %al,0xc00000b(%esi)
  40cba6:	f1                   	icebp  
  40cba7:	00 00                	add    %al,(%eax)
  40cba9:	00 04 00             	add    %al,(%eax,%eax,1)
  40cbac:	03 76 0b             	add    0xb(%esi),%esi
  40cbaf:	00 00                	add    %al,(%eax)
  40cbb1:	08 ec                	or     %ch,%ah
  40cbb3:	00 00                	add    %al,(%eax)
  40cbb5:	00 9b 0b 00 00 0c    	add    %bl,0xc00000b(%ebx)
  40cbbb:	f1                   	icebp  
  40cbbc:	00 00                	add    %al,(%eax)
  40cbbe:	00 02                	add    %al,(%edx)
  40cbc0:	00 03                	add    %al,(%ebx)
  40cbc2:	8b 0b                	mov    (%ebx),%ecx
  40cbc4:	00 00                	add    %al,(%eax)
  40cbc6:	08 ec                	or     %ch,%ah
  40cbc8:	00 00                	add    %al,(%eax)
  40cbca:	00 b0 0b 00 00 0c    	add    %dh,0xc00000b(%eax)
  40cbd0:	f1                   	icebp  
  40cbd1:	00 00                	add    %al,(%eax)
  40cbd3:	00 01                	add    %al,(%ecx)
  40cbd5:	00 03                	add    %al,(%ebx)
  40cbd7:	a0 0b 00 00 06       	mov    0x600000b,%al
  40cbdc:	04 a9                	add    $0xa9,%al
  40cbde:	05 00 00 0b 69       	add    $0x690b0000,%eax
  40cbe3:	78 38                	js     40cc1d <.debug_info+0xbf7>
  40cbe5:	36 5f                	ss pop %edi
  40cbe7:	63 6f 73             	arpl   %bp,0x73(%edi)
  40cbea:	74 00                	je     40cbec <.debug_info+0xbc6>
  40cbec:	07                   	pop    %es
  40cbed:	46                   	inc    %esi
  40cbee:	01 26                	add    %esp,(%esi)
  40cbf0:	ce                   	into   
  40cbf1:	0b 00                	or     (%eax),%eax
  40cbf3:	00 06                	add    %al,(%esi)
  40cbf5:	04 71                	add    $0x71,%al
  40cbf7:	0b 00                	or     (%eax),%eax
  40cbf9:	00 0b                	add    %cl,(%ebx)
  40cbfb:	69 78 38 36 5f 73 69 	imul   $0x69735f36,0x38(%eax),%edi
  40cc02:	7a 65                	jp     40cc69 <.debug_info+0xc43>
  40cc04:	5f                   	pop    %edi
  40cc05:	63 6f 73             	arpl   %bp,0x73(%edi)
  40cc08:	74 00                	je     40cc0a <.debug_info+0xbe4>
  40cc0a:	07                   	pop    %es
  40cc0b:	47                   	inc    %edi
  40cc0c:	01 25 71 0b 00 00    	add    %esp,0xb71
  40cc12:	15 69 78 38 36       	adc    $0x36387869,%eax
  40cc17:	5f                   	pop    %edi
  40cc18:	74 75                	je     40cc8f <.debug_info+0xc69>
  40cc1a:	6e                   	outsb  %ds:(%esi),(%dx)
  40cc1b:	65 5f                	gs pop %edi
  40cc1d:	69 6e 64 69 63 65 73 	imul   $0x73656369,0x64(%esi),%ebp
  40cc24:	00 07                	add    %al,(%edi)
  40cc26:	04 f1                	add    $0xf1,%al
  40cc28:	00 00                	add    %al,(%eax)
  40cc2a:	00 07                	add    %al,(%edi)
  40cc2c:	a8 01                	test   $0x1,%al
  40cc2e:	06                   	push   %es
  40cc2f:	2d 16 00 00 11       	sub    $0x11000016,%eax
  40cc34:	58                   	pop    %eax
  40cc35:	38 36                	cmp    %dh,(%esi)
  40cc37:	5f                   	pop    %edi
  40cc38:	54                   	push   %esp
  40cc39:	55                   	push   %ebp
  40cc3a:	4e                   	dec    %esi
  40cc3b:	45                   	inc    %ebp
  40cc3c:	5f                   	pop    %edi
  40cc3d:	53                   	push   %ebx
  40cc3e:	43                   	inc    %ebx
  40cc3f:	48                   	dec    %eax
  40cc40:	45                   	inc    %ebp
  40cc41:	44                   	inc    %esp
  40cc42:	55                   	push   %ebp
  40cc43:	4c                   	dec    %esp
  40cc44:	45                   	inc    %ebp
  40cc45:	00 00                	add    %al,(%eax)
  40cc47:	11 58 38             	adc    %ebx,0x38(%eax)
  40cc4a:	36 5f                	ss pop %edi
  40cc4c:	54                   	push   %esp
  40cc4d:	55                   	push   %ebp
  40cc4e:	4e                   	dec    %esi
  40cc4f:	45                   	inc    %ebp
  40cc50:	5f                   	pop    %edi
  40cc51:	50                   	push   %eax
  40cc52:	41                   	inc    %ecx
  40cc53:	52                   	push   %edx
  40cc54:	54                   	push   %esp
  40cc55:	49                   	dec    %ecx
  40cc56:	41                   	inc    %ecx
  40cc57:	4c                   	dec    %esp
  40cc58:	5f                   	pop    %edi
  40cc59:	52                   	push   %edx
  40cc5a:	45                   	inc    %ebp
  40cc5b:	47                   	inc    %edi
  40cc5c:	5f                   	pop    %edi
  40cc5d:	44                   	inc    %esp
  40cc5e:	45                   	inc    %ebp
  40cc5f:	50                   	push   %eax
  40cc60:	45                   	inc    %ebp
  40cc61:	4e                   	dec    %esi
  40cc62:	44                   	inc    %esp
  40cc63:	45                   	inc    %ebp
  40cc64:	4e                   	dec    %esi
  40cc65:	43                   	inc    %ebx
  40cc66:	59                   	pop    %ecx
  40cc67:	00 01                	add    %al,(%ecx)
  40cc69:	11 58 38             	adc    %ebx,0x38(%eax)
  40cc6c:	36 5f                	ss pop %edi
  40cc6e:	54                   	push   %esp
  40cc6f:	55                   	push   %ebp
  40cc70:	4e                   	dec    %esi
  40cc71:	45                   	inc    %ebp
  40cc72:	5f                   	pop    %edi
  40cc73:	53                   	push   %ebx
  40cc74:	53                   	push   %ebx
  40cc75:	45                   	inc    %ebp
  40cc76:	5f                   	pop    %edi
  40cc77:	50                   	push   %eax
  40cc78:	41                   	inc    %ecx
  40cc79:	52                   	push   %edx
  40cc7a:	54                   	push   %esp
  40cc7b:	49                   	dec    %ecx
  40cc7c:	41                   	inc    %ecx
  40cc7d:	4c                   	dec    %esp
  40cc7e:	5f                   	pop    %edi
  40cc7f:	52                   	push   %edx
  40cc80:	45                   	inc    %ebp
  40cc81:	47                   	inc    %edi
  40cc82:	5f                   	pop    %edi
  40cc83:	44                   	inc    %esp
  40cc84:	45                   	inc    %ebp
  40cc85:	50                   	push   %eax
  40cc86:	45                   	inc    %ebp
  40cc87:	4e                   	dec    %esi
  40cc88:	44                   	inc    %esp
  40cc89:	45                   	inc    %ebp
  40cc8a:	4e                   	dec    %esi
  40cc8b:	43                   	inc    %ebx
  40cc8c:	59                   	pop    %ecx
  40cc8d:	00 02                	add    %al,(%edx)
  40cc8f:	11 58 38             	adc    %ebx,0x38(%eax)
  40cc92:	36 5f                	ss pop %edi
  40cc94:	54                   	push   %esp
  40cc95:	55                   	push   %ebp
  40cc96:	4e                   	dec    %esi
  40cc97:	45                   	inc    %ebp
  40cc98:	5f                   	pop    %edi
  40cc99:	53                   	push   %ebx
  40cc9a:	53                   	push   %ebx
  40cc9b:	45                   	inc    %ebp
  40cc9c:	5f                   	pop    %edi
  40cc9d:	53                   	push   %ebx
  40cc9e:	50                   	push   %eax
  40cc9f:	4c                   	dec    %esp
  40cca0:	49                   	dec    %ecx
  40cca1:	54                   	push   %esp
  40cca2:	5f                   	pop    %edi
  40cca3:	52                   	push   %edx
  40cca4:	45                   	inc    %ebp
  40cca5:	47                   	inc    %edi
  40cca6:	53                   	push   %ebx
  40cca7:	00 03                	add    %al,(%ebx)
  40cca9:	11 58 38             	adc    %ebx,0x38(%eax)
  40ccac:	36 5f                	ss pop %edi
  40ccae:	54                   	push   %esp
  40ccaf:	55                   	push   %ebp
  40ccb0:	4e                   	dec    %esi
  40ccb1:	45                   	inc    %ebp
  40ccb2:	5f                   	pop    %edi
  40ccb3:	50                   	push   %eax
  40ccb4:	41                   	inc    %ecx
  40ccb5:	52                   	push   %edx
  40ccb6:	54                   	push   %esp
  40ccb7:	49                   	dec    %ecx
  40ccb8:	41                   	inc    %ecx
  40ccb9:	4c                   	dec    %esp
  40ccba:	5f                   	pop    %edi
  40ccbb:	46                   	inc    %esi
  40ccbc:	4c                   	dec    %esp
  40ccbd:	41                   	inc    %ecx
  40ccbe:	47                   	inc    %edi
  40ccbf:	5f                   	pop    %edi
  40ccc0:	52                   	push   %edx
  40ccc1:	45                   	inc    %ebp
  40ccc2:	47                   	inc    %edi
  40ccc3:	5f                   	pop    %edi
  40ccc4:	53                   	push   %ebx
  40ccc5:	54                   	push   %esp
  40ccc6:	41                   	inc    %ecx
  40ccc7:	4c                   	dec    %esp
  40ccc8:	4c                   	dec    %esp
  40ccc9:	00 04 11             	add    %al,(%ecx,%edx,1)
  40cccc:	58                   	pop    %eax
  40cccd:	38 36                	cmp    %dh,(%esi)
  40cccf:	5f                   	pop    %edi
  40ccd0:	54                   	push   %esp
  40ccd1:	55                   	push   %ebp
  40ccd2:	4e                   	dec    %esi
  40ccd3:	45                   	inc    %ebp
  40ccd4:	5f                   	pop    %edi
  40ccd5:	4d                   	dec    %ebp
  40ccd6:	4f                   	dec    %edi
  40ccd7:	56                   	push   %esi
  40ccd8:	58                   	pop    %eax
  40ccd9:	00 05 11 58 38 36    	add    %al,0x36385811
  40ccdf:	5f                   	pop    %edi
  40cce0:	54                   	push   %esp
  40cce1:	55                   	push   %ebp
  40cce2:	4e                   	dec    %esi
  40cce3:	45                   	inc    %ebp
  40cce4:	5f                   	pop    %edi
  40cce5:	4d                   	dec    %ebp
  40cce6:	45                   	inc    %ebp
  40cce7:	4d                   	dec    %ebp
  40cce8:	4f                   	dec    %edi
  40cce9:	52                   	push   %edx
  40ccea:	59                   	pop    %ecx
  40cceb:	5f                   	pop    %edi
  40ccec:	4d                   	dec    %ebp
  40cced:	49                   	dec    %ecx
  40ccee:	53                   	push   %ebx
  40ccef:	4d                   	dec    %ebp
  40ccf0:	41                   	inc    %ecx
  40ccf1:	54                   	push   %esp
  40ccf2:	43                   	inc    %ebx
  40ccf3:	48                   	dec    %eax
  40ccf4:	5f                   	pop    %edi
  40ccf5:	53                   	push   %ebx
  40ccf6:	54                   	push   %esp
  40ccf7:	41                   	inc    %ecx
  40ccf8:	4c                   	dec    %esp
  40ccf9:	4c                   	dec    %esp
  40ccfa:	00 06                	add    %al,(%esi)
  40ccfc:	11 58 38             	adc    %ebx,0x38(%eax)
  40ccff:	36 5f                	ss pop %edi
  40cd01:	54                   	push   %esp
  40cd02:	55                   	push   %ebp
  40cd03:	4e                   	dec    %esi
  40cd04:	45                   	inc    %ebp
  40cd05:	5f                   	pop    %edi
  40cd06:	46                   	inc    %esi
  40cd07:	55                   	push   %ebp
  40cd08:	53                   	push   %ebx
  40cd09:	45                   	inc    %ebp
  40cd0a:	5f                   	pop    %edi
  40cd0b:	43                   	inc    %ebx
  40cd0c:	4d                   	dec    %ebp
  40cd0d:	50                   	push   %eax
  40cd0e:	5f                   	pop    %edi
  40cd0f:	41                   	inc    %ecx
  40cd10:	4e                   	dec    %esi
  40cd11:	44                   	inc    %esp
  40cd12:	5f                   	pop    %edi
  40cd13:	42                   	inc    %edx
  40cd14:	52                   	push   %edx
  40cd15:	41                   	inc    %ecx
  40cd16:	4e                   	dec    %esi
  40cd17:	43                   	inc    %ebx
  40cd18:	48                   	dec    %eax
  40cd19:	5f                   	pop    %edi
  40cd1a:	33 32                	xor    (%edx),%esi
  40cd1c:	00 07                	add    %al,(%edi)
  40cd1e:	11 58 38             	adc    %ebx,0x38(%eax)
  40cd21:	36 5f                	ss pop %edi
  40cd23:	54                   	push   %esp
  40cd24:	55                   	push   %ebp
  40cd25:	4e                   	dec    %esi
  40cd26:	45                   	inc    %ebp
  40cd27:	5f                   	pop    %edi
  40cd28:	46                   	inc    %esi
  40cd29:	55                   	push   %ebp
  40cd2a:	53                   	push   %ebx
  40cd2b:	45                   	inc    %ebp
  40cd2c:	5f                   	pop    %edi
  40cd2d:	43                   	inc    %ebx
  40cd2e:	4d                   	dec    %ebp
  40cd2f:	50                   	push   %eax
  40cd30:	5f                   	pop    %edi
  40cd31:	41                   	inc    %ecx
  40cd32:	4e                   	dec    %esi
  40cd33:	44                   	inc    %esp
  40cd34:	5f                   	pop    %edi
  40cd35:	42                   	inc    %edx
  40cd36:	52                   	push   %edx
  40cd37:	41                   	inc    %ecx
  40cd38:	4e                   	dec    %esi
  40cd39:	43                   	inc    %ebx
  40cd3a:	48                   	dec    %eax
  40cd3b:	5f                   	pop    %edi
  40cd3c:	36 34 00             	ss xor $0x0,%al
  40cd3f:	08 11                	or     %dl,(%ecx)
  40cd41:	58                   	pop    %eax
  40cd42:	38 36                	cmp    %dh,(%esi)
  40cd44:	5f                   	pop    %edi
  40cd45:	54                   	push   %esp
  40cd46:	55                   	push   %ebp
  40cd47:	4e                   	dec    %esi
  40cd48:	45                   	inc    %ebp
  40cd49:	5f                   	pop    %edi
  40cd4a:	46                   	inc    %esi
  40cd4b:	55                   	push   %ebp
  40cd4c:	53                   	push   %ebx
  40cd4d:	45                   	inc    %ebp
  40cd4e:	5f                   	pop    %edi
  40cd4f:	43                   	inc    %ebx
  40cd50:	4d                   	dec    %ebp
  40cd51:	50                   	push   %eax
  40cd52:	5f                   	pop    %edi
  40cd53:	41                   	inc    %ecx
  40cd54:	4e                   	dec    %esi
  40cd55:	44                   	inc    %esp
  40cd56:	5f                   	pop    %edi
  40cd57:	42                   	inc    %edx
  40cd58:	52                   	push   %edx
  40cd59:	41                   	inc    %ecx
  40cd5a:	4e                   	dec    %esi
  40cd5b:	43                   	inc    %ebx
  40cd5c:	48                   	dec    %eax
  40cd5d:	5f                   	pop    %edi
  40cd5e:	53                   	push   %ebx
  40cd5f:	4f                   	dec    %edi
  40cd60:	46                   	inc    %esi
  40cd61:	4c                   	dec    %esp
  40cd62:	41                   	inc    %ecx
  40cd63:	47                   	inc    %edi
  40cd64:	53                   	push   %ebx
  40cd65:	00 09                	add    %cl,(%ecx)
  40cd67:	11 58 38             	adc    %ebx,0x38(%eax)
  40cd6a:	36 5f                	ss pop %edi
  40cd6c:	54                   	push   %esp
  40cd6d:	55                   	push   %ebp
  40cd6e:	4e                   	dec    %esi
  40cd6f:	45                   	inc    %ebp
  40cd70:	5f                   	pop    %edi
  40cd71:	46                   	inc    %esi
  40cd72:	55                   	push   %ebp
  40cd73:	53                   	push   %ebx
  40cd74:	45                   	inc    %ebp
  40cd75:	5f                   	pop    %edi
  40cd76:	41                   	inc    %ecx
  40cd77:	4c                   	dec    %esp
  40cd78:	55                   	push   %ebp
  40cd79:	5f                   	pop    %edi
  40cd7a:	41                   	inc    %ecx
  40cd7b:	4e                   	dec    %esi
  40cd7c:	44                   	inc    %esp
  40cd7d:	5f                   	pop    %edi
  40cd7e:	42                   	inc    %edx
  40cd7f:	52                   	push   %edx
  40cd80:	41                   	inc    %ecx
  40cd81:	4e                   	dec    %esi
  40cd82:	43                   	inc    %ebx
  40cd83:	48                   	dec    %eax
  40cd84:	00 0a                	add    %cl,(%edx)
  40cd86:	11 58 38             	adc    %ebx,0x38(%eax)
  40cd89:	36 5f                	ss pop %edi
  40cd8b:	54                   	push   %esp
  40cd8c:	55                   	push   %ebp
  40cd8d:	4e                   	dec    %esi
  40cd8e:	45                   	inc    %ebp
  40cd8f:	5f                   	pop    %edi
  40cd90:	41                   	inc    %ecx
  40cd91:	43                   	inc    %ebx
  40cd92:	43                   	inc    %ebx
  40cd93:	55                   	push   %ebp
  40cd94:	4d                   	dec    %ebp
  40cd95:	55                   	push   %ebp
  40cd96:	4c                   	dec    %esp
  40cd97:	41                   	inc    %ecx
  40cd98:	54                   	push   %esp
  40cd99:	45                   	inc    %ebp
  40cd9a:	5f                   	pop    %edi
  40cd9b:	4f                   	dec    %edi
  40cd9c:	55                   	push   %ebp
  40cd9d:	54                   	push   %esp
  40cd9e:	47                   	inc    %edi
  40cd9f:	4f                   	dec    %edi
  40cda0:	49                   	dec    %ecx
  40cda1:	4e                   	dec    %esi
  40cda2:	47                   	inc    %edi
  40cda3:	5f                   	pop    %edi
  40cda4:	41                   	inc    %ecx
  40cda5:	52                   	push   %edx
  40cda6:	47                   	inc    %edi
  40cda7:	53                   	push   %ebx
  40cda8:	00 0b                	add    %cl,(%ebx)
  40cdaa:	11 58 38             	adc    %ebx,0x38(%eax)
  40cdad:	36 5f                	ss pop %edi
  40cdaf:	54                   	push   %esp
  40cdb0:	55                   	push   %ebp
  40cdb1:	4e                   	dec    %esi
  40cdb2:	45                   	inc    %ebp
  40cdb3:	5f                   	pop    %edi
  40cdb4:	50                   	push   %eax
  40cdb5:	52                   	push   %edx
  40cdb6:	4f                   	dec    %edi
  40cdb7:	4c                   	dec    %esp
  40cdb8:	4f                   	dec    %edi
  40cdb9:	47                   	inc    %edi
  40cdba:	55                   	push   %ebp
  40cdbb:	45                   	inc    %ebp
  40cdbc:	5f                   	pop    %edi
  40cdbd:	55                   	push   %ebp
  40cdbe:	53                   	push   %ebx
  40cdbf:	49                   	dec    %ecx
  40cdc0:	4e                   	dec    %esi
  40cdc1:	47                   	inc    %edi
  40cdc2:	5f                   	pop    %edi
  40cdc3:	4d                   	dec    %ebp
  40cdc4:	4f                   	dec    %edi
  40cdc5:	56                   	push   %esi
  40cdc6:	45                   	inc    %ebp
  40cdc7:	00 0c 11             	add    %cl,(%ecx,%edx,1)
  40cdca:	58                   	pop    %eax
  40cdcb:	38 36                	cmp    %dh,(%esi)
  40cdcd:	5f                   	pop    %edi
  40cdce:	54                   	push   %esp
  40cdcf:	55                   	push   %ebp
  40cdd0:	4e                   	dec    %esi
  40cdd1:	45                   	inc    %ebp
  40cdd2:	5f                   	pop    %edi
  40cdd3:	45                   	inc    %ebp
  40cdd4:	50                   	push   %eax
  40cdd5:	49                   	dec    %ecx
  40cdd6:	4c                   	dec    %esp
  40cdd7:	4f                   	dec    %edi
  40cdd8:	47                   	inc    %edi
  40cdd9:	55                   	push   %ebp
  40cdda:	45                   	inc    %ebp
  40cddb:	5f                   	pop    %edi
  40cddc:	55                   	push   %ebp
  40cddd:	53                   	push   %ebx
  40cdde:	49                   	dec    %ecx
  40cddf:	4e                   	dec    %esi
  40cde0:	47                   	inc    %edi
  40cde1:	5f                   	pop    %edi
  40cde2:	4d                   	dec    %ebp
  40cde3:	4f                   	dec    %edi
  40cde4:	56                   	push   %esi
  40cde5:	45                   	inc    %ebp
  40cde6:	00 0d 11 58 38 36    	add    %cl,0x36385811
  40cdec:	5f                   	pop    %edi
  40cded:	54                   	push   %esp
  40cdee:	55                   	push   %ebp
  40cdef:	4e                   	dec    %esi
  40cdf0:	45                   	inc    %ebp
  40cdf1:	5f                   	pop    %edi
  40cdf2:	55                   	push   %ebp
  40cdf3:	53                   	push   %ebx
  40cdf4:	45                   	inc    %ebp
  40cdf5:	5f                   	pop    %edi
  40cdf6:	4c                   	dec    %esp
  40cdf7:	45                   	inc    %ebp
  40cdf8:	41                   	inc    %ecx
  40cdf9:	56                   	push   %esi
  40cdfa:	45                   	inc    %ebp
  40cdfb:	00 0e                	add    %cl,(%esi)
  40cdfd:	11 58 38             	adc    %ebx,0x38(%eax)
  40ce00:	36 5f                	ss pop %edi
  40ce02:	54                   	push   %esp
  40ce03:	55                   	push   %ebp
  40ce04:	4e                   	dec    %esi
  40ce05:	45                   	inc    %ebp
  40ce06:	5f                   	pop    %edi
  40ce07:	50                   	push   %eax
  40ce08:	55                   	push   %ebp
  40ce09:	53                   	push   %ebx
  40ce0a:	48                   	dec    %eax
  40ce0b:	5f                   	pop    %edi
  40ce0c:	4d                   	dec    %ebp
  40ce0d:	45                   	inc    %ebp
  40ce0e:	4d                   	dec    %ebp
  40ce0f:	4f                   	dec    %edi
  40ce10:	52                   	push   %edx
  40ce11:	59                   	pop    %ecx
  40ce12:	00 0f                	add    %cl,(%edi)
  40ce14:	11 58 38             	adc    %ebx,0x38(%eax)
  40ce17:	36 5f                	ss pop %edi
  40ce19:	54                   	push   %esp
  40ce1a:	55                   	push   %ebp
  40ce1b:	4e                   	dec    %esi
  40ce1c:	45                   	inc    %ebp
  40ce1d:	5f                   	pop    %edi
  40ce1e:	53                   	push   %ebx
  40ce1f:	49                   	dec    %ecx
  40ce20:	4e                   	dec    %esi
  40ce21:	47                   	inc    %edi
  40ce22:	4c                   	dec    %esp
  40ce23:	45                   	inc    %ebp
  40ce24:	5f                   	pop    %edi
  40ce25:	50                   	push   %eax
  40ce26:	55                   	push   %ebp
  40ce27:	53                   	push   %ebx
  40ce28:	48                   	dec    %eax
  40ce29:	00 10                	add    %dl,(%eax)
  40ce2b:	11 58 38             	adc    %ebx,0x38(%eax)
  40ce2e:	36 5f                	ss pop %edi
  40ce30:	54                   	push   %esp
  40ce31:	55                   	push   %ebp
  40ce32:	4e                   	dec    %esi
  40ce33:	45                   	inc    %ebp
  40ce34:	5f                   	pop    %edi
  40ce35:	44                   	inc    %esp
  40ce36:	4f                   	dec    %edi
  40ce37:	55                   	push   %ebp
  40ce38:	42                   	inc    %edx
  40ce39:	4c                   	dec    %esp
  40ce3a:	45                   	inc    %ebp
  40ce3b:	5f                   	pop    %edi
  40ce3c:	50                   	push   %eax
  40ce3d:	55                   	push   %ebp
  40ce3e:	53                   	push   %ebx
  40ce3f:	48                   	dec    %eax
  40ce40:	00 11                	add    %dl,(%ecx)
  40ce42:	11 58 38             	adc    %ebx,0x38(%eax)
  40ce45:	36 5f                	ss pop %edi
  40ce47:	54                   	push   %esp
  40ce48:	55                   	push   %ebp
  40ce49:	4e                   	dec    %esi
  40ce4a:	45                   	inc    %ebp
  40ce4b:	5f                   	pop    %edi
  40ce4c:	53                   	push   %ebx
  40ce4d:	49                   	dec    %ecx
  40ce4e:	4e                   	dec    %esi
  40ce4f:	47                   	inc    %edi
  40ce50:	4c                   	dec    %esp
  40ce51:	45                   	inc    %ebp
  40ce52:	5f                   	pop    %edi
  40ce53:	50                   	push   %eax
  40ce54:	4f                   	dec    %edi
  40ce55:	50                   	push   %eax
  40ce56:	00 12                	add    %dl,(%edx)
  40ce58:	11 58 38             	adc    %ebx,0x38(%eax)
  40ce5b:	36 5f                	ss pop %edi
  40ce5d:	54                   	push   %esp
  40ce5e:	55                   	push   %ebp
  40ce5f:	4e                   	dec    %esi
  40ce60:	45                   	inc    %ebp
  40ce61:	5f                   	pop    %edi
  40ce62:	44                   	inc    %esp
  40ce63:	4f                   	dec    %edi
  40ce64:	55                   	push   %ebp
  40ce65:	42                   	inc    %edx
  40ce66:	4c                   	dec    %esp
  40ce67:	45                   	inc    %ebp
  40ce68:	5f                   	pop    %edi
  40ce69:	50                   	push   %eax
  40ce6a:	4f                   	dec    %edi
  40ce6b:	50                   	push   %eax
  40ce6c:	00 13                	add    %dl,(%ebx)
  40ce6e:	11 58 38             	adc    %ebx,0x38(%eax)
  40ce71:	36 5f                	ss pop %edi
  40ce73:	54                   	push   %esp
  40ce74:	55                   	push   %ebp
  40ce75:	4e                   	dec    %esi
  40ce76:	45                   	inc    %ebp
  40ce77:	5f                   	pop    %edi
  40ce78:	50                   	push   %eax
  40ce79:	41                   	inc    %ecx
  40ce7a:	44                   	inc    %esp
  40ce7b:	5f                   	pop    %edi
  40ce7c:	53                   	push   %ebx
  40ce7d:	48                   	dec    %eax
  40ce7e:	4f                   	dec    %edi
  40ce7f:	52                   	push   %edx
  40ce80:	54                   	push   %esp
  40ce81:	5f                   	pop    %edi
  40ce82:	46                   	inc    %esi
  40ce83:	55                   	push   %ebp
  40ce84:	4e                   	dec    %esi
  40ce85:	43                   	inc    %ebx
  40ce86:	54                   	push   %esp
  40ce87:	49                   	dec    %ecx
  40ce88:	4f                   	dec    %edi
  40ce89:	4e                   	dec    %esi
  40ce8a:	00 14 11             	add    %dl,(%ecx,%edx,1)
  40ce8d:	58                   	pop    %eax
  40ce8e:	38 36                	cmp    %dh,(%esi)
  40ce90:	5f                   	pop    %edi
  40ce91:	54                   	push   %esp
  40ce92:	55                   	push   %ebp
  40ce93:	4e                   	dec    %esi
  40ce94:	45                   	inc    %ebp
  40ce95:	5f                   	pop    %edi
  40ce96:	50                   	push   %eax
  40ce97:	41                   	inc    %ecx
  40ce98:	44                   	inc    %esp
  40ce99:	5f                   	pop    %edi
  40ce9a:	52                   	push   %edx
  40ce9b:	45                   	inc    %ebp
  40ce9c:	54                   	push   %esp
  40ce9d:	55                   	push   %ebp
  40ce9e:	52                   	push   %edx
  40ce9f:	4e                   	dec    %esi
  40cea0:	53                   	push   %ebx
  40cea1:	00 15 11 58 38 36    	add    %dl,0x36385811
  40cea7:	5f                   	pop    %edi
  40cea8:	54                   	push   %esp
  40cea9:	55                   	push   %ebp
  40ceaa:	4e                   	dec    %esi
  40ceab:	45                   	inc    %ebp
  40ceac:	5f                   	pop    %edi
  40cead:	46                   	inc    %esi
  40ceae:	4f                   	dec    %edi
  40ceaf:	55                   	push   %ebp
  40ceb0:	52                   	push   %edx
  40ceb1:	5f                   	pop    %edi
  40ceb2:	4a                   	dec    %edx
  40ceb3:	55                   	push   %ebp
  40ceb4:	4d                   	dec    %ebp
  40ceb5:	50                   	push   %eax
  40ceb6:	5f                   	pop    %edi
  40ceb7:	4c                   	dec    %esp
  40ceb8:	49                   	dec    %ecx
  40ceb9:	4d                   	dec    %ebp
  40ceba:	49                   	dec    %ecx
  40cebb:	54                   	push   %esp
  40cebc:	00 16                	add    %dl,(%esi)
  40cebe:	11 58 38             	adc    %ebx,0x38(%eax)
  40cec1:	36 5f                	ss pop %edi
  40cec3:	54                   	push   %esp
  40cec4:	55                   	push   %ebp
  40cec5:	4e                   	dec    %esi
  40cec6:	45                   	inc    %ebp
  40cec7:	5f                   	pop    %edi
  40cec8:	53                   	push   %ebx
  40cec9:	4f                   	dec    %edi
  40ceca:	46                   	inc    %esi
  40cecb:	54                   	push   %esp
  40cecc:	57                   	push   %edi
  40cecd:	41                   	inc    %ecx
  40cece:	52                   	push   %edx
  40cecf:	45                   	inc    %ebp
  40ced0:	5f                   	pop    %edi
  40ced1:	50                   	push   %eax
  40ced2:	52                   	push   %edx
  40ced3:	45                   	inc    %ebp
  40ced4:	46                   	inc    %esi
  40ced5:	45                   	inc    %ebp
  40ced6:	54                   	push   %esp
  40ced7:	43                   	inc    %ebx
  40ced8:	48                   	dec    %eax
  40ced9:	49                   	dec    %ecx
  40ceda:	4e                   	dec    %esi
  40cedb:	47                   	inc    %edi
  40cedc:	5f                   	pop    %edi
  40cedd:	42                   	inc    %edx
  40cede:	45                   	inc    %ebp
  40cedf:	4e                   	dec    %esi
  40cee0:	45                   	inc    %ebp
  40cee1:	46                   	inc    %esi
  40cee2:	49                   	dec    %ecx
  40cee3:	43                   	inc    %ebx
  40cee4:	49                   	dec    %ecx
  40cee5:	41                   	inc    %ecx
  40cee6:	4c                   	dec    %esp
  40cee7:	00 17                	add    %dl,(%edi)
  40cee9:	11 58 38             	adc    %ebx,0x38(%eax)
  40ceec:	36 5f                	ss pop %edi
  40ceee:	54                   	push   %esp
  40ceef:	55                   	push   %ebp
  40cef0:	4e                   	dec    %esi
  40cef1:	45                   	inc    %ebp
  40cef2:	5f                   	pop    %edi
  40cef3:	4c                   	dec    %esp
  40cef4:	43                   	inc    %ebx
  40cef5:	50                   	push   %eax
  40cef6:	5f                   	pop    %edi
  40cef7:	53                   	push   %ebx
  40cef8:	54                   	push   %esp
  40cef9:	41                   	inc    %ecx
  40cefa:	4c                   	dec    %esp
  40cefb:	4c                   	dec    %esp
  40cefc:	00 18                	add    %bl,(%eax)
  40cefe:	11 58 38             	adc    %ebx,0x38(%eax)
  40cf01:	36 5f                	ss pop %edi
  40cf03:	54                   	push   %esp
  40cf04:	55                   	push   %ebp
  40cf05:	4e                   	dec    %esi
  40cf06:	45                   	inc    %ebp
  40cf07:	5f                   	pop    %edi
  40cf08:	52                   	push   %edx
  40cf09:	45                   	inc    %ebp
  40cf0a:	41                   	inc    %ecx
  40cf0b:	44                   	inc    %esp
  40cf0c:	5f                   	pop    %edi
  40cf0d:	4d                   	dec    %ebp
  40cf0e:	4f                   	dec    %edi
  40cf0f:	44                   	inc    %esp
  40cf10:	49                   	dec    %ecx
  40cf11:	46                   	inc    %esi
  40cf12:	59                   	pop    %ecx
  40cf13:	00 19                	add    %bl,(%ecx)
  40cf15:	11 58 38             	adc    %ebx,0x38(%eax)
  40cf18:	36 5f                	ss pop %edi
  40cf1a:	54                   	push   %esp
  40cf1b:	55                   	push   %ebp
  40cf1c:	4e                   	dec    %esi
  40cf1d:	45                   	inc    %ebp
  40cf1e:	5f                   	pop    %edi
  40cf1f:	55                   	push   %ebp
  40cf20:	53                   	push   %ebx
  40cf21:	45                   	inc    %ebp
  40cf22:	5f                   	pop    %edi
  40cf23:	49                   	dec    %ecx
  40cf24:	4e                   	dec    %esi
  40cf25:	43                   	inc    %ebx
  40cf26:	44                   	inc    %esp
  40cf27:	45                   	inc    %ebp
  40cf28:	43                   	inc    %ebx
  40cf29:	00 1a                	add    %bl,(%edx)
  40cf2b:	11 58 38             	adc    %ebx,0x38(%eax)
  40cf2e:	36 5f                	ss pop %edi
  40cf30:	54                   	push   %esp
  40cf31:	55                   	push   %ebp
  40cf32:	4e                   	dec    %esi
  40cf33:	45                   	inc    %ebp
  40cf34:	5f                   	pop    %edi
  40cf35:	49                   	dec    %ecx
  40cf36:	4e                   	dec    %esi
  40cf37:	54                   	push   %esp
  40cf38:	45                   	inc    %ebp
  40cf39:	47                   	inc    %edi
  40cf3a:	45                   	inc    %ebp
  40cf3b:	52                   	push   %edx
  40cf3c:	5f                   	pop    %edi
  40cf3d:	44                   	inc    %esp
  40cf3e:	46                   	inc    %esi
  40cf3f:	4d                   	dec    %ebp
  40cf40:	4f                   	dec    %edi
  40cf41:	44                   	inc    %esp
  40cf42:	45                   	inc    %ebp
  40cf43:	5f                   	pop    %edi
  40cf44:	4d                   	dec    %ebp
  40cf45:	4f                   	dec    %edi
  40cf46:	56                   	push   %esi
  40cf47:	45                   	inc    %ebp
  40cf48:	53                   	push   %ebx
  40cf49:	00 1b                	add    %bl,(%ebx)
  40cf4b:	11 58 38             	adc    %ebx,0x38(%eax)
  40cf4e:	36 5f                	ss pop %edi
  40cf50:	54                   	push   %esp
  40cf51:	55                   	push   %ebp
  40cf52:	4e                   	dec    %esi
  40cf53:	45                   	inc    %ebp
  40cf54:	5f                   	pop    %edi
  40cf55:	4f                   	dec    %edi
  40cf56:	50                   	push   %eax
  40cf57:	54                   	push   %esp
  40cf58:	5f                   	pop    %edi
  40cf59:	41                   	inc    %ecx
  40cf5a:	47                   	inc    %edi
  40cf5b:	55                   	push   %ebp
  40cf5c:	00 1c 11             	add    %bl,(%ecx,%edx,1)
  40cf5f:	58                   	pop    %eax
  40cf60:	38 36                	cmp    %dh,(%esi)
  40cf62:	5f                   	pop    %edi
  40cf63:	54                   	push   %esp
  40cf64:	55                   	push   %ebp
  40cf65:	4e                   	dec    %esi
  40cf66:	45                   	inc    %ebp
  40cf67:	5f                   	pop    %edi
  40cf68:	41                   	inc    %ecx
  40cf69:	56                   	push   %esi
  40cf6a:	4f                   	dec    %edi
  40cf6b:	49                   	dec    %ecx
  40cf6c:	44                   	inc    %esp
  40cf6d:	5f                   	pop    %edi
  40cf6e:	4c                   	dec    %esp
  40cf6f:	45                   	inc    %ebp
  40cf70:	41                   	inc    %ecx
  40cf71:	5f                   	pop    %edi
  40cf72:	46                   	inc    %esi
  40cf73:	4f                   	dec    %edi
  40cf74:	52                   	push   %edx
  40cf75:	5f                   	pop    %edi
  40cf76:	41                   	inc    %ecx
  40cf77:	44                   	inc    %esp
  40cf78:	44                   	inc    %esp
  40cf79:	52                   	push   %edx
  40cf7a:	00 1d 11 58 38 36    	add    %bl,0x36385811
  40cf80:	5f                   	pop    %edi
  40cf81:	54                   	push   %esp
  40cf82:	55                   	push   %ebp
  40cf83:	4e                   	dec    %esi
  40cf84:	45                   	inc    %ebp
  40cf85:	5f                   	pop    %edi
  40cf86:	53                   	push   %ebx
  40cf87:	4c                   	dec    %esp
  40cf88:	4f                   	dec    %edi
  40cf89:	57                   	push   %edi
  40cf8a:	5f                   	pop    %edi
  40cf8b:	49                   	dec    %ecx
  40cf8c:	4d                   	dec    %ebp
  40cf8d:	55                   	push   %ebp
  40cf8e:	4c                   	dec    %esp
  40cf8f:	5f                   	pop    %edi
  40cf90:	49                   	dec    %ecx
  40cf91:	4d                   	dec    %ebp
  40cf92:	4d                   	dec    %ebp
  40cf93:	33 32                	xor    (%edx),%esi
  40cf95:	5f                   	pop    %edi
  40cf96:	4d                   	dec    %ebp
  40cf97:	45                   	inc    %ebp
  40cf98:	4d                   	dec    %ebp
  40cf99:	00 1e                	add    %bl,(%esi)
  40cf9b:	11 58 38             	adc    %ebx,0x38(%eax)
  40cf9e:	36 5f                	ss pop %edi
  40cfa0:	54                   	push   %esp
  40cfa1:	55                   	push   %ebp
  40cfa2:	4e                   	dec    %esi
  40cfa3:	45                   	inc    %ebp
  40cfa4:	5f                   	pop    %edi
  40cfa5:	53                   	push   %ebx
  40cfa6:	4c                   	dec    %esp
  40cfa7:	4f                   	dec    %edi
  40cfa8:	57                   	push   %edi
  40cfa9:	5f                   	pop    %edi
  40cfaa:	49                   	dec    %ecx
  40cfab:	4d                   	dec    %ebp
  40cfac:	55                   	push   %ebp
  40cfad:	4c                   	dec    %esp
  40cfae:	5f                   	pop    %edi
  40cfaf:	49                   	dec    %ecx
  40cfb0:	4d                   	dec    %ebp
  40cfb1:	4d                   	dec    %ebp
  40cfb2:	38 00                	cmp    %al,(%eax)
  40cfb4:	1f                   	pop    %ds
  40cfb5:	11 58 38             	adc    %ebx,0x38(%eax)
  40cfb8:	36 5f                	ss pop %edi
  40cfba:	54                   	push   %esp
  40cfbb:	55                   	push   %ebp
  40cfbc:	4e                   	dec    %esi
  40cfbd:	45                   	inc    %ebp
  40cfbe:	5f                   	pop    %edi
  40cfbf:	41                   	inc    %ecx
  40cfc0:	56                   	push   %esi
  40cfc1:	4f                   	dec    %edi
  40cfc2:	49                   	dec    %ecx
  40cfc3:	44                   	inc    %esp
  40cfc4:	5f                   	pop    %edi
  40cfc5:	4d                   	dec    %ebp
  40cfc6:	45                   	inc    %ebp
  40cfc7:	4d                   	dec    %ebp
  40cfc8:	5f                   	pop    %edi
  40cfc9:	4f                   	dec    %edi
  40cfca:	50                   	push   %eax
  40cfcb:	4e                   	dec    %esi
  40cfcc:	44                   	inc    %esp
  40cfcd:	5f                   	pop    %edi
  40cfce:	46                   	inc    %esi
  40cfcf:	4f                   	dec    %edi
  40cfd0:	52                   	push   %edx
  40cfd1:	5f                   	pop    %edi
  40cfd2:	43                   	inc    %ebx
  40cfd3:	4d                   	dec    %ebp
  40cfd4:	4f                   	dec    %edi
  40cfd5:	56                   	push   %esi
  40cfd6:	45                   	inc    %ebp
  40cfd7:	00 20                	add    %ah,(%eax)
  40cfd9:	11 58 38             	adc    %ebx,0x38(%eax)
  40cfdc:	36 5f                	ss pop %edi
  40cfde:	54                   	push   %esp
  40cfdf:	55                   	push   %ebp
  40cfe0:	4e                   	dec    %esi
  40cfe1:	45                   	inc    %ebp
  40cfe2:	5f                   	pop    %edi
  40cfe3:	53                   	push   %ebx
  40cfe4:	49                   	dec    %ecx
  40cfe5:	4e                   	dec    %esi
  40cfe6:	47                   	inc    %edi
  40cfe7:	4c                   	dec    %esp
  40cfe8:	45                   	inc    %ebp
  40cfe9:	5f                   	pop    %edi
  40cfea:	53                   	push   %ebx
  40cfeb:	54                   	push   %esp
  40cfec:	52                   	push   %edx
  40cfed:	49                   	dec    %ecx
  40cfee:	4e                   	dec    %esi
  40cfef:	47                   	inc    %edi
  40cff0:	4f                   	dec    %edi
  40cff1:	50                   	push   %eax
  40cff2:	00 21                	add    %ah,(%ecx)
  40cff4:	11 58 38             	adc    %ebx,0x38(%eax)
  40cff7:	36 5f                	ss pop %edi
  40cff9:	54                   	push   %esp
  40cffa:	55                   	push   %ebp
  40cffb:	4e                   	dec    %esi
  40cffc:	45                   	inc    %ebp
  40cffd:	5f                   	pop    %edi
  40cffe:	4d                   	dec    %ebp
  40cfff:	49                   	dec    %ecx
  40d000:	53                   	push   %ebx
  40d001:	41                   	inc    %ecx
  40d002:	4c                   	dec    %esp
  40d003:	49                   	dec    %ecx
  40d004:	47                   	inc    %edi
  40d005:	4e                   	dec    %esi
  40d006:	45                   	inc    %ebp
  40d007:	44                   	inc    %esp
  40d008:	5f                   	pop    %edi
  40d009:	4d                   	dec    %ebp
  40d00a:	4f                   	dec    %edi
  40d00b:	56                   	push   %esi
  40d00c:	45                   	inc    %ebp
  40d00d:	5f                   	pop    %edi
  40d00e:	53                   	push   %ebx
  40d00f:	54                   	push   %esp
  40d010:	52                   	push   %edx
  40d011:	49                   	dec    %ecx
  40d012:	4e                   	dec    %esi
  40d013:	47                   	inc    %edi
  40d014:	5f                   	pop    %edi
  40d015:	50                   	push   %eax
  40d016:	52                   	push   %edx
  40d017:	4f                   	dec    %edi
  40d018:	5f                   	pop    %edi
  40d019:	45                   	inc    %ebp
  40d01a:	50                   	push   %eax
  40d01b:	49                   	dec    %ecx
  40d01c:	4c                   	dec    %esp
  40d01d:	4f                   	dec    %edi
  40d01e:	47                   	inc    %edi
  40d01f:	55                   	push   %ebp
  40d020:	45                   	inc    %ebp
  40d021:	53                   	push   %ebx
  40d022:	00 22                	add    %ah,(%edx)
  40d024:	11 58 38             	adc    %ebx,0x38(%eax)
  40d027:	36 5f                	ss pop %edi
  40d029:	54                   	push   %esp
  40d02a:	55                   	push   %ebp
  40d02b:	4e                   	dec    %esi
  40d02c:	45                   	inc    %ebp
  40d02d:	5f                   	pop    %edi
  40d02e:	55                   	push   %ebp
  40d02f:	53                   	push   %ebx
  40d030:	45                   	inc    %ebp
  40d031:	5f                   	pop    %edi
  40d032:	53                   	push   %ebx
  40d033:	41                   	inc    %ecx
  40d034:	48                   	dec    %eax
  40d035:	46                   	inc    %esi
  40d036:	00 23                	add    %ah,(%ebx)
  40d038:	11 58 38             	adc    %ebx,0x38(%eax)
  40d03b:	36 5f                	ss pop %edi
  40d03d:	54                   	push   %esp
  40d03e:	55                   	push   %ebp
  40d03f:	4e                   	dec    %esi
  40d040:	45                   	inc    %ebp
  40d041:	5f                   	pop    %edi
  40d042:	55                   	push   %ebp
  40d043:	53                   	push   %ebx
  40d044:	45                   	inc    %ebp
  40d045:	5f                   	pop    %edi
  40d046:	43                   	inc    %ebx
  40d047:	4c                   	dec    %esp
  40d048:	54                   	push   %esp
  40d049:	44                   	inc    %esp
  40d04a:	00 24 11             	add    %ah,(%ecx,%edx,1)
  40d04d:	58                   	pop    %eax
  40d04e:	38 36                	cmp    %dh,(%esi)
  40d050:	5f                   	pop    %edi
  40d051:	54                   	push   %esp
  40d052:	55                   	push   %ebp
  40d053:	4e                   	dec    %esi
  40d054:	45                   	inc    %ebp
  40d055:	5f                   	pop    %edi
  40d056:	55                   	push   %ebp
  40d057:	53                   	push   %ebx
  40d058:	45                   	inc    %ebp
  40d059:	5f                   	pop    %edi
  40d05a:	42                   	inc    %edx
  40d05b:	54                   	push   %esp
  40d05c:	00 25 11 58 38 36    	add    %ah,0x36385811
  40d062:	5f                   	pop    %edi
  40d063:	54                   	push   %esp
  40d064:	55                   	push   %ebp
  40d065:	4e                   	dec    %esi
  40d066:	45                   	inc    %ebp
  40d067:	5f                   	pop    %edi
  40d068:	41                   	inc    %ecx
  40d069:	56                   	push   %esi
  40d06a:	4f                   	dec    %edi
  40d06b:	49                   	dec    %ecx
  40d06c:	44                   	inc    %esp
  40d06d:	5f                   	pop    %edi
  40d06e:	46                   	inc    %esi
  40d06f:	41                   	inc    %ecx
  40d070:	4c                   	dec    %esp
  40d071:	53                   	push   %ebx
  40d072:	45                   	inc    %ebp
  40d073:	5f                   	pop    %edi
  40d074:	44                   	inc    %esp
  40d075:	45                   	inc    %ebp
  40d076:	50                   	push   %eax
  40d077:	5f                   	pop    %edi
  40d078:	46                   	inc    %esi
  40d079:	4f                   	dec    %edi
  40d07a:	52                   	push   %edx
  40d07b:	5f                   	pop    %edi
  40d07c:	42                   	inc    %edx
  40d07d:	4d                   	dec    %ebp
  40d07e:	49                   	dec    %ecx
  40d07f:	00 26                	add    %ah,(%esi)
  40d081:	11 58 38             	adc    %ebx,0x38(%eax)
  40d084:	36 5f                	ss pop %edi
  40d086:	54                   	push   %esp
  40d087:	55                   	push   %ebp
  40d088:	4e                   	dec    %esi
  40d089:	45                   	inc    %ebp
  40d08a:	5f                   	pop    %edi
  40d08b:	41                   	inc    %ecx
  40d08c:	44                   	inc    %esp
  40d08d:	4a                   	dec    %edx
  40d08e:	55                   	push   %ebp
  40d08f:	53                   	push   %ebx
  40d090:	54                   	push   %esp
  40d091:	5f                   	pop    %edi
  40d092:	55                   	push   %ebp
  40d093:	4e                   	dec    %esi
  40d094:	52                   	push   %edx
  40d095:	4f                   	dec    %edi
  40d096:	4c                   	dec    %esp
  40d097:	4c                   	dec    %esp
  40d098:	00 27                	add    %ah,(%edi)
  40d09a:	11 58 38             	adc    %ebx,0x38(%eax)
  40d09d:	36 5f                	ss pop %edi
  40d09f:	54                   	push   %esp
  40d0a0:	55                   	push   %ebp
  40d0a1:	4e                   	dec    %esi
  40d0a2:	45                   	inc    %ebp
  40d0a3:	5f                   	pop    %edi
  40d0a4:	4f                   	dec    %edi
  40d0a5:	4e                   	dec    %esi
  40d0a6:	45                   	inc    %ebp
  40d0a7:	5f                   	pop    %edi
  40d0a8:	49                   	dec    %ecx
  40d0a9:	46                   	inc    %esi
  40d0aa:	5f                   	pop    %edi
  40d0ab:	43                   	inc    %ebx
  40d0ac:	4f                   	dec    %edi
  40d0ad:	4e                   	dec    %esi
  40d0ae:	56                   	push   %esi
  40d0af:	5f                   	pop    %edi
  40d0b0:	49                   	dec    %ecx
  40d0b1:	4e                   	dec    %esi
  40d0b2:	53                   	push   %ebx
  40d0b3:	4e                   	dec    %esi
  40d0b4:	00 28                	add    %ch,(%eax)
  40d0b6:	11 58 38             	adc    %ebx,0x38(%eax)
  40d0b9:	36 5f                	ss pop %edi
  40d0bb:	54                   	push   %esp
  40d0bc:	55                   	push   %ebp
  40d0bd:	4e                   	dec    %esi
  40d0be:	45                   	inc    %ebp
  40d0bf:	5f                   	pop    %edi
  40d0c0:	55                   	push   %ebp
  40d0c1:	53                   	push   %ebx
  40d0c2:	45                   	inc    %ebp
  40d0c3:	5f                   	pop    %edi
  40d0c4:	48                   	dec    %eax
  40d0c5:	49                   	dec    %ecx
  40d0c6:	4d                   	dec    %ebp
  40d0c7:	4f                   	dec    %edi
  40d0c8:	44                   	inc    %esp
  40d0c9:	45                   	inc    %ebp
  40d0ca:	5f                   	pop    %edi
  40d0cb:	46                   	inc    %esi
  40d0cc:	49                   	dec    %ecx
  40d0cd:	4f                   	dec    %edi
  40d0ce:	50                   	push   %eax
  40d0cf:	00 29                	add    %ch,(%ecx)
  40d0d1:	11 58 38             	adc    %ebx,0x38(%eax)
  40d0d4:	36 5f                	ss pop %edi
  40d0d6:	54                   	push   %esp
  40d0d7:	55                   	push   %ebp
  40d0d8:	4e                   	dec    %esi
  40d0d9:	45                   	inc    %ebp
  40d0da:	5f                   	pop    %edi
  40d0db:	55                   	push   %ebp
  40d0dc:	53                   	push   %ebx
  40d0dd:	45                   	inc    %ebp
  40d0de:	5f                   	pop    %edi
  40d0df:	53                   	push   %ebx
  40d0e0:	49                   	dec    %ecx
  40d0e1:	4d                   	dec    %ebp
  40d0e2:	4f                   	dec    %edi
  40d0e3:	44                   	inc    %esp
  40d0e4:	45                   	inc    %ebp
  40d0e5:	5f                   	pop    %edi
  40d0e6:	46                   	inc    %esi
  40d0e7:	49                   	dec    %ecx
  40d0e8:	4f                   	dec    %edi
  40d0e9:	50                   	push   %eax
  40d0ea:	00 2a                	add    %ch,(%edx)
  40d0ec:	11 58 38             	adc    %ebx,0x38(%eax)
  40d0ef:	36 5f                	ss pop %edi
  40d0f1:	54                   	push   %esp
  40d0f2:	55                   	push   %ebp
  40d0f3:	4e                   	dec    %esi
  40d0f4:	45                   	inc    %ebp
  40d0f5:	5f                   	pop    %edi
  40d0f6:	55                   	push   %ebp
  40d0f7:	53                   	push   %ebx
  40d0f8:	45                   	inc    %ebp
  40d0f9:	5f                   	pop    %edi
  40d0fa:	46                   	inc    %esi
  40d0fb:	46                   	inc    %esi
  40d0fc:	52                   	push   %edx
  40d0fd:	45                   	inc    %ebp
  40d0fe:	45                   	inc    %ebp
  40d0ff:	50                   	push   %eax
  40d100:	00 2b                	add    %ch,(%ebx)
  40d102:	11 58 38             	adc    %ebx,0x38(%eax)
  40d105:	36 5f                	ss pop %edi
  40d107:	54                   	push   %esp
  40d108:	55                   	push   %ebp
  40d109:	4e                   	dec    %esi
  40d10a:	45                   	inc    %ebp
  40d10b:	5f                   	pop    %edi
  40d10c:	45                   	inc    %ebp
  40d10d:	58                   	pop    %eax
  40d10e:	54                   	push   %esp
  40d10f:	5f                   	pop    %edi
  40d110:	38 30                	cmp    %dh,(%eax)
  40d112:	33 38                	xor    (%eax),%edi
  40d114:	37                   	aaa    
  40d115:	5f                   	pop    %edi
  40d116:	43                   	inc    %ebx
  40d117:	4f                   	dec    %edi
  40d118:	4e                   	dec    %esi
  40d119:	53                   	push   %ebx
  40d11a:	54                   	push   %esp
  40d11b:	41                   	inc    %ecx
  40d11c:	4e                   	dec    %esi
  40d11d:	54                   	push   %esp
  40d11e:	53                   	push   %ebx
  40d11f:	00 2c 11             	add    %ch,(%ecx,%edx,1)
  40d122:	58                   	pop    %eax
  40d123:	38 36                	cmp    %dh,(%esi)
  40d125:	5f                   	pop    %edi
  40d126:	54                   	push   %esp
  40d127:	55                   	push   %ebp
  40d128:	4e                   	dec    %esi
  40d129:	45                   	inc    %ebp
  40d12a:	5f                   	pop    %edi
  40d12b:	47                   	inc    %edi
  40d12c:	45                   	inc    %ebp
  40d12d:	4e                   	dec    %esi
  40d12e:	45                   	inc    %ebp
  40d12f:	52                   	push   %edx
  40d130:	41                   	inc    %ecx
  40d131:	4c                   	dec    %esp
  40d132:	5f                   	pop    %edi
  40d133:	52                   	push   %edx
  40d134:	45                   	inc    %ebp
  40d135:	47                   	inc    %edi
  40d136:	53                   	push   %ebx
  40d137:	5f                   	pop    %edi
  40d138:	53                   	push   %ebx
  40d139:	53                   	push   %ebx
  40d13a:	45                   	inc    %ebp
  40d13b:	5f                   	pop    %edi
  40d13c:	53                   	push   %ebx
  40d13d:	50                   	push   %eax
  40d13e:	49                   	dec    %ecx
  40d13f:	4c                   	dec    %esp
  40d140:	4c                   	dec    %esp
  40d141:	00 2d 11 58 38 36    	add    %ch,0x36385811
  40d147:	5f                   	pop    %edi
  40d148:	54                   	push   %esp
  40d149:	55                   	push   %ebp
  40d14a:	4e                   	dec    %esi
  40d14b:	45                   	inc    %ebp
  40d14c:	5f                   	pop    %edi
  40d14d:	53                   	push   %ebx
  40d14e:	53                   	push   %ebx
  40d14f:	45                   	inc    %ebp
  40d150:	5f                   	pop    %edi
  40d151:	55                   	push   %ebp
  40d152:	4e                   	dec    %esi
  40d153:	41                   	inc    %ecx
  40d154:	4c                   	dec    %esp
  40d155:	49                   	dec    %ecx
  40d156:	47                   	inc    %edi
  40d157:	4e                   	dec    %esi
  40d158:	45                   	inc    %ebp
  40d159:	44                   	inc    %esp
  40d15a:	5f                   	pop    %edi
  40d15b:	4c                   	dec    %esp
  40d15c:	4f                   	dec    %edi
  40d15d:	41                   	inc    %ecx
  40d15e:	44                   	inc    %esp
  40d15f:	5f                   	pop    %edi
  40d160:	4f                   	dec    %edi
  40d161:	50                   	push   %eax
  40d162:	54                   	push   %esp
  40d163:	49                   	dec    %ecx
  40d164:	4d                   	dec    %ebp
  40d165:	41                   	inc    %ecx
  40d166:	4c                   	dec    %esp
  40d167:	00 2e                	add    %ch,(%esi)
  40d169:	11 58 38             	adc    %ebx,0x38(%eax)
  40d16c:	36 5f                	ss pop %edi
  40d16e:	54                   	push   %esp
  40d16f:	55                   	push   %ebp
  40d170:	4e                   	dec    %esi
  40d171:	45                   	inc    %ebp
  40d172:	5f                   	pop    %edi
  40d173:	53                   	push   %ebx
  40d174:	53                   	push   %ebx
  40d175:	45                   	inc    %ebp
  40d176:	5f                   	pop    %edi
  40d177:	55                   	push   %ebp
  40d178:	4e                   	dec    %esi
  40d179:	41                   	inc    %ecx
  40d17a:	4c                   	dec    %esp
  40d17b:	49                   	dec    %ecx
  40d17c:	47                   	inc    %edi
  40d17d:	4e                   	dec    %esi
  40d17e:	45                   	inc    %ebp
  40d17f:	44                   	inc    %esp
  40d180:	5f                   	pop    %edi
  40d181:	53                   	push   %ebx
  40d182:	54                   	push   %esp
  40d183:	4f                   	dec    %edi
  40d184:	52                   	push   %edx
  40d185:	45                   	inc    %ebp
  40d186:	5f                   	pop    %edi
  40d187:	4f                   	dec    %edi
  40d188:	50                   	push   %eax
  40d189:	54                   	push   %esp
  40d18a:	49                   	dec    %ecx
  40d18b:	4d                   	dec    %ebp
  40d18c:	41                   	inc    %ecx
  40d18d:	4c                   	dec    %esp
  40d18e:	00 2f                	add    %ch,(%edi)
  40d190:	11 58 38             	adc    %ebx,0x38(%eax)
  40d193:	36 5f                	ss pop %edi
  40d195:	54                   	push   %esp
  40d196:	55                   	push   %ebp
  40d197:	4e                   	dec    %esi
  40d198:	45                   	inc    %ebp
  40d199:	5f                   	pop    %edi
  40d19a:	53                   	push   %ebx
  40d19b:	53                   	push   %ebx
  40d19c:	45                   	inc    %ebp
  40d19d:	5f                   	pop    %edi
  40d19e:	50                   	push   %eax
  40d19f:	41                   	inc    %ecx
  40d1a0:	43                   	inc    %ebx
  40d1a1:	4b                   	dec    %ebx
  40d1a2:	45                   	inc    %ebp
  40d1a3:	44                   	inc    %esp
  40d1a4:	5f                   	pop    %edi
  40d1a5:	53                   	push   %ebx
  40d1a6:	49                   	dec    %ecx
  40d1a7:	4e                   	dec    %esi
  40d1a8:	47                   	inc    %edi
  40d1a9:	4c                   	dec    %esp
  40d1aa:	45                   	inc    %ebp
  40d1ab:	5f                   	pop    %edi
  40d1ac:	49                   	dec    %ecx
  40d1ad:	4e                   	dec    %esi
  40d1ae:	53                   	push   %ebx
  40d1af:	4e                   	dec    %esi
  40d1b0:	5f                   	pop    %edi
  40d1b1:	4f                   	dec    %edi
  40d1b2:	50                   	push   %eax
  40d1b3:	54                   	push   %esp
  40d1b4:	49                   	dec    %ecx
  40d1b5:	4d                   	dec    %ebp
  40d1b6:	41                   	inc    %ecx
  40d1b7:	4c                   	dec    %esp
  40d1b8:	00 30                	add    %dh,(%eax)
  40d1ba:	11 58 38             	adc    %ebx,0x38(%eax)
  40d1bd:	36 5f                	ss pop %edi
  40d1bf:	54                   	push   %esp
  40d1c0:	55                   	push   %ebp
  40d1c1:	4e                   	dec    %esi
  40d1c2:	45                   	inc    %ebp
  40d1c3:	5f                   	pop    %edi
  40d1c4:	53                   	push   %ebx
  40d1c5:	53                   	push   %ebx
  40d1c6:	45                   	inc    %ebp
  40d1c7:	5f                   	pop    %edi
  40d1c8:	54                   	push   %esp
  40d1c9:	59                   	pop    %ecx
  40d1ca:	50                   	push   %eax
  40d1cb:	45                   	inc    %ebp
  40d1cc:	4c                   	dec    %esp
  40d1cd:	45                   	inc    %ebp
  40d1ce:	53                   	push   %ebx
  40d1cf:	53                   	push   %ebx
  40d1d0:	5f                   	pop    %edi
  40d1d1:	53                   	push   %ebx
  40d1d2:	54                   	push   %esp
  40d1d3:	4f                   	dec    %edi
  40d1d4:	52                   	push   %edx
  40d1d5:	45                   	inc    %ebp
  40d1d6:	53                   	push   %ebx
  40d1d7:	00 31                	add    %dh,(%ecx)
  40d1d9:	11 58 38             	adc    %ebx,0x38(%eax)
  40d1dc:	36 5f                	ss pop %edi
  40d1de:	54                   	push   %esp
  40d1df:	55                   	push   %ebp
  40d1e0:	4e                   	dec    %esi
  40d1e1:	45                   	inc    %ebp
  40d1e2:	5f                   	pop    %edi
  40d1e3:	53                   	push   %ebx
  40d1e4:	53                   	push   %ebx
  40d1e5:	45                   	inc    %ebp
  40d1e6:	5f                   	pop    %edi
  40d1e7:	4c                   	dec    %esp
  40d1e8:	4f                   	dec    %edi
  40d1e9:	41                   	inc    %ecx
  40d1ea:	44                   	inc    %esp
  40d1eb:	30 5f 42             	xor    %bl,0x42(%edi)
  40d1ee:	59                   	pop    %ecx
  40d1ef:	5f                   	pop    %edi
  40d1f0:	50                   	push   %eax
  40d1f1:	58                   	pop    %eax
  40d1f2:	4f                   	dec    %edi
  40d1f3:	52                   	push   %edx
  40d1f4:	00 32                	add    %dh,(%edx)
  40d1f6:	11 58 38             	adc    %ebx,0x38(%eax)
  40d1f9:	36 5f                	ss pop %edi
  40d1fb:	54                   	push   %esp
  40d1fc:	55                   	push   %ebp
  40d1fd:	4e                   	dec    %esi
  40d1fe:	45                   	inc    %ebp
  40d1ff:	5f                   	pop    %edi
  40d200:	49                   	dec    %ecx
  40d201:	4e                   	dec    %esi
  40d202:	54                   	push   %esp
  40d203:	45                   	inc    %ebp
  40d204:	52                   	push   %edx
  40d205:	5f                   	pop    %edi
  40d206:	55                   	push   %ebp
  40d207:	4e                   	dec    %esi
  40d208:	49                   	dec    %ecx
  40d209:	54                   	push   %esp
  40d20a:	5f                   	pop    %edi
  40d20b:	4d                   	dec    %ebp
  40d20c:	4f                   	dec    %edi
  40d20d:	56                   	push   %esi
  40d20e:	45                   	inc    %ebp
  40d20f:	53                   	push   %ebx
  40d210:	5f                   	pop    %edi
  40d211:	54                   	push   %esp
  40d212:	4f                   	dec    %edi
  40d213:	5f                   	pop    %edi
  40d214:	56                   	push   %esi
  40d215:	45                   	inc    %ebp
  40d216:	43                   	inc    %ebx
  40d217:	00 33                	add    %dh,(%ebx)
  40d219:	11 58 38             	adc    %ebx,0x38(%eax)
  40d21c:	36 5f                	ss pop %edi
  40d21e:	54                   	push   %esp
  40d21f:	55                   	push   %ebp
  40d220:	4e                   	dec    %esi
  40d221:	45                   	inc    %ebp
  40d222:	5f                   	pop    %edi
  40d223:	49                   	dec    %ecx
  40d224:	4e                   	dec    %esi
  40d225:	54                   	push   %esp
  40d226:	45                   	inc    %ebp
  40d227:	52                   	push   %edx
  40d228:	5f                   	pop    %edi
  40d229:	55                   	push   %ebp
  40d22a:	4e                   	dec    %esi
  40d22b:	49                   	dec    %ecx
  40d22c:	54                   	push   %esp
  40d22d:	5f                   	pop    %edi
  40d22e:	4d                   	dec    %ebp
  40d22f:	4f                   	dec    %edi
  40d230:	56                   	push   %esi
  40d231:	45                   	inc    %ebp
  40d232:	53                   	push   %ebx
  40d233:	5f                   	pop    %edi
  40d234:	46                   	inc    %esi
  40d235:	52                   	push   %edx
  40d236:	4f                   	dec    %edi
  40d237:	4d                   	dec    %ebp
  40d238:	5f                   	pop    %edi
  40d239:	56                   	push   %esi
  40d23a:	45                   	inc    %ebp
  40d23b:	43                   	inc    %ebx
  40d23c:	00 34 11             	add    %dh,(%ecx,%edx,1)
  40d23f:	58                   	pop    %eax
  40d240:	38 36                	cmp    %dh,(%esi)
  40d242:	5f                   	pop    %edi
  40d243:	54                   	push   %esp
  40d244:	55                   	push   %ebp
  40d245:	4e                   	dec    %esi
  40d246:	45                   	inc    %ebp
  40d247:	5f                   	pop    %edi
  40d248:	49                   	dec    %ecx
  40d249:	4e                   	dec    %esi
  40d24a:	54                   	push   %esp
  40d24b:	45                   	inc    %ebp
  40d24c:	52                   	push   %edx
  40d24d:	5f                   	pop    %edi
  40d24e:	55                   	push   %ebp
  40d24f:	4e                   	dec    %esi
  40d250:	49                   	dec    %ecx
  40d251:	54                   	push   %esp
  40d252:	5f                   	pop    %edi
  40d253:	43                   	inc    %ebx
  40d254:	4f                   	dec    %edi
  40d255:	4e                   	dec    %esi
  40d256:	56                   	push   %esi
  40d257:	45                   	inc    %ebp
  40d258:	52                   	push   %edx
  40d259:	53                   	push   %ebx
  40d25a:	49                   	dec    %ecx
  40d25b:	4f                   	dec    %edi
  40d25c:	4e                   	dec    %esi
  40d25d:	53                   	push   %ebx
  40d25e:	00 35 11 58 38 36    	add    %dh,0x36385811
  40d264:	5f                   	pop    %edi
  40d265:	54                   	push   %esp
  40d266:	55                   	push   %ebp
  40d267:	4e                   	dec    %esi
  40d268:	45                   	inc    %ebp
  40d269:	5f                   	pop    %edi
  40d26a:	53                   	push   %ebx
  40d26b:	50                   	push   %eax
  40d26c:	4c                   	dec    %esp
  40d26d:	49                   	dec    %ecx
  40d26e:	54                   	push   %esp
  40d26f:	5f                   	pop    %edi
  40d270:	4d                   	dec    %ebp
  40d271:	45                   	inc    %ebp
  40d272:	4d                   	dec    %ebp
  40d273:	5f                   	pop    %edi
  40d274:	4f                   	dec    %edi
  40d275:	50                   	push   %eax
  40d276:	4e                   	dec    %esi
  40d277:	44                   	inc    %esp
  40d278:	5f                   	pop    %edi
  40d279:	46                   	inc    %esi
  40d27a:	4f                   	dec    %edi
  40d27b:	52                   	push   %edx
  40d27c:	5f                   	pop    %edi
  40d27d:	46                   	inc    %esi
  40d27e:	50                   	push   %eax
  40d27f:	5f                   	pop    %edi
  40d280:	43                   	inc    %ebx
  40d281:	4f                   	dec    %edi
  40d282:	4e                   	dec    %esi
  40d283:	56                   	push   %esi
  40d284:	45                   	inc    %ebp
  40d285:	52                   	push   %edx
  40d286:	54                   	push   %esp
  40d287:	53                   	push   %ebx
  40d288:	00 36                	add    %dh,(%esi)
  40d28a:	11 58 38             	adc    %ebx,0x38(%eax)
  40d28d:	36 5f                	ss pop %edi
  40d28f:	54                   	push   %esp
  40d290:	55                   	push   %ebp
  40d291:	4e                   	dec    %esi
  40d292:	45                   	inc    %ebp
  40d293:	5f                   	pop    %edi
  40d294:	55                   	push   %ebp
  40d295:	53                   	push   %ebx
  40d296:	45                   	inc    %ebp
  40d297:	5f                   	pop    %edi
  40d298:	56                   	push   %esi
  40d299:	45                   	inc    %ebp
  40d29a:	43                   	inc    %ebx
  40d29b:	54                   	push   %esp
  40d29c:	4f                   	dec    %edi
  40d29d:	52                   	push   %edx
  40d29e:	5f                   	pop    %edi
  40d29f:	46                   	inc    %esi
  40d2a0:	50                   	push   %eax
  40d2a1:	5f                   	pop    %edi
  40d2a2:	43                   	inc    %ebx
  40d2a3:	4f                   	dec    %edi
  40d2a4:	4e                   	dec    %esi
  40d2a5:	56                   	push   %esi
  40d2a6:	45                   	inc    %ebp
  40d2a7:	52                   	push   %edx
  40d2a8:	54                   	push   %esp
  40d2a9:	53                   	push   %ebx
  40d2aa:	00 37                	add    %dh,(%edi)
  40d2ac:	11 58 38             	adc    %ebx,0x38(%eax)
  40d2af:	36 5f                	ss pop %edi
  40d2b1:	54                   	push   %esp
  40d2b2:	55                   	push   %ebp
  40d2b3:	4e                   	dec    %esi
  40d2b4:	45                   	inc    %ebp
  40d2b5:	5f                   	pop    %edi
  40d2b6:	55                   	push   %ebp
  40d2b7:	53                   	push   %ebx
  40d2b8:	45                   	inc    %ebp
  40d2b9:	5f                   	pop    %edi
  40d2ba:	56                   	push   %esi
  40d2bb:	45                   	inc    %ebp
  40d2bc:	43                   	inc    %ebx
  40d2bd:	54                   	push   %esp
  40d2be:	4f                   	dec    %edi
  40d2bf:	52                   	push   %edx
  40d2c0:	5f                   	pop    %edi
  40d2c1:	43                   	inc    %ebx
  40d2c2:	4f                   	dec    %edi
  40d2c3:	4e                   	dec    %esi
  40d2c4:	56                   	push   %esi
  40d2c5:	45                   	inc    %ebp
  40d2c6:	52                   	push   %edx
  40d2c7:	54                   	push   %esp
  40d2c8:	53                   	push   %ebx
  40d2c9:	00 38                	add    %bh,(%eax)
  40d2cb:	11 58 38             	adc    %ebx,0x38(%eax)
  40d2ce:	36 5f                	ss pop %edi
  40d2d0:	54                   	push   %esp
  40d2d1:	55                   	push   %ebp
  40d2d2:	4e                   	dec    %esi
  40d2d3:	45                   	inc    %ebp
  40d2d4:	5f                   	pop    %edi
  40d2d5:	53                   	push   %ebx
  40d2d6:	4c                   	dec    %esp
  40d2d7:	4f                   	dec    %edi
  40d2d8:	57                   	push   %edi
  40d2d9:	5f                   	pop    %edi
  40d2da:	50                   	push   %eax
  40d2db:	53                   	push   %ebx
  40d2dc:	48                   	dec    %eax
  40d2dd:	55                   	push   %ebp
  40d2de:	46                   	inc    %esi
  40d2df:	42                   	inc    %edx
  40d2e0:	00 39                	add    %bh,(%ecx)
  40d2e2:	11 58 38             	adc    %ebx,0x38(%eax)
  40d2e5:	36 5f                	ss pop %edi
  40d2e7:	54                   	push   %esp
  40d2e8:	55                   	push   %ebp
  40d2e9:	4e                   	dec    %esi
  40d2ea:	45                   	inc    %ebp
  40d2eb:	5f                   	pop    %edi
  40d2ec:	41                   	inc    %ecx
  40d2ed:	56                   	push   %esi
  40d2ee:	4f                   	dec    %edi
  40d2ef:	49                   	dec    %ecx
  40d2f0:	44                   	inc    %esp
  40d2f1:	5f                   	pop    %edi
  40d2f2:	34 42                	xor    $0x42,%al
  40d2f4:	59                   	pop    %ecx
  40d2f5:	54                   	push   %esp
  40d2f6:	45                   	inc    %ebp
  40d2f7:	5f                   	pop    %edi
  40d2f8:	50                   	push   %eax
  40d2f9:	52                   	push   %edx
  40d2fa:	45                   	inc    %ebp
  40d2fb:	46                   	inc    %esi
  40d2fc:	49                   	dec    %ecx
  40d2fd:	58                   	pop    %eax
  40d2fe:	45                   	inc    %ebp
  40d2ff:	53                   	push   %ebx
  40d300:	00 3a                	add    %bh,(%edx)
  40d302:	11 58 38             	adc    %ebx,0x38(%eax)
  40d305:	36 5f                	ss pop %edi
  40d307:	54                   	push   %esp
  40d308:	55                   	push   %ebp
  40d309:	4e                   	dec    %esi
  40d30a:	45                   	inc    %ebp
  40d30b:	5f                   	pop    %edi
  40d30c:	55                   	push   %ebp
  40d30d:	53                   	push   %ebx
  40d30e:	45                   	inc    %ebp
  40d30f:	5f                   	pop    %edi
  40d310:	47                   	inc    %edi
  40d311:	41                   	inc    %ecx
  40d312:	54                   	push   %esp
  40d313:	48                   	dec    %eax
  40d314:	45                   	inc    %ebp
  40d315:	52                   	push   %edx
  40d316:	00 3b                	add    %bh,(%ebx)
  40d318:	11 58 38             	adc    %ebx,0x38(%eax)
  40d31b:	36 5f                	ss pop %edi
  40d31d:	54                   	push   %esp
  40d31e:	55                   	push   %ebp
  40d31f:	4e                   	dec    %esi
  40d320:	45                   	inc    %ebp
  40d321:	5f                   	pop    %edi
  40d322:	41                   	inc    %ecx
  40d323:	56                   	push   %esi
  40d324:	4f                   	dec    %edi
  40d325:	49                   	dec    %ecx
  40d326:	44                   	inc    %esp
  40d327:	5f                   	pop    %edi
  40d328:	31 32                	xor    %esi,(%edx)
  40d32a:	38 46 4d             	cmp    %al,0x4d(%esi)
  40d32d:	41                   	inc    %ecx
  40d32e:	5f                   	pop    %edi
  40d32f:	43                   	inc    %ebx
  40d330:	48                   	dec    %eax
  40d331:	41                   	inc    %ecx
  40d332:	49                   	dec    %ecx
  40d333:	4e                   	dec    %esi
  40d334:	53                   	push   %ebx
  40d335:	00 3c 11             	add    %bh,(%ecx,%edx,1)
  40d338:	58                   	pop    %eax
  40d339:	38 36                	cmp    %dh,(%esi)
  40d33b:	5f                   	pop    %edi
  40d33c:	54                   	push   %esp
  40d33d:	55                   	push   %ebp
  40d33e:	4e                   	dec    %esi
  40d33f:	45                   	inc    %ebp
  40d340:	5f                   	pop    %edi
  40d341:	41                   	inc    %ecx
  40d342:	56                   	push   %esi
  40d343:	4f                   	dec    %edi
  40d344:	49                   	dec    %ecx
  40d345:	44                   	inc    %esp
  40d346:	5f                   	pop    %edi
  40d347:	32 35 36 46 4d 41    	xor    0x414d4636,%dh
  40d34d:	5f                   	pop    %edi
  40d34e:	43                   	inc    %ebx
  40d34f:	48                   	dec    %eax
  40d350:	41                   	inc    %ecx
  40d351:	49                   	dec    %ecx
  40d352:	4e                   	dec    %esi
  40d353:	53                   	push   %ebx
  40d354:	00 3d 11 58 38 36    	add    %bh,0x36385811
  40d35a:	5f                   	pop    %edi
  40d35b:	54                   	push   %esp
  40d35c:	55                   	push   %ebp
  40d35d:	4e                   	dec    %esi
  40d35e:	45                   	inc    %ebp
  40d35f:	5f                   	pop    %edi
  40d360:	41                   	inc    %ecx
  40d361:	56                   	push   %esi
  40d362:	58                   	pop    %eax
  40d363:	32 35 36 5f 55 4e    	xor    0x4e555f36,%dh
  40d369:	41                   	inc    %ecx
  40d36a:	4c                   	dec    %esp
  40d36b:	49                   	dec    %ecx
  40d36c:	47                   	inc    %edi
  40d36d:	4e                   	dec    %esi
  40d36e:	45                   	inc    %ebp
  40d36f:	44                   	inc    %esp
  40d370:	5f                   	pop    %edi
  40d371:	4c                   	dec    %esp
  40d372:	4f                   	dec    %edi
  40d373:	41                   	inc    %ecx
  40d374:	44                   	inc    %esp
  40d375:	5f                   	pop    %edi
  40d376:	4f                   	dec    %edi
  40d377:	50                   	push   %eax
  40d378:	54                   	push   %esp
  40d379:	49                   	dec    %ecx
  40d37a:	4d                   	dec    %ebp
  40d37b:	41                   	inc    %ecx
  40d37c:	4c                   	dec    %esp
  40d37d:	00 3e                	add    %bh,(%esi)
  40d37f:	11 58 38             	adc    %ebx,0x38(%eax)
  40d382:	36 5f                	ss pop %edi
  40d384:	54                   	push   %esp
  40d385:	55                   	push   %ebp
  40d386:	4e                   	dec    %esi
  40d387:	45                   	inc    %ebp
  40d388:	5f                   	pop    %edi
  40d389:	41                   	inc    %ecx
  40d38a:	56                   	push   %esi
  40d38b:	58                   	pop    %eax
  40d38c:	32 35 36 5f 55 4e    	xor    0x4e555f36,%dh
  40d392:	41                   	inc    %ecx
  40d393:	4c                   	dec    %esp
  40d394:	49                   	dec    %ecx
  40d395:	47                   	inc    %edi
  40d396:	4e                   	dec    %esi
  40d397:	45                   	inc    %ebp
  40d398:	44                   	inc    %esp
  40d399:	5f                   	pop    %edi
  40d39a:	53                   	push   %ebx
  40d39b:	54                   	push   %esp
  40d39c:	4f                   	dec    %edi
  40d39d:	52                   	push   %edx
  40d39e:	45                   	inc    %ebp
  40d39f:	5f                   	pop    %edi
  40d3a0:	4f                   	dec    %edi
  40d3a1:	50                   	push   %eax
  40d3a2:	54                   	push   %esp
  40d3a3:	49                   	dec    %ecx
  40d3a4:	4d                   	dec    %ebp
  40d3a5:	41                   	inc    %ecx
  40d3a6:	4c                   	dec    %esp
  40d3a7:	00 3f                	add    %bh,(%edi)
  40d3a9:	11 58 38             	adc    %ebx,0x38(%eax)
  40d3ac:	36 5f                	ss pop %edi
  40d3ae:	54                   	push   %esp
  40d3af:	55                   	push   %ebp
  40d3b0:	4e                   	dec    %esi
  40d3b1:	45                   	inc    %ebp
  40d3b2:	5f                   	pop    %edi
  40d3b3:	41                   	inc    %ecx
  40d3b4:	56                   	push   %esi
  40d3b5:	58                   	pop    %eax
  40d3b6:	31 32                	xor    %esi,(%edx)
  40d3b8:	38 5f 4f             	cmp    %bl,0x4f(%edi)
  40d3bb:	50                   	push   %eax
  40d3bc:	54                   	push   %esp
  40d3bd:	49                   	dec    %ecx
  40d3be:	4d                   	dec    %ebp
  40d3bf:	41                   	inc    %ecx
  40d3c0:	4c                   	dec    %esp
  40d3c1:	00 40 11             	add    %al,0x11(%eax)
  40d3c4:	58                   	pop    %eax
  40d3c5:	38 36                	cmp    %dh,(%esi)
  40d3c7:	5f                   	pop    %edi
  40d3c8:	54                   	push   %esp
  40d3c9:	55                   	push   %ebp
  40d3ca:	4e                   	dec    %esi
  40d3cb:	45                   	inc    %ebp
  40d3cc:	5f                   	pop    %edi
  40d3cd:	41                   	inc    %ecx
  40d3ce:	56                   	push   %esi
  40d3cf:	58                   	pop    %eax
  40d3d0:	32 35 36 5f 4f 50    	xor    0x504f5f36,%dh
  40d3d6:	54                   	push   %esp
  40d3d7:	49                   	dec    %ecx
  40d3d8:	4d                   	dec    %ebp
  40d3d9:	41                   	inc    %ecx
  40d3da:	4c                   	dec    %esp
  40d3db:	00 41 11             	add    %al,0x11(%ecx)
  40d3de:	58                   	pop    %eax
  40d3df:	38 36                	cmp    %dh,(%esi)
  40d3e1:	5f                   	pop    %edi
  40d3e2:	54                   	push   %esp
  40d3e3:	55                   	push   %ebp
  40d3e4:	4e                   	dec    %esi
  40d3e5:	45                   	inc    %ebp
  40d3e6:	5f                   	pop    %edi
  40d3e7:	44                   	inc    %esp
  40d3e8:	4f                   	dec    %edi
  40d3e9:	55                   	push   %ebp
  40d3ea:	42                   	inc    %edx
  40d3eb:	4c                   	dec    %esp
  40d3ec:	45                   	inc    %ebp
  40d3ed:	5f                   	pop    %edi
  40d3ee:	57                   	push   %edi
  40d3ef:	49                   	dec    %ecx
  40d3f0:	54                   	push   %esp
  40d3f1:	48                   	dec    %eax
  40d3f2:	5f                   	pop    %edi
  40d3f3:	41                   	inc    %ecx
  40d3f4:	44                   	inc    %esp
  40d3f5:	44                   	inc    %esp
  40d3f6:	00 42 11             	add    %al,0x11(%edx)
  40d3f9:	58                   	pop    %eax
  40d3fa:	38 36                	cmp    %dh,(%esi)
  40d3fc:	5f                   	pop    %edi
  40d3fd:	54                   	push   %esp
  40d3fe:	55                   	push   %ebp
  40d3ff:	4e                   	dec    %esi
  40d400:	45                   	inc    %ebp
  40d401:	5f                   	pop    %edi
  40d402:	41                   	inc    %ecx
  40d403:	4c                   	dec    %esp
  40d404:	57                   	push   %edi
  40d405:	41                   	inc    %ecx
  40d406:	59                   	pop    %ecx
  40d407:	53                   	push   %ebx
  40d408:	5f                   	pop    %edi
  40d409:	46                   	inc    %esi
  40d40a:	41                   	inc    %ecx
  40d40b:	4e                   	dec    %esi
  40d40c:	43                   	inc    %ebx
  40d40d:	59                   	pop    %ecx
  40d40e:	5f                   	pop    %edi
  40d40f:	4d                   	dec    %ebp
  40d410:	41                   	inc    %ecx
  40d411:	54                   	push   %esp
  40d412:	48                   	dec    %eax
  40d413:	5f                   	pop    %edi
  40d414:	33 38                	xor    (%eax),%edi
  40d416:	37                   	aaa    
  40d417:	00 43 11             	add    %al,0x11(%ebx)
  40d41a:	58                   	pop    %eax
  40d41b:	38 36                	cmp    %dh,(%esi)
  40d41d:	5f                   	pop    %edi
  40d41e:	54                   	push   %esp
  40d41f:	55                   	push   %ebp
  40d420:	4e                   	dec    %esi
  40d421:	45                   	inc    %ebp
  40d422:	5f                   	pop    %edi
  40d423:	55                   	push   %ebp
  40d424:	4e                   	dec    %esi
  40d425:	52                   	push   %edx
  40d426:	4f                   	dec    %edi
  40d427:	4c                   	dec    %esp
  40d428:	4c                   	dec    %esp
  40d429:	5f                   	pop    %edi
  40d42a:	53                   	push   %ebx
  40d42b:	54                   	push   %esp
  40d42c:	52                   	push   %edx
  40d42d:	4c                   	dec    %esp
  40d42e:	45                   	inc    %ebp
  40d42f:	4e                   	dec    %esi
  40d430:	00 44 11 58          	add    %al,0x58(%ecx,%edx,1)
  40d434:	38 36                	cmp    %dh,(%esi)
  40d436:	5f                   	pop    %edi
  40d437:	54                   	push   %esp
  40d438:	55                   	push   %ebp
  40d439:	4e                   	dec    %esi
  40d43a:	45                   	inc    %ebp
  40d43b:	5f                   	pop    %edi
  40d43c:	53                   	push   %ebx
  40d43d:	48                   	dec    %eax
  40d43e:	49                   	dec    %ecx
  40d43f:	46                   	inc    %esi
  40d440:	54                   	push   %esp
  40d441:	31 00                	xor    %eax,(%eax)
  40d443:	45                   	inc    %ebp
  40d444:	11 58 38             	adc    %ebx,0x38(%eax)
  40d447:	36 5f                	ss pop %edi
  40d449:	54                   	push   %esp
  40d44a:	55                   	push   %ebp
  40d44b:	4e                   	dec    %esi
  40d44c:	45                   	inc    %ebp
  40d44d:	5f                   	pop    %edi
  40d44e:	5a                   	pop    %edx
  40d44f:	45                   	inc    %ebp
  40d450:	52                   	push   %edx
  40d451:	4f                   	dec    %edi
  40d452:	5f                   	pop    %edi
  40d453:	45                   	inc    %ebp
  40d454:	58                   	pop    %eax
  40d455:	54                   	push   %esp
  40d456:	45                   	inc    %ebp
  40d457:	4e                   	dec    %esi
  40d458:	44                   	inc    %esp
  40d459:	5f                   	pop    %edi
  40d45a:	57                   	push   %edi
  40d45b:	49                   	dec    %ecx
  40d45c:	54                   	push   %esp
  40d45d:	48                   	dec    %eax
  40d45e:	5f                   	pop    %edi
  40d45f:	41                   	inc    %ecx
  40d460:	4e                   	dec    %esi
  40d461:	44                   	inc    %esp
  40d462:	00 46 11             	add    %al,0x11(%esi)
  40d465:	58                   	pop    %eax
  40d466:	38 36                	cmp    %dh,(%esi)
  40d468:	5f                   	pop    %edi
  40d469:	54                   	push   %esp
  40d46a:	55                   	push   %ebp
  40d46b:	4e                   	dec    %esi
  40d46c:	45                   	inc    %ebp
  40d46d:	5f                   	pop    %edi
  40d46e:	50                   	push   %eax
  40d46f:	52                   	push   %edx
  40d470:	4f                   	dec    %edi
  40d471:	4d                   	dec    %ebp
  40d472:	4f                   	dec    %edi
  40d473:	54                   	push   %esp
  40d474:	45                   	inc    %ebp
  40d475:	5f                   	pop    %edi
  40d476:	48                   	dec    %eax
  40d477:	49                   	dec    %ecx
  40d478:	4d                   	dec    %ebp
  40d479:	4f                   	dec    %edi
  40d47a:	44                   	inc    %esp
  40d47b:	45                   	inc    %ebp
  40d47c:	5f                   	pop    %edi
  40d47d:	49                   	dec    %ecx
  40d47e:	4d                   	dec    %ebp
  40d47f:	55                   	push   %ebp
  40d480:	4c                   	dec    %esp
  40d481:	00 47 11             	add    %al,0x11(%edi)
  40d484:	58                   	pop    %eax
  40d485:	38 36                	cmp    %dh,(%esi)
  40d487:	5f                   	pop    %edi
  40d488:	54                   	push   %esp
  40d489:	55                   	push   %ebp
  40d48a:	4e                   	dec    %esi
  40d48b:	45                   	inc    %ebp
  40d48c:	5f                   	pop    %edi
  40d48d:	46                   	inc    %esi
  40d48e:	41                   	inc    %ecx
  40d48f:	53                   	push   %ebx
  40d490:	54                   	push   %esp
  40d491:	5f                   	pop    %edi
  40d492:	50                   	push   %eax
  40d493:	52                   	push   %edx
  40d494:	45                   	inc    %ebp
  40d495:	46                   	inc    %esi
  40d496:	49                   	dec    %ecx
  40d497:	58                   	pop    %eax
  40d498:	00 48 11             	add    %cl,0x11(%eax)
  40d49b:	58                   	pop    %eax
  40d49c:	38 36                	cmp    %dh,(%esi)
  40d49e:	5f                   	pop    %edi
  40d49f:	54                   	push   %esp
  40d4a0:	55                   	push   %ebp
  40d4a1:	4e                   	dec    %esi
  40d4a2:	45                   	inc    %ebp
  40d4a3:	5f                   	pop    %edi
  40d4a4:	52                   	push   %edx
  40d4a5:	45                   	inc    %ebp
  40d4a6:	41                   	inc    %ecx
  40d4a7:	44                   	inc    %esp
  40d4a8:	5f                   	pop    %edi
  40d4a9:	4d                   	dec    %ebp
  40d4aa:	4f                   	dec    %edi
  40d4ab:	44                   	inc    %esp
  40d4ac:	49                   	dec    %ecx
  40d4ad:	46                   	inc    %esi
  40d4ae:	59                   	pop    %ecx
  40d4af:	5f                   	pop    %edi
  40d4b0:	57                   	push   %edi
  40d4b1:	52                   	push   %edx
  40d4b2:	49                   	dec    %ecx
  40d4b3:	54                   	push   %esp
  40d4b4:	45                   	inc    %ebp
  40d4b5:	00 49 11             	add    %cl,0x11(%ecx)
  40d4b8:	58                   	pop    %eax
  40d4b9:	38 36                	cmp    %dh,(%esi)
  40d4bb:	5f                   	pop    %edi
  40d4bc:	54                   	push   %esp
  40d4bd:	55                   	push   %ebp
  40d4be:	4e                   	dec    %esi
  40d4bf:	45                   	inc    %ebp
  40d4c0:	5f                   	pop    %edi
  40d4c1:	4d                   	dec    %ebp
  40d4c2:	4f                   	dec    %edi
  40d4c3:	56                   	push   %esi
  40d4c4:	45                   	inc    %ebp
  40d4c5:	5f                   	pop    %edi
  40d4c6:	4d                   	dec    %ebp
  40d4c7:	31 5f 56             	xor    %ebx,0x56(%edi)
  40d4ca:	49                   	dec    %ecx
  40d4cb:	41                   	inc    %ecx
  40d4cc:	5f                   	pop    %edi
  40d4cd:	4f                   	dec    %edi
  40d4ce:	52                   	push   %edx
  40d4cf:	00 4a 11             	add    %cl,0x11(%edx)
  40d4d2:	58                   	pop    %eax
  40d4d3:	38 36                	cmp    %dh,(%esi)
  40d4d5:	5f                   	pop    %edi
  40d4d6:	54                   	push   %esp
  40d4d7:	55                   	push   %ebp
  40d4d8:	4e                   	dec    %esi
  40d4d9:	45                   	inc    %ebp
  40d4da:	5f                   	pop    %edi
  40d4db:	4e                   	dec    %esi
  40d4dc:	4f                   	dec    %edi
  40d4dd:	54                   	push   %esp
  40d4de:	5f                   	pop    %edi
  40d4df:	55                   	push   %ebp
  40d4e0:	4e                   	dec    %esi
  40d4e1:	50                   	push   %eax
  40d4e2:	41                   	inc    %ecx
  40d4e3:	49                   	dec    %ecx
  40d4e4:	52                   	push   %edx
  40d4e5:	41                   	inc    %ecx
  40d4e6:	42                   	inc    %edx
  40d4e7:	4c                   	dec    %esp
  40d4e8:	45                   	inc    %ebp
  40d4e9:	00 4b 11             	add    %cl,0x11(%ebx)
  40d4ec:	58                   	pop    %eax
  40d4ed:	38 36                	cmp    %dh,(%esi)
  40d4ef:	5f                   	pop    %edi
  40d4f0:	54                   	push   %esp
  40d4f1:	55                   	push   %ebp
  40d4f2:	4e                   	dec    %esi
  40d4f3:	45                   	inc    %ebp
  40d4f4:	5f                   	pop    %edi
  40d4f5:	50                   	push   %eax
  40d4f6:	41                   	inc    %ecx
  40d4f7:	52                   	push   %edx
  40d4f8:	54                   	push   %esp
  40d4f9:	49                   	dec    %ecx
  40d4fa:	41                   	inc    %ecx
  40d4fb:	4c                   	dec    %esp
  40d4fc:	5f                   	pop    %edi
  40d4fd:	52                   	push   %edx
  40d4fe:	45                   	inc    %ebp
  40d4ff:	47                   	inc    %edi
  40d500:	5f                   	pop    %edi
  40d501:	53                   	push   %ebx
  40d502:	54                   	push   %esp
  40d503:	41                   	inc    %ecx
  40d504:	4c                   	dec    %esp
  40d505:	4c                   	dec    %esp
  40d506:	00 4c 11 58          	add    %cl,0x58(%ecx,%edx,1)
  40d50a:	38 36                	cmp    %dh,(%esi)
  40d50c:	5f                   	pop    %edi
  40d50d:	54                   	push   %esp
  40d50e:	55                   	push   %ebp
  40d50f:	4e                   	dec    %esi
  40d510:	45                   	inc    %ebp
  40d511:	5f                   	pop    %edi
  40d512:	50                   	push   %eax
  40d513:	52                   	push   %edx
  40d514:	4f                   	dec    %edi
  40d515:	4d                   	dec    %ebp
  40d516:	4f                   	dec    %edi
  40d517:	54                   	push   %esp
  40d518:	45                   	inc    %ebp
  40d519:	5f                   	pop    %edi
  40d51a:	51                   	push   %ecx
  40d51b:	49                   	dec    %ecx
  40d51c:	4d                   	dec    %ebp
  40d51d:	4f                   	dec    %edi
  40d51e:	44                   	inc    %esp
  40d51f:	45                   	inc    %ebp
  40d520:	00 4d 11             	add    %cl,0x11(%ebp)
  40d523:	58                   	pop    %eax
  40d524:	38 36                	cmp    %dh,(%esi)
  40d526:	5f                   	pop    %edi
  40d527:	54                   	push   %esp
  40d528:	55                   	push   %ebp
  40d529:	4e                   	dec    %esi
  40d52a:	45                   	inc    %ebp
  40d52b:	5f                   	pop    %edi
  40d52c:	50                   	push   %eax
  40d52d:	52                   	push   %edx
  40d52e:	4f                   	dec    %edi
  40d52f:	4d                   	dec    %ebp
  40d530:	4f                   	dec    %edi
  40d531:	54                   	push   %esp
  40d532:	45                   	inc    %ebp
  40d533:	5f                   	pop    %edi
  40d534:	48                   	dec    %eax
  40d535:	49                   	dec    %ecx
  40d536:	5f                   	pop    %edi
  40d537:	52                   	push   %edx
  40d538:	45                   	inc    %ebp
  40d539:	47                   	inc    %edi
  40d53a:	53                   	push   %ebx
  40d53b:	00 4e 11             	add    %cl,0x11(%esi)
  40d53e:	58                   	pop    %eax
  40d53f:	38 36                	cmp    %dh,(%esi)
  40d541:	5f                   	pop    %edi
  40d542:	54                   	push   %esp
  40d543:	55                   	push   %ebp
  40d544:	4e                   	dec    %esi
  40d545:	45                   	inc    %ebp
  40d546:	5f                   	pop    %edi
  40d547:	48                   	dec    %eax
  40d548:	49                   	dec    %ecx
  40d549:	4d                   	dec    %ebp
  40d54a:	4f                   	dec    %edi
  40d54b:	44                   	inc    %esp
  40d54c:	45                   	inc    %ebp
  40d54d:	5f                   	pop    %edi
  40d54e:	4d                   	dec    %ebp
  40d54f:	41                   	inc    %ecx
  40d550:	54                   	push   %esp
  40d551:	48                   	dec    %eax
  40d552:	00 4f 11             	add    %cl,0x11(%edi)
  40d555:	58                   	pop    %eax
  40d556:	38 36                	cmp    %dh,(%esi)
  40d558:	5f                   	pop    %edi
  40d559:	54                   	push   %esp
  40d55a:	55                   	push   %ebp
  40d55b:	4e                   	dec    %esi
  40d55c:	45                   	inc    %ebp
  40d55d:	5f                   	pop    %edi
  40d55e:	53                   	push   %ebx
  40d55f:	50                   	push   %eax
  40d560:	4c                   	dec    %esp
  40d561:	49                   	dec    %ecx
  40d562:	54                   	push   %esp
  40d563:	5f                   	pop    %edi
  40d564:	4c                   	dec    %esp
  40d565:	4f                   	dec    %edi
  40d566:	4e                   	dec    %esi
  40d567:	47                   	inc    %edi
  40d568:	5f                   	pop    %edi
  40d569:	4d                   	dec    %ebp
  40d56a:	4f                   	dec    %edi
  40d56b:	56                   	push   %esi
  40d56c:	45                   	inc    %ebp
  40d56d:	53                   	push   %ebx
  40d56e:	00 50 11             	add    %dl,0x11(%eax)
  40d571:	58                   	pop    %eax
  40d572:	38 36                	cmp    %dh,(%esi)
  40d574:	5f                   	pop    %edi
  40d575:	54                   	push   %esp
  40d576:	55                   	push   %ebp
  40d577:	4e                   	dec    %esi
  40d578:	45                   	inc    %ebp
  40d579:	5f                   	pop    %edi
  40d57a:	55                   	push   %ebp
  40d57b:	53                   	push   %ebx
  40d57c:	45                   	inc    %ebp
  40d57d:	5f                   	pop    %edi
  40d57e:	58                   	pop    %eax
  40d57f:	43                   	inc    %ebx
  40d580:	48                   	dec    %eax
  40d581:	47                   	inc    %edi
  40d582:	42                   	inc    %edx
  40d583:	00 51 11             	add    %dl,0x11(%ecx)
  40d586:	58                   	pop    %eax
  40d587:	38 36                	cmp    %dh,(%esi)
  40d589:	5f                   	pop    %edi
  40d58a:	54                   	push   %esp
  40d58b:	55                   	push   %ebp
  40d58c:	4e                   	dec    %esi
  40d58d:	45                   	inc    %ebp
  40d58e:	5f                   	pop    %edi
  40d58f:	55                   	push   %ebp
  40d590:	53                   	push   %ebx
  40d591:	45                   	inc    %ebp
  40d592:	5f                   	pop    %edi
  40d593:	4d                   	dec    %ebp
  40d594:	4f                   	dec    %edi
  40d595:	56                   	push   %esi
  40d596:	30 00                	xor    %al,(%eax)
  40d598:	52                   	push   %edx
  40d599:	11 58 38             	adc    %ebx,0x38(%eax)
  40d59c:	36 5f                	ss pop %edi
  40d59e:	54                   	push   %esp
  40d59f:	55                   	push   %ebp
  40d5a0:	4e                   	dec    %esi
  40d5a1:	45                   	inc    %ebp
  40d5a2:	5f                   	pop    %edi
  40d5a3:	4e                   	dec    %esi
  40d5a4:	4f                   	dec    %edi
  40d5a5:	54                   	push   %esp
  40d5a6:	5f                   	pop    %edi
  40d5a7:	56                   	push   %esi
  40d5a8:	45                   	inc    %ebp
  40d5a9:	43                   	inc    %ebx
  40d5aa:	54                   	push   %esp
  40d5ab:	4f                   	dec    %edi
  40d5ac:	52                   	push   %edx
  40d5ad:	4d                   	dec    %ebp
  40d5ae:	4f                   	dec    %edi
  40d5af:	44                   	inc    %esp
  40d5b0:	45                   	inc    %ebp
  40d5b1:	00 53 11             	add    %dl,0x11(%ebx)
  40d5b4:	58                   	pop    %eax
  40d5b5:	38 36                	cmp    %dh,(%esi)
  40d5b7:	5f                   	pop    %edi
  40d5b8:	54                   	push   %esp
  40d5b9:	55                   	push   %ebp
  40d5ba:	4e                   	dec    %esi
  40d5bb:	45                   	inc    %ebp
  40d5bc:	5f                   	pop    %edi
  40d5bd:	41                   	inc    %ecx
  40d5be:	56                   	push   %esi
  40d5bf:	4f                   	dec    %edi
  40d5c0:	49                   	dec    %ecx
  40d5c1:	44                   	inc    %esp
  40d5c2:	5f                   	pop    %edi
  40d5c3:	56                   	push   %esi
  40d5c4:	45                   	inc    %ebp
  40d5c5:	43                   	inc    %ebx
  40d5c6:	54                   	push   %esp
  40d5c7:	4f                   	dec    %edi
  40d5c8:	52                   	push   %edx
  40d5c9:	5f                   	pop    %edi
  40d5ca:	44                   	inc    %esp
  40d5cb:	45                   	inc    %ebp
  40d5cc:	43                   	inc    %ebx
  40d5cd:	4f                   	dec    %edi
  40d5ce:	44                   	inc    %esp
  40d5cf:	45                   	inc    %ebp
  40d5d0:	00 54 11 58          	add    %dl,0x58(%ecx,%edx,1)
  40d5d4:	38 36                	cmp    %dh,(%esi)
  40d5d6:	5f                   	pop    %edi
  40d5d7:	54                   	push   %esp
  40d5d8:	55                   	push   %ebp
  40d5d9:	4e                   	dec    %esi
  40d5da:	45                   	inc    %ebp
  40d5db:	5f                   	pop    %edi
  40d5dc:	42                   	inc    %edx
  40d5dd:	52                   	push   %edx
  40d5de:	41                   	inc    %ecx
  40d5df:	4e                   	dec    %esi
  40d5e0:	43                   	inc    %ebx
  40d5e1:	48                   	dec    %eax
  40d5e2:	5f                   	pop    %edi
  40d5e3:	50                   	push   %eax
  40d5e4:	52                   	push   %edx
  40d5e5:	45                   	inc    %ebp
  40d5e6:	44                   	inc    %esp
  40d5e7:	49                   	dec    %ecx
  40d5e8:	43                   	inc    %ebx
  40d5e9:	54                   	push   %esp
  40d5ea:	49                   	dec    %ecx
  40d5eb:	4f                   	dec    %edi
  40d5ec:	4e                   	dec    %esi
  40d5ed:	5f                   	pop    %edi
  40d5ee:	48                   	dec    %eax
  40d5ef:	49                   	dec    %ecx
  40d5f0:	4e                   	dec    %esi
  40d5f1:	54                   	push   %esp
  40d5f2:	53                   	push   %ebx
  40d5f3:	00 55 11             	add    %dl,0x11(%ebp)
  40d5f6:	58                   	pop    %eax
  40d5f7:	38 36                	cmp    %dh,(%esi)
  40d5f9:	5f                   	pop    %edi
  40d5fa:	54                   	push   %esp
  40d5fb:	55                   	push   %ebp
  40d5fc:	4e                   	dec    %esi
  40d5fd:	45                   	inc    %ebp
  40d5fe:	5f                   	pop    %edi
  40d5ff:	51                   	push   %ecx
  40d600:	49                   	dec    %ecx
  40d601:	4d                   	dec    %ebp
  40d602:	4f                   	dec    %edi
  40d603:	44                   	inc    %esp
  40d604:	45                   	inc    %ebp
  40d605:	5f                   	pop    %edi
  40d606:	4d                   	dec    %ebp
  40d607:	41                   	inc    %ecx
  40d608:	54                   	push   %esp
  40d609:	48                   	dec    %eax
  40d60a:	00 56 11             	add    %dl,0x11(%esi)
  40d60d:	58                   	pop    %eax
  40d60e:	38 36                	cmp    %dh,(%esi)
  40d610:	5f                   	pop    %edi
  40d611:	54                   	push   %esp
  40d612:	55                   	push   %ebp
  40d613:	4e                   	dec    %esi
  40d614:	45                   	inc    %ebp
  40d615:	5f                   	pop    %edi
  40d616:	50                   	push   %eax
  40d617:	52                   	push   %edx
  40d618:	4f                   	dec    %edi
  40d619:	4d                   	dec    %ebp
  40d61a:	4f                   	dec    %edi
  40d61b:	54                   	push   %esp
  40d61c:	45                   	inc    %ebp
  40d61d:	5f                   	pop    %edi
  40d61e:	51                   	push   %ecx
  40d61f:	49                   	dec    %ecx
  40d620:	5f                   	pop    %edi
  40d621:	52                   	push   %edx
  40d622:	45                   	inc    %ebp
  40d623:	47                   	inc    %edi
  40d624:	53                   	push   %ebx
  40d625:	00 57 11             	add    %dl,0x11(%edi)
  40d628:	58                   	pop    %eax
  40d629:	38 36                	cmp    %dh,(%esi)
  40d62b:	5f                   	pop    %edi
  40d62c:	54                   	push   %esp
  40d62d:	55                   	push   %ebp
  40d62e:	4e                   	dec    %esi
  40d62f:	45                   	inc    %ebp
  40d630:	5f                   	pop    %edi
  40d631:	45                   	inc    %ebp
  40d632:	4d                   	dec    %ebp
  40d633:	49                   	dec    %ecx
  40d634:	54                   	push   %esp
  40d635:	5f                   	pop    %edi
  40d636:	56                   	push   %esi
  40d637:	5a                   	pop    %edx
  40d638:	45                   	inc    %ebp
  40d639:	52                   	push   %edx
  40d63a:	4f                   	dec    %edi
  40d63b:	55                   	push   %ebp
  40d63c:	50                   	push   %eax
  40d63d:	50                   	push   %eax
  40d63e:	45                   	inc    %ebp
  40d63f:	52                   	push   %edx
  40d640:	00 58 11             	add    %bl,0x11(%eax)
  40d643:	58                   	pop    %eax
  40d644:	38 36                	cmp    %dh,(%esi)
  40d646:	5f                   	pop    %edi
  40d647:	54                   	push   %esp
  40d648:	55                   	push   %ebp
  40d649:	4e                   	dec    %esi
  40d64a:	45                   	inc    %ebp
  40d64b:	5f                   	pop    %edi
  40d64c:	4c                   	dec    %esp
  40d64d:	41                   	inc    %ecx
  40d64e:	53                   	push   %ebx
  40d64f:	54                   	push   %esp
  40d650:	00 59 00             	add    %bl,0x0(%ecx)
  40d653:	08 4d 04             	or     %cl,0x4(%ebp)
  40d656:	00 00                	add    %al,(%eax)
  40d658:	3d 16 00 00 0c       	cmp    $0xc000016,%eax
  40d65d:	f1                   	icebp  
  40d65e:	00 00                	add    %al,(%eax)
  40d660:	00 58 00             	add    %bl,0x0(%eax)
  40d663:	0b 69 78             	or     0x78(%ecx),%ebp
  40d666:	38 36                	cmp    %dh,(%esi)
  40d668:	5f                   	pop    %edi
  40d669:	74 75                	je     40d6e0 <.debug_info+0x16ba>
  40d66b:	6e                   	outsb  %ds:(%esi),(%dx)
  40d66c:	65 5f                	gs pop %edi
  40d66e:	66 65 61             	gs popaw 
  40d671:	74 75                	je     40d6e8 <.debug_info+0x16c2>
  40d673:	72 65                	jb     40d6da <.debug_info+0x16b4>
  40d675:	73 00                	jae    40d677 <.debug_info+0x1651>
  40d677:	07                   	pop    %es
  40d678:	b0 01                	mov    $0x1,%al
  40d67a:	16                   	push   %ss
  40d67b:	2d 16 00 00 15       	sub    $0x15000016,%eax
  40d680:	69 78 38 36 5f 61 72 	imul   $0x72615f36,0x38(%eax),%edi
  40d687:	63 68 5f             	arpl   %bp,0x5f(%eax)
  40d68a:	69 6e 64 69 63 65 73 	imul   $0x73656369,0x64(%esi),%ebp
  40d691:	00 07                	add    %al,(%edi)
  40d693:	04 f1                	add    $0xf1,%al
  40d695:	00 00                	add    %al,(%eax)
  40d697:	00 07                	add    %al,(%edi)
  40d699:	33 02                	xor    (%edx),%eax
  40d69b:	06                   	push   %es
  40d69c:	e4 16                	in     $0x16,%al
  40d69e:	00 00                	add    %al,(%eax)
  40d6a0:	11 58 38             	adc    %ebx,0x38(%eax)
  40d6a3:	36 5f                	ss pop %edi
  40d6a5:	41                   	inc    %ecx
  40d6a6:	52                   	push   %edx
  40d6a7:	43                   	inc    %ebx
  40d6a8:	48                   	dec    %eax
  40d6a9:	5f                   	pop    %edi
  40d6aa:	43                   	inc    %ebx
  40d6ab:	4d                   	dec    %ebp
  40d6ac:	4f                   	dec    %edi
  40d6ad:	56                   	push   %esi
  40d6ae:	00 00                	add    %al,(%eax)
  40d6b0:	11 58 38             	adc    %ebx,0x38(%eax)
  40d6b3:	36 5f                	ss pop %edi
  40d6b5:	41                   	inc    %ecx
  40d6b6:	52                   	push   %edx
  40d6b7:	43                   	inc    %ebx
  40d6b8:	48                   	dec    %eax
  40d6b9:	5f                   	pop    %edi
  40d6ba:	43                   	inc    %ebx
  40d6bb:	4d                   	dec    %ebp
  40d6bc:	50                   	push   %eax
  40d6bd:	58                   	pop    %eax
  40d6be:	43                   	inc    %ebx
  40d6bf:	48                   	dec    %eax
  40d6c0:	47                   	inc    %edi
  40d6c1:	00 01                	add    %al,(%ecx)
  40d6c3:	11 58 38             	adc    %ebx,0x38(%eax)
  40d6c6:	36 5f                	ss pop %edi
  40d6c8:	41                   	inc    %ecx
  40d6c9:	52                   	push   %edx
  40d6ca:	43                   	inc    %ebx
  40d6cb:	48                   	dec    %eax
  40d6cc:	5f                   	pop    %edi
  40d6cd:	43                   	inc    %ebx
  40d6ce:	4d                   	dec    %ebp
  40d6cf:	50                   	push   %eax
  40d6d0:	58                   	pop    %eax
  40d6d1:	43                   	inc    %ebx
  40d6d2:	48                   	dec    %eax
  40d6d3:	47                   	inc    %edi
  40d6d4:	38 42 00             	cmp    %al,0x0(%edx)
  40d6d7:	02 11                	add    (%ecx),%dl
  40d6d9:	58                   	pop    %eax
  40d6da:	38 36                	cmp    %dh,(%esi)
  40d6dc:	5f                   	pop    %edi
  40d6dd:	41                   	inc    %ecx
  40d6de:	52                   	push   %edx
  40d6df:	43                   	inc    %ebx
  40d6e0:	48                   	dec    %eax
  40d6e1:	5f                   	pop    %edi
  40d6e2:	58                   	pop    %eax
  40d6e3:	41                   	inc    %ecx
  40d6e4:	44                   	inc    %esp
  40d6e5:	44                   	inc    %esp
  40d6e6:	00 03                	add    %al,(%ebx)
  40d6e8:	11 58 38             	adc    %ebx,0x38(%eax)
  40d6eb:	36 5f                	ss pop %edi
  40d6ed:	41                   	inc    %ecx
  40d6ee:	52                   	push   %edx
  40d6ef:	43                   	inc    %ebx
  40d6f0:	48                   	dec    %eax
  40d6f1:	5f                   	pop    %edi
  40d6f2:	42                   	inc    %edx
  40d6f3:	53                   	push   %ebx
  40d6f4:	57                   	push   %edi
  40d6f5:	41                   	inc    %ecx
  40d6f6:	50                   	push   %eax
  40d6f7:	00 04 11             	add    %al,(%ecx,%edx,1)
  40d6fa:	58                   	pop    %eax
  40d6fb:	38 36                	cmp    %dh,(%esi)
  40d6fd:	5f                   	pop    %edi
  40d6fe:	41                   	inc    %ecx
  40d6ff:	52                   	push   %edx
  40d700:	43                   	inc    %ebx
  40d701:	48                   	dec    %eax
  40d702:	5f                   	pop    %edi
  40d703:	4c                   	dec    %esp
  40d704:	41                   	inc    %ecx
  40d705:	53                   	push   %ebx
  40d706:	54                   	push   %esp
  40d707:	00 05 00 08 4d 04    	add    %al,0x44d0800
  40d70d:	00 00                	add    %al,(%eax)
  40d70f:	f4                   	hlt    
  40d710:	16                   	push   %ss
  40d711:	00 00                	add    %al,(%eax)
  40d713:	0c f1                	or     $0xf1,%al
  40d715:	00 00                	add    %al,(%eax)
  40d717:	00 04 00             	add    %al,(%eax,%eax,1)
  40d71a:	0b 69 78             	or     0x78(%ecx),%ebp
  40d71d:	38 36                	cmp    %dh,(%esi)
  40d71f:	5f                   	pop    %edi
  40d720:	61                   	popa   
  40d721:	72 63                	jb     40d786 <.debug_info+0x1760>
  40d723:	68 5f 66 65 61       	push   $0x6165665f
  40d728:	74 75                	je     40d79f <.debug_info+0x1779>
  40d72a:	72 65                	jb     40d791 <.debug_info+0x176b>
  40d72c:	73 00                	jae    40d72e <.debug_info+0x1708>
  40d72e:	07                   	pop    %es
  40d72f:	3d 02 16 e4 16       	cmp    $0x16e41602,%eax
  40d734:	00 00                	add    %al,(%eax)
  40d736:	0b 78 38             	or     0x38(%eax),%edi
  40d739:	36 5f                	ss pop %edi
  40d73b:	70 72                	jo     40d7af <.debug_info+0x1789>
  40d73d:	65 66 65 74 63       	gs data16 gs je 40d7a5 <.debug_info+0x177f>
  40d742:	68 5f 73 73 65       	push   $0x6573735f
  40d747:	00 07                	add    %al,(%edi)
  40d749:	4c                   	dec    %esp
  40d74a:	02 16                	add    (%esi),%dl
  40d74c:	4d                   	dec    %ebp
  40d74d:	04 00                	add    $0x0,%al
  40d74f:	00 16                	add    %dl,(%esi)
  40d751:	5f                   	pop    %edi
  40d752:	64 6f                	outsl  %fs:(%esi),(%dx)
  40d754:	6e                   	outsb  %ds:(%esi),(%dx)
  40d755:	74 5f                	je     40d7b6 <.debug_info+0x1790>
  40d757:	75 73                	jne    40d7cc <.debug_info+0x17a6>
  40d759:	65 5f                	gs pop %edi
  40d75b:	74 72                	je     40d7cf <.debug_info+0x17a9>
  40d75d:	65 65 5f             	gs gs pop %edi
  40d760:	68 65 72 65 5f       	push   $0x5f657265
  40d765:	00 0b                	add    %cl,(%ebx)
  40d767:	78 38                	js     40d7a1 <.debug_info+0x177b>
  40d769:	36 5f                	ss pop %edi
  40d76b:	6d                   	insl   (%dx),%es:(%edi)
  40d76c:	66 65 6e             	data16 outsb %gs:(%esi),(%dx)
  40d76f:	63 65 00             	arpl   %sp,0x0(%ebp)
  40d772:	07                   	pop    %es
  40d773:	6a 02                	push   $0x2
  40d775:	0d 54 17 00 00       	or     $0x1754,%eax
  40d77a:	06                   	push   %es
  40d77b:	04 2a                	add    $0x2a,%al
  40d77d:	17                   	pop    %ss
  40d77e:	00 00                	add    %al,(%eax)
  40d780:	15 72 65 67 5f       	adc    $0x5f676572,%eax
  40d785:	63 6c 61 73          	arpl   %bp,0x73(%ecx,%eiz,2)
  40d789:	73 00                	jae    40d78b <.debug_info+0x1765>
  40d78b:	07                   	pop    %es
  40d78c:	04 f1                	add    $0xf1,%al
  40d78e:	00 00                	add    %al,(%eax)
  40d790:	00 07                	add    %al,(%edi)
  40d792:	30 05 06 08 19 00    	xor    %al,0x190806
  40d798:	00 11                	add    %dl,(%ecx)
  40d79a:	4e                   	dec    %esi
  40d79b:	4f                   	dec    %edi
  40d79c:	5f                   	pop    %edi
  40d79d:	52                   	push   %edx
  40d79e:	45                   	inc    %ebp
  40d79f:	47                   	inc    %edi
  40d7a0:	53                   	push   %ebx
  40d7a1:	00 00                	add    %al,(%eax)
  40d7a3:	11 41 52             	adc    %eax,0x52(%ecx)
  40d7a6:	45                   	inc    %ebp
  40d7a7:	47                   	inc    %edi
  40d7a8:	00 01                	add    %al,(%ecx)
  40d7aa:	11 44 52 45          	adc    %eax,0x45(%edx,%edx,2)
  40d7ae:	47                   	inc    %edi
  40d7af:	00 02                	add    %al,(%edx)
  40d7b1:	11 43 52             	adc    %eax,0x52(%ebx)
  40d7b4:	45                   	inc    %ebp
  40d7b5:	47                   	inc    %edi
  40d7b6:	00 03                	add    %al,(%ebx)
  40d7b8:	11 42 52             	adc    %eax,0x52(%edx)
  40d7bb:	45                   	inc    %ebp
  40d7bc:	47                   	inc    %edi
  40d7bd:	00 04 11             	add    %al,(%ecx,%edx,1)
  40d7c0:	53                   	push   %ebx
  40d7c1:	49                   	dec    %ecx
  40d7c2:	52                   	push   %edx
  40d7c3:	45                   	inc    %ebp
  40d7c4:	47                   	inc    %edi
  40d7c5:	00 05 11 44 49 52    	add    %al,0x52494411
  40d7cb:	45                   	inc    %ebp
  40d7cc:	47                   	inc    %edi
  40d7cd:	00 06                	add    %al,(%esi)
  40d7cf:	11 41 44             	adc    %eax,0x44(%ecx)
  40d7d2:	5f                   	pop    %edi
  40d7d3:	52                   	push   %edx
  40d7d4:	45                   	inc    %ebp
  40d7d5:	47                   	inc    %edi
  40d7d6:	53                   	push   %ebx
  40d7d7:	00 07                	add    %al,(%edi)
  40d7d9:	11 43 4c             	adc    %eax,0x4c(%ebx)
  40d7dc:	4f                   	dec    %edi
  40d7dd:	42                   	inc    %edx
  40d7de:	42                   	inc    %edx
  40d7df:	45                   	inc    %ebp
  40d7e0:	52                   	push   %edx
  40d7e1:	45                   	inc    %ebp
  40d7e2:	44                   	inc    %esp
  40d7e3:	5f                   	pop    %edi
  40d7e4:	52                   	push   %edx
  40d7e5:	45                   	inc    %ebp
  40d7e6:	47                   	inc    %edi
  40d7e7:	53                   	push   %ebx
  40d7e8:	00 08                	add    %cl,(%eax)
  40d7ea:	11 51 5f             	adc    %edx,0x5f(%ecx)
  40d7ed:	52                   	push   %edx
  40d7ee:	45                   	inc    %ebp
  40d7ef:	47                   	inc    %edi
  40d7f0:	53                   	push   %ebx
  40d7f1:	00 09                	add    %cl,(%ecx)
  40d7f3:	11 4e 4f             	adc    %ecx,0x4f(%esi)
  40d7f6:	4e                   	dec    %esi
  40d7f7:	5f                   	pop    %edi
  40d7f8:	51                   	push   %ecx
  40d7f9:	5f                   	pop    %edi
  40d7fa:	52                   	push   %edx
  40d7fb:	45                   	inc    %ebp
  40d7fc:	47                   	inc    %edi
  40d7fd:	53                   	push   %ebx
  40d7fe:	00 0a                	add    %cl,(%edx)
  40d800:	11 54 4c 53          	adc    %edx,0x53(%esp,%ecx,2)
  40d804:	5f                   	pop    %edi
  40d805:	47                   	inc    %edi
  40d806:	4f                   	dec    %edi
  40d807:	54                   	push   %esp
  40d808:	42                   	inc    %edx
  40d809:	41                   	inc    %ecx
  40d80a:	53                   	push   %ebx
  40d80b:	45                   	inc    %ebp
  40d80c:	5f                   	pop    %edi
  40d80d:	52                   	push   %edx
  40d80e:	45                   	inc    %ebp
  40d80f:	47                   	inc    %edi
  40d810:	53                   	push   %ebx
  40d811:	00 0b                	add    %cl,(%ebx)
  40d813:	11 49 4e             	adc    %ecx,0x4e(%ecx)
  40d816:	44                   	inc    %esp
  40d817:	45                   	inc    %ebp
  40d818:	58                   	pop    %eax
  40d819:	5f                   	pop    %edi
  40d81a:	52                   	push   %edx
  40d81b:	45                   	inc    %ebp
  40d81c:	47                   	inc    %edi
  40d81d:	53                   	push   %ebx
  40d81e:	00 0c 11             	add    %cl,(%ecx,%edx,1)
  40d821:	4c                   	dec    %esp
  40d822:	45                   	inc    %ebp
  40d823:	47                   	inc    %edi
  40d824:	41                   	inc    %ecx
  40d825:	43                   	inc    %ebx
  40d826:	59                   	pop    %ecx
  40d827:	5f                   	pop    %edi
  40d828:	52                   	push   %edx
  40d829:	45                   	inc    %ebp
  40d82a:	47                   	inc    %edi
  40d82b:	53                   	push   %ebx
  40d82c:	00 0d 11 47 45 4e    	add    %cl,0x4e454711
  40d832:	45                   	inc    %ebp
  40d833:	52                   	push   %edx
  40d834:	41                   	inc    %ecx
  40d835:	4c                   	dec    %esp
  40d836:	5f                   	pop    %edi
  40d837:	52                   	push   %edx
  40d838:	45                   	inc    %ebp
  40d839:	47                   	inc    %edi
  40d83a:	53                   	push   %ebx
  40d83b:	00 0e                	add    %cl,(%esi)
  40d83d:	11 46 50             	adc    %eax,0x50(%esi)
  40d840:	5f                   	pop    %edi
  40d841:	54                   	push   %esp
  40d842:	4f                   	dec    %edi
  40d843:	50                   	push   %eax
  40d844:	5f                   	pop    %edi
  40d845:	52                   	push   %edx
  40d846:	45                   	inc    %ebp
  40d847:	47                   	inc    %edi
  40d848:	00 0f                	add    %cl,(%edi)
  40d84a:	11 46 50             	adc    %eax,0x50(%esi)
  40d84d:	5f                   	pop    %edi
  40d84e:	53                   	push   %ebx
  40d84f:	45                   	inc    %ebp
  40d850:	43                   	inc    %ebx
  40d851:	4f                   	dec    %edi
  40d852:	4e                   	dec    %esi
  40d853:	44                   	inc    %esp
  40d854:	5f                   	pop    %edi
  40d855:	52                   	push   %edx
  40d856:	45                   	inc    %ebp
  40d857:	47                   	inc    %edi
  40d858:	00 10                	add    %dl,(%eax)
  40d85a:	11 46 4c             	adc    %eax,0x4c(%esi)
  40d85d:	4f                   	dec    %edi
  40d85e:	41                   	inc    %ecx
  40d85f:	54                   	push   %esp
  40d860:	5f                   	pop    %edi
  40d861:	52                   	push   %edx
  40d862:	45                   	inc    %ebp
  40d863:	47                   	inc    %edi
  40d864:	53                   	push   %ebx
  40d865:	00 11                	add    %dl,(%ecx)
  40d867:	11 53 53             	adc    %edx,0x53(%ebx)
  40d86a:	45                   	inc    %ebp
  40d86b:	5f                   	pop    %edi
  40d86c:	46                   	inc    %esi
  40d86d:	49                   	dec    %ecx
  40d86e:	52                   	push   %edx
  40d86f:	53                   	push   %ebx
  40d870:	54                   	push   %esp
  40d871:	5f                   	pop    %edi
  40d872:	52                   	push   %edx
  40d873:	45                   	inc    %ebp
  40d874:	47                   	inc    %edi
  40d875:	00 12                	add    %dl,(%edx)
  40d877:	11 4e 4f             	adc    %ecx,0x4f(%esi)
  40d87a:	5f                   	pop    %edi
  40d87b:	52                   	push   %edx
  40d87c:	45                   	inc    %ebp
  40d87d:	58                   	pop    %eax
  40d87e:	5f                   	pop    %edi
  40d87f:	53                   	push   %ebx
  40d880:	53                   	push   %ebx
  40d881:	45                   	inc    %ebp
  40d882:	5f                   	pop    %edi
  40d883:	52                   	push   %edx
  40d884:	45                   	inc    %ebp
  40d885:	47                   	inc    %edi
  40d886:	53                   	push   %ebx
  40d887:	00 13                	add    %dl,(%ebx)
  40d889:	11 53 53             	adc    %edx,0x53(%ebx)
  40d88c:	45                   	inc    %ebp
  40d88d:	5f                   	pop    %edi
  40d88e:	52                   	push   %edx
  40d88f:	45                   	inc    %ebp
  40d890:	47                   	inc    %edi
  40d891:	53                   	push   %ebx
  40d892:	00 14 11             	add    %dl,(%ecx,%edx,1)
  40d895:	41                   	inc    %ecx
  40d896:	4c                   	dec    %esp
  40d897:	4c                   	dec    %esp
  40d898:	5f                   	pop    %edi
  40d899:	53                   	push   %ebx
  40d89a:	53                   	push   %ebx
  40d89b:	45                   	inc    %ebp
  40d89c:	5f                   	pop    %edi
  40d89d:	52                   	push   %edx
  40d89e:	45                   	inc    %ebp
  40d89f:	47                   	inc    %edi
  40d8a0:	53                   	push   %ebx
  40d8a1:	00 15 11 4d 4d 58    	add    %dl,0x584d4d11
  40d8a7:	5f                   	pop    %edi
  40d8a8:	52                   	push   %edx
  40d8a9:	45                   	inc    %ebp
  40d8aa:	47                   	inc    %edi
  40d8ab:	53                   	push   %ebx
  40d8ac:	00 16                	add    %dl,(%esi)
  40d8ae:	11 46 4c             	adc    %eax,0x4c(%esi)
  40d8b1:	4f                   	dec    %edi
  40d8b2:	41                   	inc    %ecx
  40d8b3:	54                   	push   %esp
  40d8b4:	5f                   	pop    %edi
  40d8b5:	53                   	push   %ebx
  40d8b6:	53                   	push   %ebx
  40d8b7:	45                   	inc    %ebp
  40d8b8:	5f                   	pop    %edi
  40d8b9:	52                   	push   %edx
  40d8ba:	45                   	inc    %ebp
  40d8bb:	47                   	inc    %edi
  40d8bc:	53                   	push   %ebx
  40d8bd:	00 17                	add    %dl,(%edi)
  40d8bf:	11 46 4c             	adc    %eax,0x4c(%esi)
  40d8c2:	4f                   	dec    %edi
  40d8c3:	41                   	inc    %ecx
  40d8c4:	54                   	push   %esp
  40d8c5:	5f                   	pop    %edi
  40d8c6:	49                   	dec    %ecx
  40d8c7:	4e                   	dec    %esi
  40d8c8:	54                   	push   %esp
  40d8c9:	5f                   	pop    %edi
  40d8ca:	52                   	push   %edx
  40d8cb:	45                   	inc    %ebp
  40d8cc:	47                   	inc    %edi
  40d8cd:	53                   	push   %ebx
  40d8ce:	00 18                	add    %bl,(%eax)
  40d8d0:	11 49 4e             	adc    %ecx,0x4e(%ecx)
  40d8d3:	54                   	push   %esp
  40d8d4:	5f                   	pop    %edi
  40d8d5:	53                   	push   %ebx
  40d8d6:	53                   	push   %ebx
  40d8d7:	45                   	inc    %ebp
  40d8d8:	5f                   	pop    %edi
  40d8d9:	52                   	push   %edx
  40d8da:	45                   	inc    %ebp
  40d8db:	47                   	inc    %edi
  40d8dc:	53                   	push   %ebx
  40d8dd:	00 19                	add    %bl,(%ecx)
  40d8df:	11 46 4c             	adc    %eax,0x4c(%esi)
  40d8e2:	4f                   	dec    %edi
  40d8e3:	41                   	inc    %ecx
  40d8e4:	54                   	push   %esp
  40d8e5:	5f                   	pop    %edi
  40d8e6:	49                   	dec    %ecx
  40d8e7:	4e                   	dec    %esi
  40d8e8:	54                   	push   %esp
  40d8e9:	5f                   	pop    %edi
  40d8ea:	53                   	push   %ebx
  40d8eb:	53                   	push   %ebx
  40d8ec:	45                   	inc    %ebp
  40d8ed:	5f                   	pop    %edi
  40d8ee:	52                   	push   %edx
  40d8ef:	45                   	inc    %ebp
  40d8f0:	47                   	inc    %edi
  40d8f1:	53                   	push   %ebx
  40d8f2:	00 1a                	add    %bl,(%edx)
  40d8f4:	11 4d 41             	adc    %ecx,0x41(%ebp)
  40d8f7:	53                   	push   %ebx
  40d8f8:	4b                   	dec    %ebx
  40d8f9:	5f                   	pop    %edi
  40d8fa:	52                   	push   %edx
  40d8fb:	45                   	inc    %ebp
  40d8fc:	47                   	inc    %edi
  40d8fd:	53                   	push   %ebx
  40d8fe:	00 1b                	add    %bl,(%ebx)
  40d900:	11 41 4c             	adc    %eax,0x4c(%ecx)
  40d903:	4c                   	dec    %esp
  40d904:	5f                   	pop    %edi
  40d905:	4d                   	dec    %ebp
  40d906:	41                   	inc    %ecx
  40d907:	53                   	push   %ebx
  40d908:	4b                   	dec    %ebx
  40d909:	5f                   	pop    %edi
  40d90a:	52                   	push   %edx
  40d90b:	45                   	inc    %ebp
  40d90c:	47                   	inc    %edi
  40d90d:	53                   	push   %ebx
  40d90e:	00 1c 11             	add    %bl,(%ecx,%edx,1)
  40d911:	41                   	inc    %ecx
  40d912:	4c                   	dec    %esp
  40d913:	4c                   	dec    %esp
  40d914:	5f                   	pop    %edi
  40d915:	52                   	push   %edx
  40d916:	45                   	inc    %ebp
  40d917:	47                   	inc    %edi
  40d918:	53                   	push   %ebx
  40d919:	00 1d 11 4c 49 4d    	add    %bl,0x4d494c11
  40d91f:	5f                   	pop    %edi
  40d920:	52                   	push   %edx
  40d921:	45                   	inc    %ebp
  40d922:	47                   	inc    %edi
  40d923:	5f                   	pop    %edi
  40d924:	43                   	inc    %ebx
  40d925:	4c                   	dec    %esp
  40d926:	41                   	inc    %ecx
  40d927:	53                   	push   %ebx
  40d928:	53                   	push   %ebx
  40d929:	45                   	inc    %ebp
  40d92a:	53                   	push   %ebx
  40d92b:	00 1e                	add    %bl,(%esi)
  40d92d:	00 03                	add    %al,(%ebx)
  40d92f:	5a                   	pop    %edx
  40d930:	17                   	pop    %ss
  40d931:	00 00                	add    %al,(%eax)
  40d933:	08 ec                	or     %ch,%ah
  40d935:	00 00                	add    %al,(%eax)
  40d937:	00 1d 19 00 00 0c    	add    %bl,0xc000019
  40d93d:	f1                   	icebp  
  40d93e:	00 00                	add    %al,(%eax)
  40d940:	00 4b 00             	add    %cl,0x0(%ebx)
  40d943:	03 0d 19 00 00 0b    	add    0xb000019,%ecx
  40d949:	64 62 78 5f          	bound  %edi,%fs:0x5f(%eax)
  40d94d:	72 65                	jb     40d9b4 <.debug_info+0x198e>
  40d94f:	67 69 73 74 65 72 5f 	imul   $0x6d5f7265,0x74(%bp,%di),%esi
  40d956:	6d 
  40d957:	61                   	popa   
  40d958:	70 00                	jo     40d95a <.debug_info+0x1934>
  40d95a:	07                   	pop    %es
  40d95b:	26 08 12             	or     %dl,%es:(%edx)
  40d95e:	1d 19 00 00 0b       	sbb    $0xb000019,%eax
  40d963:	64 62 78 36          	bound  %edi,%fs:0x36(%eax)
  40d967:	34 5f                	xor    $0x5f,%al
  40d969:	72 65                	jb     40d9d0 <.debug_info+0x19aa>
  40d96b:	67 69 73 74 65 72 5f 	imul   $0x6d5f7265,0x74(%bp,%di),%esi
  40d972:	6d 
  40d973:	61                   	popa   
  40d974:	70 00                	jo     40d976 <.debug_info+0x1950>
  40d976:	07                   	pop    %es
  40d977:	27                   	daa    
  40d978:	08 12                	or     %dl,(%edx)
  40d97a:	1d 19 00 00 0b       	sbb    $0xb000019,%eax
  40d97f:	73 76                	jae    40d9f7 <.debug_info+0x19d1>
  40d981:	72 34                	jb     40d9b7 <.debug_info+0x1991>
  40d983:	5f                   	pop    %edi
  40d984:	64 62 78 5f          	bound  %edi,%fs:0x5f(%eax)
  40d988:	72 65                	jb     40d9ef <.debug_info+0x19c9>
  40d98a:	67 69 73 74 65 72 5f 	imul   $0x6d5f7265,0x74(%bp,%di),%esi
  40d991:	6d 
  40d992:	61                   	popa   
  40d993:	70 00                	jo     40d995 <.debug_info+0x196f>
  40d995:	07                   	pop    %es
  40d996:	28 08                	sub    %cl,(%eax)
  40d998:	12 1d 19 00 00 15    	adc    0x15000019,%bl
  40d99e:	70 72                	jo     40da12 <.debug_info+0x19ec>
  40d9a0:	6f                   	outsl  %ds:(%esi),(%dx)
  40d9a1:	63 65 73             	arpl   %sp,0x73(%ebp)
  40d9a4:	73 6f                	jae    40da15 <.debug_info+0x19ef>
  40d9a6:	72 5f                	jb     40da07 <.debug_info+0x19e1>
  40d9a8:	74 79                	je     40da23 <.debug_info+0x19fd>
  40d9aa:	70 65                	jo     40da11 <.debug_info+0x19eb>
  40d9ac:	00 07                	add    %al,(%edi)
  40d9ae:	04 f1                	add    $0xf1,%al
  40d9b0:	00 00                	add    %al,(%eax)
  40d9b2:	00 07                	add    %al,(%edi)
  40d9b4:	ba 08 06 ba 1c       	mov    $0x1cba0608,%edx
  40d9b9:	00 00                	add    %al,(%eax)
  40d9bb:	11 50 52             	adc    %edx,0x52(%eax)
  40d9be:	4f                   	dec    %edi
  40d9bf:	43                   	inc    %ebx
  40d9c0:	45                   	inc    %ebp
  40d9c1:	53                   	push   %ebx
  40d9c2:	53                   	push   %ebx
  40d9c3:	4f                   	dec    %edi
  40d9c4:	52                   	push   %edx
  40d9c5:	5f                   	pop    %edi
  40d9c6:	47                   	inc    %edi
  40d9c7:	45                   	inc    %ebp
  40d9c8:	4e                   	dec    %esi
  40d9c9:	45                   	inc    %ebp
  40d9ca:	52                   	push   %edx
  40d9cb:	49                   	dec    %ecx
  40d9cc:	43                   	inc    %ebx
  40d9cd:	00 00                	add    %al,(%eax)
  40d9cf:	11 50 52             	adc    %edx,0x52(%eax)
  40d9d2:	4f                   	dec    %edi
  40d9d3:	43                   	inc    %ebx
  40d9d4:	45                   	inc    %ebp
  40d9d5:	53                   	push   %ebx
  40d9d6:	53                   	push   %ebx
  40d9d7:	4f                   	dec    %edi
  40d9d8:	52                   	push   %edx
  40d9d9:	5f                   	pop    %edi
  40d9da:	49                   	dec    %ecx
  40d9db:	33 38                	xor    (%eax),%edi
  40d9dd:	36 00 01             	add    %al,%ss:(%ecx)
  40d9e0:	11 50 52             	adc    %edx,0x52(%eax)
  40d9e3:	4f                   	dec    %edi
  40d9e4:	43                   	inc    %ebx
  40d9e5:	45                   	inc    %ebp
  40d9e6:	53                   	push   %ebx
  40d9e7:	53                   	push   %ebx
  40d9e8:	4f                   	dec    %edi
  40d9e9:	52                   	push   %edx
  40d9ea:	5f                   	pop    %edi
  40d9eb:	49                   	dec    %ecx
  40d9ec:	34 38                	xor    $0x38,%al
  40d9ee:	36 00 02             	add    %al,%ss:(%edx)
  40d9f1:	11 50 52             	adc    %edx,0x52(%eax)
  40d9f4:	4f                   	dec    %edi
  40d9f5:	43                   	inc    %ebx
  40d9f6:	45                   	inc    %ebp
  40d9f7:	53                   	push   %ebx
  40d9f8:	53                   	push   %ebx
  40d9f9:	4f                   	dec    %edi
  40d9fa:	52                   	push   %edx
  40d9fb:	5f                   	pop    %edi
  40d9fc:	50                   	push   %eax
  40d9fd:	45                   	inc    %ebp
  40d9fe:	4e                   	dec    %esi
  40d9ff:	54                   	push   %esp
  40da00:	49                   	dec    %ecx
  40da01:	55                   	push   %ebp
  40da02:	4d                   	dec    %ebp
  40da03:	00 03                	add    %al,(%ebx)
  40da05:	11 50 52             	adc    %edx,0x52(%eax)
  40da08:	4f                   	dec    %edi
  40da09:	43                   	inc    %ebx
  40da0a:	45                   	inc    %ebp
  40da0b:	53                   	push   %ebx
  40da0c:	53                   	push   %ebx
  40da0d:	4f                   	dec    %edi
  40da0e:	52                   	push   %edx
  40da0f:	5f                   	pop    %edi
  40da10:	4c                   	dec    %esp
  40da11:	41                   	inc    %ecx
  40da12:	4b                   	dec    %ebx
  40da13:	45                   	inc    %ebp
  40da14:	4d                   	dec    %ebp
  40da15:	4f                   	dec    %edi
  40da16:	4e                   	dec    %esi
  40da17:	54                   	push   %esp
  40da18:	00 04 11             	add    %al,(%ecx,%edx,1)
  40da1b:	50                   	push   %eax
  40da1c:	52                   	push   %edx
  40da1d:	4f                   	dec    %edi
  40da1e:	43                   	inc    %ebx
  40da1f:	45                   	inc    %ebp
  40da20:	53                   	push   %ebx
  40da21:	53                   	push   %ebx
  40da22:	4f                   	dec    %edi
  40da23:	52                   	push   %edx
  40da24:	5f                   	pop    %edi
  40da25:	50                   	push   %eax
  40da26:	45                   	inc    %ebp
  40da27:	4e                   	dec    %esi
  40da28:	54                   	push   %esp
  40da29:	49                   	dec    %ecx
  40da2a:	55                   	push   %ebp
  40da2b:	4d                   	dec    %ebp
  40da2c:	50                   	push   %eax
  40da2d:	52                   	push   %edx
  40da2e:	4f                   	dec    %edi
  40da2f:	00 05 11 50 52 4f    	add    %al,0x4f525011
  40da35:	43                   	inc    %ebx
  40da36:	45                   	inc    %ebp
  40da37:	53                   	push   %ebx
  40da38:	53                   	push   %ebx
  40da39:	4f                   	dec    %edi
  40da3a:	52                   	push   %edx
  40da3b:	5f                   	pop    %edi
  40da3c:	50                   	push   %eax
  40da3d:	45                   	inc    %ebp
  40da3e:	4e                   	dec    %esi
  40da3f:	54                   	push   %esp
  40da40:	49                   	dec    %ecx
  40da41:	55                   	push   %ebp
  40da42:	4d                   	dec    %ebp
  40da43:	34 00                	xor    $0x0,%al
  40da45:	06                   	push   %es
  40da46:	11 50 52             	adc    %edx,0x52(%eax)
  40da49:	4f                   	dec    %edi
  40da4a:	43                   	inc    %ebx
  40da4b:	45                   	inc    %ebp
  40da4c:	53                   	push   %ebx
  40da4d:	53                   	push   %ebx
  40da4e:	4f                   	dec    %edi
  40da4f:	52                   	push   %edx
  40da50:	5f                   	pop    %edi
  40da51:	4e                   	dec    %esi
  40da52:	4f                   	dec    %edi
  40da53:	43                   	inc    %ebx
  40da54:	4f                   	dec    %edi
  40da55:	4e                   	dec    %esi
  40da56:	41                   	inc    %ecx
  40da57:	00 07                	add    %al,(%edi)
  40da59:	11 50 52             	adc    %edx,0x52(%eax)
  40da5c:	4f                   	dec    %edi
  40da5d:	43                   	inc    %ebx
  40da5e:	45                   	inc    %ebp
  40da5f:	53                   	push   %ebx
  40da60:	53                   	push   %ebx
  40da61:	4f                   	dec    %edi
  40da62:	52                   	push   %edx
  40da63:	5f                   	pop    %edi
  40da64:	43                   	inc    %ebx
  40da65:	4f                   	dec    %edi
  40da66:	52                   	push   %edx
  40da67:	45                   	inc    %ebp
  40da68:	32 00                	xor    (%eax),%al
  40da6a:	08 11                	or     %dl,(%ecx)
  40da6c:	50                   	push   %eax
  40da6d:	52                   	push   %edx
  40da6e:	4f                   	dec    %edi
  40da6f:	43                   	inc    %ebx
  40da70:	45                   	inc    %ebp
  40da71:	53                   	push   %ebx
  40da72:	53                   	push   %ebx
  40da73:	4f                   	dec    %edi
  40da74:	52                   	push   %edx
  40da75:	5f                   	pop    %edi
  40da76:	4e                   	dec    %esi
  40da77:	45                   	inc    %ebp
  40da78:	48                   	dec    %eax
  40da79:	41                   	inc    %ecx
  40da7a:	4c                   	dec    %esp
  40da7b:	45                   	inc    %ebp
  40da7c:	4d                   	dec    %ebp
  40da7d:	00 09                	add    %cl,(%ecx)
  40da7f:	11 50 52             	adc    %edx,0x52(%eax)
  40da82:	4f                   	dec    %edi
  40da83:	43                   	inc    %ebx
  40da84:	45                   	inc    %ebp
  40da85:	53                   	push   %ebx
  40da86:	53                   	push   %ebx
  40da87:	4f                   	dec    %edi
  40da88:	52                   	push   %edx
  40da89:	5f                   	pop    %edi
  40da8a:	53                   	push   %ebx
  40da8b:	41                   	inc    %ecx
  40da8c:	4e                   	dec    %esi
  40da8d:	44                   	inc    %esp
  40da8e:	59                   	pop    %ecx
  40da8f:	42                   	inc    %edx
  40da90:	52                   	push   %edx
  40da91:	49                   	dec    %ecx
  40da92:	44                   	inc    %esp
  40da93:	47                   	inc    %edi
  40da94:	45                   	inc    %ebp
  40da95:	00 0a                	add    %cl,(%edx)
  40da97:	11 50 52             	adc    %edx,0x52(%eax)
  40da9a:	4f                   	dec    %edi
  40da9b:	43                   	inc    %ebx
  40da9c:	45                   	inc    %ebp
  40da9d:	53                   	push   %ebx
  40da9e:	53                   	push   %ebx
  40da9f:	4f                   	dec    %edi
  40daa0:	52                   	push   %edx
  40daa1:	5f                   	pop    %edi
  40daa2:	48                   	dec    %eax
  40daa3:	41                   	inc    %ecx
  40daa4:	53                   	push   %ebx
  40daa5:	57                   	push   %edi
  40daa6:	45                   	inc    %ebp
  40daa7:	4c                   	dec    %esp
  40daa8:	4c                   	dec    %esp
  40daa9:	00 0b                	add    %cl,(%ebx)
  40daab:	11 50 52             	adc    %edx,0x52(%eax)
  40daae:	4f                   	dec    %edi
  40daaf:	43                   	inc    %ebx
  40dab0:	45                   	inc    %ebp
  40dab1:	53                   	push   %ebx
  40dab2:	53                   	push   %ebx
  40dab3:	4f                   	dec    %edi
  40dab4:	52                   	push   %edx
  40dab5:	5f                   	pop    %edi
  40dab6:	42                   	inc    %edx
  40dab7:	4f                   	dec    %edi
  40dab8:	4e                   	dec    %esi
  40dab9:	4e                   	dec    %esi
  40daba:	45                   	inc    %ebp
  40dabb:	4c                   	dec    %esp
  40dabc:	4c                   	dec    %esp
  40dabd:	00 0c 11             	add    %cl,(%ecx,%edx,1)
  40dac0:	50                   	push   %eax
  40dac1:	52                   	push   %edx
  40dac2:	4f                   	dec    %edi
  40dac3:	43                   	inc    %ebx
  40dac4:	45                   	inc    %ebp
  40dac5:	53                   	push   %ebx
  40dac6:	53                   	push   %ebx
  40dac7:	4f                   	dec    %edi
  40dac8:	52                   	push   %edx
  40dac9:	5f                   	pop    %edi
  40daca:	53                   	push   %ebx
  40dacb:	49                   	dec    %ecx
  40dacc:	4c                   	dec    %esp
  40dacd:	56                   	push   %esi
  40dace:	45                   	inc    %ebp
  40dacf:	52                   	push   %edx
  40dad0:	4d                   	dec    %ebp
  40dad1:	4f                   	dec    %edi
  40dad2:	4e                   	dec    %esi
  40dad3:	54                   	push   %esp
  40dad4:	00 0d 11 50 52 4f    	add    %cl,0x4f525011
  40dada:	43                   	inc    %ebx
  40dadb:	45                   	inc    %ebp
  40dadc:	53                   	push   %ebx
  40dadd:	53                   	push   %ebx
  40dade:	4f                   	dec    %edi
  40dadf:	52                   	push   %edx
  40dae0:	5f                   	pop    %edi
  40dae1:	47                   	inc    %edi
  40dae2:	4f                   	dec    %edi
  40dae3:	4c                   	dec    %esp
  40dae4:	44                   	inc    %esp
  40dae5:	4d                   	dec    %ebp
  40dae6:	4f                   	dec    %edi
  40dae7:	4e                   	dec    %esi
  40dae8:	54                   	push   %esp
  40dae9:	00 0e                	add    %cl,(%esi)
  40daeb:	11 50 52             	adc    %edx,0x52(%eax)
  40daee:	4f                   	dec    %edi
  40daef:	43                   	inc    %ebx
  40daf0:	45                   	inc    %ebp
  40daf1:	53                   	push   %ebx
  40daf2:	53                   	push   %ebx
  40daf3:	4f                   	dec    %edi
  40daf4:	52                   	push   %edx
  40daf5:	5f                   	pop    %edi
  40daf6:	47                   	inc    %edi
  40daf7:	4f                   	dec    %edi
  40daf8:	4c                   	dec    %esp
  40daf9:	44                   	inc    %esp
  40dafa:	4d                   	dec    %ebp
  40dafb:	4f                   	dec    %edi
  40dafc:	4e                   	dec    %esi
  40dafd:	54                   	push   %esp
  40dafe:	5f                   	pop    %edi
  40daff:	50                   	push   %eax
  40db00:	4c                   	dec    %esp
  40db01:	55                   	push   %ebp
  40db02:	53                   	push   %ebx
  40db03:	00 0f                	add    %cl,(%edi)
  40db05:	11 50 52             	adc    %edx,0x52(%eax)
  40db08:	4f                   	dec    %edi
  40db09:	43                   	inc    %ebx
  40db0a:	45                   	inc    %ebp
  40db0b:	53                   	push   %ebx
  40db0c:	53                   	push   %ebx
  40db0d:	4f                   	dec    %edi
  40db0e:	52                   	push   %edx
  40db0f:	5f                   	pop    %edi
  40db10:	54                   	push   %esp
  40db11:	52                   	push   %edx
  40db12:	45                   	inc    %ebp
  40db13:	4d                   	dec    %ebp
  40db14:	4f                   	dec    %edi
  40db15:	4e                   	dec    %esi
  40db16:	54                   	push   %esp
  40db17:	00 10                	add    %dl,(%eax)
  40db19:	11 50 52             	adc    %edx,0x52(%eax)
  40db1c:	4f                   	dec    %edi
  40db1d:	43                   	inc    %ebx
  40db1e:	45                   	inc    %ebp
  40db1f:	53                   	push   %ebx
  40db20:	53                   	push   %ebx
  40db21:	4f                   	dec    %edi
  40db22:	52                   	push   %edx
  40db23:	5f                   	pop    %edi
  40db24:	4b                   	dec    %ebx
  40db25:	4e                   	dec    %esi
  40db26:	4c                   	dec    %esp
  40db27:	00 11                	add    %dl,(%ecx)
  40db29:	11 50 52             	adc    %edx,0x52(%eax)
  40db2c:	4f                   	dec    %edi
  40db2d:	43                   	inc    %ebx
  40db2e:	45                   	inc    %ebp
  40db2f:	53                   	push   %ebx
  40db30:	53                   	push   %ebx
  40db31:	4f                   	dec    %edi
  40db32:	52                   	push   %edx
  40db33:	5f                   	pop    %edi
  40db34:	4b                   	dec    %ebx
  40db35:	4e                   	dec    %esi
  40db36:	4d                   	dec    %ebp
  40db37:	00 12                	add    %dl,(%edx)
  40db39:	11 50 52             	adc    %edx,0x52(%eax)
  40db3c:	4f                   	dec    %edi
  40db3d:	43                   	inc    %ebx
  40db3e:	45                   	inc    %ebp
  40db3f:	53                   	push   %ebx
  40db40:	53                   	push   %ebx
  40db41:	4f                   	dec    %edi
  40db42:	52                   	push   %edx
  40db43:	5f                   	pop    %edi
  40db44:	53                   	push   %ebx
  40db45:	4b                   	dec    %ebx
  40db46:	59                   	pop    %ecx
  40db47:	4c                   	dec    %esp
  40db48:	41                   	inc    %ecx
  40db49:	4b                   	dec    %ebx
  40db4a:	45                   	inc    %ebp
  40db4b:	00 13                	add    %dl,(%ebx)
  40db4d:	11 50 52             	adc    %edx,0x52(%eax)
  40db50:	4f                   	dec    %edi
  40db51:	43                   	inc    %ebx
  40db52:	45                   	inc    %ebp
  40db53:	53                   	push   %ebx
  40db54:	53                   	push   %ebx
  40db55:	4f                   	dec    %edi
  40db56:	52                   	push   %edx
  40db57:	5f                   	pop    %edi
  40db58:	53                   	push   %ebx
  40db59:	4b                   	dec    %ebx
  40db5a:	59                   	pop    %ecx
  40db5b:	4c                   	dec    %esp
  40db5c:	41                   	inc    %ecx
  40db5d:	4b                   	dec    %ebx
  40db5e:	45                   	inc    %ebp
  40db5f:	5f                   	pop    %edi
  40db60:	41                   	inc    %ecx
  40db61:	56                   	push   %esi
  40db62:	58                   	pop    %eax
  40db63:	35 31 32 00 14       	xor    $0x14003231,%eax
  40db68:	11 50 52             	adc    %edx,0x52(%eax)
  40db6b:	4f                   	dec    %edi
  40db6c:	43                   	inc    %ebx
  40db6d:	45                   	inc    %ebp
  40db6e:	53                   	push   %ebx
  40db6f:	53                   	push   %ebx
  40db70:	4f                   	dec    %edi
  40db71:	52                   	push   %edx
  40db72:	5f                   	pop    %edi
  40db73:	43                   	inc    %ebx
  40db74:	41                   	inc    %ecx
  40db75:	4e                   	dec    %esi
  40db76:	4e                   	dec    %esi
  40db77:	4f                   	dec    %edi
  40db78:	4e                   	dec    %esi
  40db79:	4c                   	dec    %esp
  40db7a:	41                   	inc    %ecx
  40db7b:	4b                   	dec    %ebx
  40db7c:	45                   	inc    %ebp
  40db7d:	00 15 11 50 52 4f    	add    %dl,0x4f525011
  40db83:	43                   	inc    %ebx
  40db84:	45                   	inc    %ebp
  40db85:	53                   	push   %ebx
  40db86:	53                   	push   %ebx
  40db87:	4f                   	dec    %edi
  40db88:	52                   	push   %edx
  40db89:	5f                   	pop    %edi
  40db8a:	49                   	dec    %ecx
  40db8b:	43                   	inc    %ebx
  40db8c:	45                   	inc    %ebp
  40db8d:	4c                   	dec    %esp
  40db8e:	41                   	inc    %ecx
  40db8f:	4b                   	dec    %ebx
  40db90:	45                   	inc    %ebp
  40db91:	5f                   	pop    %edi
  40db92:	43                   	inc    %ebx
  40db93:	4c                   	dec    %esp
  40db94:	49                   	dec    %ecx
  40db95:	45                   	inc    %ebp
  40db96:	4e                   	dec    %esi
  40db97:	54                   	push   %esp
  40db98:	00 16                	add    %dl,(%esi)
  40db9a:	11 50 52             	adc    %edx,0x52(%eax)
  40db9d:	4f                   	dec    %edi
  40db9e:	43                   	inc    %ebx
  40db9f:	45                   	inc    %ebp
  40dba0:	53                   	push   %ebx
  40dba1:	53                   	push   %ebx
  40dba2:	4f                   	dec    %edi
  40dba3:	52                   	push   %edx
  40dba4:	5f                   	pop    %edi
  40dba5:	49                   	dec    %ecx
  40dba6:	43                   	inc    %ebx
  40dba7:	45                   	inc    %ebp
  40dba8:	4c                   	dec    %esp
  40dba9:	41                   	inc    %ecx
  40dbaa:	4b                   	dec    %ebx
  40dbab:	45                   	inc    %ebp
  40dbac:	5f                   	pop    %edi
  40dbad:	53                   	push   %ebx
  40dbae:	45                   	inc    %ebp
  40dbaf:	52                   	push   %edx
  40dbb0:	56                   	push   %esi
  40dbb1:	45                   	inc    %ebp
  40dbb2:	52                   	push   %edx
  40dbb3:	00 17                	add    %dl,(%edi)
  40dbb5:	11 50 52             	adc    %edx,0x52(%eax)
  40dbb8:	4f                   	dec    %edi
  40dbb9:	43                   	inc    %ebx
  40dbba:	45                   	inc    %ebp
  40dbbb:	53                   	push   %ebx
  40dbbc:	53                   	push   %ebx
  40dbbd:	4f                   	dec    %edi
  40dbbe:	52                   	push   %edx
  40dbbf:	5f                   	pop    %edi
  40dbc0:	43                   	inc    %ebx
  40dbc1:	41                   	inc    %ecx
  40dbc2:	53                   	push   %ebx
  40dbc3:	43                   	inc    %ebx
  40dbc4:	41                   	inc    %ecx
  40dbc5:	44                   	inc    %esp
  40dbc6:	45                   	inc    %ebp
  40dbc7:	4c                   	dec    %esp
  40dbc8:	41                   	inc    %ecx
  40dbc9:	4b                   	dec    %ebx
  40dbca:	45                   	inc    %ebp
  40dbcb:	00 18                	add    %bl,(%eax)
  40dbcd:	11 50 52             	adc    %edx,0x52(%eax)
  40dbd0:	4f                   	dec    %edi
  40dbd1:	43                   	inc    %ebx
  40dbd2:	45                   	inc    %ebp
  40dbd3:	53                   	push   %ebx
  40dbd4:	53                   	push   %ebx
  40dbd5:	4f                   	dec    %edi
  40dbd6:	52                   	push   %edx
  40dbd7:	5f                   	pop    %edi
  40dbd8:	49                   	dec    %ecx
  40dbd9:	4e                   	dec    %esi
  40dbda:	54                   	push   %esp
  40dbdb:	45                   	inc    %ebp
  40dbdc:	4c                   	dec    %esp
  40dbdd:	00 19                	add    %bl,(%ecx)
  40dbdf:	11 50 52             	adc    %edx,0x52(%eax)
  40dbe2:	4f                   	dec    %edi
  40dbe3:	43                   	inc    %ebx
  40dbe4:	45                   	inc    %ebp
  40dbe5:	53                   	push   %ebx
  40dbe6:	53                   	push   %ebx
  40dbe7:	4f                   	dec    %edi
  40dbe8:	52                   	push   %edx
  40dbe9:	5f                   	pop    %edi
  40dbea:	47                   	inc    %edi
  40dbeb:	45                   	inc    %ebp
  40dbec:	4f                   	dec    %edi
  40dbed:	44                   	inc    %esp
  40dbee:	45                   	inc    %ebp
  40dbef:	00 1a                	add    %bl,(%edx)
  40dbf1:	11 50 52             	adc    %edx,0x52(%eax)
  40dbf4:	4f                   	dec    %edi
  40dbf5:	43                   	inc    %ebx
  40dbf6:	45                   	inc    %ebp
  40dbf7:	53                   	push   %ebx
  40dbf8:	53                   	push   %ebx
  40dbf9:	4f                   	dec    %edi
  40dbfa:	52                   	push   %edx
  40dbfb:	5f                   	pop    %edi
  40dbfc:	4b                   	dec    %ebx
  40dbfd:	36 00 1b             	add    %bl,%ss:(%ebx)
  40dc00:	11 50 52             	adc    %edx,0x52(%eax)
  40dc03:	4f                   	dec    %edi
  40dc04:	43                   	inc    %ebx
  40dc05:	45                   	inc    %ebp
  40dc06:	53                   	push   %ebx
  40dc07:	53                   	push   %ebx
  40dc08:	4f                   	dec    %edi
  40dc09:	52                   	push   %edx
  40dc0a:	5f                   	pop    %edi
  40dc0b:	41                   	inc    %ecx
  40dc0c:	54                   	push   %esp
  40dc0d:	48                   	dec    %eax
  40dc0e:	4c                   	dec    %esp
  40dc0f:	4f                   	dec    %edi
  40dc10:	4e                   	dec    %esi
  40dc11:	00 1c 11             	add    %bl,(%ecx,%edx,1)
  40dc14:	50                   	push   %eax
  40dc15:	52                   	push   %edx
  40dc16:	4f                   	dec    %edi
  40dc17:	43                   	inc    %ebx
  40dc18:	45                   	inc    %ebp
  40dc19:	53                   	push   %ebx
  40dc1a:	53                   	push   %ebx
  40dc1b:	4f                   	dec    %edi
  40dc1c:	52                   	push   %edx
  40dc1d:	5f                   	pop    %edi
  40dc1e:	4b                   	dec    %ebx
  40dc1f:	38 00                	cmp    %al,(%eax)
  40dc21:	1d 11 50 52 4f       	sbb    $0x4f525011,%eax
  40dc26:	43                   	inc    %ebx
  40dc27:	45                   	inc    %ebp
  40dc28:	53                   	push   %ebx
  40dc29:	53                   	push   %ebx
  40dc2a:	4f                   	dec    %edi
  40dc2b:	52                   	push   %edx
  40dc2c:	5f                   	pop    %edi
  40dc2d:	41                   	inc    %ecx
  40dc2e:	4d                   	dec    %ebp
  40dc2f:	44                   	inc    %esp
  40dc30:	46                   	inc    %esi
  40dc31:	41                   	inc    %ecx
  40dc32:	4d                   	dec    %ebp
  40dc33:	31 30                	xor    %esi,(%eax)
  40dc35:	00 1e                	add    %bl,(%esi)
  40dc37:	11 50 52             	adc    %edx,0x52(%eax)
  40dc3a:	4f                   	dec    %edi
  40dc3b:	43                   	inc    %ebx
  40dc3c:	45                   	inc    %ebp
  40dc3d:	53                   	push   %ebx
  40dc3e:	53                   	push   %ebx
  40dc3f:	4f                   	dec    %edi
  40dc40:	52                   	push   %edx
  40dc41:	5f                   	pop    %edi
  40dc42:	42                   	inc    %edx
  40dc43:	44                   	inc    %esp
  40dc44:	56                   	push   %esi
  40dc45:	45                   	inc    %ebp
  40dc46:	52                   	push   %edx
  40dc47:	31 00                	xor    %eax,(%eax)
  40dc49:	1f                   	pop    %ds
  40dc4a:	11 50 52             	adc    %edx,0x52(%eax)
  40dc4d:	4f                   	dec    %edi
  40dc4e:	43                   	inc    %ebx
  40dc4f:	45                   	inc    %ebp
  40dc50:	53                   	push   %ebx
  40dc51:	53                   	push   %ebx
  40dc52:	4f                   	dec    %edi
  40dc53:	52                   	push   %edx
  40dc54:	5f                   	pop    %edi
  40dc55:	42                   	inc    %edx
  40dc56:	44                   	inc    %esp
  40dc57:	56                   	push   %esi
  40dc58:	45                   	inc    %ebp
  40dc59:	52                   	push   %edx
  40dc5a:	32 00                	xor    (%eax),%al
  40dc5c:	20 11                	and    %dl,(%ecx)
  40dc5e:	50                   	push   %eax
  40dc5f:	52                   	push   %edx
  40dc60:	4f                   	dec    %edi
  40dc61:	43                   	inc    %ebx
  40dc62:	45                   	inc    %ebp
  40dc63:	53                   	push   %ebx
  40dc64:	53                   	push   %ebx
  40dc65:	4f                   	dec    %edi
  40dc66:	52                   	push   %edx
  40dc67:	5f                   	pop    %edi
  40dc68:	42                   	inc    %edx
  40dc69:	44                   	inc    %esp
  40dc6a:	56                   	push   %esi
  40dc6b:	45                   	inc    %ebp
  40dc6c:	52                   	push   %edx
  40dc6d:	33 00                	xor    (%eax),%eax
  40dc6f:	21 11                	and    %edx,(%ecx)
  40dc71:	50                   	push   %eax
  40dc72:	52                   	push   %edx
  40dc73:	4f                   	dec    %edi
  40dc74:	43                   	inc    %ebx
  40dc75:	45                   	inc    %ebp
  40dc76:	53                   	push   %ebx
  40dc77:	53                   	push   %ebx
  40dc78:	4f                   	dec    %edi
  40dc79:	52                   	push   %edx
  40dc7a:	5f                   	pop    %edi
  40dc7b:	42                   	inc    %edx
  40dc7c:	44                   	inc    %esp
  40dc7d:	56                   	push   %esi
  40dc7e:	45                   	inc    %ebp
  40dc7f:	52                   	push   %edx
  40dc80:	34 00                	xor    $0x0,%al
  40dc82:	22 11                	and    (%ecx),%dl
  40dc84:	50                   	push   %eax
  40dc85:	52                   	push   %edx
  40dc86:	4f                   	dec    %edi
  40dc87:	43                   	inc    %ebx
  40dc88:	45                   	inc    %ebp
  40dc89:	53                   	push   %ebx
  40dc8a:	53                   	push   %ebx
  40dc8b:	4f                   	dec    %edi
  40dc8c:	52                   	push   %edx
  40dc8d:	5f                   	pop    %edi
  40dc8e:	42                   	inc    %edx
  40dc8f:	54                   	push   %esp
  40dc90:	56                   	push   %esi
  40dc91:	45                   	inc    %ebp
  40dc92:	52                   	push   %edx
  40dc93:	31 00                	xor    %eax,(%eax)
  40dc95:	23 11                	and    (%ecx),%edx
  40dc97:	50                   	push   %eax
  40dc98:	52                   	push   %edx
  40dc99:	4f                   	dec    %edi
  40dc9a:	43                   	inc    %ebx
  40dc9b:	45                   	inc    %ebp
  40dc9c:	53                   	push   %ebx
  40dc9d:	53                   	push   %ebx
  40dc9e:	4f                   	dec    %edi
  40dc9f:	52                   	push   %edx
  40dca0:	5f                   	pop    %edi
  40dca1:	42                   	inc    %edx
  40dca2:	54                   	push   %esp
  40dca3:	56                   	push   %esi
  40dca4:	45                   	inc    %ebp
  40dca5:	52                   	push   %edx
  40dca6:	32 00                	xor    (%eax),%al
  40dca8:	24 11                	and    $0x11,%al
  40dcaa:	50                   	push   %eax
  40dcab:	52                   	push   %edx
  40dcac:	4f                   	dec    %edi
  40dcad:	43                   	inc    %ebx
  40dcae:	45                   	inc    %ebp
  40dcaf:	53                   	push   %ebx
  40dcb0:	53                   	push   %ebx
  40dcb1:	4f                   	dec    %edi
  40dcb2:	52                   	push   %edx
  40dcb3:	5f                   	pop    %edi
  40dcb4:	5a                   	pop    %edx
  40dcb5:	4e                   	dec    %esi
  40dcb6:	56                   	push   %esi
  40dcb7:	45                   	inc    %ebp
  40dcb8:	52                   	push   %edx
  40dcb9:	31 00                	xor    %eax,(%eax)
  40dcbb:	25 11 50 52 4f       	and    $0x4f525011,%eax
  40dcc0:	43                   	inc    %ebx
  40dcc1:	45                   	inc    %ebp
  40dcc2:	53                   	push   %ebx
  40dcc3:	53                   	push   %ebx
  40dcc4:	4f                   	dec    %edi
  40dcc5:	52                   	push   %edx
  40dcc6:	5f                   	pop    %edi
  40dcc7:	5a                   	pop    %edx
  40dcc8:	4e                   	dec    %esi
  40dcc9:	56                   	push   %esi
  40dcca:	45                   	inc    %ebp
  40dccb:	52                   	push   %edx
  40dccc:	32 00                	xor    (%eax),%al
  40dcce:	26 11 50 52          	adc    %edx,%es:0x52(%eax)
  40dcd2:	4f                   	dec    %edi
  40dcd3:	43                   	inc    %ebx
  40dcd4:	45                   	inc    %ebp
  40dcd5:	53                   	push   %ebx
  40dcd6:	53                   	push   %ebx
  40dcd7:	4f                   	dec    %edi
  40dcd8:	52                   	push   %edx
  40dcd9:	5f                   	pop    %edi
  40dcda:	6d                   	insl   (%dx),%es:(%edi)
  40dcdb:	61                   	popa   
  40dcdc:	78 00                	js     40dcde <.debug_info+0x1cb8>
  40dcde:	27                   	daa    
  40dcdf:	00 0b                	add    %cl,(%ebx)
  40dce1:	69 78 38 36 5f 74 75 	imul   $0x75745f36,0x38(%eax),%edi
  40dce8:	6e                   	outsb  %ds:(%esi),(%dx)
  40dce9:	65 00 07             	add    %al,%gs:(%edi)
  40dcec:	72 09                	jb     40dcf7 <.debug_info+0x1cd1>
  40dcee:	1c 77                	sbb    $0x77,%al
  40dcf0:	19 00                	sbb    %eax,(%eax)
  40dcf2:	00 0b                	add    %cl,(%ebx)
  40dcf4:	69 78 38 36 5f 61 72 	imul   $0x72615f36,0x38(%eax),%edi
  40dcfb:	63 68 00             	arpl   %bp,0x0(%eax)
  40dcfe:	07                   	pop    %es
  40dcff:	73 09                	jae    40dd0a <.debug_info+0x1ce4>
  40dd01:	1c 77                	sbb    $0x77,%al
  40dd03:	19 00                	sbb    %eax,(%eax)
  40dd05:	00 0b                	add    %cl,(%ebx)
  40dd07:	69 78 38 36 5f 70 72 	imul   $0x72705f36,0x38(%eax),%edi
  40dd0e:	65 66 65 72 72       	gs data16 gs jb 40dd85 <.debug_info+0x1d5f>
  40dd13:	65 64 5f             	gs fs pop %edi
  40dd16:	73 74                	jae    40dd8c <.debug_info+0x1d66>
  40dd18:	61                   	popa   
  40dd19:	63 6b 5f             	arpl   %bp,0x5f(%ebx)
  40dd1c:	62 6f 75             	bound  %ebp,0x75(%edi)
  40dd1f:	6e                   	outsb  %ds:(%esi),(%dx)
  40dd20:	64 61                	fs popa 
  40dd22:	72 79                	jb     40dd9d <.debug_info+0x1d77>
  40dd24:	00 07                	add    %al,(%edi)
  40dd26:	7a 09                	jp     40dd31 <.debug_info+0x1d0b>
  40dd28:	15 f1 00 00 00       	adc    $0xf1,%eax
  40dd2d:	0b 69 78             	or     0x78(%ecx),%ebp
  40dd30:	38 36                	cmp    %dh,(%esi)
  40dd32:	5f                   	pop    %edi
  40dd33:	69 6e 63 6f 6d 69 6e 	imul   $0x6e696d6f,0x63(%esi),%ebp
  40dd3a:	67 5f                	addr16 pop %edi
  40dd3c:	73 74                	jae    40ddb2 <.debug_info+0x1d8c>
  40dd3e:	61                   	popa   
  40dd3f:	63 6b 5f             	arpl   %bp,0x5f(%ebx)
  40dd42:	62 6f 75             	bound  %ebp,0x75(%edi)
  40dd45:	6e                   	outsb  %ds:(%esi),(%dx)
  40dd46:	64 61                	fs popa 
  40dd48:	72 79                	jb     40ddc3 <.debug_info+0x1d9d>
  40dd4a:	00 07                	add    %al,(%edi)
  40dd4c:	7b 09                	jnp    40dd57 <.debug_info+0x1d31>
  40dd4e:	15 f1 00 00 00       	adc    $0xf1,%eax
  40dd53:	08 08                	or     %cl,(%eax)
  40dd55:	19 00                	sbb    %eax,(%eax)
  40dd57:	00 3d 1d 00 00 0c    	add    %bh,0xc00001d
  40dd5d:	f1                   	icebp  
  40dd5e:	00 00                	add    %al,(%eax)
  40dd60:	00 4b 00             	add    %cl,0x0(%ebx)
  40dd63:	03 2d 1d 00 00 0b    	add    0xb00001d,%ebp
  40dd69:	72 65                	jb     40ddd0 <.debug_info+0x1daa>
  40dd6b:	67 63 6c 61          	arpl   %bp,0x61(%si)
  40dd6f:	73 73                	jae    40dde4 <.debug_info+0x1dbe>
  40dd71:	5f                   	pop    %edi
  40dd72:	6d                   	insl   (%dx),%es:(%edi)
  40dd73:	61                   	popa   
  40dd74:	70 00                	jo     40dd76 <.debug_info+0x1d50>
  40dd76:	07                   	pop    %es
  40dd77:	7e 09                	jle    40dd82 <.debug_info+0x1d5c>
  40dd79:	1d 3d 1d 00 00       	sbb    $0x1d3d,%eax
  40dd7e:	02 01                	add    (%ecx),%al
  40dd80:	06                   	push   %es
  40dd81:	73 69                	jae    40ddec <.debug_info+0x1dc6>
  40dd83:	67 6e                	outsb  %ds:(%si),(%dx)
  40dd85:	65 64 20 63 68       	gs and %ah,%fs:0x68(%ebx)
  40dd8a:	61                   	popa   
  40dd8b:	72 00                	jb     40dd8d <.debug_info+0x1d67>
  40dd8d:	07                   	pop    %es
  40dd8e:	55                   	push   %ebp
  40dd8f:	51                   	push   %ecx
  40dd90:	49                   	dec    %ecx
  40dd91:	74 79                	je     40de0c <.debug_info+0x1de6>
  40dd93:	70 65                	jo     40ddfa <.debug_info+0x1dd4>
  40dd95:	00 09                	add    %cl,(%ecx)
  40dd97:	7b 16                	jnp    40ddaf <.debug_info+0x1d89>
  40dd99:	4d                   	dec    %ebp
  40dd9a:	04 00                	add    $0x0,%al
  40dd9c:	00 03                	add    %al,(%ebx)
  40dd9e:	67 1d 00 00 02 08    	addr16 sbb $0x8020000,%eax
  40dda4:	07                   	pop    %es
  40dda5:	6c                   	insb   (%dx),%es:(%edi)
  40dda6:	6f                   	outsl  %ds:(%esi),(%dx)
  40dda7:	6e                   	outsb  %ds:(%esi),(%dx)
  40dda8:	67 20 6c 6f          	and    %ch,0x6f(%si)
  40ddac:	6e                   	outsb  %ds:(%esi),(%dx)
  40ddad:	67 20 75 6e          	and    %dh,0x6e(%di)
  40ddb1:	73 69                	jae    40de1c <.debug_info+0x1df6>
  40ddb3:	67 6e                	outsb  %ds:(%si),(%dx)
  40ddb5:	65 64 20 69 6e       	gs and %ch,%fs:0x6e(%ecx)
  40ddba:	74 00                	je     40ddbc <.debug_info+0x1d96>
  40ddbc:	02 04 04             	add    (%esp,%eax,1),%al
  40ddbf:	66 6c                	data16 insb (%dx),%es:(%edi)
  40ddc1:	6f                   	outsl  %ds:(%esi),(%dx)
  40ddc2:	61                   	popa   
  40ddc3:	74 00                	je     40ddc5 <.debug_info+0x1d9f>
  40ddc5:	02 08                	add    (%eax),%cl
  40ddc7:	03 63 6f             	add    0x6f(%ebx),%esp
  40ddca:	6d                   	insl   (%dx),%es:(%edi)
  40ddcb:	70 6c                	jo     40de39 <.debug_info+0x1e13>
  40ddcd:	65 78 20             	gs js  40ddf0 <.debug_info+0x1dca>
  40ddd0:	66 6c                	data16 insb (%dx),%es:(%edi)
  40ddd2:	6f                   	outsl  %ds:(%esi),(%dx)
  40ddd3:	61                   	popa   
  40ddd4:	74 00                	je     40ddd6 <.debug_info+0x1db0>
  40ddd6:	02 08                	add    (%eax),%cl
  40ddd8:	04 64                	add    $0x64,%al
  40ddda:	6f                   	outsl  %ds:(%esi),(%dx)
  40dddb:	75 62                	jne    40de3f <.debug_info+0x1e19>
  40dddd:	6c                   	insb   (%dx),%es:(%edi)
  40ddde:	65 00 02             	add    %al,%gs:(%edx)
  40dde1:	10 03                	adc    %al,(%ebx)
  40dde3:	63 6f 6d             	arpl   %bp,0x6d(%edi)
  40dde6:	70 6c                	jo     40de54 <.debug_info+0x1e2e>
  40dde8:	65 78 20             	gs js  40de0b <.debug_info+0x1de5>
  40ddeb:	64 6f                	outsl  %fs:(%esi),(%dx)
  40dded:	75 62                	jne    40de51 <.debug_info+0x1e2b>
  40ddef:	6c                   	insb   (%dx),%es:(%edi)
  40ddf0:	65 00 02             	add    %al,%gs:(%edx)
  40ddf3:	18 03                	sbb    %al,(%ebx)
  40ddf5:	63 6f 6d             	arpl   %bp,0x6d(%edi)
  40ddf8:	70 6c                	jo     40de66 <.debug_info+0x1e40>
  40ddfa:	65 78 20             	gs js  40de1d <.debug_info+0x1df7>
  40ddfd:	6c                   	insb   (%dx),%es:(%edi)
  40ddfe:	6f                   	outsl  %ds:(%esi),(%dx)
  40ddff:	6e                   	outsb  %ds:(%esi),(%dx)
  40de00:	67 20 64 6f          	and    %ah,0x6f(%si)
  40de04:	75 62                	jne    40de68 <.debug_info+0x1e42>
  40de06:	6c                   	insb   (%dx),%es:(%edi)
  40de07:	65 00 02             	add    %al,%gs:(%edx)
  40de0a:	20 03                	and    %al,(%ebx)
  40de0c:	63 6f 6d             	arpl   %bp,0x6d(%edi)
  40de0f:	70 6c                	jo     40de7d <.debug_info+0x1e57>
  40de11:	65 78 20             	gs js  40de34 <.debug_info+0x1e0e>
  40de14:	5f                   	pop    %edi
  40de15:	46                   	inc    %esi
  40de16:	6c                   	insb   (%dx),%es:(%edi)
  40de17:	6f                   	outsl  %ds:(%esi),(%dx)
  40de18:	61                   	popa   
  40de19:	74 31                	je     40de4c <.debug_info+0x1e26>
  40de1b:	32 38                	xor    (%eax),%bh
  40de1d:	00 08                	add    %cl,(%eax)
  40de1f:	77 1d                	ja     40de3e <.debug_info+0x1e18>
  40de21:	00 00                	add    %al,(%eax)
  40de23:	08 1e                	or     %bl,(%esi)
  40de25:	00 00                	add    %al,(%eax)
  40de27:	0c f1                	or     $0xf1,%al
  40de29:	00 00                	add    %al,(%eax)
  40de2b:	00 ff                	add    %bh,%bh
  40de2d:	00 03                	add    %al,(%ebx)
  40de2f:	f8                   	clc    
  40de30:	1d 00 00 0b 5f       	sbb    $0x5f0b0000,%eax
  40de35:	5f                   	pop    %edi
  40de36:	70 6f                	jo     40dea7 <.debug_info+0x1e81>
  40de38:	70 63                	jo     40de9d <.debug_info+0x1e77>
  40de3a:	6f                   	outsl  %ds:(%esi),(%dx)
  40de3b:	75 6e                	jne    40deab <.debug_info+0x1e85>
  40de3d:	74 5f                	je     40de9e <.debug_info+0x1e78>
  40de3f:	74 61                	je     40dea2 <.debug_info+0x1e7c>
  40de41:	62 00                	bound  %eax,(%eax)
  40de43:	09 fc                	or     %edi,%esp
  40de45:	01 16                	add    %edx,(%esi)
  40de47:	08 1e                	or     %bl,(%esi)
  40de49:	00 00                	add    %al,(%eax)
  40de4b:	0b 5f 5f             	or     0x5f(%edi),%ebx
  40de4e:	63 6c 7a 5f          	arpl   %bp,0x5f(%edx,%edi,2)
  40de52:	74 61                	je     40deb5 <.debug_info+0x1e8f>
  40de54:	62 00                	bound  %eax,(%eax)
  40de56:	09 02                	or     %eax,(%edx)
  40de58:	02 16                	add    (%esi),%dl
  40de5a:	08 1e                	or     %bl,(%esi)
  40de5c:	00 00                	add    %al,(%eax)
  40de5e:	07                   	pop    %es
  40de5f:	66 75 6e             	data16 jne 40ded0 <.debug_info+0x1eaa>
  40de62:	63 5f 70             	arpl   %bx,0x70(%edi)
  40de65:	74 72                	je     40ded9 <.debug_info+0x1eb3>
  40de67:	00 0a                	add    %cl,(%edx)
  40de69:	2a 10                	sub    (%eax),%dl
  40de6b:	49                   	dec    %ecx
  40de6c:	1e                   	push   %ds
  40de6d:	00 00                	add    %al,(%eax)
  40de6f:	06                   	push   %es
  40de70:	04 4f                	add    $0x4f,%al
  40de72:	1e                   	push   %ds
  40de73:	00 00                	add    %al,(%eax)
  40de75:	17                   	pop    %ss
  40de76:	08 38                	or     %bh,(%eax)
  40de78:	1e                   	push   %ds
  40de79:	00 00                	add    %al,(%eax)
  40de7b:	5b                   	pop    %ebx
  40de7c:	1e                   	push   %ds
  40de7d:	00 00                	add    %al,(%eax)
  40de7f:	09 00                	or     %eax,(%eax)
  40de81:	0a 5f 5f             	or     0x5f(%edi),%bl
  40de84:	43                   	inc    %ebx
  40de85:	54                   	push   %esp
  40de86:	4f                   	dec    %edi
  40de87:	52                   	push   %edx
  40de88:	5f                   	pop    %edi
  40de89:	4c                   	dec    %esp
  40de8a:	49                   	dec    %ecx
  40de8b:	53                   	push   %ebx
  40de8c:	54                   	push   %esp
  40de8d:	5f                   	pop    %edi
  40de8e:	5f                   	pop    %edi
  40de8f:	00 0a                	add    %cl,(%edx)
  40de91:	2f                   	das    
  40de92:	11 50 1e             	adc    %edx,0x1e(%eax)
  40de95:	00 00                	add    %al,(%eax)
  40de97:	0a 5f 5f             	or     0x5f(%edi),%bl
  40de9a:	44                   	inc    %esp
  40de9b:	54                   	push   %esp
  40de9c:	4f                   	dec    %edi
  40de9d:	52                   	push   %edx
  40de9e:	5f                   	pop    %edi
  40de9f:	4c                   	dec    %esp
  40dea0:	49                   	dec    %ecx
  40dea1:	53                   	push   %ebx
  40dea2:	54                   	push   %esp
  40dea3:	5f                   	pop    %edi
  40dea4:	5f                   	pop    %edi
  40dea5:	00 0a                	add    %cl,(%edx)
  40dea7:	30 11                	xor    %dl,(%ecx)
  40dea9:	50                   	push   %eax
  40deaa:	1e                   	push   %ds
  40deab:	00 00                	add    %al,(%eax)
  40dead:	18 5b 1e             	sbb    %bl,0x1e(%ebx)
  40deb0:	00 00                	add    %al,(%eax)
  40deb2:	0b 36                	or     (%esi),%esi
  40deb4:	09 0a                	or     %ecx,(%edx)
  40deb6:	05 03 e0 3f 40       	add    $0x403fe003,%eax
  40debb:	00 18                	add    %bl,(%eax)
  40debd:	71 1e                	jno    40dedd <.debug_info+0x1eb7>
  40debf:	00 00                	add    %al,(%eax)
  40dec1:	0b 37                	or     (%edi),%esi
  40dec3:	09 0a                	or     %ecx,(%edx)
  40dec5:	05 03 ec 3f 40       	add    $0x403fec03,%eax
	...

Disassembly of section .debug_abbrev:

0040e000 <.debug_abbrev>:
  40e000:	01 11                	add    %edx,(%ecx)
  40e002:	00 10                	add    %dl,(%eax)
  40e004:	06                   	push   %es
  40e005:	11 01                	adc    %eax,(%ecx)
  40e007:	12 01                	adc    (%ecx),%al
  40e009:	03 0e                	add    (%esi),%ecx
  40e00b:	1b 0e                	sbb    (%esi),%ecx
  40e00d:	25 0e 13 05 00       	and    $0x5130e,%eax
	...

0040e014 <.debug_abbrev>:
  40e014:	01 11                	add    %edx,(%ecx)
  40e016:	01 25 08 13 0b 03    	add    %esp,0x30b1308
  40e01c:	08 1b                	or     %bl,(%ebx)
  40e01e:	08 10                	or     %dl,(%eax)
  40e020:	17                   	pop    %ss
  40e021:	00 00                	add    %al,(%eax)
  40e023:	02 24 00             	add    (%eax,%eax,1),%ah
  40e026:	0b 0b                	or     (%ebx),%ecx
  40e028:	3e 0b 03             	or     %ds:(%ebx),%eax
  40e02b:	08 00                	or     %al,(%eax)
  40e02d:	00 03                	add    %al,(%ebx)
  40e02f:	26 00 49 13          	add    %cl,%es:0x13(%ecx)
  40e033:	00 00                	add    %al,(%eax)
  40e035:	04 13                	add    $0x13,%al
  40e037:	01 03                	add    %eax,(%ebx)
  40e039:	08 0b                	or     %cl,(%ebx)
  40e03b:	0b 3a                	or     (%edx),%edi
  40e03d:	0b 3b                	or     (%ebx),%edi
  40e03f:	0b 39                	or     (%ecx),%edi
  40e041:	0b 01                	or     (%ecx),%eax
  40e043:	13 00                	adc    (%eax),%eax
  40e045:	00 05 0d 00 03 08    	add    %al,0x803000d
  40e04b:	3a 0b                	cmp    (%ebx),%cl
  40e04d:	3b 0b                	cmp    (%ebx),%ecx
  40e04f:	39 0b                	cmp    %ecx,(%ebx)
  40e051:	49                   	dec    %ecx
  40e052:	13 38                	adc    (%eax),%edi
  40e054:	0b 00                	or     (%eax),%eax
  40e056:	00 06                	add    %al,(%esi)
  40e058:	0f 00 0b             	str    (%ebx)
  40e05b:	0b 49 13             	or     0x13(%ecx),%ecx
  40e05e:	00 00                	add    %al,(%eax)
  40e060:	07                   	pop    %es
  40e061:	16                   	push   %ss
  40e062:	00 03                	add    %al,(%ebx)
  40e064:	08 3a                	or     %bh,(%edx)
  40e066:	0b 3b                	or     (%ebx),%edi
  40e068:	0b 39                	or     (%ecx),%edi
  40e06a:	0b 49 13             	or     0x13(%ecx),%ecx
  40e06d:	00 00                	add    %al,(%eax)
  40e06f:	08 01                	or     %al,(%ecx)
  40e071:	01 49 13             	add    %ecx,0x13(%ecx)
  40e074:	01 13                	add    %edx,(%ebx)
  40e076:	00 00                	add    %al,(%eax)
  40e078:	09 21                	or     %esp,(%ecx)
  40e07a:	00 00                	add    %al,(%eax)
  40e07c:	00 0a                	add    %cl,(%edx)
  40e07e:	34 00                	xor    $0x0,%al
  40e080:	03 08                	add    (%eax),%ecx
  40e082:	3a 0b                	cmp    (%ebx),%cl
  40e084:	3b 0b                	cmp    (%ebx),%ecx
  40e086:	39 0b                	cmp    %ecx,(%ebx)
  40e088:	49                   	dec    %ecx
  40e089:	13 3f                	adc    (%edi),%edi
  40e08b:	19 3c 19             	sbb    %edi,(%ecx,%ebx,1)
  40e08e:	00 00                	add    %al,(%eax)
  40e090:	0b 34 00             	or     (%eax,%eax,1),%esi
  40e093:	03 08                	add    (%eax),%ecx
  40e095:	3a 0b                	cmp    (%ebx),%cl
  40e097:	3b 05 39 0b 49 13    	cmp    0x13490b39,%eax
  40e09d:	3f                   	aas    
  40e09e:	19 3c 19             	sbb    %edi,(%ecx,%ebx,1)
  40e0a1:	00 00                	add    %al,(%eax)
  40e0a3:	0c 21                	or     $0x21,%al
  40e0a5:	00 49 13             	add    %cl,0x13(%ecx)
  40e0a8:	2f                   	das    
  40e0a9:	0b 00                	or     (%eax),%eax
  40e0ab:	00 0d 15 01 27 19    	add    %cl,0x19270115
  40e0b1:	49                   	dec    %ecx
  40e0b2:	13 01                	adc    (%ecx),%eax
  40e0b4:	13 00                	adc    (%eax),%eax
  40e0b6:	00 0e                	add    %cl,(%esi)
  40e0b8:	05 00 49 13 00       	add    $0x134900,%eax
  40e0bd:	00 0f                	add    %cl,(%edi)
  40e0bf:	26 00 00             	add    %al,%es:(%eax)
  40e0c2:	00 10                	add    %dl,(%eax)
  40e0c4:	04 01                	add    $0x1,%al
  40e0c6:	03 08                	add    (%eax),%ecx
  40e0c8:	3e 0b 0b             	or     %ds:(%ebx),%ecx
  40e0cb:	0b 49 13             	or     0x13(%ecx),%ecx
  40e0ce:	3a 0b                	cmp    (%ebx),%cl
  40e0d0:	3b 0b                	cmp    (%ebx),%ecx
  40e0d2:	39 0b                	cmp    %ecx,(%ebx)
  40e0d4:	01 13                	add    %edx,(%ebx)
  40e0d6:	00 00                	add    %al,(%eax)
  40e0d8:	11 28                	adc    %ebp,(%eax)
  40e0da:	00 03                	add    %al,(%ebx)
  40e0dc:	08 1c 0b             	or     %bl,(%ebx,%ecx,1)
  40e0df:	00 00                	add    %al,(%eax)
  40e0e1:	12 13                	adc    (%ebx),%dl
  40e0e3:	01 03                	add    %eax,(%ebx)
  40e0e5:	08 0b                	or     %cl,(%ebx)
  40e0e7:	05 3a 0b 3b 0b       	add    $0xb3b0b3a,%eax
  40e0ec:	39 0b                	cmp    %ecx,(%ebx)
  40e0ee:	01 13                	add    %edx,(%ebx)
  40e0f0:	00 00                	add    %al,(%eax)
  40e0f2:	13 0d 00 03 08 3a    	adc    0x3a080300,%ecx
  40e0f8:	0b 3b                	or     (%ebx),%edi
  40e0fa:	05 39 0b 49 13       	add    $0x13490b39,%eax
  40e0ff:	38 0b                	cmp    %cl,(%ebx)
  40e101:	00 00                	add    %al,(%eax)
  40e103:	14 0d                	adc    $0xd,%al
  40e105:	00 03                	add    %al,(%ebx)
  40e107:	08 3a                	or     %bh,(%edx)
  40e109:	0b 3b                	or     (%ebx),%edi
  40e10b:	05 39 0b 49 13       	add    $0x13490b39,%eax
  40e110:	38 05 00 00 15 04    	cmp    %al,0x4150000
  40e116:	01 03                	add    %eax,(%ebx)
  40e118:	08 3e                	or     %bh,(%esi)
  40e11a:	0b 0b                	or     (%ebx),%ecx
  40e11c:	0b 49 13             	or     0x13(%ecx),%ecx
  40e11f:	3a 0b                	cmp    (%ebx),%cl
  40e121:	3b 05 39 0b 01 13    	cmp    0x13010b39,%eax
  40e127:	00 00                	add    %al,(%eax)
  40e129:	16                   	push   %ss
  40e12a:	17                   	pop    %ss
  40e12b:	00 03                	add    %al,(%ebx)
  40e12d:	08 3c 19             	or     %bh,(%ecx,%ebx,1)
  40e130:	00 00                	add    %al,(%eax)
  40e132:	17                   	pop    %ss
  40e133:	15 00 27 19 00       	adc    $0x192700,%eax
  40e138:	00 18                	add    %bl,(%eax)
  40e13a:	34 00                	xor    $0x0,%al
  40e13c:	47                   	inc    %edi
  40e13d:	13 3a                	adc    (%edx),%edi
  40e13f:	0b 3b                	or     (%ebx),%edi
  40e141:	05 39 0b 02 18       	add    $0x18020b39,%eax
  40e146:	00 00                	add    %al,(%eax)
	...

Disassembly of section .debug_line:

0040f000 <.debug_line>:
  40f000:	6d                   	insl   (%dx),%es:(%edi)
  40f001:	00 00                	add    %al,(%eax)
  40f003:	00 03                	add    %al,(%ebx)
  40f005:	00 49 00             	add    %cl,0x0(%ecx)
  40f008:	00 00                	add    %al,(%eax)
  40f00a:	01 01                	add    %eax,(%ecx)
  40f00c:	fb                   	sti    
  40f00d:	0e                   	push   %cs
  40f00e:	0d 00 01 01 01       	or     $0x1010100,%eax
  40f013:	01 00                	add    %eax,(%eax)
  40f015:	00 00                	add    %al,(%eax)
  40f017:	01 00                	add    %eax,(%eax)
  40f019:	00 01                	add    %al,(%ecx)
  40f01b:	2e 2e 2f             	cs cs das 
  40f01e:	2e 2e 2f             	cs cs das 
  40f021:	2e 2e 2f             	cs cs das 
  40f024:	73 72                	jae    40f098 <.debug_line+0x27>
  40f026:	63 2f                	arpl   %bp,(%edi)
  40f028:	67 63 63 2d          	arpl   %sp,0x2d(%bp,%di)
  40f02c:	39 2e                	cmp    %ebp,(%esi)
  40f02e:	32 2e                	xor    (%esi),%ch
  40f030:	30 2f                	xor    %ch,(%edi)
  40f032:	6c                   	insb   (%dx),%es:(%edi)
  40f033:	69 62 67 63 63 2f 63 	imul   $0x632f6363,0x67(%edx),%esp
  40f03a:	6f                   	outsl  %ds:(%esi),(%dx)
  40f03b:	6e                   	outsb  %ds:(%esi),(%dx)
  40f03c:	66 69 67 2f 69 33    	imul   $0x3369,0x2f(%edi),%sp
  40f042:	38 36                	cmp    %dh,(%esi)
  40f044:	00 00                	add    %al,(%eax)
  40f046:	63 79 67             	arpl   %di,0x67(%ecx)
  40f049:	77 69                	ja     40f0b4 <.debug_line+0x43>
  40f04b:	6e                   	outsb  %ds:(%esi),(%dx)
  40f04c:	2e 53                	cs push %ebx
  40f04e:	00 01                	add    %al,(%ecx)
  40f050:	00 00                	add    %al,(%eax)
  40f052:	00 00                	add    %al,(%eax)
  40f054:	05 02 30 3e 40       	add    $0x403e3002,%eax
  40f059:	00 03                	add    %al,(%ebx)
  40f05b:	8e 01                	mov    (%ecx),%es
  40f05d:	01 22                	add    %esp,(%edx)
  40f05f:	22 59 4b             	and    0x4b(%ecx),%bl
  40f062:	30 67 3d             	xor    %ah,0x3d(%edi)
  40f065:	59                   	pop    %ecx
  40f066:	59                   	pop    %ecx
  40f067:	30 2f                	xor    %ch,(%edi)
  40f069:	3e 22 22             	and    %ds:(%edx),%ah
  40f06c:	02 01                	add    (%ecx),%al
  40f06e:	00 01                	add    %al,(%ecx)
  40f070:	01               	add    %edx,0x1(%ebx)

0040f071 <.debug_line>:
  40f071:	53                   	push   %ebx
  40f072:	01 00                	add    %eax,(%eax)
  40f074:	00 03                	add    %al,(%ebx)
  40f076:	00 4d 01             	add    %cl,0x1(%ebp)
  40f079:	00 00                	add    %al,(%eax)
  40f07b:	01 01                	add    %eax,(%ecx)
  40f07d:	fb                   	sti    
  40f07e:	0e                   	push   %cs
  40f07f:	0d 00 01 01 01       	or     $0x1010100,%eax
  40f084:	01 00                	add    %eax,(%eax)
  40f086:	00 00                	add    %al,(%eax)
  40f088:	01 00                	add    %eax,(%eax)
  40f08a:	00 01                	add    %al,(%ecx)
  40f08c:	2f                   	das    
  40f08d:	68 6f 6d 65 2f       	push   $0x2f656d6f
  40f092:	6b 65 69 74          	imul   $0x74,0x69(%ebp),%esp
  40f096:	68 2f 6d 69 6e       	push   $0x6e696d2f
  40f09b:	67 77 33             	addr16 ja 40f0d1 <.debug_line+0x60>
  40f09e:	32 2d 67 63 63 2d    	xor    0x2d636367,%ch
  40f0a4:	39 2e                	cmp    %ebp,(%esi)
  40f0a6:	32 2e                	xor    (%esi),%ch
  40f0a8:	30 2f                	xor    %ch,(%edi)
  40f0aa:	69 6e 63 6c 75 64 65 	imul   $0x6564756c,0x63(%esi),%ebp
  40f0b1:	00 2e                	add    %ch,(%esi)
  40f0b3:	2e 2f                	cs das 
  40f0b5:	2e 2e 2f             	cs cs das 
  40f0b8:	2e 2e 2f             	cs cs das 
  40f0bb:	73 72                	jae    40f12f <.debug_line+0xbe>
  40f0bd:	63 2f                	arpl   %bp,(%edi)
  40f0bf:	67 63 63 2d          	arpl   %sp,0x2d(%bp,%di)
  40f0c3:	39 2e                	cmp    %ebp,(%esi)
  40f0c5:	32 2e                	xor    (%esi),%ch
  40f0c7:	30 2f                	xor    %ch,(%edi)
  40f0c9:	6c                   	insb   (%dx),%es:(%edi)
  40f0ca:	69 62 67 63 63 2f 2e 	imul   $0x2e2f6363,0x67(%edx),%esp
  40f0d1:	2e 2f                	cs das 
  40f0d3:	69 6e 63 6c 75 64 65 	imul   $0x6564756c,0x63(%esi),%ebp
  40f0da:	00 2e                	add    %ch,(%esi)
  40f0dc:	2e 2f                	cs das 
  40f0de:	2e 2e 2f             	cs cs das 
  40f0e1:	2e 2f                	cs das 
  40f0e3:	67 63 63 00          	arpl   %sp,0x0(%bp,%di)
  40f0e7:	2e 2e 2f             	cs cs das 
  40f0ea:	2e 2e 2f             	cs cs das 
  40f0ed:	2e 2e 2f             	cs cs das 
  40f0f0:	73 72                	jae    40f164 <.debug_line+0xf3>
  40f0f2:	63 2f                	arpl   %bp,(%edi)
  40f0f4:	67 63 63 2d          	arpl   %sp,0x2d(%bp,%di)
  40f0f8:	39 2e                	cmp    %ebp,(%esi)
  40f0fa:	32 2e                	xor    (%esi),%ch
  40f0fc:	30 2f                	xor    %ch,(%edi)
  40f0fe:	6c                   	insb   (%dx),%es:(%edi)
  40f0ff:	69 62 67 63 63 2f 2e 	imul   $0x2e2f6363,0x67(%edx),%esp
  40f106:	2e 2f                	cs das 
  40f108:	67 63 63 2f          	arpl   %sp,0x2f(%bp,%di)
  40f10c:	63 6f 6e             	arpl   %bp,0x6e(%edi)
  40f10f:	66 69 67 2f 69 33    	imul   $0x3369,0x2f(%edi),%sp
  40f115:	38 36                	cmp    %dh,(%esi)
  40f117:	00 2e                	add    %ch,(%esi)
  40f119:	2e 2f                	cs das 
  40f11b:	2e 2e 2f             	cs cs das 
  40f11e:	2e 2e 2f             	cs cs das 
  40f121:	73 72                	jae    40f195 <.debug_line+0x124>
  40f123:	63 2f                	arpl   %bp,(%edi)
  40f125:	67 63 63 2d          	arpl   %sp,0x2d(%bp,%di)
  40f129:	39 2e                	cmp    %ebp,(%esi)
  40f12b:	32 2e                	xor    (%esi),%ch
  40f12d:	30 2f                	xor    %ch,(%edi)
  40f12f:	6c                   	insb   (%dx),%es:(%edi)
  40f130:	69 62 67 63 63 00 00 	imul   $0x6363,0x67(%edx),%esp
  40f137:	73 74                	jae    40f1ad <.debug_line+0x13c>
  40f139:	64 69 6f 2e 68 00 01 	imul   $0x10068,%fs:0x2e(%edi),%ebp
  40f140:	00 
  40f141:	00 73 74             	add    %dh,0x74(%ebx)
  40f144:	64 6c                	fs insb (%dx),%es:(%edi)
  40f146:	69 62 2e 68 00 01 00 	imul   $0x10068,0x2e(%edx),%esp
  40f14d:	00 67 65             	add    %ah,0x65(%edi)
  40f150:	74 6f                	je     40f1c1 <.debug_line+0x150>
  40f152:	70 74                	jo     40f1c8 <.debug_line+0x157>
  40f154:	2e 68 00 01 00 00    	cs push $0x100
  40f15a:	74 69                	je     40f1c5 <.debug_line+0x154>
  40f15c:	6d                   	insl   (%dx),%es:(%edi)
  40f15d:	65 2e 68 00 01 00 00 	gs cs push $0x100
  40f164:	68 61 73 68 74       	push   $0x74687361
  40f169:	61                   	popa   
  40f16a:	62 2e                	bound  %ebp,(%esi)
  40f16c:	68 00 02 00 00       	push   $0x200
  40f171:	69 6e 73 6e 2d 63 6f 	imul   $0x6f632d6e,0x73(%esi),%ebp
  40f178:	6e                   	outsb  %ds:(%esi),(%dx)
  40f179:	73 74                	jae    40f1ef <.debug_line+0x17e>
  40f17b:	61                   	popa   
  40f17c:	6e                   	outsb  %ds:(%esi),(%dx)
  40f17d:	74 73                	je     40f1f2 <.debug_line+0x181>
  40f17f:	2e 68 00 03 00 00    	cs push $0x300
  40f185:	69 33 38 36 2e 68    	imul   $0x682e3638,(%ebx),%esi
  40f18b:	00 04 00             	add    %al,(%eax,%eax,1)
  40f18e:	00 69 33             	add    %ch,0x33(%ecx)
  40f191:	38 36                	cmp    %dh,(%esi)
  40f193:	2d 6f 70 74 73       	sub    $0x7374706f,%eax
  40f198:	2e 68 00 04 00 00    	cs push $0x400
  40f19e:	6c                   	insb   (%dx),%es:(%edi)
  40f19f:	69 62 67 63 63 32 2e 	imul   $0x2e326363,0x67(%edx),%esp
  40f1a6:	68 00 05 00 00       	push   $0x500
  40f1ab:	67 62 6c 2d          	bound  %ebp,0x2d(%si)
  40f1af:	63 74 6f 72          	arpl   %si,0x72(%edi,%ebp,2)
  40f1b3:	73 2e                	jae    40f1e3 <.debug_line+0x172>
  40f1b5:	68 00 05 00 00       	push   $0x500
  40f1ba:	6c                   	insb   (%dx),%es:(%edi)
  40f1bb:	69 62 67 63 63 32 2e 	imul   $0x2e326363,0x67(%edx),%esp
  40f1c2:	63 00                	arpl   %ax,(%eax)
  40f1c4:	05                   	.byte 0x5
  40f1c5:	00 00                	add    %al,(%eax)
	...

Disassembly of section .debug_frame:

00410000 <.debug_frame>:
  410000:	10 00                	adc    %al,(%eax)
  410002:	00 00                	add    %al,(%eax)
  410004:	ff                   	(bad)  
  410005:	ff                   	(bad)  
  410006:	ff                   	(bad)  
  410007:	ff 01                	incl   (%ecx)
  410009:	00 01                	add    %al,(%ecx)
  41000b:	7c 08                	jl     410015 <.debug_frame+0x15>
  41000d:	0c 04                	or     $0x4,%al
  41000f:	04 88                	add    $0x88,%al
  410011:	01 00                	add    %eax,(%eax)
  410013:	00 20                	add    %ah,(%eax)
  410015:	00 00                	add    %al,(%eax)
  410017:	00 00                	add    %al,(%eax)
  410019:	00 00                	add    %al,(%eax)
  41001b:	00 30                	add    %dh,(%eax)
  41001d:	3e 40                	ds inc %eax
  41001f:	00 2a                	add    %ch,(%edx)
  410021:	00 00                	add    %al,(%eax)
  410023:	00 41 0e             	add    %al,0xe(%ecx)
  410026:	08 81 02 41 0e 0c    	or     %al,0xc0e4102(%ecx)
  41002c:	80 03 66             	addb   $0x66,(%ebx)
  41002f:	0e                   	push   %cs
  410030:	08 c0                	or     %al,%al
  410032:	41                   	inc    %ecx
  410033:	0e                   	push   %cs
  410034:	04 c1                	add    $0xc1,%al
	...

Disassembly of section .debug_str:

00411000 <.debug_str>:
  411000:	2e 2e 2f             	cs cs das 
  411003:	2e 2e 2f             	cs cs das 
  411006:	2e 2e 2f             	cs cs das 
  411009:	73 72                	jae    41107d <.debug_str+0x7d>
  41100b:	63 2f                	arpl   %bp,(%edi)
  41100d:	67 63 63 2d          	arpl   %sp,0x2d(%bp,%di)
  411011:	39 2e                	cmp    %ebp,(%esi)
  411013:	32 2e                	xor    (%esi),%ch
  411015:	30 2f                	xor    %ch,(%edi)
  411017:	6c                   	insb   (%dx),%es:(%edi)
  411018:	69 62 67 63 63 2f 63 	imul   $0x632f6363,0x67(%edx),%esp
  41101f:	6f                   	outsl  %ds:(%esi),(%dx)
  411020:	6e                   	outsb  %ds:(%esi),(%dx)
  411021:	66 69 67 2f 69 33    	imul   $0x3369,0x2f(%edi),%sp
  411027:	38 36                	cmp    %dh,(%esi)
  411029:	2f                   	das    
  41102a:	63 79 67             	arpl   %di,0x67(%ecx)
  41102d:	77 69                	ja     411098 <.debug_str+0x98>
  41102f:	6e                   	outsb  %ds:(%esi),(%dx)
  411030:	2e 53                	cs push %ebx
  411032:	00 2f                	add    %ch,(%edi)
  411034:	68 6f 6d 65 2f       	push   $0x2f656d6f
  411039:	6b 65 69 74          	imul   $0x74,0x69(%ebp),%esp
  41103d:	68 2f 62 75 69       	push   $0x6975622f
  411042:	6c                   	insb   (%dx),%es:(%edi)
  411043:	64 73 2f             	fs jae 411075 <.debug_str+0x75>
  411046:	6d                   	insl   (%dx),%es:(%edi)
  411047:	69 6e 67 77 2f 67 63 	imul   $0x63672f77,0x67(%esi),%ebp
  41104e:	63 2d 39 2e 32 2e    	arpl   %bp,0x2e322e39
  411054:	30 2d 6d 69 6e 67    	xor    %ch,0x676e696d
  41105a:	77 33                	ja     41108f <.debug_str+0x8f>
  41105c:	32 2d 63 72 6f 73    	xor    0x736f7263,%ch
  411062:	73 2d                	jae    411091 <.debug_str+0x91>
  411064:	6e                   	outsb  %ds:(%esi),(%dx)
  411065:	61                   	popa   
  411066:	74 69                	je     4110d1 <.debug_str+0xd1>
  411068:	76 65                	jbe    4110cf <.debug_str+0xcf>
  41106a:	2f                   	das    
  41106b:	6d                   	insl   (%dx),%es:(%edi)
  41106c:	69 6e 67 77 33 32 2f 	imul   $0x2f323377,0x67(%esi),%ebp
  411073:	6c                   	insb   (%dx),%es:(%edi)
  411074:	69 62 67 63 63 00 47 	imul   $0x47006363,0x67(%edx),%esp
  41107b:	4e                   	dec    %esi
  41107c:	55                   	push   %ebp
  41107d:	20 41 53             	and    %al,0x53(%ecx)
  411080:	20 32                	and    %dh,(%edx)
  411082:	2e 33 32             	xor    %cs:(%edx),%esi
	...
