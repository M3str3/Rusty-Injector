
.\example\messagebox\messagebox.exe:     file format pei-i386


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
  40103c:	e8 73 2e 00 00       	call   403eb4 <_signal>
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
  401076:	e8 39 2e 00 00       	call   403eb4 <_signal>
  40107b:	83 f8 01             	cmp    $0x1,%eax
  40107e:	75 ca                	jne    40104a <.text+0x4a>
  401080:	c7 44 24 04 01 00 00 	movl   $0x1,0x4(%esp)
  401087:	00 
  401088:	c7 04 24 08 00 00 00 	movl   $0x8,(%esp)
  40108f:	e8 20 2e 00 00       	call   403eb4 <_signal>
  401094:	ba ff ff ff ff       	mov    $0xffffffff,%edx
  401099:	eb b9                	jmp    401054 <.text+0x54>
  40109b:	8d 74 26 00          	lea    0x0(%esi,%eiz,1),%esi
  40109f:	90                   	nop
  4010a0:	3d 05 00 00 c0       	cmp    $0xc0000005,%eax
  4010a5:	75 ab                	jne    401052 <.text+0x52>
  4010a7:	c7 44 24 04 00 00 00 	movl   $0x0,0x4(%esp)
  4010ae:	00 
  4010af:	c7 04 24 0b 00 00 00 	movl   $0xb,(%esp)
  4010b6:	e8 f9 2d 00 00       	call   403eb4 <_signal>
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
  4010fa:	e8 b5 2d 00 00       	call   403eb4 <_signal>
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
  40112f:	e8 80 2d 00 00       	call   403eb4 <_signal>
  401134:	c7 04 24 00 00 00 00 	movl   $0x0,(%esp)
  40113b:	e8 b0 0f 00 00       	call   4020f0 <_fesetenv>
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
  401172:	e8 3d 2d 00 00       	call   403eb4 <_signal>
  401177:	83 ca ff             	or     $0xffffffff,%edx
  40117a:	e9 d5 fe ff ff       	jmp    401054 <.text+0x54>
  40117f:	c7 44 24 04 01 00 00 	movl   $0x1,0x4(%esp)
  401186:	00 
  401187:	c7 04 24 04 00 00 00 	movl   $0x4,(%esp)
  40118e:	e8 21 2d 00 00       	call   403eb4 <_signal>
  401193:	83 ca ff             	or     $0xffffffff,%edx
  401196:	e9 b9 fe ff ff       	jmp    401054 <.text+0x54>
  40119b:	8d 74 26 00          	lea    0x0(%esi,%eiz,1),%esi
  40119f:	90                   	nop
  4011a0:	53                   	push   %ebx
  4011a1:	83 ec 18             	sub    $0x18,%esp
  4011a4:	a1 a0 61 40 00       	mov    0x4061a0,%eax
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
  4011d0:	e8 97 2d 00 00       	call   403f6c <_SetUnhandledExceptionFilter@4>
  4011d5:	83 ec 04             	sub    $0x4,%esp
  4011d8:	e8 d3 06 00 00       	call   4018b0 <___cpu_features_init>
  4011dd:	a1 08 50 40 00       	mov    0x405008,%eax
  4011e2:	89 04 24             	mov    %eax,(%esp)
  4011e5:	e8 06 0f 00 00       	call   4020f0 <_fesetenv>
  4011ea:	e8 61 02 00 00       	call   401450 <__setargv>
  4011ef:	a1 20 80 40 00       	mov    0x408020,%eax
  4011f4:	85 c0                	test   %eax,%eax
  4011f6:	75 4a                	jne    401242 <.text+0x242>
  4011f8:	e8 37 2d 00 00       	call   403f34 <___p__fmode>
  4011fd:	8b 15 0c 50 40 00    	mov    0x40500c,%edx
  401203:	89 10                	mov    %edx,(%eax)
  401205:	e8 f6 0c 00 00       	call   401f00 <__pei386_runtime_relocator>
  40120a:	83 e4 f0             	and    $0xfffffff0,%esp
  40120d:	e8 4e 08 00 00       	call   401a60 <___main>
  401212:	e8 25 2d 00 00       	call   403f3c <___p__environ>
  401217:	8b 00                	mov    (%eax),%eax
  401219:	89 44 24 08          	mov    %eax,0x8(%esp)
  40121d:	a1 00 80 40 00       	mov    0x408000,%eax
  401222:	89 44 24 04          	mov    %eax,0x4(%esp)
  401226:	a1 04 80 40 00       	mov    0x408004,%eax
  40122b:	89 04 24             	mov    %eax,(%esp)
  40122e:	e8 cd 2d 00 00       	call   404000 <_main>
  401233:	89 c3                	mov    %eax,%ebx
  401235:	e8 ea 2c 00 00       	call   403f24 <__cexit>
  40123a:	89 1c 24             	mov    %ebx,(%esp)
  40123d:	e8 9a 2d 00 00       	call   403fdc <_ExitProcess@4>
  401242:	8b 1d fc 91 40 00    	mov    0x4091fc,%ebx
  401248:	89 44 24 04          	mov    %eax,0x4(%esp)
  40124c:	a3 0c 50 40 00       	mov    %eax,0x40500c
  401251:	8b 43 10             	mov    0x10(%ebx),%eax
  401254:	89 04 24             	mov    %eax,(%esp)
  401257:	e8 a0 2c 00 00       	call   403efc <__setmode>
  40125c:	a1 20 80 40 00       	mov    0x408020,%eax
  401261:	89 44 24 04          	mov    %eax,0x4(%esp)
  401265:	8b 43 30             	mov    0x30(%ebx),%eax
  401268:	89 04 24             	mov    %eax,(%esp)
  40126b:	e8 8c 2c 00 00       	call   403efc <__setmode>
  401270:	a1 20 80 40 00       	mov    0x408020,%eax
  401275:	89 44 24 04          	mov    %eax,0x4(%esp)
  401279:	8b 43 50             	mov    0x50(%ebx),%eax
  40127c:	89 04 24             	mov    %eax,(%esp)
  40127f:	e8 78 2c 00 00       	call   403efc <__setmode>
  401284:	e9 6f ff ff ff       	jmp    4011f8 <.text+0x1f8>
  401289:	8d b4 26 00 00 00 00 	lea    0x0(%esi,%eiz,1),%esi

00401290 <__mingw32_init_mainargs>:
  401290:	83 ec 3c             	sub    $0x3c,%esp
  401293:	8d 44 24 2c          	lea    0x2c(%esp),%eax
  401297:	c7 44 24 04 00 80 40 	movl   $0x408000,0x4(%esp)
  40129e:	00 
  40129f:	89 44 24 10          	mov    %eax,0x10(%esp)
  4012a3:	a1 04 50 40 00       	mov    0x405004,%eax
  4012a8:	c7 04 24 04 80 40 00 	movl   $0x408004,(%esp)
  4012af:	83 e0 01             	and    $0x1,%eax
  4012b2:	c7 44 24 2c 00 00 00 	movl   $0x0,0x2c(%esp)
  4012b9:	00 
  4012ba:	89 44 24 0c          	mov    %eax,0xc(%esp)
  4012be:	8d 44 24 28          	lea    0x28(%esp),%eax
  4012c2:	89 44 24 08          	mov    %eax,0x8(%esp)
  4012c6:	e8 79 2c 00 00       	call   403f44 <___getmainargs>
  4012cb:	83 c4 3c             	add    $0x3c,%esp
  4012ce:	c3                   	ret    
  4012cf:	90                   	nop

004012d0 <_mainCRTStartup>:
  4012d0:	83 ec 1c             	sub    $0x1c,%esp
  4012d3:	c7 04 24 01 00 00 00 	movl   $0x1,(%esp)
  4012da:	ff 15 e8 91 40 00    	call   *0x4091e8
  4012e0:	e8 bb fe ff ff       	call   4011a0 <.text+0x1a0>
  4012e5:	8d b4 26 00 00 00 00 	lea    0x0(%esi,%eiz,1),%esi
  4012ec:	8d 74 26 00          	lea    0x0(%esi,%eiz,1),%esi

004012f0 <_WinMainCRTStartup>:
  4012f0:	83 ec 1c             	sub    $0x1c,%esp
  4012f3:	c7 04 24 02 00 00 00 	movl   $0x2,(%esp)
  4012fa:	ff 15 e8 91 40 00    	call   *0x4091e8
  401300:	e8 9b fe ff ff       	call   4011a0 <.text+0x1a0>
  401305:	8d b4 26 00 00 00 00 	lea    0x0(%esi,%eiz,1),%esi
  40130c:	8d 74 26 00          	lea    0x0(%esi,%eiz,1),%esi

00401310 <_atexit>:
  401310:	ff 25 18 92 40 00    	jmp    *0x409218
  401316:	8d b4 26 00 00 00 00 	lea    0x0(%esi,%eiz,1),%esi
  40131d:	8d 76 00             	lea    0x0(%esi),%esi

00401320 <__onexit>:
  401320:	ff 25 08 92 40 00    	jmp    *0x409208
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
  401338:	c7 04 24 00 60 40 00 	movl   $0x406000,(%esp)
  40133f:	e8 58 2c 00 00       	call   403f9c <_GetModuleHandleA@4>
  401344:	83 ec 04             	sub    $0x4,%esp
  401347:	85 c0                	test   %eax,%eax
  401349:	74 75                	je     4013c0 <___gcc_register_frame+0x90>
  40134b:	c7 04 24 00 60 40 00 	movl   $0x406000,(%esp)
  401352:	89 c3                	mov    %eax,%ebx
  401354:	e8 1b 2c 00 00       	call   403f74 <_LoadLibraryA@4>
  401359:	83 ec 04             	sub    $0x4,%esp
  40135c:	a3 70 80 40 00       	mov    %eax,0x408070
  401361:	c7 44 24 04 13 60 40 	movl   $0x406013,0x4(%esp)
  401368:	00 
  401369:	89 1c 24             	mov    %ebx,(%esp)
  40136c:	e8 23 2c 00 00       	call   403f94 <_GetProcAddress@8>
  401371:	83 ec 08             	sub    $0x8,%esp
  401374:	89 c6                	mov    %eax,%esi
  401376:	c7 44 24 04 29 60 40 	movl   $0x406029,0x4(%esp)
  40137d:	00 
  40137e:	89 1c 24             	mov    %ebx,(%esp)
  401381:	e8 0e 2c 00 00       	call   403f94 <_GetProcAddress@8>
  401386:	a3 00 50 40 00       	mov    %eax,0x405000
  40138b:	83 ec 08             	sub    $0x8,%esp
  40138e:	85 f6                	test   %esi,%esi
  401390:	74 11                	je     4013a3 <___gcc_register_frame+0x73>
  401392:	c7 44 24 04 08 80 40 	movl   $0x408008,0x4(%esp)
  401399:	00 
  40139a:	c7 04 24 c8 70 40 00 	movl   $0x4070c8,(%esp)
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
  4013c0:	c7 05 00 50 40 00 48 	movl   $0x403e48,0x405000
  4013c7:	3e 40 00 
  4013ca:	be 40 3e 40 00       	mov    $0x403e40,%esi
  4013cf:	eb bd                	jmp    40138e <___gcc_register_frame+0x5e>
  4013d1:	8d b4 26 00 00 00 00 	lea    0x0(%esi,%eiz,1),%esi
  4013d8:	8d b4 26 00 00 00 00 	lea    0x0(%esi,%eiz,1),%esi
  4013df:	90                   	nop

004013e0 <___gcc_deregister_frame>:
  4013e0:	55                   	push   %ebp
  4013e1:	89 e5                	mov    %esp,%ebp
  4013e3:	83 ec 18             	sub    $0x18,%esp
  4013e6:	a1 00 50 40 00       	mov    0x405000,%eax
  4013eb:	85 c0                	test   %eax,%eax
  4013ed:	74 09                	je     4013f8 <___gcc_deregister_frame+0x18>
  4013ef:	c7 04 24 c8 70 40 00 	movl   $0x4070c8,(%esp)
  4013f6:	ff d0                	call   *%eax
  4013f8:	a1 70 80 40 00       	mov    0x408070,%eax
  4013fd:	85 c0                	test   %eax,%eax
  4013ff:	74 0b                	je     40140c <___gcc_deregister_frame+0x2c>
  401401:	89 04 24             	mov    %eax,(%esp)
  401404:	e8 b3 2b 00 00       	call   403fbc <_FreeLibrary@4>
  401409:	83 ec 04             	sub    $0x4,%esp
  40140c:	c9                   	leave  
  40140d:	c3                   	ret    
  40140e:	90                   	nop
  40140f:	90                   	nop

00401410 <_WinMain@16>:
  401410:	55                   	push   %ebp
  401411:	89 e5                	mov    %esp,%ebp
  401413:	83 ec 18             	sub    $0x18,%esp
  401416:	c7 44 24 0c 00 00 00 	movl   $0x0,0xc(%esp)
  40141d:	00 
  40141e:	c7 44 24 08 44 60 40 	movl   $0x406044,0x8(%esp)
  401425:	00 
  401426:	c7 44 24 04 6c 60 40 	movl   $0x40606c,0x4(%esp)
  40142d:	00 
  40142e:	c7 04 24 00 00 00 00 	movl   $0x0,(%esp)
  401435:	e8 12 2b 00 00       	call   403f4c <_MessageBoxW@16>
  40143a:	83 ec 10             	sub    $0x10,%esp
  40143d:	b8 00 00 00 00       	mov    $0x0,%eax
  401442:	c9                   	leave  
  401443:	c2 10 00             	ret    $0x10
  401446:	90                   	nop
  401447:	90                   	nop
  401448:	66 90                	xchg   %ax,%ax
  40144a:	66 90                	xchg   %ax,%ax
  40144c:	66 90                	xchg   %ax,%ax
  40144e:	66 90                	xchg   %ax,%ax

00401450 <__setargv>:
  401450:	55                   	push   %ebp
  401451:	89 e5                	mov    %esp,%ebp
  401453:	57                   	push   %edi
  401454:	56                   	push   %esi
  401455:	53                   	push   %ebx
  401456:	81 ec 4c 01 00 00    	sub    $0x14c,%esp
  40145c:	f6 05 04 50 40 00 02 	testb  $0x2,0x405004
  401463:	75 13                	jne    401478 <__setargv+0x28>
  401465:	e8 26 fe ff ff       	call   401290 <__mingw32_init_mainargs>
  40146a:	8d 65 f4             	lea    -0xc(%ebp),%esp
  40146d:	5b                   	pop    %ebx
  40146e:	5e                   	pop    %esi
  40146f:	5f                   	pop    %edi
  401470:	5d                   	pop    %ebp
  401471:	c3                   	ret    
  401472:	8d b6 00 00 00 00    	lea    0x0(%esi),%esi
  401478:	e8 37 2b 00 00       	call   403fb4 <_GetCommandLineA@0>
  40147d:	89 a5 c0 fe ff ff    	mov    %esp,-0x140(%ebp)
  401483:	89 04 24             	mov    %eax,(%esp)
  401486:	89 c3                	mov    %eax,%ebx
  401488:	e8 17 2a 00 00       	call   403ea4 <_strlen>
  40148d:	8d 44 00 11          	lea    0x11(%eax,%eax,1),%eax
  401491:	c1 e8 04             	shr    $0x4,%eax
  401494:	c1 e0 04             	shl    $0x4,%eax
  401497:	e8 b4 29 00 00       	call   403e50 <___chkstk_ms>
  40149c:	c7 85 f0 fe ff ff 00 	movl   $0x0,-0x110(%ebp)
  4014a3:	00 00 00 
  4014a6:	29 c4                	sub    %eax,%esp
  4014a8:	0f be 3b             	movsbl (%ebx),%edi
  4014ab:	a1 04 50 40 00       	mov    0x405004,%eax
  4014b0:	8d 74 24 10          	lea    0x10(%esp),%esi
  4014b4:	89 b5 c8 fe ff ff    	mov    %esi,-0x138(%ebp)
  4014ba:	25 00 44 00 00       	and    $0x4400,%eax
  4014bf:	83 c8 10             	or     $0x10,%eax
  4014c2:	89 85 c4 fe ff ff    	mov    %eax,-0x13c(%ebp)
  4014c8:	8d 43 01             	lea    0x1(%ebx),%eax
  4014cb:	89 fb                	mov    %edi,%ebx
  4014cd:	89 85 d4 fe ff ff    	mov    %eax,-0x12c(%ebp)
  4014d3:	85 ff                	test   %edi,%edi
  4014d5:	0f 84 e4 00 00 00    	je     4015bf <__setargv+0x16f>
  4014db:	c7 85 cc fe ff ff 00 	movl   $0x0,-0x134(%ebp)
  4014e2:	00 00 00 
  4014e5:	89 f0                	mov    %esi,%eax
  4014e7:	31 d2                	xor    %edx,%edx
  4014e9:	c7 85 d0 fe ff ff 00 	movl   $0x0,-0x130(%ebp)
  4014f0:	00 00 00 
  4014f3:	8d 74 26 00          	lea    0x0(%esi,%eiz,1),%esi
  4014f7:	90                   	nop
  4014f8:	80 fb 3f             	cmp    $0x3f,%bl
  4014fb:	0f 8f e7 02 00 00    	jg     4017e8 <__setargv+0x398>
  401501:	80 fb 21             	cmp    $0x21,%bl
  401504:	0f 8f e6 01 00 00    	jg     4016f0 <__setargv+0x2a0>
  40150a:	8d 34 10             	lea    (%eax,%edx,1),%esi
  40150d:	85 d2                	test   %edx,%edx
  40150f:	0f 84 70 03 00 00    	je     401885 <__setargv+0x435>
  401515:	8d 76 00             	lea    0x0(%esi),%esi
  401518:	83 c0 01             	add    $0x1,%eax
  40151b:	c6 40 ff 5c          	movb   $0x5c,-0x1(%eax)
  40151f:	39 f0                	cmp    %esi,%eax
  401521:	75 f5                	jne    401518 <__setargv+0xc8>
  401523:	8b 85 d0 fe ff ff    	mov    -0x130(%ebp),%eax
  401529:	85 c0                	test   %eax,%eax
  40152b:	0f 85 27 01 00 00    	jne    401658 <__setargv+0x208>
  401531:	a1 d8 91 40 00       	mov    0x4091d8,%eax
  401536:	83 38 01             	cmpl   $0x1,(%eax)
  401539:	0f 85 f1 00 00 00    	jne    401630 <__setargv+0x1e0>
  40153f:	a1 0c 92 40 00       	mov    0x40920c,%eax
  401544:	8b 00                	mov    (%eax),%eax
  401546:	f6 04 78 40          	testb  $0x40,(%eax,%edi,2)
  40154a:	0f 84 f8 00 00 00    	je     401648 <__setargv+0x1f8>
  401550:	39 b5 c8 fe ff ff    	cmp    %esi,-0x138(%ebp)
  401556:	0f 82 44 01 00 00    	jb     4016a0 <__setargv+0x250>
  40155c:	8b 9d cc fe ff ff    	mov    -0x134(%ebp),%ebx
  401562:	85 db                	test   %ebx,%ebx
  401564:	0f 85 36 01 00 00    	jne    4016a0 <__setargv+0x250>
  40156a:	c7 85 cc fe ff ff 00 	movl   $0x0,-0x134(%ebp)
  401571:	00 00 00 
  401574:	89 f0                	mov    %esi,%eax
  401576:	31 d2                	xor    %edx,%edx
  401578:	e9 e2 00 00 00       	jmp    40165f <__setargv+0x20f>
  40157d:	89 c2                	mov    %eax,%edx
  40157f:	90                   	nop
  401580:	39 95 c8 fe ff ff    	cmp    %edx,-0x138(%ebp)
  401586:	72 0a                	jb     401592 <__setargv+0x142>
  401588:	8b 8d cc fe ff ff    	mov    -0x134(%ebp),%ecx
  40158e:	85 c9                	test   %ecx,%ecx
  401590:	74 2d                	je     4015bf <__setargv+0x16f>
  401592:	8d 85 e4 fe ff ff    	lea    -0x11c(%ebp),%eax
  401598:	c6 02 00             	movb   $0x0,(%edx)
  40159b:	89 44 24 0c          	mov    %eax,0xc(%esp)
  40159f:	c7 44 24 08 00 00 00 	movl   $0x0,0x8(%esp)
  4015a6:	00 
  4015a7:	8b 85 c4 fe ff ff    	mov    -0x13c(%ebp),%eax
  4015ad:	89 44 24 04          	mov    %eax,0x4(%esp)
  4015b1:	8b 85 c8 fe ff ff    	mov    -0x138(%ebp),%eax
  4015b7:	89 04 24             	mov    %eax,(%esp)
  4015ba:	e8 81 1b 00 00       	call   403140 <___mingw_glob>
  4015bf:	8b 85 e8 fe ff ff    	mov    -0x118(%ebp),%eax
  4015c5:	a3 04 80 40 00       	mov    %eax,0x408004
  4015ca:	8b 85 ec fe ff ff    	mov    -0x114(%ebp),%eax
  4015d0:	a3 00 80 40 00       	mov    %eax,0x408000
  4015d5:	8b a5 c0 fe ff ff    	mov    -0x140(%ebp),%esp
  4015db:	e8 4c 29 00 00       	call   403f2c <___p__pgmptr>
  4015e0:	8b 00                	mov    (%eax),%eax
  4015e2:	85 c0                	test   %eax,%eax
  4015e4:	0f 85 80 fe ff ff    	jne    40146a <__setargv+0x1a>
  4015ea:	8d 9d e4 fe ff ff    	lea    -0x11c(%ebp),%ebx
  4015f0:	c7 44 24 08 04 01 00 	movl   $0x104,0x8(%esp)
  4015f7:	00 
  4015f8:	89 5c 24 04          	mov    %ebx,0x4(%esp)
  4015fc:	c7 04 24 00 00 00 00 	movl   $0x0,(%esp)
  401603:	e8 9c 29 00 00       	call   403fa4 <_GetModuleFileNameA@12>
  401608:	83 e8 01             	sub    $0x1,%eax
  40160b:	83 ec 0c             	sub    $0xc,%esp
  40160e:	3d 02 01 00 00       	cmp    $0x102,%eax
  401613:	0f 87 51 fe ff ff    	ja     40146a <__setargv+0x1a>
  401619:	e8 0e 29 00 00       	call   403f2c <___p__pgmptr>
  40161e:	89 1c 24             	mov    %ebx,(%esp)
  401621:	89 c6                	mov    %eax,%esi
  401623:	e8 5c 28 00 00       	call   403e84 <_strdup>
  401628:	89 06                	mov    %eax,(%esi)
  40162a:	e9 3b fe ff ff       	jmp    40146a <__setargv+0x1a>
  40162f:	90                   	nop
  401630:	c7 44 24 04 40 00 00 	movl   $0x40,0x4(%esp)
  401637:	00 
  401638:	89 3c 24             	mov    %edi,(%esp)
  40163b:	e8 cc 28 00 00       	call   403f0c <__isctype>
  401640:	85 c0                	test   %eax,%eax
  401642:	0f 85 08 ff ff ff    	jne    401550 <__setargv+0x100>
  401648:	83 ff 09             	cmp    $0x9,%edi
  40164b:	0f 84 ff fe ff ff    	je     401550 <__setargv+0x100>
  401651:	8d b4 26 00 00 00 00 	lea    0x0(%esi,%eiz,1),%esi
  401658:	88 1e                	mov    %bl,(%esi)
  40165a:	8d 46 01             	lea    0x1(%esi),%eax
  40165d:	31 d2                	xor    %edx,%edx
  40165f:	83 85 d4 fe ff ff 01 	addl   $0x1,-0x12c(%ebp)
  401666:	8b bd d4 fe ff ff    	mov    -0x12c(%ebp),%edi
  40166c:	0f be 7f ff          	movsbl -0x1(%edi),%edi
  401670:	89 fb                	mov    %edi,%ebx
  401672:	85 ff                	test   %edi,%edi
  401674:	0f 85 7e fe ff ff    	jne    4014f8 <__setargv+0xa8>
  40167a:	85 d2                	test   %edx,%edx
  40167c:	0f 84 fb fe ff ff    	je     40157d <__setargv+0x12d>
  401682:	01 c2                	add    %eax,%edx
  401684:	8d 74 26 00          	lea    0x0(%esi,%eiz,1),%esi
  401688:	83 c0 01             	add    $0x1,%eax
  40168b:	c6 40 ff 5c          	movb   $0x5c,-0x1(%eax)
  40168f:	39 d0                	cmp    %edx,%eax
  401691:	75 f5                	jne    401688 <__setargv+0x238>
  401693:	e9 e8 fe ff ff       	jmp    401580 <__setargv+0x130>
  401698:	8d b4 26 00 00 00 00 	lea    0x0(%esi,%eiz,1),%esi
  40169f:	90                   	nop
  4016a0:	8d 85 e4 fe ff ff    	lea    -0x11c(%ebp),%eax
  4016a6:	c6 06 00             	movb   $0x0,(%esi)
  4016a9:	89 44 24 0c          	mov    %eax,0xc(%esp)
  4016ad:	c7 44 24 08 00 00 00 	movl   $0x0,0x8(%esp)
  4016b4:	00 
  4016b5:	8b b5 c4 fe ff ff    	mov    -0x13c(%ebp),%esi
  4016bb:	89 74 24 04          	mov    %esi,0x4(%esp)
  4016bf:	8b bd c8 fe ff ff    	mov    -0x138(%ebp),%edi
  4016c5:	83 ce 01             	or     $0x1,%esi
  4016c8:	89 3c 24             	mov    %edi,(%esp)
  4016cb:	e8 70 1a 00 00       	call   403140 <___mingw_glob>
  4016d0:	89 b5 c4 fe ff ff    	mov    %esi,-0x13c(%ebp)
  4016d6:	89 f8                	mov    %edi,%eax
  4016d8:	31 d2                	xor    %edx,%edx
  4016da:	c7 85 cc fe ff ff 00 	movl   $0x0,-0x134(%ebp)
  4016e1:	00 00 00 
  4016e4:	e9 76 ff ff ff       	jmp    40165f <__setargv+0x20f>
  4016e9:	8d b4 26 00 00 00 00 	lea    0x0(%esi,%eiz,1),%esi
  4016f0:	8d 4b de             	lea    -0x22(%ebx),%ecx
  4016f3:	80 f9 1d             	cmp    $0x1d,%cl
  4016f6:	0f 87 0e fe ff ff    	ja     40150a <__setargv+0xba>
  4016fc:	0f b6 c9             	movzbl %cl,%ecx
  4016ff:	ff 24 8d 94 60 40 00 	jmp    *0x406094(,%ecx,4)
  401706:	8d 72 ff             	lea    -0x1(%edx),%esi
  401709:	83 ff 7f             	cmp    $0x7f,%edi
  40170c:	0f 94 c1             	sete   %cl
  40170f:	89 cf                	mov    %ecx,%edi
  401711:	8b 8d d0 fe ff ff    	mov    -0x130(%ebp),%ecx
  401717:	85 c9                	test   %ecx,%ecx
  401719:	0f 95 c1             	setne  %cl
  40171c:	09 f9                	or     %edi,%ecx
  40171e:	85 d2                	test   %edx,%edx
  401720:	0f 84 66 01 00 00    	je     40188c <__setargv+0x43c>
  401726:	8d 54 30 01          	lea    0x1(%eax,%esi,1),%edx
  40172a:	8d b6 00 00 00 00    	lea    0x0(%esi),%esi
  401730:	83 c0 01             	add    $0x1,%eax
  401733:	c6 40 ff 5c          	movb   $0x5c,-0x1(%eax)
  401737:	39 d0                	cmp    %edx,%eax
  401739:	75 f5                	jne    401730 <__setargv+0x2e0>
  40173b:	89 d6                	mov    %edx,%esi
  40173d:	84 c9                	test   %cl,%cl
  40173f:	0f 84 13 ff ff ff    	je     401658 <__setargv+0x208>
  401745:	c6 02 7f             	movb   $0x7f,(%edx)
  401748:	8d 72 01             	lea    0x1(%edx),%esi
  40174b:	e9 08 ff ff ff       	jmp    401658 <__setargv+0x208>
  401750:	f6 05 04 50 40 00 10 	testb  $0x10,0x405004
  401757:	0f 84 ad fd ff ff    	je     40150a <__setargv+0xba>
  40175d:	89 d1                	mov    %edx,%ecx
  40175f:	d1 f9                	sar    %ecx
  401761:	0f 84 33 01 00 00    	je     40189a <__setargv+0x44a>
  401767:	01 c1                	add    %eax,%ecx
  401769:	8d b4 26 00 00 00 00 	lea    0x0(%esi,%eiz,1),%esi
  401770:	83 c0 01             	add    $0x1,%eax
  401773:	c6 40 ff 5c          	movb   $0x5c,-0x1(%eax)
  401777:	39 c8                	cmp    %ecx,%eax
  401779:	75 f5                	jne    401770 <__setargv+0x320>
  40177b:	83 bd d0 fe ff ff 22 	cmpl   $0x22,-0x130(%ebp)
  401782:	74 09                	je     40178d <__setargv+0x33d>
  401784:	83 e2 01             	and    $0x1,%edx
  401787:	0f 84 de 00 00 00    	je     40186b <__setargv+0x41b>
  40178d:	c6 01 27             	movb   $0x27,(%ecx)
  401790:	8d 41 01             	lea    0x1(%ecx),%eax
  401793:	31 d2                	xor    %edx,%edx
  401795:	c7 85 cc fe ff ff 01 	movl   $0x1,-0x134(%ebp)
  40179c:	00 00 00 
  40179f:	e9 bb fe ff ff       	jmp    40165f <__setargv+0x20f>
  4017a4:	89 d1                	mov    %edx,%ecx
  4017a6:	d1 f9                	sar    %ecx
  4017a8:	0f 84 e5 00 00 00    	je     401893 <__setargv+0x443>
  4017ae:	01 c1                	add    %eax,%ecx
  4017b0:	83 c0 01             	add    $0x1,%eax
  4017b3:	c6 40 ff 5c          	movb   $0x5c,-0x1(%eax)
  4017b7:	39 c8                	cmp    %ecx,%eax
  4017b9:	75 f5                	jne    4017b0 <__setargv+0x360>
  4017bb:	83 bd d0 fe ff ff 27 	cmpl   $0x27,-0x130(%ebp)
  4017c2:	74 7c                	je     401840 <__setargv+0x3f0>
  4017c4:	83 e2 01             	and    $0x1,%edx
  4017c7:	75 77                	jne    401840 <__setargv+0x3f0>
  4017c9:	83 b5 d0 fe ff ff 22 	xorl   $0x22,-0x130(%ebp)
  4017d0:	89 c8                	mov    %ecx,%eax
  4017d2:	31 d2                	xor    %edx,%edx
  4017d4:	c7 85 cc fe ff ff 01 	movl   $0x1,-0x134(%ebp)
  4017db:	00 00 00 
  4017de:	e9 7c fe ff ff       	jmp    40165f <__setargv+0x20f>
  4017e3:	8d 74 26 00          	lea    0x0(%esi,%eiz,1),%esi
  4017e7:	90                   	nop
  4017e8:	80 fb 5a             	cmp    $0x5a,%bl
  4017eb:	0f 8e 19 fd ff ff    	jle    40150a <__setargv+0xba>
  4017f1:	8d 4b a5             	lea    -0x5b(%ebx),%ecx
  4017f4:	80 f9 24             	cmp    $0x24,%cl
  4017f7:	0f 87 0d fd ff ff    	ja     40150a <__setargv+0xba>
  4017fd:	0f b6 c9             	movzbl %cl,%ecx
  401800:	ff 24 8d 0c 61 40 00 	jmp    *0x40610c(,%ecx,4)
  401807:	83 bd d0 fe ff ff 27 	cmpl   $0x27,-0x130(%ebp)
  40180e:	74 50                	je     401860 <__setargv+0x410>
  401810:	83 c2 01             	add    $0x1,%edx
  401813:	e9 47 fe ff ff       	jmp    40165f <__setargv+0x20f>
  401818:	8d 72 ff             	lea    -0x1(%edx),%esi
  40181b:	f6 05 04 50 40 00 20 	testb  $0x20,0x405004
  401822:	0f 85 e1 fe ff ff    	jne    401709 <__setargv+0x2b9>
  401828:	b9 01 00 00 00       	mov    $0x1,%ecx
  40182d:	85 d2                	test   %edx,%edx
  40182f:	0f 85 f1 fe ff ff    	jne    401726 <__setargv+0x2d6>
  401835:	89 c2                	mov    %eax,%edx
  401837:	e9 09 ff ff ff       	jmp    401745 <__setargv+0x2f5>
  40183c:	8d 74 26 00          	lea    0x0(%esi,%eiz,1),%esi
  401840:	c6 01 22             	movb   $0x22,(%ecx)
  401843:	8d 41 01             	lea    0x1(%ecx),%eax
  401846:	31 d2                	xor    %edx,%edx
  401848:	c7 85 cc fe ff ff 01 	movl   $0x1,-0x134(%ebp)
  40184f:	00 00 00 
  401852:	e9 08 fe ff ff       	jmp    40165f <__setargv+0x20f>
  401857:	8d b4 26 00 00 00 00 	lea    0x0(%esi,%eiz,1),%esi
  40185e:	66 90                	xchg   %ax,%ax
  401860:	c6 00 5c             	movb   $0x5c,(%eax)
  401863:	83 c0 01             	add    $0x1,%eax
  401866:	e9 f4 fd ff ff       	jmp    40165f <__setargv+0x20f>
  40186b:	83 b5 d0 fe ff ff 27 	xorl   $0x27,-0x130(%ebp)
  401872:	89 c8                	mov    %ecx,%eax
  401874:	31 d2                	xor    %edx,%edx
  401876:	c7 85 cc fe ff ff 01 	movl   $0x1,-0x134(%ebp)
  40187d:	00 00 00 
  401880:	e9 da fd ff ff       	jmp    40165f <__setargv+0x20f>
  401885:	89 c6                	mov    %eax,%esi
  401887:	e9 97 fc ff ff       	jmp    401523 <__setargv+0xd3>
  40188c:	89 c2                	mov    %eax,%edx
  40188e:	e9 a8 fe ff ff       	jmp    40173b <__setargv+0x2eb>
  401893:	89 c1                	mov    %eax,%ecx
  401895:	e9 21 ff ff ff       	jmp    4017bb <__setargv+0x36b>
  40189a:	89 c1                	mov    %eax,%ecx
  40189c:	e9 da fe ff ff       	jmp    40177b <__setargv+0x32b>
  4018a1:	90                   	nop
  4018a2:	90                   	nop
  4018a3:	90                   	nop
  4018a4:	90                   	nop
  4018a5:	90                   	nop
  4018a6:	90                   	nop
  4018a7:	90                   	nop
  4018a8:	90                   	nop
  4018a9:	90                   	nop
  4018aa:	90                   	nop
  4018ab:	90                   	nop
  4018ac:	90                   	nop
  4018ad:	90                   	nop
  4018ae:	90                   	nop
  4018af:	90                   	nop

004018b0 <___cpu_features_init>:
  4018b0:	9c                   	pushf  
  4018b1:	9c                   	pushf  
  4018b2:	58                   	pop    %eax
  4018b3:	89 c2                	mov    %eax,%edx
  4018b5:	35 00 00 20 00       	xor    $0x200000,%eax
  4018ba:	50                   	push   %eax
  4018bb:	9d                   	popf   
  4018bc:	9c                   	pushf  
  4018bd:	58                   	pop    %eax
  4018be:	9d                   	popf   
  4018bf:	31 d0                	xor    %edx,%eax
  4018c1:	a9 00 00 20 00       	test   $0x200000,%eax
  4018c6:	0f 84 e9 00 00 00    	je     4019b5 <___cpu_features_init+0x105>
  4018cc:	53                   	push   %ebx
  4018cd:	31 c0                	xor    %eax,%eax
  4018cf:	0f a2                	cpuid  
  4018d1:	85 c0                	test   %eax,%eax
  4018d3:	0f 84 db 00 00 00    	je     4019b4 <___cpu_features_init+0x104>
  4018d9:	b8 01 00 00 00       	mov    $0x1,%eax
  4018de:	0f a2                	cpuid  
  4018e0:	31 c0                	xor    %eax,%eax
  4018e2:	f6 c6 01             	test   $0x1,%dh
  4018e5:	74 03                	je     4018ea <___cpu_features_init+0x3a>
  4018e7:	83 c8 01             	or     $0x1,%eax
  4018ea:	f6 c5 20             	test   $0x20,%ch
  4018ed:	74 05                	je     4018f4 <___cpu_features_init+0x44>
  4018ef:	0d 80 00 00 00       	or     $0x80,%eax
  4018f4:	f6 c6 80             	test   $0x80,%dh
  4018f7:	74 03                	je     4018fc <___cpu_features_init+0x4c>
  4018f9:	83 c8 02             	or     $0x2,%eax
  4018fc:	f7 c2 00 00 80 00    	test   $0x800000,%edx
  401902:	74 03                	je     401907 <___cpu_features_init+0x57>
  401904:	83 c8 04             	or     $0x4,%eax
  401907:	f7 c2 00 00 00 01    	test   $0x1000000,%edx
  40190d:	74 6d                	je     40197c <___cpu_features_init+0xcc>
  40190f:	83 c8 08             	or     $0x8,%eax
  401912:	55                   	push   %ebp
  401913:	89 e5                	mov    %esp,%ebp
  401915:	81 ec 00 02 00 00    	sub    $0x200,%esp
  40191b:	83 e4 f0             	and    $0xfffffff0,%esp
  40191e:	0f ae 04 24          	fxsave (%esp)
  401922:	8b 9c 24 c8 00 00 00 	mov    0xc8(%esp),%ebx
  401929:	81 b4 24 c8 00 00 00 	xorl   $0x13c0de,0xc8(%esp)
  401930:	de c0 13 00 
  401934:	0f ae 0c 24          	fxrstor (%esp)
  401938:	89 9c 24 c8 00 00 00 	mov    %ebx,0xc8(%esp)
  40193f:	0f ae 04 24          	fxsave (%esp)
  401943:	87 9c 24 c8 00 00 00 	xchg   %ebx,0xc8(%esp)
  40194a:	0f ae 0c 24          	fxrstor (%esp)
  40194e:	33 9c 24 c8 00 00 00 	xor    0xc8(%esp),%ebx
  401955:	c9                   	leave  
  401956:	81 fb de c0 13 00    	cmp    $0x13c0de,%ebx
  40195c:	75 1e                	jne    40197c <___cpu_features_init+0xcc>
  40195e:	f7 c2 00 00 00 02    	test   $0x2000000,%edx
  401964:	74 03                	je     401969 <___cpu_features_init+0xb9>
  401966:	83 c8 10             	or     $0x10,%eax
  401969:	f7 c2 00 00 00 04    	test   $0x4000000,%edx
  40196f:	74 03                	je     401974 <___cpu_features_init+0xc4>
  401971:	83 c8 20             	or     $0x20,%eax
  401974:	f6 c1 01             	test   $0x1,%cl
  401977:	74 03                	je     40197c <___cpu_features_init+0xcc>
  401979:	83 c8 40             	or     $0x40,%eax
  40197c:	a3 24 80 40 00       	mov    %eax,0x408024
  401981:	b8 00 00 00 80       	mov    $0x80000000,%eax
  401986:	0f a2                	cpuid  
  401988:	3d 00 00 00 80       	cmp    $0x80000000,%eax
  40198d:	76 25                	jbe    4019b4 <___cpu_features_init+0x104>
  40198f:	b8 01 00 00 80       	mov    $0x80000001,%eax
  401994:	0f a2                	cpuid  
  401996:	31 c0                	xor    %eax,%eax
  401998:	85 d2                	test   %edx,%edx
  40199a:	79 05                	jns    4019a1 <___cpu_features_init+0xf1>
  40199c:	b8 00 01 00 00       	mov    $0x100,%eax
  4019a1:	f7 c2 00 00 00 40    	test   $0x40000000,%edx
  4019a7:	74 05                	je     4019ae <___cpu_features_init+0xfe>
  4019a9:	0d 00 02 00 00       	or     $0x200,%eax
  4019ae:	09 05 24 80 40 00    	or     %eax,0x408024
  4019b4:	5b                   	pop    %ebx
  4019b5:	f3 c3                	repz ret 
  4019b7:	90                   	nop
  4019b8:	90                   	nop
  4019b9:	90                   	nop
  4019ba:	90                   	nop
  4019bb:	90                   	nop
  4019bc:	90                   	nop
  4019bd:	90                   	nop
  4019be:	90                   	nop
  4019bf:	90                   	nop

004019c0 <___do_global_dtors>:
  4019c0:	a1 10 50 40 00       	mov    0x405010,%eax
  4019c5:	8b 00                	mov    (%eax),%eax
  4019c7:	85 c0                	test   %eax,%eax
  4019c9:	74 25                	je     4019f0 <___do_global_dtors+0x30>
  4019cb:	83 ec 0c             	sub    $0xc,%esp
  4019ce:	66 90                	xchg   %ax,%ax
  4019d0:	ff d0                	call   *%eax
  4019d2:	a1 10 50 40 00       	mov    0x405010,%eax
  4019d7:	8d 50 04             	lea    0x4(%eax),%edx
  4019da:	8b 40 04             	mov    0x4(%eax),%eax
  4019dd:	89 15 10 50 40 00    	mov    %edx,0x405010
  4019e3:	85 c0                	test   %eax,%eax
  4019e5:	75 e9                	jne    4019d0 <___do_global_dtors+0x10>
  4019e7:	83 c4 0c             	add    $0xc,%esp
  4019ea:	c3                   	ret    
  4019eb:	8d 74 26 00          	lea    0x0(%esi,%eiz,1),%esi
  4019ef:	90                   	nop
  4019f0:	c3                   	ret    
  4019f1:	8d b4 26 00 00 00 00 	lea    0x0(%esi,%eiz,1),%esi
  4019f8:	8d b4 26 00 00 00 00 	lea    0x0(%esi,%eiz,1),%esi
  4019ff:	90                   	nop

00401a00 <___do_global_ctors>:
  401a00:	53                   	push   %ebx
  401a01:	83 ec 18             	sub    $0x18,%esp
  401a04:	8b 1d f0 40 40 00    	mov    0x4040f0,%ebx
  401a0a:	83 fb ff             	cmp    $0xffffffff,%ebx
  401a0d:	74 29                	je     401a38 <___do_global_ctors+0x38>
  401a0f:	85 db                	test   %ebx,%ebx
  401a11:	74 11                	je     401a24 <___do_global_ctors+0x24>
  401a13:	8d 74 26 00          	lea    0x0(%esi,%eiz,1),%esi
  401a17:	90                   	nop
  401a18:	ff 14 9d f0 40 40 00 	call   *0x4040f0(,%ebx,4)
  401a1f:	83 eb 01             	sub    $0x1,%ebx
  401a22:	75 f4                	jne    401a18 <___do_global_ctors+0x18>
  401a24:	c7 04 24 c0 19 40 00 	movl   $0x4019c0,(%esp)
  401a2b:	e8 e0 f8 ff ff       	call   401310 <_atexit>
  401a30:	83 c4 18             	add    $0x18,%esp
  401a33:	5b                   	pop    %ebx
  401a34:	c3                   	ret    
  401a35:	8d 76 00             	lea    0x0(%esi),%esi
  401a38:	31 c0                	xor    %eax,%eax
  401a3a:	8d b6 00 00 00 00    	lea    0x0(%esi),%esi
  401a40:	89 c3                	mov    %eax,%ebx
  401a42:	83 c0 01             	add    $0x1,%eax
  401a45:	8b 14 85 f0 40 40 00 	mov    0x4040f0(,%eax,4),%edx
  401a4c:	85 d2                	test   %edx,%edx
  401a4e:	75 f0                	jne    401a40 <___do_global_ctors+0x40>
  401a50:	eb bd                	jmp    401a0f <___do_global_ctors+0xf>
  401a52:	8d b4 26 00 00 00 00 	lea    0x0(%esi,%eiz,1),%esi
  401a59:	8d b4 26 00 00 00 00 	lea    0x0(%esi,%eiz,1),%esi

00401a60 <___main>:
  401a60:	a1 28 80 40 00       	mov    0x408028,%eax
  401a65:	85 c0                	test   %eax,%eax
  401a67:	74 07                	je     401a70 <___main+0x10>
  401a69:	c3                   	ret    
  401a6a:	8d b6 00 00 00 00    	lea    0x0(%esi),%esi
  401a70:	c7 05 28 80 40 00 01 	movl   $0x1,0x408028
  401a77:	00 00 00 
  401a7a:	eb 84                	jmp    401a00 <___do_global_ctors>
  401a7c:	90                   	nop
  401a7d:	90                   	nop
  401a7e:	90                   	nop
  401a7f:	90                   	nop

00401a80 <.text>:
  401a80:	83 ec 1c             	sub    $0x1c,%esp
  401a83:	8b 44 24 24          	mov    0x24(%esp),%eax
  401a87:	83 f8 03             	cmp    $0x3,%eax
  401a8a:	74 14                	je     401aa0 <.text+0x20>
  401a8c:	85 c0                	test   %eax,%eax
  401a8e:	74 10                	je     401aa0 <.text+0x20>
  401a90:	b8 01 00 00 00       	mov    $0x1,%eax
  401a95:	83 c4 1c             	add    $0x1c,%esp
  401a98:	c2 0c 00             	ret    $0xc
  401a9b:	8d 74 26 00          	lea    0x0(%esi,%eiz,1),%esi
  401a9f:	90                   	nop
  401aa0:	89 44 24 04          	mov    %eax,0x4(%esp)
  401aa4:	8b 54 24 28          	mov    0x28(%esp),%edx
  401aa8:	8b 44 24 20          	mov    0x20(%esp),%eax
  401aac:	89 54 24 08          	mov    %edx,0x8(%esp)
  401ab0:	89 04 24             	mov    %eax,(%esp)
  401ab3:	e8 48 02 00 00       	call   401d00 <___mingw_TLScallback>
  401ab8:	b8 01 00 00 00       	mov    $0x1,%eax
  401abd:	83 c4 1c             	add    $0x1c,%esp
  401ac0:	c2 0c 00             	ret    $0xc
  401ac3:	8d b4 26 00 00 00 00 	lea    0x0(%esi,%eiz,1),%esi
  401aca:	8d b6 00 00 00 00    	lea    0x0(%esi),%esi

00401ad0 <___dyn_tls_init@12>:
  401ad0:	56                   	push   %esi
  401ad1:	53                   	push   %ebx
  401ad2:	83 ec 14             	sub    $0x14,%esp
  401ad5:	83 3d 64 80 40 00 02 	cmpl   $0x2,0x408064
  401adc:	8b 44 24 24          	mov    0x24(%esp),%eax
  401ae0:	74 0a                	je     401aec <___dyn_tls_init@12+0x1c>
  401ae2:	c7 05 64 80 40 00 02 	movl   $0x2,0x408064
  401ae9:	00 00 00 
  401aec:	83 f8 02             	cmp    $0x2,%eax
  401aef:	74 17                	je     401b08 <___dyn_tls_init@12+0x38>
  401af1:	83 f8 01             	cmp    $0x1,%eax
  401af4:	74 52                	je     401b48 <___dyn_tls_init@12+0x78>
  401af6:	83 c4 14             	add    $0x14,%esp
  401af9:	b8 01 00 00 00       	mov    $0x1,%eax
  401afe:	5b                   	pop    %ebx
  401aff:	5e                   	pop    %esi
  401b00:	c2 0c 00             	ret    $0xc
  401b03:	8d 74 26 00          	lea    0x0(%esi,%eiz,1),%esi
  401b07:	90                   	nop
  401b08:	b8 14 a0 40 00       	mov    $0x40a014,%eax
  401b0d:	2d 14 a0 40 00       	sub    $0x40a014,%eax
  401b12:	89 c6                	mov    %eax,%esi
  401b14:	c1 fe 02             	sar    $0x2,%esi
  401b17:	85 c0                	test   %eax,%eax
  401b19:	7e db                	jle    401af6 <___dyn_tls_init@12+0x26>
  401b1b:	31 db                	xor    %ebx,%ebx
  401b1d:	8d 76 00             	lea    0x0(%esi),%esi
  401b20:	8b 04 9d 14 a0 40 00 	mov    0x40a014(,%ebx,4),%eax
  401b27:	85 c0                	test   %eax,%eax
  401b29:	74 02                	je     401b2d <___dyn_tls_init@12+0x5d>
  401b2b:	ff d0                	call   *%eax
  401b2d:	83 c3 01             	add    $0x1,%ebx
  401b30:	39 de                	cmp    %ebx,%esi
  401b32:	7f ec                	jg     401b20 <___dyn_tls_init@12+0x50>
  401b34:	83 c4 14             	add    $0x14,%esp
  401b37:	b8 01 00 00 00       	mov    $0x1,%eax
  401b3c:	5b                   	pop    %ebx
  401b3d:	5e                   	pop    %esi
  401b3e:	c2 0c 00             	ret    $0xc
  401b41:	8d b4 26 00 00 00 00 	lea    0x0(%esi,%eiz,1),%esi
  401b48:	8b 44 24 28          	mov    0x28(%esp),%eax
  401b4c:	c7 44 24 04 01 00 00 	movl   $0x1,0x4(%esp)
  401b53:	00 
  401b54:	89 44 24 08          	mov    %eax,0x8(%esp)
  401b58:	8b 44 24 20          	mov    0x20(%esp),%eax
  401b5c:	89 04 24             	mov    %eax,(%esp)
  401b5f:	e8 9c 01 00 00       	call   401d00 <___mingw_TLScallback>
  401b64:	83 c4 14             	add    $0x14,%esp
  401b67:	b8 01 00 00 00       	mov    $0x1,%eax
  401b6c:	5b                   	pop    %ebx
  401b6d:	5e                   	pop    %esi
  401b6e:	c2 0c 00             	ret    $0xc
  401b71:	8d b4 26 00 00 00 00 	lea    0x0(%esi,%eiz,1),%esi
  401b78:	8d b4 26 00 00 00 00 	lea    0x0(%esi,%eiz,1),%esi
  401b7f:	90                   	nop

00401b80 <___tlregdtor>:
  401b80:	31 c0                	xor    %eax,%eax
  401b82:	c3                   	ret    
  401b83:	90                   	nop
  401b84:	90                   	nop
  401b85:	90                   	nop
  401b86:	90                   	nop
  401b87:	90                   	nop
  401b88:	90                   	nop
  401b89:	90                   	nop
  401b8a:	90                   	nop
  401b8b:	90                   	nop
  401b8c:	90                   	nop
  401b8d:	90                   	nop
  401b8e:	90                   	nop
  401b8f:	90                   	nop

00401b90 <.text>:
  401b90:	56                   	push   %esi
  401b91:	53                   	push   %ebx
  401b92:	83 ec 14             	sub    $0x14,%esp
  401b95:	c7 04 24 44 80 40 00 	movl   $0x408044,(%esp)
  401b9c:	e8 43 24 00 00       	call   403fe4 <_EnterCriticalSection@4>
  401ba1:	8b 1d 3c 80 40 00    	mov    0x40803c,%ebx
  401ba7:	83 ec 04             	sub    $0x4,%esp
  401baa:	85 db                	test   %ebx,%ebx
  401bac:	74 2d                	je     401bdb <.text+0x4b>
  401bae:	66 90                	xchg   %ax,%ax
  401bb0:	8b 03                	mov    (%ebx),%eax
  401bb2:	89 04 24             	mov    %eax,(%esp)
  401bb5:	e8 aa 23 00 00       	call   403f64 <_TlsGetValue@4>
  401bba:	83 ec 04             	sub    $0x4,%esp
  401bbd:	89 c6                	mov    %eax,%esi
  401bbf:	e8 e8 23 00 00       	call   403fac <_GetLastError@0>
  401bc4:	85 c0                	test   %eax,%eax
  401bc6:	75 0c                	jne    401bd4 <.text+0x44>
  401bc8:	85 f6                	test   %esi,%esi
  401bca:	74 08                	je     401bd4 <.text+0x44>
  401bcc:	8b 43 04             	mov    0x4(%ebx),%eax
  401bcf:	89 34 24             	mov    %esi,(%esp)
  401bd2:	ff d0                	call   *%eax
  401bd4:	8b 5b 08             	mov    0x8(%ebx),%ebx
  401bd7:	85 db                	test   %ebx,%ebx
  401bd9:	75 d5                	jne    401bb0 <.text+0x20>
  401bdb:	c7 04 24 44 80 40 00 	movl   $0x408044,(%esp)
  401be2:	e8 95 23 00 00       	call   403f7c <_LeaveCriticalSection@4>
  401be7:	83 ec 04             	sub    $0x4,%esp
  401bea:	83 c4 14             	add    $0x14,%esp
  401bed:	5b                   	pop    %ebx
  401bee:	5e                   	pop    %esi
  401bef:	c3                   	ret    

00401bf0 <____w64_mingwthr_add_key_dtor>:
  401bf0:	a1 40 80 40 00       	mov    0x408040,%eax
  401bf5:	85 c0                	test   %eax,%eax
  401bf7:	75 07                	jne    401c00 <____w64_mingwthr_add_key_dtor+0x10>
  401bf9:	c3                   	ret    
  401bfa:	8d b6 00 00 00 00    	lea    0x0(%esi),%esi
  401c00:	53                   	push   %ebx
  401c01:	83 ec 18             	sub    $0x18,%esp
  401c04:	c7 44 24 04 0c 00 00 	movl   $0xc,0x4(%esp)
  401c0b:	00 
  401c0c:	c7 04 24 01 00 00 00 	movl   $0x1,(%esp)
  401c13:	e8 d4 22 00 00       	call   403eec <_calloc>
  401c18:	89 c3                	mov    %eax,%ebx
  401c1a:	85 c0                	test   %eax,%eax
  401c1c:	74 40                	je     401c5e <____w64_mingwthr_add_key_dtor+0x6e>
  401c1e:	8b 44 24 20          	mov    0x20(%esp),%eax
  401c22:	c7 04 24 44 80 40 00 	movl   $0x408044,(%esp)
  401c29:	89 03                	mov    %eax,(%ebx)
  401c2b:	8b 44 24 24          	mov    0x24(%esp),%eax
  401c2f:	89 43 04             	mov    %eax,0x4(%ebx)
  401c32:	e8 ad 23 00 00       	call   403fe4 <_EnterCriticalSection@4>
  401c37:	a1 3c 80 40 00       	mov    0x40803c,%eax
  401c3c:	89 1d 3c 80 40 00    	mov    %ebx,0x40803c
  401c42:	83 ec 04             	sub    $0x4,%esp
  401c45:	c7 04 24 44 80 40 00 	movl   $0x408044,(%esp)
  401c4c:	89 43 08             	mov    %eax,0x8(%ebx)
  401c4f:	e8 28 23 00 00       	call   403f7c <_LeaveCriticalSection@4>
  401c54:	31 c0                	xor    %eax,%eax
  401c56:	83 ec 04             	sub    $0x4,%esp
  401c59:	83 c4 18             	add    $0x18,%esp
  401c5c:	5b                   	pop    %ebx
  401c5d:	c3                   	ret    
  401c5e:	83 c8 ff             	or     $0xffffffff,%eax
  401c61:	eb f6                	jmp    401c59 <____w64_mingwthr_add_key_dtor+0x69>
  401c63:	8d b4 26 00 00 00 00 	lea    0x0(%esi,%eiz,1),%esi
  401c6a:	8d b6 00 00 00 00    	lea    0x0(%esi),%esi

00401c70 <____w64_mingwthr_remove_key_dtor>:
  401c70:	53                   	push   %ebx
  401c71:	83 ec 18             	sub    $0x18,%esp
  401c74:	a1 40 80 40 00       	mov    0x408040,%eax
  401c79:	8b 5c 24 20          	mov    0x20(%esp),%ebx
  401c7d:	85 c0                	test   %eax,%eax
  401c7f:	75 0f                	jne    401c90 <____w64_mingwthr_remove_key_dtor+0x20>
  401c81:	83 c4 18             	add    $0x18,%esp
  401c84:	31 c0                	xor    %eax,%eax
  401c86:	5b                   	pop    %ebx
  401c87:	c3                   	ret    
  401c88:	8d b4 26 00 00 00 00 	lea    0x0(%esi,%eiz,1),%esi
  401c8f:	90                   	nop
  401c90:	c7 04 24 44 80 40 00 	movl   $0x408044,(%esp)
  401c97:	e8 48 23 00 00       	call   403fe4 <_EnterCriticalSection@4>
  401c9c:	a1 3c 80 40 00       	mov    0x40803c,%eax
  401ca1:	83 ec 04             	sub    $0x4,%esp
  401ca4:	85 c0                	test   %eax,%eax
  401ca6:	74 28                	je     401cd0 <____w64_mingwthr_remove_key_dtor+0x60>
  401ca8:	31 c9                	xor    %ecx,%ecx
  401caa:	eb 0c                	jmp    401cb8 <____w64_mingwthr_remove_key_dtor+0x48>
  401cac:	8d 74 26 00          	lea    0x0(%esi,%eiz,1),%esi
  401cb0:	89 c1                	mov    %eax,%ecx
  401cb2:	85 d2                	test   %edx,%edx
  401cb4:	74 1a                	je     401cd0 <____w64_mingwthr_remove_key_dtor+0x60>
  401cb6:	89 d0                	mov    %edx,%eax
  401cb8:	8b 10                	mov    (%eax),%edx
  401cba:	39 da                	cmp    %ebx,%edx
  401cbc:	8b 50 08             	mov    0x8(%eax),%edx
  401cbf:	75 ef                	jne    401cb0 <____w64_mingwthr_remove_key_dtor+0x40>
  401cc1:	85 c9                	test   %ecx,%ecx
  401cc3:	74 2b                	je     401cf0 <____w64_mingwthr_remove_key_dtor+0x80>
  401cc5:	89 51 08             	mov    %edx,0x8(%ecx)
  401cc8:	89 04 24             	mov    %eax,(%esp)
  401ccb:	e8 a0 04 00 00       	call   402170 <___mingw_aligned_free>
  401cd0:	c7 04 24 44 80 40 00 	movl   $0x408044,(%esp)
  401cd7:	e8 a0 22 00 00       	call   403f7c <_LeaveCriticalSection@4>
  401cdc:	31 c0                	xor    %eax,%eax
  401cde:	83 ec 04             	sub    $0x4,%esp
  401ce1:	83 c4 18             	add    $0x18,%esp
  401ce4:	5b                   	pop    %ebx
  401ce5:	c3                   	ret    
  401ce6:	8d b4 26 00 00 00 00 	lea    0x0(%esi,%eiz,1),%esi
  401ced:	8d 76 00             	lea    0x0(%esi),%esi
  401cf0:	89 15 3c 80 40 00    	mov    %edx,0x40803c
  401cf6:	eb d0                	jmp    401cc8 <____w64_mingwthr_remove_key_dtor+0x58>
  401cf8:	8d b4 26 00 00 00 00 	lea    0x0(%esi,%eiz,1),%esi
  401cff:	90                   	nop

00401d00 <___mingw_TLScallback>:
  401d00:	83 ec 1c             	sub    $0x1c,%esp
  401d03:	8b 44 24 24          	mov    0x24(%esp),%eax
  401d07:	83 f8 01             	cmp    $0x1,%eax
  401d0a:	74 14                	je     401d20 <___mingw_TLScallback+0x20>
  401d0c:	83 f8 03             	cmp    $0x3,%eax
  401d0f:	74 5f                	je     401d70 <___mingw_TLScallback+0x70>
  401d11:	85 c0                	test   %eax,%eax
  401d13:	74 2b                	je     401d40 <___mingw_TLScallback+0x40>
  401d15:	b8 01 00 00 00       	mov    $0x1,%eax
  401d1a:	83 c4 1c             	add    $0x1c,%esp
  401d1d:	c3                   	ret    
  401d1e:	66 90                	xchg   %ax,%ax
  401d20:	a1 40 80 40 00       	mov    0x408040,%eax
  401d25:	85 c0                	test   %eax,%eax
  401d27:	74 7f                	je     401da8 <___mingw_TLScallback+0xa8>
  401d29:	c7 05 40 80 40 00 01 	movl   $0x1,0x408040
  401d30:	00 00 00 
  401d33:	b8 01 00 00 00       	mov    $0x1,%eax
  401d38:	83 c4 1c             	add    $0x1c,%esp
  401d3b:	c3                   	ret    
  401d3c:	8d 74 26 00          	lea    0x0(%esi,%eiz,1),%esi
  401d40:	a1 40 80 40 00       	mov    0x408040,%eax
  401d45:	85 c0                	test   %eax,%eax
  401d47:	75 47                	jne    401d90 <___mingw_TLScallback+0x90>
  401d49:	a1 40 80 40 00       	mov    0x408040,%eax
  401d4e:	83 f8 01             	cmp    $0x1,%eax
  401d51:	75 c2                	jne    401d15 <___mingw_TLScallback+0x15>
  401d53:	c7 04 24 44 80 40 00 	movl   $0x408044,(%esp)
  401d5a:	c7 05 40 80 40 00 00 	movl   $0x0,0x408040
  401d61:	00 00 00 
  401d64:	e8 83 22 00 00       	call   403fec <_DeleteCriticalSection@4>
  401d69:	83 ec 04             	sub    $0x4,%esp
  401d6c:	eb a7                	jmp    401d15 <___mingw_TLScallback+0x15>
  401d6e:	66 90                	xchg   %ax,%ax
  401d70:	a1 40 80 40 00       	mov    0x408040,%eax
  401d75:	85 c0                	test   %eax,%eax
  401d77:	74 9c                	je     401d15 <___mingw_TLScallback+0x15>
  401d79:	e8 12 fe ff ff       	call   401b90 <.text>
  401d7e:	b8 01 00 00 00       	mov    $0x1,%eax
  401d83:	83 c4 1c             	add    $0x1c,%esp
  401d86:	c3                   	ret    
  401d87:	8d b4 26 00 00 00 00 	lea    0x0(%esi,%eiz,1),%esi
  401d8e:	66 90                	xchg   %ax,%ax
  401d90:	e8 fb fd ff ff       	call   401b90 <.text>
  401d95:	a1 40 80 40 00       	mov    0x408040,%eax
  401d9a:	83 f8 01             	cmp    $0x1,%eax
  401d9d:	0f 85 72 ff ff ff    	jne    401d15 <___mingw_TLScallback+0x15>
  401da3:	eb ae                	jmp    401d53 <___mingw_TLScallback+0x53>
  401da5:	8d 76 00             	lea    0x0(%esi),%esi
  401da8:	c7 04 24 44 80 40 00 	movl   $0x408044,(%esp)
  401daf:	e8 d0 21 00 00       	call   403f84 <_InitializeCriticalSection@4>
  401db4:	83 ec 04             	sub    $0x4,%esp
  401db7:	e9 6d ff ff ff       	jmp    401d29 <___mingw_TLScallback+0x29>
  401dbc:	90                   	nop
  401dbd:	90                   	nop
  401dbe:	90                   	nop
  401dbf:	90                   	nop

00401dc0 <.text>:
  401dc0:	56                   	push   %esi
  401dc1:	53                   	push   %ebx
  401dc2:	83 ec 14             	sub    $0x14,%esp
  401dc5:	a1 fc 91 40 00       	mov    0x4091fc,%eax
  401dca:	c7 44 24 08 17 00 00 	movl   $0x17,0x8(%esp)
  401dd1:	00 
  401dd2:	8d 74 24 24          	lea    0x24(%esp),%esi
  401dd6:	8d 58 40             	lea    0x40(%eax),%ebx
  401dd9:	c7 44 24 04 01 00 00 	movl   $0x1,0x4(%esp)
  401de0:	00 
  401de1:	89 5c 24 0c          	mov    %ebx,0xc(%esp)
  401de5:	c7 04 24 a4 61 40 00 	movl   $0x4061a4,(%esp)
  401dec:	e8 f3 20 00 00       	call   403ee4 <_fwrite>
  401df1:	8b 44 24 20          	mov    0x20(%esp),%eax
  401df5:	89 74 24 08          	mov    %esi,0x8(%esp)
  401df9:	89 1c 24             	mov    %ebx,(%esp)
  401dfc:	89 44 24 04          	mov    %eax,0x4(%esp)
  401e00:	e8 8f 20 00 00       	call   403e94 <_vfprintf>
  401e05:	e8 ea 20 00 00       	call   403ef4 <_abort>
  401e0a:	8d b6 00 00 00 00    	lea    0x0(%esi),%esi
  401e10:	55                   	push   %ebp
  401e11:	57                   	push   %edi
  401e12:	89 d7                	mov    %edx,%edi
  401e14:	56                   	push   %esi
  401e15:	89 ce                	mov    %ecx,%esi
  401e17:	53                   	push   %ebx
  401e18:	89 c3                	mov    %eax,%ebx
  401e1a:	83 ec 3c             	sub    $0x3c,%esp
  401e1d:	8d 44 24 14          	lea    0x14(%esp),%eax
  401e21:	c7 44 24 08 1c 00 00 	movl   $0x1c,0x8(%esp)
  401e28:	00 
  401e29:	89 44 24 04          	mov    %eax,0x4(%esp)
  401e2d:	89 1c 24             	mov    %ebx,(%esp)
  401e30:	e8 1f 21 00 00       	call   403f54 <_VirtualQuery@12>
  401e35:	83 ec 0c             	sub    $0xc,%esp
  401e38:	85 c0                	test   %eax,%eax
  401e3a:	0f 84 a4 00 00 00    	je     401ee4 <.text+0x124>
  401e40:	8b 44 24 28          	mov    0x28(%esp),%eax
  401e44:	83 f8 40             	cmp    $0x40,%eax
  401e47:	74 05                	je     401e4e <.text+0x8e>
  401e49:	83 f8 04             	cmp    $0x4,%eax
  401e4c:	75 22                	jne    401e70 <.text+0xb0>
  401e4e:	85 f6                	test   %esi,%esi
  401e50:	74 10                	je     401e62 <.text+0xa2>
  401e52:	31 c0                	xor    %eax,%eax
  401e54:	0f b6 0c 07          	movzbl (%edi,%eax,1),%ecx
  401e58:	88 0c 03             	mov    %cl,(%ebx,%eax,1)
  401e5b:	83 c0 01             	add    $0x1,%eax
  401e5e:	39 f0                	cmp    %esi,%eax
  401e60:	72 f2                	jb     401e54 <.text+0x94>
  401e62:	83 c4 3c             	add    $0x3c,%esp
  401e65:	5b                   	pop    %ebx
  401e66:	5e                   	pop    %esi
  401e67:	5f                   	pop    %edi
  401e68:	5d                   	pop    %ebp
  401e69:	c3                   	ret    
  401e6a:	8d b6 00 00 00 00    	lea    0x0(%esi),%esi
  401e70:	8b 44 24 20          	mov    0x20(%esp),%eax
  401e74:	8d 6c 24 10          	lea    0x10(%esp),%ebp
  401e78:	c7 44 24 08 40 00 00 	movl   $0x40,0x8(%esp)
  401e7f:	00 
  401e80:	89 6c 24 0c          	mov    %ebp,0xc(%esp)
  401e84:	89 44 24 04          	mov    %eax,0x4(%esp)
  401e88:	8b 44 24 14          	mov    0x14(%esp),%eax
  401e8c:	89 04 24             	mov    %eax,(%esp)
  401e8f:	e8 c8 20 00 00       	call   403f5c <_VirtualProtect@16>
  401e94:	83 ec 10             	sub    $0x10,%esp
  401e97:	8b 4c 24 28          	mov    0x28(%esp),%ecx
  401e9b:	85 f6                	test   %esi,%esi
  401e9d:	74 10                	je     401eaf <.text+0xef>
  401e9f:	31 d2                	xor    %edx,%edx
  401ea1:	0f b6 04 17          	movzbl (%edi,%edx,1),%eax
  401ea5:	88 04 13             	mov    %al,(%ebx,%edx,1)
  401ea8:	83 c2 01             	add    $0x1,%edx
  401eab:	39 f2                	cmp    %esi,%edx
  401ead:	72 f2                	jb     401ea1 <.text+0xe1>
  401eaf:	83 f9 40             	cmp    $0x40,%ecx
  401eb2:	74 ae                	je     401e62 <.text+0xa2>
  401eb4:	83 f9 04             	cmp    $0x4,%ecx
  401eb7:	74 a9                	je     401e62 <.text+0xa2>
  401eb9:	8b 44 24 10          	mov    0x10(%esp),%eax
  401ebd:	89 6c 24 0c          	mov    %ebp,0xc(%esp)
  401ec1:	89 44 24 08          	mov    %eax,0x8(%esp)
  401ec5:	8b 44 24 20          	mov    0x20(%esp),%eax
  401ec9:	89 44 24 04          	mov    %eax,0x4(%esp)
  401ecd:	8b 44 24 14          	mov    0x14(%esp),%eax
  401ed1:	89 04 24             	mov    %eax,(%esp)
  401ed4:	e8 83 20 00 00       	call   403f5c <_VirtualProtect@16>
  401ed9:	83 ec 10             	sub    $0x10,%esp
  401edc:	83 c4 3c             	add    $0x3c,%esp
  401edf:	5b                   	pop    %ebx
  401ee0:	5e                   	pop    %esi
  401ee1:	5f                   	pop    %edi
  401ee2:	5d                   	pop    %ebp
  401ee3:	c3                   	ret    
  401ee4:	89 5c 24 08          	mov    %ebx,0x8(%esp)
  401ee8:	c7 44 24 04 1c 00 00 	movl   $0x1c,0x4(%esp)
  401eef:	00 
  401ef0:	c7 04 24 bc 61 40 00 	movl   $0x4061bc,(%esp)
  401ef7:	e8 c4 fe ff ff       	call   401dc0 <.text>
  401efc:	8d 74 26 00          	lea    0x0(%esi,%eiz,1),%esi

00401f00 <__pei386_runtime_relocator>:
  401f00:	a1 5c 80 40 00       	mov    0x40805c,%eax
  401f05:	85 c0                	test   %eax,%eax
  401f07:	74 07                	je     401f10 <__pei386_runtime_relocator+0x10>
  401f09:	c3                   	ret    
  401f0a:	8d b6 00 00 00 00    	lea    0x0(%esi),%esi
  401f10:	c7 05 5c 80 40 00 01 	movl   $0x1,0x40805c
  401f17:	00 00 00 
  401f1a:	b8 a4 67 40 00       	mov    $0x4067a4,%eax
  401f1f:	2d a4 67 40 00       	sub    $0x4067a4,%eax
  401f24:	83 f8 07             	cmp    $0x7,%eax
  401f27:	7e e0                	jle    401f09 <__pei386_runtime_relocator+0x9>
  401f29:	57                   	push   %edi
  401f2a:	56                   	push   %esi
  401f2b:	53                   	push   %ebx
  401f2c:	83 ec 20             	sub    $0x20,%esp
  401f2f:	8b 15 a4 67 40 00    	mov    0x4067a4,%edx
  401f35:	83 f8 0b             	cmp    $0xb,%eax
  401f38:	0f 8f 92 00 00 00    	jg     401fd0 <__pei386_runtime_relocator+0xd0>
  401f3e:	bb a4 67 40 00       	mov    $0x4067a4,%ebx
  401f43:	85 d2                	test   %edx,%edx
  401f45:	0f 85 3a 01 00 00    	jne    402085 <__pei386_runtime_relocator+0x185>
  401f4b:	8b 43 04             	mov    0x4(%ebx),%eax
  401f4e:	85 c0                	test   %eax,%eax
  401f50:	0f 85 2f 01 00 00    	jne    402085 <__pei386_runtime_relocator+0x185>
  401f56:	8b 43 08             	mov    0x8(%ebx),%eax
  401f59:	83 f8 01             	cmp    $0x1,%eax
  401f5c:	0f 85 78 01 00 00    	jne    4020da <__pei386_runtime_relocator+0x1da>
  401f62:	8d b6 00 00 00 00    	lea    0x0(%esi),%esi
  401f68:	83 c3 0c             	add    $0xc,%ebx
  401f6b:	81 fb a4 67 40 00    	cmp    $0x4067a4,%ebx
  401f71:	73 4c                	jae    401fbf <__pei386_runtime_relocator+0xbf>
  401f73:	8b 03                	mov    (%ebx),%eax
  401f75:	8b 4b 04             	mov    0x4(%ebx),%ecx
  401f78:	0f b6 53 08          	movzbl 0x8(%ebx),%edx
  401f7c:	8d b8 00 00 40 00    	lea    0x400000(%eax),%edi
  401f82:	8d b1 00 00 40 00    	lea    0x400000(%ecx),%esi
  401f88:	8b 80 00 00 40 00    	mov    0x400000(%eax),%eax
  401f8e:	83 fa 10             	cmp    $0x10,%edx
  401f91:	0f 84 89 00 00 00    	je     402020 <__pei386_runtime_relocator+0x120>
  401f97:	83 fa 20             	cmp    $0x20,%edx
  401f9a:	75 64                	jne    402000 <__pei386_runtime_relocator+0x100>
  401f9c:	29 f8                	sub    %edi,%eax
  401f9e:	03 06                	add    (%esi),%eax
  401fa0:	b9 04 00 00 00       	mov    $0x4,%ecx
  401fa5:	83 c3 0c             	add    $0xc,%ebx
  401fa8:	89 44 24 1c          	mov    %eax,0x1c(%esp)
  401fac:	8d 54 24 1c          	lea    0x1c(%esp),%edx
  401fb0:	89 f0                	mov    %esi,%eax
  401fb2:	e8 59 fe ff ff       	call   401e10 <.text+0x50>
  401fb7:	81 fb a4 67 40 00    	cmp    $0x4067a4,%ebx
  401fbd:	72 b4                	jb     401f73 <__pei386_runtime_relocator+0x73>
  401fbf:	83 c4 20             	add    $0x20,%esp
  401fc2:	5b                   	pop    %ebx
  401fc3:	5e                   	pop    %esi
  401fc4:	5f                   	pop    %edi
  401fc5:	c3                   	ret    
  401fc6:	8d b4 26 00 00 00 00 	lea    0x0(%esi,%eiz,1),%esi
  401fcd:	8d 76 00             	lea    0x0(%esi),%esi
  401fd0:	85 d2                	test   %edx,%edx
  401fd2:	0f 85 a8 00 00 00    	jne    402080 <__pei386_runtime_relocator+0x180>
  401fd8:	a1 a8 67 40 00       	mov    0x4067a8,%eax
  401fdd:	89 c7                	mov    %eax,%edi
  401fdf:	0b 3d ac 67 40 00    	or     0x4067ac,%edi
  401fe5:	0f 85 e5 00 00 00    	jne    4020d0 <__pei386_runtime_relocator+0x1d0>
  401feb:	8b 15 b0 67 40 00    	mov    0x4067b0,%edx
  401ff1:	bb b0 67 40 00       	mov    $0x4067b0,%ebx
  401ff6:	e9 48 ff ff ff       	jmp    401f43 <__pei386_runtime_relocator+0x43>
  401ffb:	8d 74 26 00          	lea    0x0(%esi,%eiz,1),%esi
  401fff:	90                   	nop
  402000:	83 fa 08             	cmp    $0x8,%edx
  402003:	74 4b                	je     402050 <__pei386_runtime_relocator+0x150>
  402005:	89 54 24 04          	mov    %edx,0x4(%esp)
  402009:	c7 04 24 24 62 40 00 	movl   $0x406224,(%esp)
  402010:	c7 44 24 1c 00 00 00 	movl   $0x0,0x1c(%esp)
  402017:	00 
  402018:	e8 a3 fd ff ff       	call   401dc0 <.text>
  40201d:	8d 76 00             	lea    0x0(%esi),%esi
  402020:	0f b7 91 00 00 40 00 	movzwl 0x400000(%ecx),%edx
  402027:	66 85 d2             	test   %dx,%dx
  40202a:	79 06                	jns    402032 <__pei386_runtime_relocator+0x132>
  40202c:	81 ca 00 00 ff ff    	or     $0xffff0000,%edx
  402032:	29 fa                	sub    %edi,%edx
  402034:	b9 02 00 00 00       	mov    $0x2,%ecx
  402039:	01 d0                	add    %edx,%eax
  40203b:	8d 54 24 1c          	lea    0x1c(%esp),%edx
  40203f:	89 44 24 1c          	mov    %eax,0x1c(%esp)
  402043:	89 f0                	mov    %esi,%eax
  402045:	e8 c6 fd ff ff       	call   401e10 <.text+0x50>
  40204a:	e9 19 ff ff ff       	jmp    401f68 <__pei386_runtime_relocator+0x68>
  40204f:	90                   	nop
  402050:	0f b6 0e             	movzbl (%esi),%ecx
  402053:	84 c9                	test   %cl,%cl
  402055:	79 06                	jns    40205d <__pei386_runtime_relocator+0x15d>
  402057:	81 c9 00 ff ff ff    	or     $0xffffff00,%ecx
  40205d:	29 f9                	sub    %edi,%ecx
  40205f:	8d 54 24 1c          	lea    0x1c(%esp),%edx
  402063:	01 c8                	add    %ecx,%eax
  402065:	b9 01 00 00 00       	mov    $0x1,%ecx
  40206a:	89 44 24 1c          	mov    %eax,0x1c(%esp)
  40206e:	89 f0                	mov    %esi,%eax
  402070:	e8 9b fd ff ff       	call   401e10 <.text+0x50>
  402075:	e9 ee fe ff ff       	jmp    401f68 <__pei386_runtime_relocator+0x68>
  40207a:	8d b6 00 00 00 00    	lea    0x0(%esi),%esi
  402080:	bb a4 67 40 00       	mov    $0x4067a4,%ebx
  402085:	81 fb a4 67 40 00    	cmp    $0x4067a4,%ebx
  40208b:	0f 83 2e ff ff ff    	jae    401fbf <__pei386_runtime_relocator+0xbf>
  402091:	8d b4 26 00 00 00 00 	lea    0x0(%esi,%eiz,1),%esi
  402098:	8b 53 04             	mov    0x4(%ebx),%edx
  40209b:	8b 03                	mov    (%ebx),%eax
  40209d:	b9 04 00 00 00       	mov    $0x4,%ecx
  4020a2:	83 c3 08             	add    $0x8,%ebx
  4020a5:	03 82 00 00 40 00    	add    0x400000(%edx),%eax
  4020ab:	8d b2 00 00 40 00    	lea    0x400000(%edx),%esi
  4020b1:	8d 54 24 1c          	lea    0x1c(%esp),%edx
  4020b5:	89 44 24 1c          	mov    %eax,0x1c(%esp)
  4020b9:	89 f0                	mov    %esi,%eax
  4020bb:	e8 50 fd ff ff       	call   401e10 <.text+0x50>
  4020c0:	81 fb a4 67 40 00    	cmp    $0x4067a4,%ebx
  4020c6:	72 d0                	jb     402098 <__pei386_runtime_relocator+0x198>
  4020c8:	83 c4 20             	add    $0x20,%esp
  4020cb:	5b                   	pop    %ebx
  4020cc:	5e                   	pop    %esi
  4020cd:	5f                   	pop    %edi
  4020ce:	c3                   	ret    
  4020cf:	90                   	nop
  4020d0:	bb a4 67 40 00       	mov    $0x4067a4,%ebx
  4020d5:	e9 74 fe ff ff       	jmp    401f4e <__pei386_runtime_relocator+0x4e>
  4020da:	89 44 24 04          	mov    %eax,0x4(%esp)
  4020de:	c7 04 24 f0 61 40 00 	movl   $0x4061f0,(%esp)
  4020e5:	e8 d6 fc ff ff       	call   401dc0 <.text>
  4020ea:	90                   	nop
  4020eb:	90                   	nop
  4020ec:	90                   	nop
  4020ed:	90                   	nop
  4020ee:	90                   	nop
  4020ef:	90                   	nop

004020f0 <_fesetenv>:
  4020f0:	83 ec 1c             	sub    $0x1c,%esp
  4020f3:	8b 44 24 20          	mov    0x20(%esp),%eax
  4020f7:	c7 44 24 0c 80 1f 00 	movl   $0x1f80,0xc(%esp)
  4020fe:	00 
  4020ff:	83 f8 fd             	cmp    $0xfffffffd,%eax
  402102:	74 4c                	je     402150 <_fesetenv+0x60>
  402104:	83 f8 fc             	cmp    $0xfffffffc,%eax
  402107:	74 2f                	je     402138 <_fesetenv+0x48>
  402109:	85 c0                	test   %eax,%eax
  40210b:	74 53                	je     402160 <_fesetenv+0x70>
  40210d:	83 f8 ff             	cmp    $0xffffffff,%eax
  402110:	74 48                	je     40215a <_fesetenv+0x6a>
  402112:	83 f8 fe             	cmp    $0xfffffffe,%eax
  402115:	74 2b                	je     402142 <_fesetenv+0x52>
  402117:	d9 20                	fldenv (%eax)
  402119:	0f b7 40 1c          	movzwl 0x1c(%eax),%eax
  40211d:	89 44 24 0c          	mov    %eax,0xc(%esp)
  402121:	f6 05 24 80 40 00 10 	testb  $0x10,0x408024
  402128:	74 05                	je     40212f <_fesetenv+0x3f>
  40212a:	0f ae 54 24 0c       	ldmxcsr 0xc(%esp)
  40212f:	31 c0                	xor    %eax,%eax
  402131:	83 c4 1c             	add    $0x1c,%esp
  402134:	c3                   	ret    
  402135:	8d 76 00             	lea    0x0(%esi),%esi
  402138:	c7 05 14 50 40 00 fe 	movl   $0xfffffffe,0x405014
  40213f:	ff ff ff 
  402142:	ff 15 f4 91 40 00    	call   *0x4091f4
  402148:	eb d7                	jmp    402121 <_fesetenv+0x31>
  40214a:	8d b6 00 00 00 00    	lea    0x0(%esi),%esi
  402150:	c7 05 14 50 40 00 ff 	movl   $0xffffffff,0x405014
  402157:	ff ff ff 
  40215a:	db e3                	fninit 
  40215c:	eb c3                	jmp    402121 <_fesetenv+0x31>
  40215e:	66 90                	xchg   %ax,%ax
  402160:	a1 14 50 40 00       	mov    0x405014,%eax
  402165:	eb a6                	jmp    40210d <_fesetenv+0x1d>
  402167:	90                   	nop
  402168:	90                   	nop
  402169:	90                   	nop
  40216a:	90                   	nop
  40216b:	90                   	nop
  40216c:	90                   	nop
  40216d:	90                   	nop
  40216e:	90                   	nop
  40216f:	90                   	nop

00402170 <___mingw_aligned_free>:
  402170:	83 ec 2c             	sub    $0x2c,%esp
  402173:	8d 44 24 10          	lea    0x10(%esp),%eax
  402177:	89 44 24 04          	mov    %eax,0x4(%esp)
  40217b:	8b 44 24 30          	mov    0x30(%esp),%eax
  40217f:	89 04 24             	mov    %eax,(%esp)
  402182:	e8 99 1a 00 00       	call   403c20 <___mingw_memalign_base>
  402187:	89 04 24             	mov    %eax,(%esp)
  40218a:	ff 15 50 92 40 00    	call   *0x409250
  402190:	83 c4 2c             	add    $0x2c,%esp
  402193:	c3                   	ret    
  402194:	90                   	nop
  402195:	90                   	nop
  402196:	90                   	nop
  402197:	90                   	nop
  402198:	90                   	nop
  402199:	90                   	nop
  40219a:	90                   	nop
  40219b:	90                   	nop
  40219c:	90                   	nop
  40219d:	90                   	nop
  40219e:	90                   	nop
  40219f:	90                   	nop

004021a0 <.text>:
  4021a0:	55                   	push   %ebp
  4021a1:	57                   	push   %edi
  4021a2:	56                   	push   %esi
  4021a3:	53                   	push   %ebx
  4021a4:	83 ec 3c             	sub    $0x3c,%esp
  4021a7:	0f be 28             	movsbl (%eax),%ebp
  4021aa:	89 54 24 1c          	mov    %edx,0x1c(%esp)
  4021ae:	89 4c 24 28          	mov    %ecx,0x28(%esp)
  4021b2:	89 eb                	mov    %ebp,%ebx
  4021b4:	83 fd 2d             	cmp    $0x2d,%ebp
  4021b7:	0f 84 db 00 00 00    	je     402298 <.text+0xf8>
  4021bd:	89 c2                	mov    %eax,%edx
  4021bf:	83 fd 5d             	cmp    $0x5d,%ebp
  4021c2:	0f 84 d0 00 00 00    	je     402298 <.text+0xf8>
  4021c8:	8b 44 24 28          	mov    0x28(%esp),%eax
  4021cc:	25 00 40 00 00       	and    $0x4000,%eax
  4021d1:	89 44 24 20          	mov    %eax,0x20(%esp)
  4021d5:	89 e8                	mov    %ebp,%eax
  4021d7:	89 d5                	mov    %edx,%ebp
  4021d9:	89 da                	mov    %ebx,%edx
  4021db:	89 c3                	mov    %eax,%ebx
  4021dd:	eb 0b                	jmp    4021ea <.text+0x4a>
  4021df:	90                   	nop
  4021e0:	89 d6                	mov    %edx,%esi
  4021e2:	2b 74 24 1c          	sub    0x1c(%esp),%esi
  4021e6:	85 f6                	test   %esi,%esi
  4021e8:	74 64                	je     40224e <.text+0xae>
  4021ea:	8d 7d 01             	lea    0x1(%ebp),%edi
  4021ed:	89 de                	mov    %ebx,%esi
  4021ef:	83 fb 5d             	cmp    $0x5d,%ebx
  4021f2:	0f 84 d0 00 00 00    	je     4022c8 <.text+0x128>
  4021f8:	83 fb 2d             	cmp    $0x2d,%ebx
  4021fb:	0f 84 b7 00 00 00    	je     4022b8 <.text+0x118>
  402201:	85 db                	test   %ebx,%ebx
  402203:	0f 84 bf 00 00 00    	je     4022c8 <.text+0x128>
  402209:	83 fe 2f             	cmp    $0x2f,%esi
  40220c:	0f 84 b6 00 00 00    	je     4022c8 <.text+0x128>
  402212:	83 fe 5c             	cmp    $0x5c,%esi
  402215:	0f 84 ad 00 00 00    	je     4022c8 <.text+0x128>
  40221b:	0f be 1f             	movsbl (%edi),%ebx
  40221e:	89 fd                	mov    %edi,%ebp
  402220:	89 f2                	mov    %esi,%edx
  402222:	8b 44 24 20          	mov    0x20(%esp),%eax
  402226:	85 c0                	test   %eax,%eax
  402228:	75 b6                	jne    4021e0 <.text+0x40>
  40222a:	89 14 24             	mov    %edx,(%esp)
  40222d:	89 54 24 24          	mov    %edx,0x24(%esp)
  402231:	e8 66 1c 00 00       	call   403e9c <_tolower>
  402236:	89 c6                	mov    %eax,%esi
  402238:	8b 44 24 1c          	mov    0x1c(%esp),%eax
  40223c:	89 04 24             	mov    %eax,(%esp)
  40223f:	e8 58 1c 00 00       	call   403e9c <_tolower>
  402244:	8b 54 24 24          	mov    0x24(%esp),%edx
  402248:	29 c6                	sub    %eax,%esi
  40224a:	85 f6                	test   %esi,%esi
  40224c:	75 9c                	jne    4021ea <.text+0x4a>
  40224e:	89 d9                	mov    %ebx,%ecx
  402250:	8b 5c 24 28          	mov    0x28(%esp),%ebx
  402254:	89 ea                	mov    %ebp,%edx
  402256:	83 e3 20             	and    $0x20,%ebx
  402259:	8d 42 01             	lea    0x1(%edx),%eax
  40225c:	80 f9 5d             	cmp    $0x5d,%cl
  40225f:	74 69                	je     4022ca <.text+0x12a>
  402261:	80 f9 7f             	cmp    $0x7f,%cl
  402264:	74 17                	je     40227d <.text+0xdd>
  402266:	84 c9                	test   %cl,%cl
  402268:	74 5e                	je     4022c8 <.text+0x128>
  40226a:	0f b6 4a 01          	movzbl 0x1(%edx),%ecx
  40226e:	89 c2                	mov    %eax,%edx
  402270:	8d 42 01             	lea    0x1(%edx),%eax
  402273:	80 f9 5d             	cmp    $0x5d,%cl
  402276:	74 52                	je     4022ca <.text+0x12a>
  402278:	80 f9 7f             	cmp    $0x7f,%cl
  40227b:	75 e9                	jne    402266 <.text+0xc6>
  40227d:	0f b6 4a 01          	movzbl 0x1(%edx),%ecx
  402281:	85 db                	test   %ebx,%ebx
  402283:	0f 85 1f 02 00 00    	jne    4024a8 <.text+0x308>
  402289:	8d 72 02             	lea    0x2(%edx),%esi
  40228c:	89 c2                	mov    %eax,%edx
  40228e:	89 f0                	mov    %esi,%eax
  402290:	eb d4                	jmp    402266 <.text+0xc6>
  402292:	8d b6 00 00 00 00    	lea    0x0(%esi),%esi
  402298:	0f b6 48 01          	movzbl 0x1(%eax),%ecx
  40229c:	8d 50 01             	lea    0x1(%eax),%edx
  40229f:	3b 6c 24 1c          	cmp    0x1c(%esp),%ebp
  4022a3:	0f 84 a7 01 00 00    	je     402450 <.text+0x2b0>
  4022a9:	0f be e9             	movsbl %cl,%ebp
  4022ac:	e9 17 ff ff ff       	jmp    4021c8 <.text+0x28>
  4022b1:	8d b4 26 00 00 00 00 	lea    0x0(%esi,%eiz,1),%esi
  4022b8:	0f be 5d 01          	movsbl 0x1(%ebp),%ebx
  4022bc:	80 fb 5d             	cmp    $0x5d,%bl
  4022bf:	74 17                	je     4022d8 <.text+0x138>
  4022c1:	0f be f3             	movsbl %bl,%esi
  4022c4:	85 f6                	test   %esi,%esi
  4022c6:	75 20                	jne    4022e8 <.text+0x148>
  4022c8:	31 c0                	xor    %eax,%eax
  4022ca:	83 c4 3c             	add    $0x3c,%esp
  4022cd:	5b                   	pop    %ebx
  4022ce:	5e                   	pop    %esi
  4022cf:	5f                   	pop    %edi
  4022d0:	5d                   	pop    %ebp
  4022d1:	c3                   	ret    
  4022d2:	8d b6 00 00 00 00    	lea    0x0(%esi),%esi
  4022d8:	89 fd                	mov    %edi,%ebp
  4022da:	ba 2d 00 00 00       	mov    $0x2d,%edx
  4022df:	e9 3e ff ff ff       	jmp    402222 <.text+0x82>
  4022e4:	8d 74 26 00          	lea    0x0(%esi,%eiz,1),%esi
  4022e8:	8d 7d 02             	lea    0x2(%ebp),%edi
  4022eb:	89 6c 24 24          	mov    %ebp,0x24(%esp)
  4022ef:	89 d5                	mov    %edx,%ebp
  4022f1:	89 7c 24 2c          	mov    %edi,0x2c(%esp)
  4022f5:	89 f7                	mov    %esi,%edi
  4022f7:	8b 74 24 20          	mov    0x20(%esp),%esi
  4022fb:	eb 10                	jmp    40230d <.text+0x16d>
  4022fd:	8d 76 00             	lea    0x0(%esi),%esi
  402300:	89 eb                	mov    %ebp,%ebx
  402302:	2b 5c 24 1c          	sub    0x1c(%esp),%ebx
  402306:	83 c5 01             	add    $0x1,%ebp
  402309:	85 db                	test   %ebx,%ebx
  40230b:	74 27                	je     402334 <.text+0x194>
  40230d:	39 fd                	cmp    %edi,%ebp
  40230f:	7d 7f                	jge    402390 <.text+0x1f0>
  402311:	85 f6                	test   %esi,%esi
  402313:	75 eb                	jne    402300 <.text+0x160>
  402315:	89 2c 24             	mov    %ebp,(%esp)
  402318:	83 c5 01             	add    $0x1,%ebp
  40231b:	e8 7c 1b 00 00       	call   403e9c <_tolower>
  402320:	89 c3                	mov    %eax,%ebx
  402322:	8b 44 24 1c          	mov    0x1c(%esp),%eax
  402326:	89 04 24             	mov    %eax,(%esp)
  402329:	e8 6e 1b 00 00       	call   403e9c <_tolower>
  40232e:	29 c3                	sub    %eax,%ebx
  402330:	85 db                	test   %ebx,%ebx
  402332:	75 d9                	jne    40230d <.text+0x16d>
  402334:	8b 54 24 24          	mov    0x24(%esp),%edx
  402338:	8b 4c 24 28          	mov    0x28(%esp),%ecx
  40233c:	8b 7c 24 2c          	mov    0x2c(%esp),%edi
  402340:	0f b6 52 02          	movzbl 0x2(%edx),%edx
  402344:	83 e1 20             	and    $0x20,%ecx
  402347:	8d 47 01             	lea    0x1(%edi),%eax
  40234a:	80 fa 5d             	cmp    $0x5d,%dl
  40234d:	0f 84 77 ff ff ff    	je     4022ca <.text+0x12a>
  402353:	80 fa 7f             	cmp    $0x7f,%dl
  402356:	74 1f                	je     402377 <.text+0x1d7>
  402358:	84 d2                	test   %dl,%dl
  40235a:	0f 84 68 ff ff ff    	je     4022c8 <.text+0x128>
  402360:	0f b6 57 01          	movzbl 0x1(%edi),%edx
  402364:	89 c7                	mov    %eax,%edi
  402366:	8d 47 01             	lea    0x1(%edi),%eax
  402369:	80 fa 5d             	cmp    $0x5d,%dl
  40236c:	0f 84 58 ff ff ff    	je     4022ca <.text+0x12a>
  402372:	80 fa 7f             	cmp    $0x7f,%dl
  402375:	75 e1                	jne    402358 <.text+0x1b8>
  402377:	0f b6 57 01          	movzbl 0x1(%edi),%edx
  40237b:	85 c9                	test   %ecx,%ecx
  40237d:	0f 85 bd 00 00 00    	jne    402440 <.text+0x2a0>
  402383:	8d 5f 02             	lea    0x2(%edi),%ebx
  402386:	89 c7                	mov    %eax,%edi
  402388:	89 d8                	mov    %ebx,%eax
  40238a:	eb cc                	jmp    402358 <.text+0x1b8>
  40238c:	8d 74 26 00          	lea    0x0(%esi,%eiz,1),%esi
  402390:	89 fe                	mov    %edi,%esi
  402392:	89 ea                	mov    %ebp,%edx
  402394:	8b 7c 24 2c          	mov    0x2c(%esp),%edi
  402398:	8b 6c 24 24          	mov    0x24(%esp),%ebp
  40239c:	89 7c 24 24          	mov    %edi,0x24(%esp)
  4023a0:	89 f7                	mov    %esi,%edi
  4023a2:	89 d6                	mov    %edx,%esi
  4023a4:	89 6c 24 2c          	mov    %ebp,0x2c(%esp)
  4023a8:	8b 6c 24 20          	mov    0x20(%esp),%ebp
  4023ac:	eb 0f                	jmp    4023bd <.text+0x21d>
  4023ae:	66 90                	xchg   %ax,%ax
  4023b0:	89 f3                	mov    %esi,%ebx
  4023b2:	2b 5c 24 1c          	sub    0x1c(%esp),%ebx
  4023b6:	83 ee 01             	sub    $0x1,%esi
  4023b9:	85 db                	test   %ebx,%ebx
  4023bb:	74 2b                	je     4023e8 <.text+0x248>
  4023bd:	39 fe                	cmp    %edi,%esi
  4023bf:	0f 8e eb 00 00 00    	jle    4024b0 <.text+0x310>
  4023c5:	85 ed                	test   %ebp,%ebp
  4023c7:	75 e7                	jne    4023b0 <.text+0x210>
  4023c9:	89 34 24             	mov    %esi,(%esp)
  4023cc:	83 ee 01             	sub    $0x1,%esi
  4023cf:	e8 c8 1a 00 00       	call   403e9c <_tolower>
  4023d4:	89 c3                	mov    %eax,%ebx
  4023d6:	8b 44 24 1c          	mov    0x1c(%esp),%eax
  4023da:	89 04 24             	mov    %eax,(%esp)
  4023dd:	e8 ba 1a 00 00       	call   403e9c <_tolower>
  4023e2:	29 c3                	sub    %eax,%ebx
  4023e4:	85 db                	test   %ebx,%ebx
  4023e6:	75 d5                	jne    4023bd <.text+0x21d>
  4023e8:	8b 54 24 2c          	mov    0x2c(%esp),%edx
  4023ec:	8b 4c 24 28          	mov    0x28(%esp),%ecx
  4023f0:	8b 7c 24 24          	mov    0x24(%esp),%edi
  4023f4:	0f b6 52 02          	movzbl 0x2(%edx),%edx
  4023f8:	83 e1 20             	and    $0x20,%ecx
  4023fb:	8d 47 01             	lea    0x1(%edi),%eax
  4023fe:	80 fa 5d             	cmp    $0x5d,%dl
  402401:	0f 84 c3 fe ff ff    	je     4022ca <.text+0x12a>
  402407:	80 fa 7f             	cmp    $0x7f,%dl
  40240a:	74 1f                	je     40242b <.text+0x28b>
  40240c:	84 d2                	test   %dl,%dl
  40240e:	0f 84 b4 fe ff ff    	je     4022c8 <.text+0x128>
  402414:	0f b6 57 01          	movzbl 0x1(%edi),%edx
  402418:	89 c7                	mov    %eax,%edi
  40241a:	8d 47 01             	lea    0x1(%edi),%eax
  40241d:	80 fa 5d             	cmp    $0x5d,%dl
  402420:	0f 84 a4 fe ff ff    	je     4022ca <.text+0x12a>
  402426:	80 fa 7f             	cmp    $0x7f,%dl
  402429:	75 e1                	jne    40240c <.text+0x26c>
  40242b:	0f b6 57 01          	movzbl 0x1(%edi),%edx
  40242f:	85 c9                	test   %ecx,%ecx
  402431:	0f 85 89 00 00 00    	jne    4024c0 <.text+0x320>
  402437:	8d 5f 02             	lea    0x2(%edi),%ebx
  40243a:	89 c7                	mov    %eax,%edi
  40243c:	89 d8                	mov    %ebx,%eax
  40243e:	eb cc                	jmp    40240c <.text+0x26c>
  402440:	89 c7                	mov    %eax,%edi
  402442:	e9 00 ff ff ff       	jmp    402347 <.text+0x1a7>
  402447:	8d b4 26 00 00 00 00 	lea    0x0(%esi,%eiz,1),%esi
  40244e:	66 90                	xchg   %ax,%ax
  402450:	8b 5c 24 28          	mov    0x28(%esp),%ebx
  402454:	83 e3 20             	and    $0x20,%ebx
  402457:	8d 42 01             	lea    0x1(%edx),%eax
  40245a:	80 f9 5d             	cmp    $0x5d,%cl
  40245d:	0f 84 67 fe ff ff    	je     4022ca <.text+0x12a>
  402463:	80 f9 7f             	cmp    $0x7f,%cl
  402466:	74 1f                	je     402487 <.text+0x2e7>
  402468:	84 c9                	test   %cl,%cl
  40246a:	0f 84 58 fe ff ff    	je     4022c8 <.text+0x128>
  402470:	0f b6 4a 01          	movzbl 0x1(%edx),%ecx
  402474:	89 c2                	mov    %eax,%edx
  402476:	8d 42 01             	lea    0x1(%edx),%eax
  402479:	80 f9 5d             	cmp    $0x5d,%cl
  40247c:	0f 84 48 fe ff ff    	je     4022ca <.text+0x12a>
  402482:	80 f9 7f             	cmp    $0x7f,%cl
  402485:	75 e1                	jne    402468 <.text+0x2c8>
  402487:	0f b6 4a 01          	movzbl 0x1(%edx),%ecx
  40248b:	85 db                	test   %ebx,%ebx
  40248d:	75 11                	jne    4024a0 <.text+0x300>
  40248f:	8d 72 02             	lea    0x2(%edx),%esi
  402492:	89 c2                	mov    %eax,%edx
  402494:	89 f0                	mov    %esi,%eax
  402496:	eb d0                	jmp    402468 <.text+0x2c8>
  402498:	8d b4 26 00 00 00 00 	lea    0x0(%esi,%eiz,1),%esi
  40249f:	90                   	nop
  4024a0:	89 c2                	mov    %eax,%edx
  4024a2:	eb b3                	jmp    402457 <.text+0x2b7>
  4024a4:	8d 74 26 00          	lea    0x0(%esi,%eiz,1),%esi
  4024a8:	89 c2                	mov    %eax,%edx
  4024aa:	e9 aa fd ff ff       	jmp    402259 <.text+0xb9>
  4024af:	90                   	nop
  4024b0:	89 fe                	mov    %edi,%esi
  4024b2:	8b 7c 24 24          	mov    0x24(%esp),%edi
  4024b6:	e9 4e fd ff ff       	jmp    402209 <.text+0x69>
  4024bb:	8d 74 26 00          	lea    0x0(%esi,%eiz,1),%esi
  4024bf:	90                   	nop
  4024c0:	89 c7                	mov    %eax,%edi
  4024c2:	e9 34 ff ff ff       	jmp    4023fb <.text+0x25b>
  4024c7:	8d b4 26 00 00 00 00 	lea    0x0(%esi,%eiz,1),%esi
  4024ce:	66 90                	xchg   %ax,%ax
  4024d0:	55                   	push   %ebp
  4024d1:	89 c5                	mov    %eax,%ebp
  4024d3:	57                   	push   %edi
  4024d4:	56                   	push   %esi
  4024d5:	89 d6                	mov    %edx,%esi
  4024d7:	53                   	push   %ebx
  4024d8:	83 ec 2c             	sub    $0x2c,%esp
  4024db:	0f b6 3a             	movzbl (%edx),%edi
  4024de:	0f be 10             	movsbl (%eax),%edx
  4024e1:	89 fb                	mov    %edi,%ebx
  4024e3:	89 d0                	mov    %edx,%eax
  4024e5:	80 fb 2e             	cmp    $0x2e,%bl
  4024e8:	0f 84 32 01 00 00    	je     402620 <.text+0x480>
  4024ee:	8d 5d 01             	lea    0x1(%ebp),%ebx
  4024f1:	85 d2                	test   %edx,%edx
  4024f3:	0f 84 f9 00 00 00    	je     4025f2 <.text+0x452>
  4024f9:	89 cf                	mov    %ecx,%edi
  4024fb:	83 e7 20             	and    $0x20,%edi
  4024fe:	89 7c 24 14          	mov    %edi,0x14(%esp)
  402502:	89 f7                	mov    %esi,%edi
  402504:	3c 3f                	cmp    $0x3f,%al
  402506:	0f 84 f4 00 00 00    	je     402600 <.text+0x460>
  40250c:	3c 5b                	cmp    $0x5b,%al
  40250e:	0f 84 9c 00 00 00    	je     4025b0 <.text+0x410>
  402514:	3c 2a                	cmp    $0x2a,%al
  402516:	74 5b                	je     402573 <.text+0x3d3>
  402518:	f6 c1 20             	test   $0x20,%cl
  40251b:	75 09                	jne    402526 <.text+0x386>
  40251d:	83 fa 7f             	cmp    $0x7f,%edx
  402520:	0f 84 42 01 00 00    	je     402668 <.text+0x4c8>
  402526:	0f be 06             	movsbl (%esi),%eax
  402529:	84 c0                	test   %al,%al
  40252b:	74 75                	je     4025a2 <.text+0x402>
  40252d:	89 44 24 10          	mov    %eax,0x10(%esp)
  402531:	f6 c5 40             	test   $0x40,%ch
  402534:	0f 85 d6 00 00 00    	jne    402610 <.text+0x470>
  40253a:	89 14 24             	mov    %edx,(%esp)
  40253d:	89 4c 24 1c          	mov    %ecx,0x1c(%esp)
  402541:	89 54 24 18          	mov    %edx,0x18(%esp)
  402545:	e8 52 19 00 00       	call   403e9c <_tolower>
  40254a:	89 c5                	mov    %eax,%ebp
  40254c:	8b 44 24 10          	mov    0x10(%esp),%eax
  402550:	89 04 24             	mov    %eax,(%esp)
  402553:	e8 44 19 00 00       	call   403e9c <_tolower>
  402558:	8b 4c 24 1c          	mov    0x1c(%esp),%ecx
  40255c:	8b 54 24 18          	mov    0x18(%esp),%edx
  402560:	29 c5                	sub    %eax,%ebp
  402562:	85 ed                	test   %ebp,%ebp
  402564:	0f 84 9f 00 00 00    	je     402609 <.text+0x469>
  40256a:	2b 54 24 10          	sub    0x10(%esp),%edx
  40256e:	eb 32                	jmp    4025a2 <.text+0x402>
  402570:	83 c3 01             	add    $0x1,%ebx
  402573:	0f b6 03             	movzbl (%ebx),%eax
  402576:	3c 2a                	cmp    $0x2a,%al
  402578:	74 f6                	je     402570 <.text+0x3d0>
  40257a:	31 d2                	xor    %edx,%edx
  40257c:	84 c0                	test   %al,%al
  40257e:	74 22                	je     4025a2 <.text+0x402>
  402580:	89 ce                	mov    %ecx,%esi
  402582:	81 ce 00 00 01 00    	or     $0x10000,%esi
  402588:	89 f1                	mov    %esi,%ecx
  40258a:	89 fa                	mov    %edi,%edx
  40258c:	89 d8                	mov    %ebx,%eax
  40258e:	e8 3d ff ff ff       	call   4024d0 <.text+0x330>
  402593:	85 c0                	test   %eax,%eax
  402595:	74 09                	je     4025a0 <.text+0x400>
  402597:	83 c7 01             	add    $0x1,%edi
  40259a:	80 7f ff 00          	cmpb   $0x0,-0x1(%edi)
  40259e:	75 e8                	jne    402588 <.text+0x3e8>
  4025a0:	89 c2                	mov    %eax,%edx
  4025a2:	83 c4 2c             	add    $0x2c,%esp
  4025a5:	89 d0                	mov    %edx,%eax
  4025a7:	5b                   	pop    %ebx
  4025a8:	5e                   	pop    %esi
  4025a9:	5f                   	pop    %edi
  4025aa:	5d                   	pop    %ebp
  4025ab:	c3                   	ret    
  4025ac:	8d 74 26 00          	lea    0x0(%esi,%eiz,1),%esi
  4025b0:	0f be 16             	movsbl (%esi),%edx
  4025b3:	85 d2                	test   %edx,%edx
  4025b5:	0f 84 32 01 00 00    	je     4026ed <.text+0x54d>
  4025bb:	80 7d 01 21          	cmpb   $0x21,0x1(%ebp)
  4025bf:	74 7f                	je     402640 <.text+0x4a0>
  4025c1:	89 d8                	mov    %ebx,%eax
  4025c3:	89 4c 24 10          	mov    %ecx,0x10(%esp)
  4025c7:	e8 d4 fb ff ff       	call   4021a0 <.text>
  4025cc:	89 c5                	mov    %eax,%ebp
  4025ce:	85 c0                	test   %eax,%eax
  4025d0:	0f 84 03 01 00 00    	je     4026d9 <.text+0x539>
  4025d6:	0f b6 00             	movzbl (%eax),%eax
  4025d9:	8b 4c 24 10          	mov    0x10(%esp),%ecx
  4025dd:	0f be d0             	movsbl %al,%edx
  4025e0:	8d 5d 01             	lea    0x1(%ebp),%ebx
  4025e3:	83 c6 01             	add    $0x1,%esi
  4025e6:	85 d2                	test   %edx,%edx
  4025e8:	0f 85 14 ff ff ff    	jne    402502 <.text+0x362>
  4025ee:	0f b6 7f 01          	movzbl 0x1(%edi),%edi
  4025f2:	89 f8                	mov    %edi,%eax
  4025f4:	0f be d0             	movsbl %al,%edx
  4025f7:	f7 da                	neg    %edx
  4025f9:	eb a7                	jmp    4025a2 <.text+0x402>
  4025fb:	8d 74 26 00          	lea    0x0(%esi,%eiz,1),%esi
  4025ff:	90                   	nop
  402600:	80 3e 00             	cmpb   $0x0,(%esi)
  402603:	0f 84 da 00 00 00    	je     4026e3 <.text+0x543>
  402609:	0f b6 03             	movzbl (%ebx),%eax
  40260c:	89 dd                	mov    %ebx,%ebp
  40260e:	eb cd                	jmp    4025dd <.text+0x43d>
  402610:	89 d5                	mov    %edx,%ebp
  402612:	29 c5                	sub    %eax,%ebp
  402614:	e9 49 ff ff ff       	jmp    402562 <.text+0x3c2>
  402619:	8d b4 26 00 00 00 00 	lea    0x0(%esi,%eiz,1),%esi
  402620:	80 fa 2e             	cmp    $0x2e,%dl
  402623:	74 5b                	je     402680 <.text+0x4e0>
  402625:	f7 c1 00 00 01 00    	test   $0x10000,%ecx
  40262b:	0f 85 bd fe ff ff    	jne    4024ee <.text+0x34e>
  402631:	83 ea 2e             	sub    $0x2e,%edx
  402634:	e9 69 ff ff ff       	jmp    4025a2 <.text+0x402>
  402639:	8d b4 26 00 00 00 00 	lea    0x0(%esi,%eiz,1),%esi
  402640:	8d 5d 02             	lea    0x2(%ebp),%ebx
  402643:	89 4c 24 10          	mov    %ecx,0x10(%esp)
  402647:	89 d8                	mov    %ebx,%eax
  402649:	e8 52 fb ff ff       	call   4021a0 <.text>
  40264e:	8b 4c 24 10          	mov    0x10(%esp),%ecx
  402652:	89 c2                	mov    %eax,%edx
  402654:	0f b6 45 02          	movzbl 0x2(%ebp),%eax
  402658:	85 d2                	test   %edx,%edx
  40265a:	74 2c                	je     402688 <.text+0x4e8>
  40265c:	89 dd                	mov    %ebx,%ebp
  40265e:	e9 7a ff ff ff       	jmp    4025dd <.text+0x43d>
  402663:	8d 74 26 00          	lea    0x0(%esi,%eiz,1),%esi
  402667:	90                   	nop
  402668:	0f be 55 01          	movsbl 0x1(%ebp),%edx
  40266c:	85 d2                	test   %edx,%edx
  40266e:	0f 84 b2 fe ff ff    	je     402526 <.text+0x386>
  402674:	8d 5d 02             	lea    0x2(%ebp),%ebx
  402677:	e9 aa fe ff ff       	jmp    402526 <.text+0x386>
  40267c:	8d 74 26 00          	lea    0x0(%esi,%eiz,1),%esi
  402680:	8d 5d 01             	lea    0x1(%ebp),%ebx
  402683:	e9 71 fe ff ff       	jmp    4024f9 <.text+0x359>
  402688:	3c 5d                	cmp    $0x5d,%al
  40268a:	75 0c                	jne    402698 <.text+0x4f8>
  40268c:	0f b6 45 03          	movzbl 0x3(%ebp),%eax
  402690:	8d 5d 03             	lea    0x3(%ebp),%ebx
  402693:	8d 74 26 00          	lea    0x0(%esi,%eiz,1),%esi
  402697:	90                   	nop
  402698:	8d 6b 01             	lea    0x1(%ebx),%ebp
  40269b:	3c 5d                	cmp    $0x5d,%al
  40269d:	74 15                	je     4026b4 <.text+0x514>
  40269f:	3c 7f                	cmp    $0x7f,%al
  4026a1:	74 1d                	je     4026c0 <.text+0x520>
  4026a3:	84 c0                	test   %al,%al
  4026a5:	74 32                	je     4026d9 <.text+0x539>
  4026a7:	0f b6 43 01          	movzbl 0x1(%ebx),%eax
  4026ab:	89 eb                	mov    %ebp,%ebx
  4026ad:	8d 6b 01             	lea    0x1(%ebx),%ebp
  4026b0:	3c 5d                	cmp    $0x5d,%al
  4026b2:	75 eb                	jne    40269f <.text+0x4ff>
  4026b4:	0f b6 43 01          	movzbl 0x1(%ebx),%eax
  4026b8:	e9 20 ff ff ff       	jmp    4025dd <.text+0x43d>
  4026bd:	8d 76 00             	lea    0x0(%esi),%esi
  4026c0:	8b 54 24 14          	mov    0x14(%esp),%edx
  4026c4:	0f b6 43 01          	movzbl 0x1(%ebx),%eax
  4026c8:	85 d2                	test   %edx,%edx
  4026ca:	75 09                	jne    4026d5 <.text+0x535>
  4026cc:	8d 53 02             	lea    0x2(%ebx),%edx
  4026cf:	89 eb                	mov    %ebp,%ebx
  4026d1:	89 d5                	mov    %edx,%ebp
  4026d3:	eb ce                	jmp    4026a3 <.text+0x503>
  4026d5:	89 eb                	mov    %ebp,%ebx
  4026d7:	eb bf                	jmp    402698 <.text+0x4f8>
  4026d9:	ba 5d 00 00 00       	mov    $0x5d,%edx
  4026de:	e9 bf fe ff ff       	jmp    4025a2 <.text+0x402>
  4026e3:	ba 3f 00 00 00       	mov    $0x3f,%edx
  4026e8:	e9 b5 fe ff ff       	jmp    4025a2 <.text+0x402>
  4026ed:	ba 5b 00 00 00       	mov    $0x5b,%edx
  4026f2:	e9 ab fe ff ff       	jmp    4025a2 <.text+0x402>
  4026f7:	8d b4 26 00 00 00 00 	lea    0x0(%esi,%eiz,1),%esi
  4026fe:	66 90                	xchg   %ax,%ax
  402700:	57                   	push   %edi
  402701:	8d 48 01             	lea    0x1(%eax),%ecx
  402704:	56                   	push   %esi
  402705:	53                   	push   %ebx
  402706:	89 c3                	mov    %eax,%ebx
  402708:	0f be 00             	movsbl (%eax),%eax
  40270b:	85 c0                	test   %eax,%eax
  40270d:	74 61                	je     402770 <.text+0x5d0>
  40270f:	c1 ea 05             	shr    $0x5,%edx
  402712:	31 ff                	xor    %edi,%edi
  402714:	89 d6                	mov    %edx,%esi
  402716:	83 f6 01             	xor    $0x1,%esi
  402719:	83 e6 01             	and    $0x1,%esi
  40271c:	eb 23                	jmp    402741 <.text+0x5a1>
  40271e:	66 90                	xchg   %ax,%ax
  402720:	83 f8 2a             	cmp    $0x2a,%eax
  402723:	74 6b                	je     402790 <.text+0x5f0>
  402725:	83 f8 3f             	cmp    $0x3f,%eax
  402728:	74 66                	je     402790 <.text+0x5f0>
  40272a:	83 f8 5b             	cmp    $0x5b,%eax
  40272d:	89 cb                	mov    %ecx,%ebx
  40272f:	0f 94 c0             	sete   %al
  402732:	0f b6 c0             	movzbl %al,%eax
  402735:	89 c7                	mov    %eax,%edi
  402737:	0f be 03             	movsbl (%ebx),%eax
  40273a:	83 c1 01             	add    $0x1,%ecx
  40273d:	85 c0                	test   %eax,%eax
  40273f:	74 2f                	je     402770 <.text+0x5d0>
  402741:	83 f8 7f             	cmp    $0x7f,%eax
  402744:	75 06                	jne    40274c <.text+0x5ac>
  402746:	89 f2                	mov    %esi,%edx
  402748:	84 d2                	test   %dl,%dl
  40274a:	75 2c                	jne    402778 <.text+0x5d8>
  40274c:	85 ff                	test   %edi,%edi
  40274e:	74 d0                	je     402720 <.text+0x580>
  402750:	83 ff 01             	cmp    $0x1,%edi
  402753:	7e 05                	jle    40275a <.text+0x5ba>
  402755:	83 f8 5d             	cmp    $0x5d,%eax
  402758:	74 36                	je     402790 <.text+0x5f0>
  40275a:	89 cb                	mov    %ecx,%ebx
  40275c:	83 f8 21             	cmp    $0x21,%eax
  40275f:	74 d6                	je     402737 <.text+0x597>
  402761:	89 cb                	mov    %ecx,%ebx
  402763:	83 c7 01             	add    $0x1,%edi
  402766:	83 c1 01             	add    $0x1,%ecx
  402769:	0f be 03             	movsbl (%ebx),%eax
  40276c:	85 c0                	test   %eax,%eax
  40276e:	75 d1                	jne    402741 <.text+0x5a1>
  402770:	5b                   	pop    %ebx
  402771:	5e                   	pop    %esi
  402772:	5f                   	pop    %edi
  402773:	c3                   	ret    
  402774:	8d 74 26 00          	lea    0x0(%esi,%eiz,1),%esi
  402778:	80 7b 01 00          	cmpb   $0x0,0x1(%ebx)
  40277c:	8d 4b 02             	lea    0x2(%ebx),%ecx
  40277f:	74 18                	je     402799 <.text+0x5f9>
  402781:	85 ff                	test   %edi,%edi
  402783:	74 a5                	je     40272a <.text+0x58a>
  402785:	eb da                	jmp    402761 <.text+0x5c1>
  402787:	8d b4 26 00 00 00 00 	lea    0x0(%esi,%eiz,1),%esi
  40278e:	66 90                	xchg   %ax,%ax
  402790:	5b                   	pop    %ebx
  402791:	b8 01 00 00 00       	mov    $0x1,%eax
  402796:	5e                   	pop    %esi
  402797:	5f                   	pop    %edi
  402798:	c3                   	ret    
  402799:	31 c0                	xor    %eax,%eax
  40279b:	eb d3                	jmp    402770 <.text+0x5d0>
  40279d:	8d 76 00             	lea    0x0(%esi),%esi
  4027a0:	57                   	push   %edi
  4027a1:	56                   	push   %esi
  4027a2:	89 c6                	mov    %eax,%esi
  4027a4:	53                   	push   %ebx
  4027a5:	89 d3                	mov    %edx,%ebx
  4027a7:	83 ec 10             	sub    $0x10,%esp
  4027aa:	8b 42 0c             	mov    0xc(%edx),%eax
  4027ad:	03 42 04             	add    0x4(%edx),%eax
  4027b0:	8d 04 85 08 00 00 00 	lea    0x8(,%eax,4),%eax
  4027b7:	89 44 24 04          	mov    %eax,0x4(%esp)
  4027bb:	8b 42 08             	mov    0x8(%edx),%eax
  4027be:	89 04 24             	mov    %eax,(%esp)
  4027c1:	e8 1a 15 00 00       	call   403ce0 <___mingw_realloc>
  4027c6:	85 c0                	test   %eax,%eax
  4027c8:	74 26                	je     4027f0 <.text+0x650>
  4027ca:	8b 4b 04             	mov    0x4(%ebx),%ecx
  4027cd:	8b 53 0c             	mov    0xc(%ebx),%edx
  4027d0:	89 43 08             	mov    %eax,0x8(%ebx)
  4027d3:	8d 79 01             	lea    0x1(%ecx),%edi
  4027d6:	01 d1                	add    %edx,%ecx
  4027d8:	01 fa                	add    %edi,%edx
  4027da:	89 7b 04             	mov    %edi,0x4(%ebx)
  4027dd:	89 34 88             	mov    %esi,(%eax,%ecx,4)
  4027e0:	c7 04 90 00 00 00 00 	movl   $0x0,(%eax,%edx,4)
  4027e7:	83 c4 10             	add    $0x10,%esp
  4027ea:	31 c0                	xor    %eax,%eax
  4027ec:	5b                   	pop    %ebx
  4027ed:	5e                   	pop    %esi
  4027ee:	5f                   	pop    %edi
  4027ef:	c3                   	ret    
  4027f0:	83 c4 10             	add    $0x10,%esp
  4027f3:	b8 01 00 00 00       	mov    $0x1,%eax
  4027f8:	5b                   	pop    %ebx
  4027f9:	5e                   	pop    %esi
  4027fa:	5f                   	pop    %edi
  4027fb:	c3                   	ret    
  4027fc:	8d 74 26 00          	lea    0x0(%esi,%eiz,1),%esi
  402800:	56                   	push   %esi
  402801:	89 d6                	mov    %edx,%esi
  402803:	53                   	push   %ebx
  402804:	89 c3                	mov    %eax,%ebx
  402806:	83 ec 14             	sub    $0x14,%esp
  402809:	8b 00                	mov    (%eax),%eax
  40280b:	85 c0                	test   %eax,%eax
  40280d:	74 05                	je     402814 <.text+0x674>
  40280f:	e8 ec ff ff ff       	call   402800 <.text+0x660>
  402814:	8b 43 08             	mov    0x8(%ebx),%eax
  402817:	85 c0                	test   %eax,%eax
  402819:	74 04                	je     40281f <.text+0x67f>
  40281b:	85 f6                	test   %esi,%esi
  40281d:	75 21                	jne    402840 <.text+0x6a0>
  40281f:	8b 43 04             	mov    0x4(%ebx),%eax
  402822:	85 c0                	test   %eax,%eax
  402824:	74 07                	je     40282d <.text+0x68d>
  402826:	89 f2                	mov    %esi,%edx
  402828:	e8 d3 ff ff ff       	call   402800 <.text+0x660>
  40282d:	89 1c 24             	mov    %ebx,(%esp)
  402830:	e8 3b f9 ff ff       	call   402170 <___mingw_aligned_free>
  402835:	83 c4 14             	add    $0x14,%esp
  402838:	5b                   	pop    %ebx
  402839:	5e                   	pop    %esi
  40283a:	c3                   	ret    
  40283b:	8d 74 26 00          	lea    0x0(%esi,%eiz,1),%esi
  40283f:	90                   	nop
  402840:	89 f2                	mov    %esi,%edx
  402842:	e8 59 ff ff ff       	call   4027a0 <.text+0x600>
  402847:	eb d6                	jmp    40281f <.text+0x67f>
  402849:	8d b4 26 00 00 00 00 	lea    0x0(%esi,%eiz,1),%esi
  402850:	56                   	push   %esi
  402851:	89 c6                	mov    %eax,%esi
  402853:	53                   	push   %ebx
  402854:	83 ec 14             	sub    $0x14,%esp
  402857:	8b 40 0c             	mov    0xc(%eax),%eax
  40285a:	8d 58 01             	lea    0x1(%eax),%ebx
  40285d:	8d 04 9d 00 00 00 00 	lea    0x0(,%ebx,4),%eax
  402864:	89 04 24             	mov    %eax,(%esp)
  402867:	e8 70 16 00 00       	call   403edc <_malloc>
  40286c:	89 46 08             	mov    %eax,0x8(%esi)
  40286f:	85 c0                	test   %eax,%eax
  402871:	74 21                	je     402894 <.text+0x6f4>
  402873:	c7 46 04 00 00 00 00 	movl   $0x0,0x4(%esi)
  40287a:	85 db                	test   %ebx,%ebx
  40287c:	7e 0e                	jle    40288c <.text+0x6ec>
  40287e:	66 90                	xchg   %ax,%ax
  402880:	83 eb 01             	sub    $0x1,%ebx
  402883:	c7 04 98 00 00 00 00 	movl   $0x0,(%eax,%ebx,4)
  40288a:	75 f4                	jne    402880 <.text+0x6e0>
  40288c:	31 c0                	xor    %eax,%eax
  40288e:	83 c4 14             	add    $0x14,%esp
  402891:	5b                   	pop    %ebx
  402892:	5e                   	pop    %esi
  402893:	c3                   	ret    
  402894:	b8 03 00 00 00       	mov    $0x3,%eax
  402899:	eb f3                	jmp    40288e <.text+0x6ee>
  40289b:	8d 74 26 00          	lea    0x0(%esi,%eiz,1),%esi
  40289f:	90                   	nop
  4028a0:	55                   	push   %ebp
  4028a1:	89 e5                	mov    %esp,%ebp
  4028a3:	57                   	push   %edi
  4028a4:	56                   	push   %esi
  4028a5:	53                   	push   %ebx
  4028a6:	83 ec 6c             	sub    $0x6c,%esp
  4028a9:	89 45 c4             	mov    %eax,-0x3c(%ebp)
  4028ac:	89 55 d0             	mov    %edx,-0x30(%ebp)
  4028af:	89 4d c8             	mov    %ecx,-0x38(%ebp)
  4028b2:	80 e6 04             	and    $0x4,%dh
  4028b5:	0f 85 3d 01 00 00    	jne    4029f8 <.text+0x858>
  4028bb:	8b 7d c4             	mov    -0x3c(%ebp),%edi
  4028be:	89 65 bc             	mov    %esp,-0x44(%ebp)
  4028c1:	89 3c 24             	mov    %edi,(%esp)
  4028c4:	e8 db 15 00 00       	call   403ea4 <_strlen>
  4028c9:	8d 50 01             	lea    0x1(%eax),%edx
  4028cc:	83 c0 10             	add    $0x10,%eax
  4028cf:	c1 e8 04             	shr    $0x4,%eax
  4028d2:	c1 e0 04             	shl    $0x4,%eax
  4028d5:	e8 76 15 00 00       	call   403e50 <___chkstk_ms>
  4028da:	29 c4                	sub    %eax,%esp
  4028dc:	8d 44 24 0c          	lea    0xc(%esp),%eax
  4028e0:	89 54 24 08          	mov    %edx,0x8(%esp)
  4028e4:	89 7c 24 04          	mov    %edi,0x4(%esp)
  4028e8:	89 04 24             	mov    %eax,(%esp)
  4028eb:	e8 dc 15 00 00       	call   403ecc <_memcpy>
  4028f0:	89 04 24             	mov    %eax,(%esp)
  4028f3:	e8 a8 09 00 00       	call   4032a0 <___mingw_dirname>
  4028f8:	c7 45 e4 00 00 00 00 	movl   $0x0,-0x1c(%ebp)
  4028ff:	89 45 c0             	mov    %eax,-0x40(%ebp)
  402902:	89 c7                	mov    %eax,%edi
  402904:	8d 45 d8             	lea    -0x28(%ebp),%eax
  402907:	e8 44 ff ff ff       	call   402850 <.text+0x6b0>
  40290c:	89 45 d4             	mov    %eax,-0x2c(%ebp)
  40290f:	85 c0                	test   %eax,%eax
  402911:	0f 85 81 03 00 00    	jne    402c98 <.text+0xaf8>
  402917:	85 ff                	test   %edi,%edi
  402919:	74 12                	je     40292d <.text+0x78d>
  40291b:	8b 55 d0             	mov    -0x30(%ebp),%edx
  40291e:	89 f8                	mov    %edi,%eax
  402920:	e8 db fd ff ff       	call   402700 <.text+0x560>
  402925:	85 c0                	test   %eax,%eax
  402927:	0f 85 f9 05 00 00    	jne    402f26 <.text+0xd86>
  40292d:	8b 75 c0             	mov    -0x40(%ebp),%esi
  402930:	89 e3                	mov    %esp,%ebx
  402932:	89 34 24             	mov    %esi,(%esp)
  402935:	e8 6a 15 00 00       	call   403ea4 <_strlen>
  40293a:	83 c0 10             	add    $0x10,%eax
  40293d:	c1 e8 04             	shr    $0x4,%eax
  402940:	c1 e0 04             	shl    $0x4,%eax
  402943:	e8 08 15 00 00       	call   403e50 <___chkstk_ms>
  402948:	29 c4                	sub    %eax,%esp
  40294a:	89 f2                	mov    %esi,%edx
  40294c:	8d 7c 24 0c          	lea    0xc(%esp),%edi
  402950:	89 f9                	mov    %edi,%ecx
  402952:	eb 10                	jmp    402964 <.text+0x7c4>
  402954:	8d 74 26 00          	lea    0x0(%esi,%eiz,1),%esi
  402958:	83 c1 01             	add    $0x1,%ecx
  40295b:	89 f2                	mov    %esi,%edx
  40295d:	88 41 ff             	mov    %al,-0x1(%ecx)
  402960:	84 c0                	test   %al,%al
  402962:	74 1b                	je     40297f <.text+0x7df>
  402964:	0f b6 02             	movzbl (%edx),%eax
  402967:	8d 72 01             	lea    0x1(%edx),%esi
  40296a:	3c 7f                	cmp    $0x7f,%al
  40296c:	75 ea                	jne    402958 <.text+0x7b8>
  40296e:	0f b6 42 01          	movzbl 0x1(%edx),%eax
  402972:	83 c1 01             	add    $0x1,%ecx
  402975:	83 c2 02             	add    $0x2,%edx
  402978:	88 41 ff             	mov    %al,-0x1(%ecx)
  40297b:	84 c0                	test   %al,%al
  40297d:	75 e5                	jne    402964 <.text+0x7c4>
  40297f:	89 3c 24             	mov    %edi,(%esp)
  402982:	e8 fd 14 00 00       	call   403e84 <_strdup>
  402987:	c7 45 d4 01 00 00 00 	movl   $0x1,-0x2c(%ebp)
  40298e:	89 dc                	mov    %ebx,%esp
  402990:	85 c0                	test   %eax,%eax
  402992:	0f 84 00 03 00 00    	je     402c98 <.text+0xaf8>
  402998:	8d 55 d8             	lea    -0x28(%ebp),%edx
  40299b:	e8 00 fe ff ff       	call   4027a0 <.text+0x600>
  4029a0:	89 45 d4             	mov    %eax,-0x2c(%ebp)
  4029a3:	8b 4d d4             	mov    -0x2c(%ebp),%ecx
  4029a6:	85 c9                	test   %ecx,%ecx
  4029a8:	0f 85 ea 02 00 00    	jne    402c98 <.text+0xaf8>
  4029ae:	8b 5d c4             	mov    -0x3c(%ebp),%ebx
  4029b1:	0f b6 43 01          	movzbl 0x1(%ebx),%eax
  4029b5:	3c 2f                	cmp    $0x2f,%al
  4029b7:	0f 84 33 03 00 00    	je     402cf0 <.text+0xb50>
  4029bd:	3c 5c                	cmp    $0x5c,%al
  4029bf:	0f 84 2b 03 00 00    	je     402cf0 <.text+0xb50>
  4029c5:	8b 45 c0             	mov    -0x40(%ebp),%eax
  4029c8:	80 38 2e             	cmpb   $0x2e,(%eax)
  4029cb:	0f 85 1f 03 00 00    	jne    402cf0 <.text+0xb50>
  4029d1:	80 78 01 00          	cmpb   $0x0,0x1(%eax)
  4029d5:	0f 85 15 03 00 00    	jne    402cf0 <.text+0xb50>
  4029db:	f6 45 d0 10          	testb  $0x10,-0x30(%ebp)
  4029df:	0f 85 af 06 00 00    	jne    403094 <.text+0xef4>
  4029e5:	c6 45 9f 5c          	movb   $0x5c,-0x61(%ebp)
  4029e9:	c7 45 c0 00 00 00 00 	movl   $0x0,-0x40(%ebp)
  4029f0:	e9 4e 03 00 00       	jmp    402d43 <.text+0xba3>
  4029f5:	8d 76 00             	lea    0x0(%esi),%esi
  4029f8:	89 65 b8             	mov    %esp,-0x48(%ebp)
  4029fb:	89 c6                	mov    %eax,%esi
  4029fd:	89 04 24             	mov    %eax,(%esp)
  402a00:	e8 9f 14 00 00       	call   403ea4 <_strlen>
  402a05:	83 c0 10             	add    $0x10,%eax
  402a08:	c1 e8 04             	shr    $0x4,%eax
  402a0b:	c1 e0 04             	shl    $0x4,%eax
  402a0e:	e8 3d 14 00 00       	call   403e50 <___chkstk_ms>
  402a13:	0f b6 1e             	movzbl (%esi),%ebx
  402a16:	29 c4                	sub    %eax,%esp
  402a18:	8d 7c 24 0c          	lea    0xc(%esp),%edi
  402a1c:	89 7d bc             	mov    %edi,-0x44(%ebp)
  402a1f:	8d 4e 01             	lea    0x1(%esi),%ecx
  402a22:	80 fb 7f             	cmp    $0x7f,%bl
  402a25:	74 22                	je     402a49 <.text+0x8a9>
  402a27:	80 fb 7b             	cmp    $0x7b,%bl
  402a2a:	74 44                	je     402a70 <.text+0x8d0>
  402a2c:	88 1f                	mov    %bl,(%edi)
  402a2e:	8d 47 01             	lea    0x1(%edi),%eax
  402a31:	84 db                	test   %bl,%bl
  402a33:	0f 84 99 02 00 00    	je     402cd2 <.text+0xb32>
  402a39:	0f b6 5e 01          	movzbl 0x1(%esi),%ebx
  402a3d:	89 ce                	mov    %ecx,%esi
  402a3f:	89 c7                	mov    %eax,%edi
  402a41:	8d 4e 01             	lea    0x1(%esi),%ecx
  402a44:	80 fb 7f             	cmp    $0x7f,%bl
  402a47:	75 de                	jne    402a27 <.text+0x887>
  402a49:	0f b6 5e 01          	movzbl 0x1(%esi),%ebx
  402a4d:	c6 07 7f             	movb   $0x7f,(%edi)
  402a50:	84 db                	test   %bl,%bl
  402a52:	75 0c                	jne    402a60 <.text+0x8c0>
  402a54:	8d 46 02             	lea    0x2(%esi),%eax
  402a57:	83 c7 01             	add    $0x1,%edi
  402a5a:	89 ce                	mov    %ecx,%esi
  402a5c:	89 c1                	mov    %eax,%ecx
  402a5e:	eb cc                	jmp    402a2c <.text+0x88c>
  402a60:	88 5f 01             	mov    %bl,0x1(%edi)
  402a63:	83 c6 02             	add    $0x2,%esi
  402a66:	0f b6 1e             	movzbl (%esi),%ebx
  402a69:	83 c7 02             	add    $0x2,%edi
  402a6c:	eb b1                	jmp    402a1f <.text+0x87f>
  402a6e:	66 90                	xchg   %ax,%ax
  402a70:	0f b6 5e 01          	movzbl 0x1(%esi),%ebx
  402a74:	89 f2                	mov    %esi,%edx
  402a76:	89 75 c0             	mov    %esi,-0x40(%ebp)
  402a79:	89 4d d4             	mov    %ecx,-0x2c(%ebp)
  402a7c:	8d 72 01             	lea    0x1(%edx),%esi
  402a7f:	b9 01 00 00 00       	mov    $0x1,%ecx
  402a84:	89 d8                	mov    %ebx,%eax
  402a86:	c7 45 cc 2c 00 00 00 	movl   $0x2c,-0x34(%ebp)
  402a8d:	3c 7b                	cmp    $0x7b,%al
  402a8f:	74 2b                	je     402abc <.text+0x91c>
  402a91:	8d b4 26 00 00 00 00 	lea    0x0(%esi,%eiz,1),%esi
  402a98:	7f 36                	jg     402ad0 <.text+0x930>
  402a9a:	84 c0                	test   %al,%al
  402a9c:	0f 84 1e 01 00 00    	je     402bc0 <.text+0xa20>
  402aa2:	3c 2c                	cmp    $0x2c,%al
  402aa4:	75 09                	jne    402aaf <.text+0x90f>
  402aa6:	83 f9 01             	cmp    $0x1,%ecx
  402aa9:	0f 84 11 02 00 00    	je     402cc0 <.text+0xb20>
  402aaf:	0f b6 42 02          	movzbl 0x2(%edx),%eax
  402ab3:	89 f2                	mov    %esi,%edx
  402ab5:	8d 72 01             	lea    0x1(%edx),%esi
  402ab8:	3c 7b                	cmp    $0x7b,%al
  402aba:	75 dc                	jne    402a98 <.text+0x8f8>
  402abc:	0f b6 42 02          	movzbl 0x2(%edx),%eax
  402ac0:	83 c1 01             	add    $0x1,%ecx
  402ac3:	89 f2                	mov    %esi,%edx
  402ac5:	eb ee                	jmp    402ab5 <.text+0x915>
  402ac7:	8d b4 26 00 00 00 00 	lea    0x0(%esi,%eiz,1),%esi
  402ace:	66 90                	xchg   %ax,%ax
  402ad0:	3c 7d                	cmp    $0x7d,%al
  402ad2:	0f 85 18 01 00 00    	jne    402bf0 <.text+0xa50>
  402ad8:	83 e9 01             	sub    $0x1,%ecx
  402adb:	75 d2                	jne    402aaf <.text+0x90f>
  402add:	83 7d cc 7b          	cmpl   $0x7b,-0x34(%ebp)
  402ae1:	8b 75 c0             	mov    -0x40(%ebp),%esi
  402ae4:	8b 4d d4             	mov    -0x2c(%ebp),%ecx
  402ae7:	0f 85 d6 00 00 00    	jne    402bc3 <.text+0xa23>
  402aed:	89 7d d4             	mov    %edi,-0x2c(%ebp)
  402af0:	8b 7d d0             	mov    -0x30(%ebp),%edi
  402af3:	8b 45 d4             	mov    -0x2c(%ebp),%eax
  402af6:	ba 01 00 00 00       	mov    $0x1,%edx
  402afb:	80 fb 7f             	cmp    $0x7f,%bl
  402afe:	0f 84 98 00 00 00    	je     402b9c <.text+0x9fc>
  402b04:	8d 74 26 00          	lea    0x0(%esi,%eiz,1),%esi
  402b08:	83 c6 01             	add    $0x1,%esi
  402b0b:	89 c1                	mov    %eax,%ecx
  402b0d:	80 fb 7d             	cmp    $0x7d,%bl
  402b10:	74 6e                	je     402b80 <.text+0x9e0>
  402b12:	80 fb 2c             	cmp    $0x2c,%bl
  402b15:	0f 85 b5 00 00 00    	jne    402bd0 <.text+0xa30>
  402b1b:	83 fa 01             	cmp    $0x1,%edx
  402b1e:	0f 85 ac 00 00 00    	jne    402bd0 <.text+0xa30>
  402b24:	89 f2                	mov    %esi,%edx
  402b26:	bb 01 00 00 00       	mov    $0x1,%ebx
  402b2b:	8d 74 26 00          	lea    0x0(%esi,%eiz,1),%esi
  402b2f:	90                   	nop
  402b30:	8d 42 01             	lea    0x1(%edx),%eax
  402b33:	0f b6 52 01          	movzbl 0x1(%edx),%edx
  402b37:	80 fa 7f             	cmp    $0x7f,%dl
  402b3a:	74 1c                	je     402b58 <.text+0x9b8>
  402b3c:	e9 ef 00 00 00       	jmp    402c30 <.text+0xa90>
  402b41:	8d b4 26 00 00 00 00 	lea    0x0(%esi,%eiz,1),%esi
  402b48:	0f b6 50 02          	movzbl 0x2(%eax),%edx
  402b4c:	83 c0 02             	add    $0x2,%eax
  402b4f:	80 fa 7f             	cmp    $0x7f,%dl
  402b52:	0f 85 d8 00 00 00    	jne    402c30 <.text+0xa90>
  402b58:	80 78 01 00          	cmpb   $0x0,0x1(%eax)
  402b5c:	75 ea                	jne    402b48 <.text+0x9a8>
  402b5e:	c6 01 00             	movb   $0x0,(%ecx)
  402b61:	c7 45 d4 01 00 00 00 	movl   $0x1,-0x2c(%ebp)
  402b68:	8b 65 b8             	mov    -0x48(%ebp),%esp
  402b6b:	8b 45 d4             	mov    -0x2c(%ebp),%eax
  402b6e:	8d 65 f4             	lea    -0xc(%ebp),%esp
  402b71:	5b                   	pop    %ebx
  402b72:	5e                   	pop    %esi
  402b73:	5f                   	pop    %edi
  402b74:	5d                   	pop    %ebp
  402b75:	c3                   	ret    
  402b76:	8d b4 26 00 00 00 00 	lea    0x0(%esi,%eiz,1),%esi
  402b7d:	8d 76 00             	lea    0x0(%esi),%esi
  402b80:	83 ea 01             	sub    $0x1,%edx
  402b83:	0f 84 c7 00 00 00    	je     402c50 <.text+0xab0>
  402b89:	c6 01 7d             	movb   $0x7d,(%ecx)
  402b8c:	8d 41 01             	lea    0x1(%ecx),%eax
  402b8f:	0f b6 5e 01          	movzbl 0x1(%esi),%ebx
  402b93:	80 fb 7f             	cmp    $0x7f,%bl
  402b96:	0f 85 6c ff ff ff    	jne    402b08 <.text+0x968>
  402b9c:	0f b6 5e 02          	movzbl 0x2(%esi),%ebx
  402ba0:	c6 00 7f             	movb   $0x7f,(%eax)
  402ba3:	8d 48 02             	lea    0x2(%eax),%ecx
  402ba6:	88 58 01             	mov    %bl,0x1(%eax)
  402ba9:	84 db                	test   %bl,%bl
  402bab:	74 6b                	je     402c18 <.text+0xa78>
  402bad:	0f b6 5e 03          	movzbl 0x3(%esi),%ebx
  402bb1:	83 c6 03             	add    $0x3,%esi
  402bb4:	e9 54 ff ff ff       	jmp    402b0d <.text+0x96d>
  402bb9:	8d b4 26 00 00 00 00 	lea    0x0(%esi,%eiz,1),%esi
  402bc0:	8b 4d d4             	mov    -0x2c(%ebp),%ecx
  402bc3:	c6 07 7b             	movb   $0x7b,(%edi)
  402bc6:	89 ce                	mov    %ecx,%esi
  402bc8:	83 c7 01             	add    $0x1,%edi
  402bcb:	e9 4f fe ff ff       	jmp    402a1f <.text+0x87f>
  402bd0:	8d 41 01             	lea    0x1(%ecx),%eax
  402bd3:	80 fb 7b             	cmp    $0x7b,%bl
  402bd6:	75 08                	jne    402be0 <.text+0xa40>
  402bd8:	c6 01 7b             	movb   $0x7b,(%ecx)
  402bdb:	83 c2 01             	add    $0x1,%edx
  402bde:	eb af                	jmp    402b8f <.text+0x9ef>
  402be0:	88 19                	mov    %bl,(%ecx)
  402be2:	84 db                	test   %bl,%bl
  402be4:	75 a9                	jne    402b8f <.text+0x9ef>
  402be6:	eb 34                	jmp    402c1c <.text+0xa7c>
  402be8:	8d b4 26 00 00 00 00 	lea    0x0(%esi,%eiz,1),%esi
  402bef:	90                   	nop
  402bf0:	3c 7f                	cmp    $0x7f,%al
  402bf2:	0f 85 b7 fe ff ff    	jne    402aaf <.text+0x90f>
  402bf8:	0f b6 42 02          	movzbl 0x2(%edx),%eax
  402bfc:	84 c0                	test   %al,%al
  402bfe:	0f 84 af fe ff ff    	je     402ab3 <.text+0x913>
  402c04:	8d 72 02             	lea    0x2(%edx),%esi
  402c07:	0f b6 42 03          	movzbl 0x3(%edx),%eax
  402c0b:	89 f2                	mov    %esi,%edx
  402c0d:	e9 a3 fe ff ff       	jmp    402ab5 <.text+0x915>
  402c12:	8d b6 00 00 00 00    	lea    0x0(%esi),%esi
  402c18:	c6 40 02 00          	movb   $0x0,0x2(%eax)
  402c1c:	c7 45 d4 01 00 00 00 	movl   $0x1,-0x2c(%ebp)
  402c23:	e9 40 ff ff ff       	jmp    402b68 <.text+0x9c8>
  402c28:	8d b4 26 00 00 00 00 	lea    0x0(%esi,%eiz,1),%esi
  402c2f:	90                   	nop
  402c30:	80 fa 7b             	cmp    $0x7b,%dl
  402c33:	74 7b                	je     402cb0 <.text+0xb10>
  402c35:	80 fa 7d             	cmp    $0x7d,%dl
  402c38:	0f 84 a2 00 00 00    	je     402ce0 <.text+0xb40>
  402c3e:	84 d2                	test   %dl,%dl
  402c40:	0f 84 18 ff ff ff    	je     402b5e <.text+0x9be>
  402c46:	89 c2                	mov    %eax,%edx
  402c48:	e9 e3 fe ff ff       	jmp    402b30 <.text+0x990>
  402c4d:	8d 76 00             	lea    0x0(%esi),%esi
  402c50:	89 f0                	mov    %esi,%eax
  402c52:	83 c0 01             	add    $0x1,%eax
  402c55:	8d 76 00             	lea    0x0(%esi),%esi
  402c58:	0f b6 10             	movzbl (%eax),%edx
  402c5b:	83 c1 01             	add    $0x1,%ecx
  402c5e:	83 c0 01             	add    $0x1,%eax
  402c61:	88 51 ff             	mov    %dl,-0x1(%ecx)
  402c64:	84 d2                	test   %dl,%dl
  402c66:	75 f0                	jne    402c58 <.text+0xab8>
  402c68:	8b 45 08             	mov    0x8(%ebp),%eax
  402c6b:	89 fa                	mov    %edi,%edx
  402c6d:	83 cf 01             	or     $0x1,%edi
  402c70:	89 04 24             	mov    %eax,(%esp)
  402c73:	8b 4d c8             	mov    -0x38(%ebp),%ecx
  402c76:	8b 45 bc             	mov    -0x44(%ebp),%eax
  402c79:	e8 22 fc ff ff       	call   4028a0 <.text+0x700>
  402c7e:	83 f8 01             	cmp    $0x1,%eax
  402c81:	74 99                	je     402c1c <.text+0xa7c>
  402c83:	80 3e 2c             	cmpb   $0x2c,(%esi)
  402c86:	0f 85 92 02 00 00    	jne    402f1e <.text+0xd7e>
  402c8c:	0f b6 5e 01          	movzbl 0x1(%esi),%ebx
  402c90:	e9 5e fe ff ff       	jmp    402af3 <.text+0x953>
  402c95:	8d 76 00             	lea    0x0(%esi),%esi
  402c98:	8b 45 d4             	mov    -0x2c(%ebp),%eax
  402c9b:	8b 65 bc             	mov    -0x44(%ebp),%esp
  402c9e:	8d 65 f4             	lea    -0xc(%ebp),%esp
  402ca1:	5b                   	pop    %ebx
  402ca2:	5e                   	pop    %esi
  402ca3:	5f                   	pop    %edi
  402ca4:	5d                   	pop    %ebp
  402ca5:	c3                   	ret    
  402ca6:	8d b4 26 00 00 00 00 	lea    0x0(%esi,%eiz,1),%esi
  402cad:	8d 76 00             	lea    0x0(%esi),%esi
  402cb0:	83 c3 01             	add    $0x1,%ebx
  402cb3:	89 c2                	mov    %eax,%edx
  402cb5:	e9 76 fe ff ff       	jmp    402b30 <.text+0x990>
  402cba:	8d b6 00 00 00 00    	lea    0x0(%esi),%esi
  402cc0:	0f b6 42 02          	movzbl 0x2(%edx),%eax
  402cc4:	c7 45 cc 7b 00 00 00 	movl   $0x7b,-0x34(%ebp)
  402ccb:	89 f2                	mov    %esi,%edx
  402ccd:	e9 e3 fd ff ff       	jmp    402ab5 <.text+0x915>
  402cd2:	8b 65 b8             	mov    -0x48(%ebp),%esp
  402cd5:	e9 e1 fb ff ff       	jmp    4028bb <.text+0x71b>
  402cda:	8d b6 00 00 00 00    	lea    0x0(%esi),%esi
  402ce0:	83 eb 01             	sub    $0x1,%ebx
  402ce3:	0f 84 69 ff ff ff    	je     402c52 <.text+0xab2>
  402ce9:	89 c2                	mov    %eax,%edx
  402ceb:	e9 40 fe ff ff       	jmp    402b30 <.text+0x990>
  402cf0:	8b 45 c0             	mov    -0x40(%ebp),%eax
  402cf3:	89 04 24             	mov    %eax,(%esp)
  402cf6:	e8 a9 11 00 00       	call   403ea4 <_strlen>
  402cfb:	8b 7d c4             	mov    -0x3c(%ebp),%edi
  402cfe:	8b 55 c4             	mov    -0x3c(%ebp),%edx
  402d01:	8d 1c 07             	lea    (%edi,%eax,1),%ebx
  402d04:	0f b6 03             	movzbl (%ebx),%eax
  402d07:	39 df                	cmp    %ebx,%edi
  402d09:	73 17                	jae    402d22 <.text+0xb82>
  402d0b:	8d 74 26 00          	lea    0x0(%esi,%eiz,1),%esi
  402d0f:	90                   	nop
  402d10:	3c 2f                	cmp    $0x2f,%al
  402d12:	74 1c                	je     402d30 <.text+0xb90>
  402d14:	3c 5c                	cmp    $0x5c,%al
  402d16:	74 0a                	je     402d22 <.text+0xb82>
  402d18:	83 eb 01             	sub    $0x1,%ebx
  402d1b:	0f b6 03             	movzbl (%ebx),%eax
  402d1e:	39 da                	cmp    %ebx,%edx
  402d20:	75 ee                	jne    402d10 <.text+0xb70>
  402d22:	3c 2f                	cmp    $0x2f,%al
  402d24:	74 0a                	je     402d30 <.text+0xb90>
  402d26:	3c 5c                	cmp    $0x5c,%al
  402d28:	74 06                	je     402d30 <.text+0xb90>
  402d2a:	c6 45 9f 5c          	movb   $0x5c,-0x61(%ebp)
  402d2e:	eb 13                	jmp    402d43 <.text+0xba3>
  402d30:	83 c3 01             	add    $0x1,%ebx
  402d33:	89 c2                	mov    %eax,%edx
  402d35:	0f b6 03             	movzbl (%ebx),%eax
  402d38:	3c 2f                	cmp    $0x2f,%al
  402d3a:	74 f4                	je     402d30 <.text+0xb90>
  402d3c:	3c 5c                	cmp    $0x5c,%al
  402d3e:	74 f0                	je     402d30 <.text+0xb90>
  402d40:	88 55 9f             	mov    %dl,-0x61(%ebp)
  402d43:	8b 7d e0             	mov    -0x20(%ebp),%edi
  402d46:	c7 45 d4 02 00 00 00 	movl   $0x2,-0x2c(%ebp)
  402d4d:	8b 07                	mov    (%edi),%eax
  402d4f:	85 c0                	test   %eax,%eax
  402d51:	0f 84 36 02 00 00    	je     402f8d <.text+0xded>
  402d57:	8b 4d d0             	mov    -0x30(%ebp),%ecx
  402d5a:	89 5d b8             	mov    %ebx,-0x48(%ebp)
  402d5d:	89 fb                	mov    %edi,%ebx
  402d5f:	81 e1 00 80 00 00    	and    $0x8000,%ecx
  402d65:	89 4d c4             	mov    %ecx,-0x3c(%ebp)
  402d68:	eb 4c                	jmp    402db6 <.text+0xc16>
  402d6a:	8d b6 00 00 00 00    	lea    0x0(%esi),%esi
  402d70:	f6 45 d0 04          	testb  $0x4,-0x30(%ebp)
  402d74:	75 22                	jne    402d98 <.text+0xbf8>
  402d76:	8b 7d c8             	mov    -0x38(%ebp),%edi
  402d79:	85 ff                	test   %edi,%edi
  402d7b:	74 22                	je     402d9f <.text+0xbff>
  402d7d:	e8 9a 11 00 00       	call   403f1c <__errno>
  402d82:	8b 00                	mov    (%eax),%eax
  402d84:	89 44 24 04          	mov    %eax,0x4(%esp)
  402d88:	8b 03                	mov    (%ebx),%eax
  402d8a:	89 04 24             	mov    %eax,(%esp)
  402d8d:	ff d7                	call   *%edi
  402d8f:	85 c0                	test   %eax,%eax
  402d91:	74 0c                	je     402d9f <.text+0xbff>
  402d93:	8d 74 26 00          	lea    0x0(%esi,%eiz,1),%esi
  402d97:	90                   	nop
  402d98:	c7 45 d4 01 00 00 00 	movl   $0x1,-0x2c(%ebp)
  402d9f:	8b 03                	mov    (%ebx),%eax
  402da1:	83 c3 04             	add    $0x4,%ebx
  402da4:	89 04 24             	mov    %eax,(%esp)
  402da7:	e8 c4 f3 ff ff       	call   402170 <___mingw_aligned_free>
  402dac:	8b 03                	mov    (%ebx),%eax
  402dae:	85 c0                	test   %eax,%eax
  402db0:	0f 84 e7 01 00 00    	je     402f9d <.text+0xdfd>
  402db6:	83 7d d4 01          	cmpl   $0x1,-0x2c(%ebp)
  402dba:	74 dc                	je     402d98 <.text+0xbf8>
  402dbc:	89 04 24             	mov    %eax,(%esp)
  402dbf:	e8 ac 0a 00 00       	call   403870 <___mingw_opendir>
  402dc4:	89 45 cc             	mov    %eax,-0x34(%ebp)
  402dc7:	85 c0                	test   %eax,%eax
  402dc9:	74 a5                	je     402d70 <.text+0xbd0>
  402dcb:	8b 45 c0             	mov    -0x40(%ebp),%eax
  402dce:	c7 45 b4 00 00 00 00 	movl   $0x0,-0x4c(%ebp)
  402dd5:	85 c0                	test   %eax,%eax
  402dd7:	74 0d                	je     402de6 <.text+0xc46>
  402dd9:	8b 03                	mov    (%ebx),%eax
  402ddb:	89 04 24             	mov    %eax,(%esp)
  402dde:	e8 c1 10 00 00       	call   403ea4 <_strlen>
  402de3:	89 45 b4             	mov    %eax,-0x4c(%ebp)
  402de6:	8b 45 b4             	mov    -0x4c(%ebp),%eax
  402de9:	c7 45 b0 00 00 00 00 	movl   $0x0,-0x50(%ebp)
  402df0:	83 c0 02             	add    $0x2,%eax
  402df3:	89 45 a0             	mov    %eax,-0x60(%ebp)
  402df6:	8d b4 26 00 00 00 00 	lea    0x0(%esi,%eiz,1),%esi
  402dfd:	8d 76 00             	lea    0x0(%esi),%esi
  402e00:	8b 45 cc             	mov    -0x34(%ebp),%eax
  402e03:	89 04 24             	mov    %eax,(%esp)
  402e06:	e8 65 0c 00 00       	call   403a70 <___mingw_readdir>
  402e0b:	89 c6                	mov    %eax,%esi
  402e0d:	85 c0                	test   %eax,%eax
  402e0f:	0f 84 30 01 00 00    	je     402f45 <.text+0xda5>
  402e15:	8b 7d c4             	mov    -0x3c(%ebp),%edi
  402e18:	85 ff                	test   %edi,%edi
  402e1a:	74 06                	je     402e22 <.text+0xc82>
  402e1c:	83 7e 08 10          	cmpl   $0x10,0x8(%esi)
  402e20:	75 de                	jne    402e00 <.text+0xc60>
  402e22:	8d 7e 0c             	lea    0xc(%esi),%edi
  402e25:	8b 4d d0             	mov    -0x30(%ebp),%ecx
  402e28:	8b 45 b8             	mov    -0x48(%ebp),%eax
  402e2b:	89 fa                	mov    %edi,%edx
  402e2d:	e8 9e f6 ff ff       	call   4024d0 <.text+0x330>
  402e32:	85 c0                	test   %eax,%eax
  402e34:	75 ca                	jne    402e00 <.text+0xc60>
  402e36:	0f b7 4e 06          	movzwl 0x6(%esi),%ecx
  402e3a:	8b 45 a0             	mov    -0x60(%ebp),%eax
  402e3d:	89 65 ac             	mov    %esp,-0x54(%ebp)
  402e40:	8d 44 01 0f          	lea    0xf(%ecx,%eax,1),%eax
  402e44:	c1 e8 04             	shr    $0x4,%eax
  402e47:	c1 e0 04             	shl    $0x4,%eax
  402e4a:	e8 01 10 00 00       	call   403e50 <___chkstk_ms>
  402e4f:	8b 75 b4             	mov    -0x4c(%ebp),%esi
  402e52:	29 c4                	sub    %eax,%esp
  402e54:	8d 54 24 0c          	lea    0xc(%esp),%edx
  402e58:	89 55 a8             	mov    %edx,-0x58(%ebp)
  402e5b:	89 d0                	mov    %edx,%eax
  402e5d:	85 f6                	test   %esi,%esi
  402e5f:	0f 85 3f 01 00 00    	jne    402fa4 <.text+0xe04>
  402e65:	83 c1 01             	add    $0x1,%ecx
  402e68:	89 55 a4             	mov    %edx,-0x5c(%ebp)
  402e6b:	89 4c 24 08          	mov    %ecx,0x8(%esp)
  402e6f:	89 7c 24 04          	mov    %edi,0x4(%esp)
  402e73:	89 e7                	mov    %esp,%edi
  402e75:	89 04 24             	mov    %eax,(%esp)
  402e78:	e8 4f 10 00 00       	call   403ecc <_memcpy>
  402e7d:	8b 55 a4             	mov    -0x5c(%ebp),%edx
  402e80:	89 14 24             	mov    %edx,(%esp)
  402e83:	e8 1c 10 00 00       	call   403ea4 <_strlen>
  402e88:	83 c0 10             	add    $0x10,%eax
  402e8b:	c1 e8 04             	shr    $0x4,%eax
  402e8e:	c1 e0 04             	shl    $0x4,%eax
  402e91:	e8 ba 0f 00 00       	call   403e50 <___chkstk_ms>
  402e96:	8b 75 a8             	mov    -0x58(%ebp),%esi
  402e99:	29 c4                	sub    %eax,%esp
  402e9b:	8d 44 24 0c          	lea    0xc(%esp),%eax
  402e9f:	89 45 a4             	mov    %eax,-0x5c(%ebp)
  402ea2:	89 c2                	mov    %eax,%edx
  402ea4:	eb 16                	jmp    402ebc <.text+0xd1c>
  402ea6:	8d b4 26 00 00 00 00 	lea    0x0(%esi,%eiz,1),%esi
  402ead:	8d 76 00             	lea    0x0(%esi),%esi
  402eb0:	83 c2 01             	add    $0x1,%edx
  402eb3:	89 ce                	mov    %ecx,%esi
  402eb5:	88 42 ff             	mov    %al,-0x1(%edx)
  402eb8:	84 c0                	test   %al,%al
  402eba:	74 1b                	je     402ed7 <.text+0xd37>
  402ebc:	0f b6 06             	movzbl (%esi),%eax
  402ebf:	8d 4e 01             	lea    0x1(%esi),%ecx
  402ec2:	3c 7f                	cmp    $0x7f,%al
  402ec4:	75 ea                	jne    402eb0 <.text+0xd10>
  402ec6:	0f b6 46 01          	movzbl 0x1(%esi),%eax
  402eca:	83 c2 01             	add    $0x1,%edx
  402ecd:	83 c6 02             	add    $0x2,%esi
  402ed0:	88 42 ff             	mov    %al,-0x1(%edx)
  402ed3:	84 c0                	test   %al,%al
  402ed5:	75 e5                	jne    402ebc <.text+0xd1c>
  402ed7:	8b 45 a4             	mov    -0x5c(%ebp),%eax
  402eda:	89 04 24             	mov    %eax,(%esp)
  402edd:	e8 a2 0f 00 00       	call   403e84 <_strdup>
  402ee2:	89 fc                	mov    %edi,%esp
  402ee4:	89 c6                	mov    %eax,%esi
  402ee6:	85 c0                	test   %eax,%eax
  402ee8:	0f 84 38 02 00 00    	je     403126 <.text+0xf86>
  402eee:	8b 7d d4             	mov    -0x2c(%ebp),%edi
  402ef1:	31 c0                	xor    %eax,%eax
  402ef3:	83 ff 02             	cmp    $0x2,%edi
  402ef6:	0f 94 c0             	sete   %al
  402ef9:	83 e8 01             	sub    $0x1,%eax
  402efc:	21 c7                	and    %eax,%edi
  402efe:	89 7d d4             	mov    %edi,-0x2c(%ebp)
  402f01:	f6 45 d0 40          	testb  $0x40,-0x30(%ebp)
  402f05:	0f 84 e2 00 00 00    	je     402fed <.text+0xe4d>
  402f0b:	8b 55 08             	mov    0x8(%ebp),%edx
  402f0e:	85 d2                	test   %edx,%edx
  402f10:	0f 85 5e 01 00 00    	jne    403074 <.text+0xed4>
  402f16:	8b 65 ac             	mov    -0x54(%ebp),%esp
  402f19:	e9 e2 fe ff ff       	jmp    402e00 <.text+0xc60>
  402f1e:	89 45 d4             	mov    %eax,-0x2c(%ebp)
  402f21:	e9 42 fc ff ff       	jmp    402b68 <.text+0x9c8>
  402f26:	8d 45 d8             	lea    -0x28(%ebp),%eax
  402f29:	8b 55 d0             	mov    -0x30(%ebp),%edx
  402f2c:	89 04 24             	mov    %eax,(%esp)
  402f2f:	8b 4d c8             	mov    -0x38(%ebp),%ecx
  402f32:	8b 45 c0             	mov    -0x40(%ebp),%eax
  402f35:	80 ce 80             	or     $0x80,%dh
  402f38:	e8 63 f9 ff ff       	call   4028a0 <.text+0x700>
  402f3d:	89 45 d4             	mov    %eax,-0x2c(%ebp)
  402f40:	e9 5e fa ff ff       	jmp    4029a3 <.text+0x803>
  402f45:	8b 45 cc             	mov    -0x34(%ebp),%eax
  402f48:	89 04 24             	mov    %eax,(%esp)
  402f4b:	e8 70 0b 00 00       	call   403ac0 <___mingw_closedir>
  402f50:	8b 45 b0             	mov    -0x50(%ebp),%eax
  402f53:	85 c0                	test   %eax,%eax
  402f55:	0f 84 44 fe ff ff    	je     402d9f <.text+0xbff>
  402f5b:	8b 55 08             	mov    0x8(%ebp),%edx
  402f5e:	8b 45 b0             	mov    -0x50(%ebp),%eax
  402f61:	e8 9a f8 ff ff       	call   402800 <.text+0x660>
  402f66:	e9 34 fe ff ff       	jmp    402d9f <.text+0xbff>
  402f6b:	89 34 24             	mov    %esi,(%esp)
  402f6e:	e8 11 0f 00 00       	call   403e84 <_strdup>
  402f73:	89 dc                	mov    %ebx,%esp
  402f75:	85 c0                	test   %eax,%eax
  402f77:	74 24                	je     402f9d <.text+0xdfd>
  402f79:	8b 55 08             	mov    0x8(%ebp),%edx
  402f7c:	85 d2                	test   %edx,%edx
  402f7e:	74 1d                	je     402f9d <.text+0xdfd>
  402f80:	8b 55 08             	mov    0x8(%ebp),%edx
  402f83:	e8 18 f8 ff ff       	call   4027a0 <.text+0x600>
  402f88:	8b 45 e0             	mov    -0x20(%ebp),%eax
  402f8b:	89 c7                	mov    %eax,%edi
  402f8d:	89 3c 24             	mov    %edi,(%esp)
  402f90:	e8 db f1 ff ff       	call   402170 <___mingw_aligned_free>
  402f95:	8b 65 bc             	mov    -0x44(%ebp),%esp
  402f98:	e9 ce fb ff ff       	jmp    402b6b <.text+0x9cb>
  402f9d:	8b 45 e0             	mov    -0x20(%ebp),%eax
  402fa0:	89 c7                	mov    %eax,%edi
  402fa2:	eb e9                	jmp    402f8d <.text+0xded>
  402fa4:	8b 75 b4             	mov    -0x4c(%ebp),%esi
  402fa7:	8b 03                	mov    (%ebx),%eax
  402fa9:	89 4d 98             	mov    %ecx,-0x68(%ebp)
  402fac:	89 14 24             	mov    %edx,(%esp)
  402faf:	89 74 24 08          	mov    %esi,0x8(%esp)
  402fb3:	89 44 24 04          	mov    %eax,0x4(%esp)
  402fb7:	89 55 a4             	mov    %edx,-0x5c(%ebp)
  402fba:	e8 0d 0f 00 00       	call   403ecc <_memcpy>
  402fbf:	0f b6 44 34 0b       	movzbl 0xb(%esp,%esi,1),%eax
  402fc4:	8b 55 a4             	mov    -0x5c(%ebp),%edx
  402fc7:	8b 4d 98             	mov    -0x68(%ebp),%ecx
  402fca:	3c 2f                	cmp    $0x2f,%al
  402fcc:	0f 84 b1 00 00 00    	je     403083 <.text+0xee3>
  402fd2:	3c 5c                	cmp    $0x5c,%al
  402fd4:	0f 84 a9 00 00 00    	je     403083 <.text+0xee3>
  402fda:	8b 75 b4             	mov    -0x4c(%ebp),%esi
  402fdd:	0f b6 45 9f          	movzbl -0x61(%ebp),%eax
  402fe1:	88 04 32             	mov    %al,(%edx,%esi,1)
  402fe4:	8d 44 32 01          	lea    0x1(%edx,%esi,1),%eax
  402fe8:	e9 78 fe ff ff       	jmp    402e65 <.text+0xcc5>
  402fed:	8b 7d b0             	mov    -0x50(%ebp),%edi
  402ff0:	85 ff                	test   %edi,%edi
  402ff2:	0f 84 ff 00 00 00    	je     4030f7 <.text+0xf57>
  402ff8:	8b 45 d0             	mov    -0x30(%ebp),%eax
  402ffb:	89 5d a8             	mov    %ebx,-0x58(%ebp)
  402ffe:	25 00 40 00 00       	and    $0x4000,%eax
  403003:	89 c3                	mov    %eax,%ebx
  403005:	eb 1f                	jmp    403026 <.text+0xe86>
  403007:	8d b4 26 00 00 00 00 	lea    0x0(%esi,%eiz,1),%esi
  40300e:	66 90                	xchg   %ax,%ax
  403010:	e8 97 0e 00 00       	call   403eac <_strcoll>
  403015:	8b 0f                	mov    (%edi),%ecx
  403017:	8b 57 04             	mov    0x4(%edi),%edx
  40301a:	85 c0                	test   %eax,%eax
  40301c:	7f 02                	jg     403020 <.text+0xe80>
  40301e:	89 ca                	mov    %ecx,%edx
  403020:	85 d2                	test   %edx,%edx
  403022:	74 17                	je     40303b <.text+0xe9b>
  403024:	89 d7                	mov    %edx,%edi
  403026:	8b 47 08             	mov    0x8(%edi),%eax
  403029:	89 34 24             	mov    %esi,(%esp)
  40302c:	89 44 24 04          	mov    %eax,0x4(%esp)
  403030:	85 db                	test   %ebx,%ebx
  403032:	75 dc                	jne    403010 <.text+0xe70>
  403034:	e8 43 0e 00 00       	call   403e7c <_stricoll>
  403039:	eb da                	jmp    403015 <.text+0xe75>
  40303b:	8b 5d a8             	mov    -0x58(%ebp),%ebx
  40303e:	89 45 a8             	mov    %eax,-0x58(%ebp)
  403041:	c7 04 24 0c 00 00 00 	movl   $0xc,(%esp)
  403048:	e8 8f 0e 00 00       	call   403edc <_malloc>
  40304d:	8b 55 a8             	mov    -0x58(%ebp),%edx
  403050:	85 c0                	test   %eax,%eax
  403052:	0f 84 be fe ff ff    	je     402f16 <.text+0xd76>
  403058:	89 70 08             	mov    %esi,0x8(%eax)
  40305b:	c7 40 04 00 00 00 00 	movl   $0x0,0x4(%eax)
  403062:	c7 00 00 00 00 00    	movl   $0x0,(%eax)
  403068:	85 d2                	test   %edx,%edx
  40306a:	7e 21                	jle    40308d <.text+0xeed>
  40306c:	89 47 04             	mov    %eax,0x4(%edi)
  40306f:	e9 a2 fe ff ff       	jmp    402f16 <.text+0xd76>
  403074:	8b 55 08             	mov    0x8(%ebp),%edx
  403077:	89 f0                	mov    %esi,%eax
  403079:	e8 22 f7 ff ff       	call   4027a0 <.text+0x600>
  40307e:	e9 93 fe ff ff       	jmp    402f16 <.text+0xd76>
  403083:	8b 45 b4             	mov    -0x4c(%ebp),%eax
  403086:	01 d0                	add    %edx,%eax
  403088:	e9 d8 fd ff ff       	jmp    402e65 <.text+0xcc5>
  40308d:	89 07                	mov    %eax,(%edi)
  40308f:	e9 82 fe ff ff       	jmp    402f16 <.text+0xd76>
  403094:	8b 7d c4             	mov    -0x3c(%ebp),%edi
  403097:	8b 55 d0             	mov    -0x30(%ebp),%edx
  40309a:	89 f8                	mov    %edi,%eax
  40309c:	e8 5f f6 ff ff       	call   402700 <.text+0x560>
  4030a1:	89 45 d4             	mov    %eax,-0x2c(%ebp)
  4030a4:	85 c0                	test   %eax,%eax
  4030a6:	74 08                	je     4030b0 <.text+0xf10>
  4030a8:	8b 5d c4             	mov    -0x3c(%ebp),%ebx
  4030ab:	e9 35 f9 ff ff       	jmp    4029e5 <.text+0x845>
  4030b0:	89 3c 24             	mov    %edi,(%esp)
  4030b3:	89 e3                	mov    %esp,%ebx
  4030b5:	e8 ea 0d 00 00       	call   403ea4 <_strlen>
  4030ba:	83 c0 10             	add    $0x10,%eax
  4030bd:	c1 e8 04             	shr    $0x4,%eax
  4030c0:	c1 e0 04             	shl    $0x4,%eax
  4030c3:	e8 88 0d 00 00       	call   403e50 <___chkstk_ms>
  4030c8:	29 c4                	sub    %eax,%esp
  4030ca:	89 f9                	mov    %edi,%ecx
  4030cc:	8d 74 24 0c          	lea    0xc(%esp),%esi
  4030d0:	89 f2                	mov    %esi,%edx
  4030d2:	eb 10                	jmp    4030e4 <.text+0xf44>
  4030d4:	89 f9                	mov    %edi,%ecx
  4030d6:	83 c2 01             	add    $0x1,%edx
  4030d9:	88 42 ff             	mov    %al,-0x1(%edx)
  4030dc:	84 c0                	test   %al,%al
  4030de:	0f 84 87 fe ff ff    	je     402f6b <.text+0xdcb>
  4030e4:	0f b6 01             	movzbl (%ecx),%eax
  4030e7:	8d 79 01             	lea    0x1(%ecx),%edi
  4030ea:	3c 7f                	cmp    $0x7f,%al
  4030ec:	75 e6                	jne    4030d4 <.text+0xf34>
  4030ee:	0f b6 41 01          	movzbl 0x1(%ecx),%eax
  4030f2:	83 c1 02             	add    $0x2,%ecx
  4030f5:	eb df                	jmp    4030d6 <.text+0xf36>
  4030f7:	c7 04 24 0c 00 00 00 	movl   $0xc,(%esp)
  4030fe:	e8 d9 0d 00 00       	call   403edc <_malloc>
  403103:	89 45 b0             	mov    %eax,-0x50(%ebp)
  403106:	85 c0                	test   %eax,%eax
  403108:	0f 84 08 fe ff ff    	je     402f16 <.text+0xd76>
  40310e:	8b 45 b0             	mov    -0x50(%ebp),%eax
  403111:	89 70 08             	mov    %esi,0x8(%eax)
  403114:	c7 40 04 00 00 00 00 	movl   $0x0,0x4(%eax)
  40311b:	c7 00 00 00 00 00    	movl   $0x0,(%eax)
  403121:	e9 f0 fd ff ff       	jmp    402f16 <.text+0xd76>
  403126:	c7 45 d4 03 00 00 00 	movl   $0x3,-0x2c(%ebp)
  40312d:	e9 e4 fd ff ff       	jmp    402f16 <.text+0xd76>
  403132:	8d b4 26 00 00 00 00 	lea    0x0(%esi,%eiz,1),%esi
  403139:	8d b4 26 00 00 00 00 	lea    0x0(%esi,%eiz,1),%esi

00403140 <___mingw_glob>:
  403140:	55                   	push   %ebp
  403141:	89 e5                	mov    %esp,%ebp
  403143:	57                   	push   %edi
  403144:	56                   	push   %esi
  403145:	53                   	push   %ebx
  403146:	83 ec 2c             	sub    $0x2c,%esp
  403149:	8b 75 14             	mov    0x14(%ebp),%esi
  40314c:	8b 5d 08             	mov    0x8(%ebp),%ebx
  40314f:	8b 7d 0c             	mov    0xc(%ebp),%edi
  403152:	85 f6                	test   %esi,%esi
  403154:	74 08                	je     40315e <___mingw_glob+0x1e>
  403156:	f7 c7 02 00 00 00    	test   $0x2,%edi
  40315c:	74 3a                	je     403198 <___mingw_glob+0x58>
  40315e:	81 3e 50 62 40 00    	cmpl   $0x406250,(%esi)
  403164:	74 0d                	je     403173 <___mingw_glob+0x33>
  403166:	89 f0                	mov    %esi,%eax
  403168:	e8 e3 f6 ff ff       	call   402850 <.text+0x6b0>
  40316d:	c7 06 50 62 40 00    	movl   $0x406250,(%esi)
  403173:	89 34 24             	mov    %esi,(%esp)
  403176:	8b 4d 10             	mov    0x10(%ebp),%ecx
  403179:	89 fa                	mov    %edi,%edx
  40317b:	89 d8                	mov    %ebx,%eax
  40317d:	e8 1e f7 ff ff       	call   4028a0 <.text+0x700>
  403182:	89 c1                	mov    %eax,%ecx
  403184:	83 f8 02             	cmp    $0x2,%eax
  403187:	74 1f                	je     4031a8 <___mingw_glob+0x68>
  403189:	8d 65 f4             	lea    -0xc(%ebp),%esp
  40318c:	89 c8                	mov    %ecx,%eax
  40318e:	5b                   	pop    %ebx
  40318f:	5e                   	pop    %esi
  403190:	5f                   	pop    %edi
  403191:	5d                   	pop    %ebp
  403192:	c3                   	ret    
  403193:	8d 74 26 00          	lea    0x0(%esi,%eiz,1),%esi
  403197:	90                   	nop
  403198:	c7 46 0c 00 00 00 00 	movl   $0x0,0xc(%esi)
  40319f:	eb bd                	jmp    40315e <___mingw_glob+0x1e>
  4031a1:	8d b4 26 00 00 00 00 	lea    0x0(%esi,%eiz,1),%esi
  4031a8:	83 e7 10             	and    $0x10,%edi
  4031ab:	74 dc                	je     403189 <___mingw_glob+0x49>
  4031ad:	89 45 dc             	mov    %eax,-0x24(%ebp)
  4031b0:	89 65 e4             	mov    %esp,-0x1c(%ebp)
  4031b3:	89 1c 24             	mov    %ebx,(%esp)
  4031b6:	e8 e9 0c 00 00       	call   403ea4 <_strlen>
  4031bb:	83 c0 10             	add    $0x10,%eax
  4031be:	c1 e8 04             	shr    $0x4,%eax
  4031c1:	c1 e0 04             	shl    $0x4,%eax
  4031c4:	e8 87 0c 00 00       	call   403e50 <___chkstk_ms>
  4031c9:	8b 4d dc             	mov    -0x24(%ebp),%ecx
  4031cc:	29 c4                	sub    %eax,%esp
  4031ce:	8d 44 24 04          	lea    0x4(%esp),%eax
  4031d2:	89 45 e0             	mov    %eax,-0x20(%ebp)
  4031d5:	89 c2                	mov    %eax,%edx
  4031d7:	eb 13                	jmp    4031ec <___mingw_glob+0xac>
  4031d9:	8d b4 26 00 00 00 00 	lea    0x0(%esi,%eiz,1),%esi
  4031e0:	83 c2 01             	add    $0x1,%edx
  4031e3:	89 fb                	mov    %edi,%ebx
  4031e5:	88 42 ff             	mov    %al,-0x1(%edx)
  4031e8:	84 c0                	test   %al,%al
  4031ea:	74 1b                	je     403207 <___mingw_glob+0xc7>
  4031ec:	0f b6 03             	movzbl (%ebx),%eax
  4031ef:	8d 7b 01             	lea    0x1(%ebx),%edi
  4031f2:	3c 7f                	cmp    $0x7f,%al
  4031f4:	75 ea                	jne    4031e0 <___mingw_glob+0xa0>
  4031f6:	0f b6 43 01          	movzbl 0x1(%ebx),%eax
  4031fa:	83 c2 01             	add    $0x1,%edx
  4031fd:	83 c3 02             	add    $0x2,%ebx
  403200:	88 42 ff             	mov    %al,-0x1(%edx)
  403203:	84 c0                	test   %al,%al
  403205:	75 e5                	jne    4031ec <___mingw_glob+0xac>
  403207:	8b 45 e0             	mov    -0x20(%ebp),%eax
  40320a:	89 4d dc             	mov    %ecx,-0x24(%ebp)
  40320d:	89 04 24             	mov    %eax,(%esp)
  403210:	e8 6f 0c 00 00       	call   403e84 <_strdup>
  403215:	8b 65 e4             	mov    -0x1c(%ebp),%esp
  403218:	8b 4d dc             	mov    -0x24(%ebp),%ecx
  40321b:	85 c0                	test   %eax,%eax
  40321d:	0f 84 66 ff ff ff    	je     403189 <___mingw_glob+0x49>
  403223:	89 f2                	mov    %esi,%edx
  403225:	89 4d e4             	mov    %ecx,-0x1c(%ebp)
  403228:	e8 73 f5 ff ff       	call   4027a0 <.text+0x600>
  40322d:	8b 4d e4             	mov    -0x1c(%ebp),%ecx
  403230:	e9 54 ff ff ff       	jmp    403189 <___mingw_glob+0x49>
  403235:	8d b4 26 00 00 00 00 	lea    0x0(%esi,%eiz,1),%esi
  40323c:	8d 74 26 00          	lea    0x0(%esi,%eiz,1),%esi

00403240 <___mingw_globfree>:
  403240:	57                   	push   %edi
  403241:	56                   	push   %esi
  403242:	53                   	push   %ebx
  403243:	83 ec 10             	sub    $0x10,%esp
  403246:	8b 74 24 20          	mov    0x20(%esp),%esi
  40324a:	81 3e 50 62 40 00    	cmpl   $0x406250,(%esi)
  403250:	74 0e                	je     403260 <___mingw_globfree+0x20>
  403252:	83 c4 10             	add    $0x10,%esp
  403255:	5b                   	pop    %ebx
  403256:	5e                   	pop    %esi
  403257:	5f                   	pop    %edi
  403258:	c3                   	ret    
  403259:	8d b4 26 00 00 00 00 	lea    0x0(%esi,%eiz,1),%esi
  403260:	8b 7e 04             	mov    0x4(%esi),%edi
  403263:	8b 5e 0c             	mov    0xc(%esi),%ebx
  403266:	85 ff                	test   %edi,%edi
  403268:	7e 1b                	jle    403285 <___mingw_globfree+0x45>
  40326a:	01 df                	add    %ebx,%edi
  40326c:	8d 74 26 00          	lea    0x0(%esi,%eiz,1),%esi
  403270:	8b 46 08             	mov    0x8(%esi),%eax
  403273:	8b 04 98             	mov    (%eax,%ebx,4),%eax
  403276:	83 c3 01             	add    $0x1,%ebx
  403279:	89 04 24             	mov    %eax,(%esp)
  40327c:	e8 ef ee ff ff       	call   402170 <___mingw_aligned_free>
  403281:	39 df                	cmp    %ebx,%edi
  403283:	75 eb                	jne    403270 <___mingw_globfree+0x30>
  403285:	8b 46 08             	mov    0x8(%esi),%eax
  403288:	89 44 24 20          	mov    %eax,0x20(%esp)
  40328c:	83 c4 10             	add    $0x10,%esp
  40328f:	5b                   	pop    %ebx
  403290:	5e                   	pop    %esi
  403291:	5f                   	pop    %edi
  403292:	e9 d9 ee ff ff       	jmp    402170 <___mingw_aligned_free>
  403297:	90                   	nop
  403298:	90                   	nop
  403299:	90                   	nop
  40329a:	90                   	nop
  40329b:	90                   	nop
  40329c:	90                   	nop
  40329d:	90                   	nop
  40329e:	90                   	nop
  40329f:	90                   	nop

004032a0 <___mingw_dirname>:
  4032a0:	55                   	push   %ebp
  4032a1:	89 e5                	mov    %esp,%ebp
  4032a3:	57                   	push   %edi
  4032a4:	56                   	push   %esi
  4032a5:	53                   	push   %ebx
  4032a6:	83 ec 2c             	sub    $0x2c,%esp
  4032a9:	c7 44 24 04 00 00 00 	movl   $0x0,0x4(%esp)
  4032b0:	00 
  4032b1:	c7 04 24 02 00 00 00 	movl   $0x2,(%esp)
  4032b8:	e8 ff 0b 00 00       	call   403ebc <_setlocale>
  4032bd:	89 c3                	mov    %eax,%ebx
  4032bf:	85 c0                	test   %eax,%eax
  4032c1:	74 0a                	je     4032cd <___mingw_dirname+0x2d>
  4032c3:	89 04 24             	mov    %eax,(%esp)
  4032c6:	e8 b9 0b 00 00       	call   403e84 <_strdup>
  4032cb:	89 c3                	mov    %eax,%ebx
  4032cd:	c7 44 24 04 64 62 40 	movl   $0x406264,0x4(%esp)
  4032d4:	00 
  4032d5:	c7 04 24 02 00 00 00 	movl   $0x2,(%esp)
  4032dc:	e8 db 0b 00 00       	call   403ebc <_setlocale>
  4032e1:	8b 4d 08             	mov    0x8(%ebp),%ecx
  4032e4:	85 c9                	test   %ecx,%ecx
  4032e6:	74 08                	je     4032f0 <___mingw_dirname+0x50>
  4032e8:	8b 45 08             	mov    0x8(%ebp),%eax
  4032eb:	80 38 00             	cmpb   $0x0,(%eax)
  4032ee:	75 78                	jne    403368 <___mingw_dirname+0xc8>
  4032f0:	c7 44 24 08 00 00 00 	movl   $0x0,0x8(%esp)
  4032f7:	00 
  4032f8:	c7 44 24 04 66 62 40 	movl   $0x406266,0x4(%esp)
  4032ff:	00 
  403300:	c7 04 24 00 00 00 00 	movl   $0x0,(%esp)
  403307:	e8 80 0b 00 00       	call   403e8c <_wcstombs>
  40330c:	8d 70 01             	lea    0x1(%eax),%esi
  40330f:	89 74 24 04          	mov    %esi,0x4(%esp)
  403313:	a1 68 80 40 00       	mov    0x408068,%eax
  403318:	89 04 24             	mov    %eax,(%esp)
  40331b:	e8 c0 09 00 00       	call   403ce0 <___mingw_realloc>
  403320:	a3 68 80 40 00       	mov    %eax,0x408068
  403325:	89 74 24 08          	mov    %esi,0x8(%esp)
  403329:	c7 44 24 04 66 62 40 	movl   $0x406266,0x4(%esp)
  403330:	00 
  403331:	89 04 24             	mov    %eax,(%esp)
  403334:	e8 53 0b 00 00       	call   403e8c <_wcstombs>
  403339:	89 5c 24 04          	mov    %ebx,0x4(%esp)
  40333d:	c7 04 24 02 00 00 00 	movl   $0x2,(%esp)
  403344:	e8 73 0b 00 00       	call   403ebc <_setlocale>
  403349:	89 1c 24             	mov    %ebx,(%esp)
  40334c:	e8 1f ee ff ff       	call   402170 <___mingw_aligned_free>
  403351:	8b 35 68 80 40 00    	mov    0x408068,%esi
  403357:	8d 65 f4             	lea    -0xc(%ebp),%esp
  40335a:	89 f0                	mov    %esi,%eax
  40335c:	5b                   	pop    %ebx
  40335d:	5e                   	pop    %esi
  40335e:	5f                   	pop    %edi
  40335f:	5d                   	pop    %ebp
  403360:	c3                   	ret    
  403361:	8d b4 26 00 00 00 00 	lea    0x0(%esi,%eiz,1),%esi
  403368:	89 65 dc             	mov    %esp,-0x24(%ebp)
  40336b:	c7 44 24 08 00 00 00 	movl   $0x0,0x8(%esp)
  403372:	00 
  403373:	8b 45 08             	mov    0x8(%ebp),%eax
  403376:	c7 04 24 00 00 00 00 	movl   $0x0,(%esp)
  40337d:	89 44 24 04          	mov    %eax,0x4(%esp)
  403381:	e8 4e 0b 00 00       	call   403ed4 <_mbstowcs>
  403386:	89 c2                	mov    %eax,%edx
  403388:	8d 44 00 11          	lea    0x11(%eax,%eax,1),%eax
  40338c:	c1 e8 04             	shr    $0x4,%eax
  40338f:	c1 e0 04             	shl    $0x4,%eax
  403392:	e8 b9 0a 00 00       	call   403e50 <___chkstk_ms>
  403397:	29 c4                	sub    %eax,%esp
  403399:	89 54 24 08          	mov    %edx,0x8(%esp)
  40339d:	8b 45 08             	mov    0x8(%ebp),%eax
  4033a0:	8d 7c 24 0c          	lea    0xc(%esp),%edi
  4033a4:	89 3c 24             	mov    %edi,(%esp)
  4033a7:	89 44 24 04          	mov    %eax,0x4(%esp)
  4033ab:	e8 24 0b 00 00       	call   403ed4 <_mbstowcs>
  4033b0:	31 d2                	xor    %edx,%edx
  4033b2:	83 f8 01             	cmp    $0x1,%eax
  4033b5:	89 45 d8             	mov    %eax,-0x28(%ebp)
  4033b8:	66 89 14 47          	mov    %dx,(%edi,%eax,2)
  4033bc:	0f b7 07             	movzwl (%edi),%eax
  4033bf:	76 3f                	jbe    403400 <___mingw_dirname+0x160>
  4033c1:	89 c1                	mov    %eax,%ecx
  4033c3:	66 89 45 e2          	mov    %ax,-0x1e(%ebp)
  4033c7:	0f b7 47 02          	movzwl 0x2(%edi),%eax
  4033cb:	89 7d e4             	mov    %edi,-0x1c(%ebp)
  4033ce:	66 83 f9 2f          	cmp    $0x2f,%cx
  4033d2:	0f 84 08 02 00 00    	je     4035e0 <___mingw_dirname+0x340>
  4033d8:	66 83 f9 5c          	cmp    $0x5c,%cx
  4033dc:	0f 84 fe 01 00 00    	je     4035e0 <___mingw_dirname+0x340>
  4033e2:	66 83 f8 3a          	cmp    $0x3a,%ax
  4033e6:	75 1f                	jne    403407 <___mingw_dirname+0x167>
  4033e8:	8d 47 04             	lea    0x4(%edi),%eax
  4033eb:	89 45 e4             	mov    %eax,-0x1c(%ebp)
  4033ee:	0f b7 47 04          	movzwl 0x4(%edi),%eax
  4033f2:	66 89 45 e2          	mov    %ax,-0x1e(%ebp)
  4033f6:	eb 0f                	jmp    403407 <___mingw_dirname+0x167>
  4033f8:	8d b4 26 00 00 00 00 	lea    0x0(%esi,%eiz,1),%esi
  4033ff:	90                   	nop
  403400:	66 89 45 e2          	mov    %ax,-0x1e(%ebp)
  403404:	89 7d e4             	mov    %edi,-0x1c(%ebp)
  403407:	66 83 7d e2 00       	cmpw   $0x0,-0x1e(%ebp)
  40340c:	75 12                	jne    403420 <___mingw_dirname+0x180>
  40340e:	8b 65 dc             	mov    -0x24(%ebp),%esp
  403411:	e9 da fe ff ff       	jmp    4032f0 <___mingw_dirname+0x50>
  403416:	8d b4 26 00 00 00 00 	lea    0x0(%esi,%eiz,1),%esi
  40341d:	8d 76 00             	lea    0x0(%esi),%esi
  403420:	8b 45 e4             	mov    -0x1c(%ebp),%eax
  403423:	0f b7 55 e2          	movzwl -0x1e(%ebp),%edx
  403427:	89 c1                	mov    %eax,%ecx
  403429:	eb 19                	jmp    403444 <___mingw_dirname+0x1a4>
  40342b:	8d 74 26 00          	lea    0x0(%esi,%eiz,1),%esi
  40342f:	90                   	nop
  403430:	89 c6                	mov    %eax,%esi
  403432:	66 83 fa 5c          	cmp    $0x5c,%dx
  403436:	74 23                	je     40345b <___mingw_dirname+0x1bb>
  403438:	0f b7 56 02          	movzwl 0x2(%esi),%edx
  40343c:	83 c0 02             	add    $0x2,%eax
  40343f:	66 85 d2             	test   %dx,%dx
  403442:	74 34                	je     403478 <___mingw_dirname+0x1d8>
  403444:	66 83 fa 2f          	cmp    $0x2f,%dx
  403448:	75 e6                	jne    403430 <___mingw_dirname+0x190>
  40344a:	0f b7 10             	movzwl (%eax),%edx
  40344d:	66 83 fa 2f          	cmp    $0x2f,%dx
  403451:	75 11                	jne    403464 <___mingw_dirname+0x1c4>
  403453:	8d 74 26 00          	lea    0x0(%esi,%eiz,1),%esi
  403457:	90                   	nop
  403458:	83 c0 02             	add    $0x2,%eax
  40345b:	0f b7 10             	movzwl (%eax),%edx
  40345e:	66 83 fa 2f          	cmp    $0x2f,%dx
  403462:	74 f4                	je     403458 <___mingw_dirname+0x1b8>
  403464:	66 83 fa 5c          	cmp    $0x5c,%dx
  403468:	74 ee                	je     403458 <___mingw_dirname+0x1b8>
  40346a:	89 c6                	mov    %eax,%esi
  40346c:	66 85 d2             	test   %dx,%dx
  40346f:	74 07                	je     403478 <___mingw_dirname+0x1d8>
  403471:	89 c1                	mov    %eax,%ecx
  403473:	eb c3                	jmp    403438 <___mingw_dirname+0x198>
  403475:	8d 76 00             	lea    0x0(%esi),%esi
  403478:	39 4d e4             	cmp    %ecx,-0x1c(%ebp)
  40347b:	0f 82 8f 00 00 00    	jb     403510 <___mingw_dirname+0x270>
  403481:	0f b7 45 e2          	movzwl -0x1e(%ebp),%eax
  403485:	66 83 f8 2f          	cmp    $0x2f,%ax
  403489:	74 11                	je     40349c <___mingw_dirname+0x1fc>
  40348b:	66 83 f8 5c          	cmp    $0x5c,%ax
  40348f:	74 0b                	je     40349c <___mingw_dirname+0x1fc>
  403491:	8b 45 e4             	mov    -0x1c(%ebp),%eax
  403494:	b9 2e 00 00 00       	mov    $0x2e,%ecx
  403499:	66 89 08             	mov    %cx,(%eax)
  40349c:	8b 45 e4             	mov    -0x1c(%ebp),%eax
  40349f:	31 d2                	xor    %edx,%edx
  4034a1:	66 89 50 02          	mov    %dx,0x2(%eax)
  4034a5:	c7 44 24 08 00 00 00 	movl   $0x0,0x8(%esp)
  4034ac:	00 
  4034ad:	89 7c 24 04          	mov    %edi,0x4(%esp)
  4034b1:	c7 04 24 00 00 00 00 	movl   $0x0,(%esp)
  4034b8:	e8 cf 09 00 00       	call   403e8c <_wcstombs>
  4034bd:	8d 50 01             	lea    0x1(%eax),%edx
  4034c0:	89 54 24 04          	mov    %edx,0x4(%esp)
  4034c4:	a1 68 80 40 00       	mov    0x408068,%eax
  4034c9:	89 55 e4             	mov    %edx,-0x1c(%ebp)
  4034cc:	89 04 24             	mov    %eax,(%esp)
  4034cf:	e8 0c 08 00 00       	call   403ce0 <___mingw_realloc>
  4034d4:	8b 55 e4             	mov    -0x1c(%ebp),%edx
  4034d7:	a3 68 80 40 00       	mov    %eax,0x408068
  4034dc:	89 c6                	mov    %eax,%esi
  4034de:	89 54 24 08          	mov    %edx,0x8(%esp)
  4034e2:	89 7c 24 04          	mov    %edi,0x4(%esp)
  4034e6:	89 04 24             	mov    %eax,(%esp)
  4034e9:	e8 9e 09 00 00       	call   403e8c <_wcstombs>
  4034ee:	89 5c 24 04          	mov    %ebx,0x4(%esp)
  4034f2:	c7 04 24 02 00 00 00 	movl   $0x2,(%esp)
  4034f9:	e8 be 09 00 00       	call   403ebc <_setlocale>
  4034fe:	89 1c 24             	mov    %ebx,(%esp)
  403501:	e8 6a ec ff ff       	call   402170 <___mingw_aligned_free>
  403506:	8b 65 dc             	mov    -0x24(%ebp),%esp
  403509:	e9 49 fe ff ff       	jmp    403357 <___mingw_dirname+0xb7>
  40350e:	66 90                	xchg   %ax,%ax
  403510:	89 c8                	mov    %ecx,%eax
  403512:	83 e9 02             	sub    $0x2,%ecx
  403515:	39 4d e4             	cmp    %ecx,-0x1c(%ebp)
  403518:	0f 83 4d 01 00 00    	jae    40366b <___mingw_dirname+0x3cb>
  40351e:	0f b7 01             	movzwl (%ecx),%eax
  403521:	66 83 f8 2f          	cmp    $0x2f,%ax
  403525:	74 e9                	je     403510 <___mingw_dirname+0x270>
  403527:	66 83 f8 5c          	cmp    $0x5c,%ax
  40352b:	74 e3                	je     403510 <___mingw_dirname+0x270>
  40352d:	31 c0                	xor    %eax,%eax
  40352f:	66 89 41 02          	mov    %ax,0x2(%ecx)
  403533:	0f b7 07             	movzwl (%edi),%eax
  403536:	89 f9                	mov    %edi,%ecx
  403538:	66 83 f8 2f          	cmp    $0x2f,%ax
  40353c:	74 12                	je     403550 <___mingw_dirname+0x2b0>
  40353e:	66 83 f8 5c          	cmp    $0x5c,%ax
  403542:	0f 85 cd 00 00 00    	jne    403615 <___mingw_dirname+0x375>
  403548:	8d b4 26 00 00 00 00 	lea    0x0(%esi,%eiz,1),%esi
  40354f:	90                   	nop
  403550:	0f b7 51 02          	movzwl 0x2(%ecx),%edx
  403554:	83 c1 02             	add    $0x2,%ecx
  403557:	66 83 fa 2f          	cmp    $0x2f,%dx
  40355b:	74 f3                	je     403550 <___mingw_dirname+0x2b0>
  40355d:	66 83 fa 5c          	cmp    $0x5c,%dx
  403561:	74 ed                	je     403550 <___mingw_dirname+0x2b0>
  403563:	89 ca                	mov    %ecx,%edx
  403565:	29 fa                	sub    %edi,%edx
  403567:	83 fa 04             	cmp    $0x4,%edx
  40356a:	0f 8e a5 00 00 00    	jle    403615 <___mingw_dirname+0x375>
  403570:	89 f9                	mov    %edi,%ecx
  403572:	66 85 c0             	test   %ax,%ax
  403575:	0f 84 c0 00 00 00    	je     40363b <___mingw_dirname+0x39b>
  40357b:	89 5d e4             	mov    %ebx,-0x1c(%ebp)
  40357e:	89 ca                	mov    %ecx,%edx
  403580:	eb 24                	jmp    4035a6 <___mingw_dirname+0x306>
  403582:	8d b6 00 00 00 00    	lea    0x0(%esi),%esi
  403588:	0f b7 5a 02          	movzwl 0x2(%edx),%ebx
  40358c:	8d 72 02             	lea    0x2(%edx),%esi
  40358f:	66 83 f8 5c          	cmp    $0x5c,%ax
  403593:	0f 84 97 00 00 00    	je     403630 <___mingw_dirname+0x390>
  403599:	89 d8                	mov    %ebx,%eax
  40359b:	89 f2                	mov    %esi,%edx
  40359d:	66 85 c0             	test   %ax,%ax
  4035a0:	0f 84 92 00 00 00    	je     403638 <___mingw_dirname+0x398>
  4035a6:	83 c1 02             	add    $0x2,%ecx
  4035a9:	66 89 41 fe          	mov    %ax,-0x2(%ecx)
  4035ad:	66 83 f8 2f          	cmp    $0x2f,%ax
  4035b1:	75 d5                	jne    403588 <___mingw_dirname+0x2e8>
  4035b3:	0f b7 1a             	movzwl (%edx),%ebx
  4035b6:	66 83 fb 5c          	cmp    $0x5c,%bx
  4035ba:	74 0c                	je     4035c8 <___mingw_dirname+0x328>
  4035bc:	89 d8                	mov    %ebx,%eax
  4035be:	66 83 fb 2f          	cmp    $0x2f,%bx
  4035c2:	75 d9                	jne    40359d <___mingw_dirname+0x2fd>
  4035c4:	8d 74 26 00          	lea    0x0(%esi,%eiz,1),%esi
  4035c8:	0f b7 42 02          	movzwl 0x2(%edx),%eax
  4035cc:	83 c2 02             	add    $0x2,%edx
  4035cf:	66 83 f8 2f          	cmp    $0x2f,%ax
  4035d3:	74 f3                	je     4035c8 <___mingw_dirname+0x328>
  4035d5:	66 83 f8 5c          	cmp    $0x5c,%ax
  4035d9:	74 ed                	je     4035c8 <___mingw_dirname+0x328>
  4035db:	eb c0                	jmp    40359d <___mingw_dirname+0x2fd>
  4035dd:	8d 76 00             	lea    0x0(%esi),%esi
  4035e0:	66 39 45 e2          	cmp    %ax,-0x1e(%ebp)
  4035e4:	0f 85 1d fe ff ff    	jne    403407 <___mingw_dirname+0x167>
  4035ea:	66 83 7f 04 00       	cmpw   $0x0,0x4(%edi)
  4035ef:	0f 85 12 fe ff ff    	jne    403407 <___mingw_dirname+0x167>
  4035f5:	89 5c 24 04          	mov    %ebx,0x4(%esp)
  4035f9:	c7 04 24 02 00 00 00 	movl   $0x2,(%esp)
  403600:	e8 b7 08 00 00       	call   403ebc <_setlocale>
  403605:	89 1c 24             	mov    %ebx,(%esp)
  403608:	e8 63 eb ff ff       	call   402170 <___mingw_aligned_free>
  40360d:	8b 75 08             	mov    0x8(%ebp),%esi
  403610:	e9 f1 fe ff ff       	jmp    403506 <___mingw_dirname+0x266>
  403615:	66 39 47 02          	cmp    %ax,0x2(%edi)
  403619:	0f 85 51 ff ff ff    	jne    403570 <___mingw_dirname+0x2d0>
  40361f:	0f b7 01             	movzwl (%ecx),%eax
  403622:	e9 4b ff ff ff       	jmp    403572 <___mingw_dirname+0x2d2>
  403627:	8d b4 26 00 00 00 00 	lea    0x0(%esi,%eiz,1),%esi
  40362e:	66 90                	xchg   %ax,%ax
  403630:	89 f2                	mov    %esi,%edx
  403632:	eb 82                	jmp    4035b6 <___mingw_dirname+0x316>
  403634:	8d 74 26 00          	lea    0x0(%esi,%eiz,1),%esi
  403638:	8b 5d e4             	mov    -0x1c(%ebp),%ebx
  40363b:	8b 45 d8             	mov    -0x28(%ebp),%eax
  40363e:	31 f6                	xor    %esi,%esi
  403640:	66 89 31             	mov    %si,(%ecx)
  403643:	89 44 24 08          	mov    %eax,0x8(%esp)
  403647:	89 7c 24 04          	mov    %edi,0x4(%esp)
  40364b:	8b 45 08             	mov    0x8(%ebp),%eax
  40364e:	89 04 24             	mov    %eax,(%esp)
  403651:	e8 36 08 00 00       	call   403e8c <_wcstombs>
  403656:	8b 75 08             	mov    0x8(%ebp),%esi
  403659:	83 f8 ff             	cmp    $0xffffffff,%eax
  40365c:	0f 84 8c fe ff ff    	je     4034ee <___mingw_dirname+0x24e>
  403662:	c6 04 06 00          	movb   $0x0,(%esi,%eax,1)
  403666:	e9 83 fe ff ff       	jmp    4034ee <___mingw_dirname+0x24e>
  40366b:	0f 85 bc fe ff ff    	jne    40352d <___mingw_dirname+0x28d>
  403671:	0f b7 75 e2          	movzwl -0x1e(%ebp),%esi
  403675:	66 83 fe 2f          	cmp    $0x2f,%si
  403679:	74 0a                	je     403685 <___mingw_dirname+0x3e5>
  40367b:	66 83 fe 5c          	cmp    $0x5c,%si
  40367f:	0f 85 a8 fe ff ff    	jne    40352d <___mingw_dirname+0x28d>
  403685:	0f b7 75 e2          	movzwl -0x1e(%ebp),%esi
  403689:	66 39 71 02          	cmp    %si,0x2(%ecx)
  40368d:	0f 85 9a fe ff ff    	jne    40352d <___mingw_dirname+0x28d>
  403693:	0f b7 51 04          	movzwl 0x4(%ecx),%edx
  403697:	66 83 fa 2f          	cmp    $0x2f,%dx
  40369b:	0f 84 8c fe ff ff    	je     40352d <___mingw_dirname+0x28d>
  4036a1:	66 83 fa 5c          	cmp    $0x5c,%dx
  4036a5:	0f 84 82 fe ff ff    	je     40352d <___mingw_dirname+0x28d>
  4036ab:	89 c1                	mov    %eax,%ecx
  4036ad:	e9 7b fe ff ff       	jmp    40352d <___mingw_dirname+0x28d>
  4036b2:	90                   	nop
  4036b3:	90                   	nop
  4036b4:	90                   	nop
  4036b5:	90                   	nop
  4036b6:	90                   	nop
  4036b7:	90                   	nop
  4036b8:	90                   	nop
  4036b9:	90                   	nop
  4036ba:	90                   	nop
  4036bb:	90                   	nop
  4036bc:	90                   	nop
  4036bd:	90                   	nop
  4036be:	90                   	nop
  4036bf:	90                   	nop

004036c0 <.text>:
  4036c0:	56                   	push   %esi
  4036c1:	53                   	push   %ebx
  4036c2:	89 d3                	mov    %edx,%ebx
  4036c4:	81 ec 54 01 00 00    	sub    $0x154,%esp
  4036ca:	8d 54 24 10          	lea    0x10(%esp),%edx
  4036ce:	89 04 24             	mov    %eax,(%esp)
  4036d1:	89 54 24 04          	mov    %edx,0x4(%esp)
  4036d5:	e8 f2 08 00 00       	call   403fcc <_FindFirstFileA@8>
  4036da:	83 ec 08             	sub    $0x8,%esp
  4036dd:	89 c6                	mov    %eax,%esi
  4036df:	83 f8 ff             	cmp    $0xffffffff,%eax
  4036e2:	74 74                	je     403758 <.text+0x98>
  4036e4:	31 c0                	xor    %eax,%eax
  4036e6:	8d 4b 0c             	lea    0xc(%ebx),%ecx
  4036e9:	66 89 43 06          	mov    %ax,0x6(%ebx)
  4036ed:	0f b6 44 24 3c       	movzbl 0x3c(%esp),%eax
  4036f2:	88 43 0c             	mov    %al,0xc(%ebx)
  4036f5:	84 c0                	test   %al,%al
  4036f7:	74 27                	je     403720 <.text+0x60>
  4036f9:	31 c0                	xor    %eax,%eax
  4036fb:	eb 07                	jmp    403704 <.text+0x44>
  4036fd:	8d 76 00             	lea    0x0(%esi),%esi
  403700:	0f b7 43 06          	movzwl 0x6(%ebx),%eax
  403704:	83 c0 01             	add    $0x1,%eax
  403707:	66 89 43 06          	mov    %ax,0x6(%ebx)
  40370b:	66 3d 04 01          	cmp    $0x104,%ax
  40370f:	0f b7 c0             	movzwl %ax,%eax
  403712:	0f b6 44 04 3c       	movzbl 0x3c(%esp,%eax,1),%eax
  403717:	83 d1 00             	adc    $0x0,%ecx
  40371a:	88 01                	mov    %al,(%ecx)
  40371c:	84 c0                	test   %al,%al
  40371e:	75 e0                	jne    403700 <.text+0x40>
  403720:	8b 44 24 10          	mov    0x10(%esp),%eax
  403724:	24 58                	and    $0x58,%al
  403726:	83 f8 10             	cmp    $0x10,%eax
  403729:	77 15                	ja     403740 <.text+0x80>
  40372b:	89 43 08             	mov    %eax,0x8(%ebx)
  40372e:	81 c4 54 01 00 00    	add    $0x154,%esp
  403734:	89 f0                	mov    %esi,%eax
  403736:	5b                   	pop    %ebx
  403737:	5e                   	pop    %esi
  403738:	c3                   	ret    
  403739:	8d b4 26 00 00 00 00 	lea    0x0(%esi,%eiz,1),%esi
  403740:	c7 43 08 18 00 00 00 	movl   $0x18,0x8(%ebx)
  403747:	81 c4 54 01 00 00    	add    $0x154,%esp
  40374d:	89 f0                	mov    %esi,%eax
  40374f:	5b                   	pop    %ebx
  403750:	5e                   	pop    %esi
  403751:	c3                   	ret    
  403752:	8d b6 00 00 00 00    	lea    0x0(%esi),%esi
  403758:	e8 4f 08 00 00       	call   403fac <_GetLastError@0>
  40375d:	89 c3                	mov    %eax,%ebx
  40375f:	e8 b8 07 00 00       	call   403f1c <__errno>
  403764:	89 18                	mov    %ebx,(%eax)
  403766:	83 fb 03             	cmp    $0x3,%ebx
  403769:	74 24                	je     40378f <.text+0xcf>
  40376b:	e8 ac 07 00 00       	call   403f1c <__errno>
  403770:	81 38 0b 01 00 00    	cmpl   $0x10b,(%eax)
  403776:	74 24                	je     40379c <.text+0xdc>
  403778:	e8 9f 07 00 00       	call   403f1c <__errno>
  40377d:	83 38 02             	cmpl   $0x2,(%eax)
  403780:	74 ac                	je     40372e <.text+0x6e>
  403782:	e8 95 07 00 00       	call   403f1c <__errno>
  403787:	c7 00 16 00 00 00    	movl   $0x16,(%eax)
  40378d:	eb 9f                	jmp    40372e <.text+0x6e>
  40378f:	e8 88 07 00 00       	call   403f1c <__errno>
  403794:	c7 00 02 00 00 00    	movl   $0x2,(%eax)
  40379a:	eb 92                	jmp    40372e <.text+0x6e>
  40379c:	e8 7b 07 00 00       	call   403f1c <__errno>
  4037a1:	c7 00 14 00 00 00    	movl   $0x14,(%eax)
  4037a7:	eb 85                	jmp    40372e <.text+0x6e>
  4037a9:	8d b4 26 00 00 00 00 	lea    0x0(%esi,%eiz,1),%esi
  4037b0:	56                   	push   %esi
  4037b1:	53                   	push   %ebx
  4037b2:	89 d3                	mov    %edx,%ebx
  4037b4:	81 ec 54 01 00 00    	sub    $0x154,%esp
  4037ba:	8d 54 24 10          	lea    0x10(%esp),%edx
  4037be:	89 04 24             	mov    %eax,(%esp)
  4037c1:	89 54 24 04          	mov    %edx,0x4(%esp)
  4037c5:	e8 fa 07 00 00       	call   403fc4 <_FindNextFileA@8>
  4037ca:	83 ec 08             	sub    $0x8,%esp
  4037cd:	89 c6                	mov    %eax,%esi
  4037cf:	85 c0                	test   %eax,%eax
  4037d1:	74 75                	je     403848 <.text+0x188>
  4037d3:	31 c0                	xor    %eax,%eax
  4037d5:	8d 4b 0c             	lea    0xc(%ebx),%ecx
  4037d8:	66 89 43 06          	mov    %ax,0x6(%ebx)
  4037dc:	0f b6 44 24 3c       	movzbl 0x3c(%esp),%eax
  4037e1:	88 43 0c             	mov    %al,0xc(%ebx)
  4037e4:	84 c0                	test   %al,%al
  4037e6:	74 28                	je     403810 <.text+0x150>
  4037e8:	31 c0                	xor    %eax,%eax
  4037ea:	eb 08                	jmp    4037f4 <.text+0x134>
  4037ec:	8d 74 26 00          	lea    0x0(%esi,%eiz,1),%esi
  4037f0:	0f b7 43 06          	movzwl 0x6(%ebx),%eax
  4037f4:	83 c0 01             	add    $0x1,%eax
  4037f7:	66 89 43 06          	mov    %ax,0x6(%ebx)
  4037fb:	66 3d 04 01          	cmp    $0x104,%ax
  4037ff:	0f b7 c0             	movzwl %ax,%eax
  403802:	0f b6 44 04 3c       	movzbl 0x3c(%esp,%eax,1),%eax
  403807:	83 d1 00             	adc    $0x0,%ecx
  40380a:	88 01                	mov    %al,(%ecx)
  40380c:	84 c0                	test   %al,%al
  40380e:	75 e0                	jne    4037f0 <.text+0x130>
  403810:	8b 44 24 10          	mov    0x10(%esp),%eax
  403814:	24 58                	and    $0x58,%al
  403816:	83 f8 10             	cmp    $0x10,%eax
  403819:	77 15                	ja     403830 <.text+0x170>
  40381b:	89 43 08             	mov    %eax,0x8(%ebx)
  40381e:	81 c4 54 01 00 00    	add    $0x154,%esp
  403824:	89 f0                	mov    %esi,%eax
  403826:	5b                   	pop    %ebx
  403827:	5e                   	pop    %esi
  403828:	c3                   	ret    
  403829:	8d b4 26 00 00 00 00 	lea    0x0(%esi,%eiz,1),%esi
  403830:	c7 43 08 18 00 00 00 	movl   $0x18,0x8(%ebx)
  403837:	81 c4 54 01 00 00    	add    $0x154,%esp
  40383d:	89 f0                	mov    %esi,%eax
  40383f:	5b                   	pop    %ebx
  403840:	5e                   	pop    %esi
  403841:	c3                   	ret    
  403842:	8d b6 00 00 00 00    	lea    0x0(%esi),%esi
  403848:	e8 5f 07 00 00       	call   403fac <_GetLastError@0>
  40384d:	83 f8 12             	cmp    $0x12,%eax
  403850:	74 cc                	je     40381e <.text+0x15e>
  403852:	e8 c5 06 00 00       	call   403f1c <__errno>
  403857:	c7 00 02 00 00 00    	movl   $0x2,(%eax)
  40385d:	81 c4 54 01 00 00    	add    $0x154,%esp
  403863:	89 f0                	mov    %esi,%eax
  403865:	5b                   	pop    %ebx
  403866:	5e                   	pop    %esi
  403867:	c3                   	ret    
  403868:	8d b4 26 00 00 00 00 	lea    0x0(%esi,%eiz,1),%esi
  40386f:	90                   	nop

00403870 <___mingw_opendir>:
  403870:	55                   	push   %ebp
  403871:	57                   	push   %edi
  403872:	56                   	push   %esi
  403873:	53                   	push   %ebx
  403874:	81 ec 2c 01 00 00    	sub    $0x12c,%esp
  40387a:	8b 84 24 40 01 00 00 	mov    0x140(%esp),%eax
  403881:	85 c0                	test   %eax,%eax
  403883:	0f 84 af 01 00 00    	je     403a38 <___mingw_opendir+0x1c8>
  403889:	80 38 00             	cmpb   $0x0,(%eax)
  40388c:	0f 84 86 01 00 00    	je     403a18 <___mingw_opendir+0x1a8>
  403892:	8d 74 24 1c          	lea    0x1c(%esp),%esi
  403896:	c7 44 24 08 04 01 00 	movl   $0x104,0x8(%esp)
  40389d:	00 
  40389e:	89 44 24 04          	mov    %eax,0x4(%esp)
  4038a2:	89 34 24             	mov    %esi,(%esp)
  4038a5:	e8 6a 06 00 00       	call   403f14 <__fullpath>
  4038aa:	80 7c 24 1c 00       	cmpb   $0x0,0x1c(%esp)
  4038af:	89 f2                	mov    %esi,%edx
  4038b1:	74 4d                	je     403900 <___mingw_opendir+0x90>
  4038b3:	8b 0a                	mov    (%edx),%ecx
  4038b5:	83 c2 04             	add    $0x4,%edx
  4038b8:	8d 81 ff fe fe fe    	lea    -0x1010101(%ecx),%eax
  4038be:	f7 d1                	not    %ecx
  4038c0:	21 c8                	and    %ecx,%eax
  4038c2:	25 80 80 80 80       	and    $0x80808080,%eax
  4038c7:	74 ea                	je     4038b3 <___mingw_opendir+0x43>
  4038c9:	a9 80 80 00 00       	test   $0x8080,%eax
  4038ce:	0f 84 34 01 00 00    	je     403a08 <___mingw_opendir+0x198>
  4038d4:	89 c3                	mov    %eax,%ebx
  4038d6:	00 c3                	add    %al,%bl
  4038d8:	83 da 03             	sbb    $0x3,%edx
  4038db:	29 f2                	sub    %esi,%edx
  4038dd:	0f b6 4c 14 1b       	movzbl 0x1b(%esp,%edx,1),%ecx
  4038e2:	8d 04 16             	lea    (%esi,%edx,1),%eax
  4038e5:	80 f9 2f             	cmp    $0x2f,%cl
  4038e8:	74 40                	je     40392a <___mingw_opendir+0xba>
  4038ea:	80 f9 5c             	cmp    $0x5c,%cl
  4038ed:	74 3b                	je     40392a <___mingw_opendir+0xba>
  4038ef:	b9 5c 00 00 00       	mov    $0x5c,%ecx
  4038f4:	66 89 08             	mov    %cx,(%eax)
  4038f7:	8d 44 16 01          	lea    0x1(%esi,%edx,1),%eax
  4038fb:	eb 2d                	jmp    40392a <___mingw_opendir+0xba>
  4038fd:	8d 76 00             	lea    0x0(%esi),%esi
  403900:	8b 0a                	mov    (%edx),%ecx
  403902:	83 c2 04             	add    $0x4,%edx
  403905:	8d 81 ff fe fe fe    	lea    -0x1010101(%ecx),%eax
  40390b:	f7 d1                	not    %ecx
  40390d:	21 c8                	and    %ecx,%eax
  40390f:	25 80 80 80 80       	and    $0x80808080,%eax
  403914:	74 ea                	je     403900 <___mingw_opendir+0x90>
  403916:	a9 80 80 00 00       	test   $0x8080,%eax
  40391b:	0f 84 d7 00 00 00    	je     4039f8 <___mingw_opendir+0x188>
  403921:	89 c3                	mov    %eax,%ebx
  403923:	00 c3                	add    %al,%bl
  403925:	89 d0                	mov    %edx,%eax
  403927:	83 d8 03             	sbb    $0x3,%eax
  40392a:	ba 2a 00 00 00       	mov    $0x2a,%edx
  40392f:	89 f3                	mov    %esi,%ebx
  403931:	66 89 10             	mov    %dx,(%eax)
  403934:	8b 13                	mov    (%ebx),%edx
  403936:	83 c3 04             	add    $0x4,%ebx
  403939:	8d 82 ff fe fe fe    	lea    -0x1010101(%edx),%eax
  40393f:	f7 d2                	not    %edx
  403941:	21 d0                	and    %edx,%eax
  403943:	25 80 80 80 80       	and    $0x80808080,%eax
  403948:	74 ea                	je     403934 <___mingw_opendir+0xc4>
  40394a:	a9 80 80 00 00       	test   $0x8080,%eax
  40394f:	75 06                	jne    403957 <___mingw_opendir+0xe7>
  403951:	c1 e8 10             	shr    $0x10,%eax
  403954:	83 c3 02             	add    $0x2,%ebx
  403957:	89 c1                	mov    %eax,%ecx
  403959:	00 c1                	add    %al,%cl
  40395b:	83 db 03             	sbb    $0x3,%ebx
  40395e:	29 f3                	sub    %esi,%ebx
  403960:	8d 83 1c 01 00 00    	lea    0x11c(%ebx),%eax
  403966:	89 04 24             	mov    %eax,(%esp)
  403969:	e8 6e 05 00 00       	call   403edc <_malloc>
  40396e:	89 c5                	mov    %eax,%ebp
  403970:	85 c0                	test   %eax,%eax
  403972:	0f 84 e7 00 00 00    	je     403a5f <___mingw_opendir+0x1ef>
  403978:	8d 4b 01             	lea    0x1(%ebx),%ecx
  40397b:	8d 80 18 01 00 00    	lea    0x118(%eax),%eax
  403981:	83 f9 04             	cmp    $0x4,%ecx
  403984:	72 52                	jb     4039d8 <___mingw_opendir+0x168>
  403986:	8b 54 0c 18          	mov    0x18(%esp,%ecx,1),%edx
  40398a:	c1 eb 02             	shr    $0x2,%ebx
  40398d:	89 c7                	mov    %eax,%edi
  40398f:	89 54 08 fc          	mov    %edx,-0x4(%eax,%ecx,1)
  403993:	89 d9                	mov    %ebx,%ecx
  403995:	f3 a5                	rep movsl %ds:(%esi),%es:(%edi)
  403997:	89 ea                	mov    %ebp,%edx
  403999:	e8 22 fd ff ff       	call   4036c0 <.text>
  40399e:	89 85 10 01 00 00    	mov    %eax,0x110(%ebp)
  4039a4:	83 f8 ff             	cmp    $0xffffffff,%eax
  4039a7:	0f 84 a3 00 00 00    	je     403a50 <___mingw_opendir+0x1e0>
  4039ad:	b8 10 01 00 00       	mov    $0x110,%eax
  4039b2:	c7 45 00 00 00 00 00 	movl   $0x0,0x0(%ebp)
  4039b9:	c7 85 14 01 00 00 00 	movl   $0x0,0x114(%ebp)
  4039c0:	00 00 00 
  4039c3:	66 89 45 04          	mov    %ax,0x4(%ebp)
  4039c7:	81 c4 2c 01 00 00    	add    $0x12c,%esp
  4039cd:	89 e8                	mov    %ebp,%eax
  4039cf:	5b                   	pop    %ebx
  4039d0:	5e                   	pop    %esi
  4039d1:	5f                   	pop    %edi
  4039d2:	5d                   	pop    %ebp
  4039d3:	c3                   	ret    
  4039d4:	8d 74 26 00          	lea    0x0(%esi,%eiz,1),%esi
  4039d8:	85 c9                	test   %ecx,%ecx
  4039da:	74 bb                	je     403997 <___mingw_opendir+0x127>
  4039dc:	0f b6 16             	movzbl (%esi),%edx
  4039df:	88 10                	mov    %dl,(%eax)
  4039e1:	f6 c1 02             	test   $0x2,%cl
  4039e4:	74 b1                	je     403997 <___mingw_opendir+0x127>
  4039e6:	0f b7 54 0e fe       	movzwl -0x2(%esi,%ecx,1),%edx
  4039eb:	66 89 54 08 fe       	mov    %dx,-0x2(%eax,%ecx,1)
  4039f0:	eb a5                	jmp    403997 <___mingw_opendir+0x127>
  4039f2:	8d b6 00 00 00 00    	lea    0x0(%esi),%esi
  4039f8:	c1 e8 10             	shr    $0x10,%eax
  4039fb:	83 c2 02             	add    $0x2,%edx
  4039fe:	e9 1e ff ff ff       	jmp    403921 <___mingw_opendir+0xb1>
  403a03:	8d 74 26 00          	lea    0x0(%esi,%eiz,1),%esi
  403a07:	90                   	nop
  403a08:	c1 e8 10             	shr    $0x10,%eax
  403a0b:	83 c2 02             	add    $0x2,%edx
  403a0e:	e9 c1 fe ff ff       	jmp    4038d4 <___mingw_opendir+0x64>
  403a13:	8d 74 26 00          	lea    0x0(%esi,%eiz,1),%esi
  403a17:	90                   	nop
  403a18:	e8 ff 04 00 00       	call   403f1c <__errno>
  403a1d:	31 ed                	xor    %ebp,%ebp
  403a1f:	c7 00 02 00 00 00    	movl   $0x2,(%eax)
  403a25:	81 c4 2c 01 00 00    	add    $0x12c,%esp
  403a2b:	89 e8                	mov    %ebp,%eax
  403a2d:	5b                   	pop    %ebx
  403a2e:	5e                   	pop    %esi
  403a2f:	5f                   	pop    %edi
  403a30:	5d                   	pop    %ebp
  403a31:	c3                   	ret    
  403a32:	8d b6 00 00 00 00    	lea    0x0(%esi),%esi
  403a38:	e8 df 04 00 00       	call   403f1c <__errno>
  403a3d:	31 ed                	xor    %ebp,%ebp
  403a3f:	c7 00 16 00 00 00    	movl   $0x16,(%eax)
  403a45:	eb 80                	jmp    4039c7 <___mingw_opendir+0x157>
  403a47:	8d b4 26 00 00 00 00 	lea    0x0(%esi,%eiz,1),%esi
  403a4e:	66 90                	xchg   %ax,%ax
  403a50:	89 2c 24             	mov    %ebp,(%esp)
  403a53:	31 ed                	xor    %ebp,%ebp
  403a55:	e8 16 e7 ff ff       	call   402170 <___mingw_aligned_free>
  403a5a:	e9 68 ff ff ff       	jmp    4039c7 <___mingw_opendir+0x157>
  403a5f:	e8 b8 04 00 00       	call   403f1c <__errno>
  403a64:	c7 00 0c 00 00 00    	movl   $0xc,(%eax)
  403a6a:	e9 58 ff ff ff       	jmp    4039c7 <___mingw_opendir+0x157>
  403a6f:	90                   	nop

00403a70 <___mingw_readdir>:
  403a70:	53                   	push   %ebx
  403a71:	83 ec 08             	sub    $0x8,%esp
  403a74:	8b 44 24 10          	mov    0x10(%esp),%eax
  403a78:	85 c0                	test   %eax,%eax
  403a7a:	74 34                	je     403ab0 <___mingw_readdir+0x40>
  403a7c:	8b 90 14 01 00 00    	mov    0x114(%eax),%edx
  403a82:	89 c3                	mov    %eax,%ebx
  403a84:	8d 4a 01             	lea    0x1(%edx),%ecx
  403a87:	89 88 14 01 00 00    	mov    %ecx,0x114(%eax)
  403a8d:	85 d2                	test   %edx,%edx
  403a8f:	7e 16                	jle    403aa7 <___mingw_readdir+0x37>
  403a91:	8b 80 10 01 00 00    	mov    0x110(%eax),%eax
  403a97:	89 da                	mov    %ebx,%edx
  403a99:	e8 12 fd ff ff       	call   4037b0 <.text+0xf0>
  403a9e:	83 f8 01             	cmp    $0x1,%eax
  403aa1:	19 c0                	sbb    %eax,%eax
  403aa3:	f7 d0                	not    %eax
  403aa5:	21 c3                	and    %eax,%ebx
  403aa7:	83 c4 08             	add    $0x8,%esp
  403aaa:	89 d8                	mov    %ebx,%eax
  403aac:	5b                   	pop    %ebx
  403aad:	c3                   	ret    
  403aae:	66 90                	xchg   %ax,%ax
  403ab0:	e8 67 04 00 00       	call   403f1c <__errno>
  403ab5:	31 db                	xor    %ebx,%ebx
  403ab7:	c7 00 09 00 00 00    	movl   $0x9,(%eax)
  403abd:	eb e8                	jmp    403aa7 <___mingw_readdir+0x37>
  403abf:	90                   	nop

00403ac0 <___mingw_closedir>:
  403ac0:	53                   	push   %ebx
  403ac1:	83 ec 18             	sub    $0x18,%esp
  403ac4:	8b 5c 24 20          	mov    0x20(%esp),%ebx
  403ac8:	85 db                	test   %ebx,%ebx
  403aca:	74 24                	je     403af0 <___mingw_closedir+0x30>
  403acc:	8b 83 10 01 00 00    	mov    0x110(%ebx),%eax
  403ad2:	89 04 24             	mov    %eax,(%esp)
  403ad5:	e8 fa 04 00 00       	call   403fd4 <_FindClose@4>
  403ada:	83 ec 04             	sub    $0x4,%esp
  403add:	85 c0                	test   %eax,%eax
  403adf:	74 0f                	je     403af0 <___mingw_closedir+0x30>
  403ae1:	89 1c 24             	mov    %ebx,(%esp)
  403ae4:	e8 87 e6 ff ff       	call   402170 <___mingw_aligned_free>
  403ae9:	31 c0                	xor    %eax,%eax
  403aeb:	83 c4 18             	add    $0x18,%esp
  403aee:	5b                   	pop    %ebx
  403aef:	c3                   	ret    
  403af0:	e8 27 04 00 00       	call   403f1c <__errno>
  403af5:	c7 00 09 00 00 00    	movl   $0x9,(%eax)
  403afb:	b8 ff ff ff ff       	mov    $0xffffffff,%eax
  403b00:	eb e9                	jmp    403aeb <___mingw_closedir+0x2b>
  403b02:	8d b4 26 00 00 00 00 	lea    0x0(%esi,%eiz,1),%esi
  403b09:	8d b4 26 00 00 00 00 	lea    0x0(%esi,%eiz,1),%esi

00403b10 <___mingw_rewinddir>:
  403b10:	53                   	push   %ebx
  403b11:	83 ec 18             	sub    $0x18,%esp
  403b14:	8b 5c 24 20          	mov    0x20(%esp),%ebx
  403b18:	85 db                	test   %ebx,%ebx
  403b1a:	74 15                	je     403b31 <___mingw_rewinddir+0x21>
  403b1c:	8b 83 10 01 00 00    	mov    0x110(%ebx),%eax
  403b22:	89 04 24             	mov    %eax,(%esp)
  403b25:	e8 aa 04 00 00       	call   403fd4 <_FindClose@4>
  403b2a:	83 ec 04             	sub    $0x4,%esp
  403b2d:	85 c0                	test   %eax,%eax
  403b2f:	75 17                	jne    403b48 <___mingw_rewinddir+0x38>
  403b31:	e8 e6 03 00 00       	call   403f1c <__errno>
  403b36:	c7 00 09 00 00 00    	movl   $0x9,(%eax)
  403b3c:	83 c4 18             	add    $0x18,%esp
  403b3f:	5b                   	pop    %ebx
  403b40:	c3                   	ret    
  403b41:	8d b4 26 00 00 00 00 	lea    0x0(%esi,%eiz,1),%esi
  403b48:	8d 83 18 01 00 00    	lea    0x118(%ebx),%eax
  403b4e:	89 da                	mov    %ebx,%edx
  403b50:	e8 6b fb ff ff       	call   4036c0 <.text>
  403b55:	89 83 10 01 00 00    	mov    %eax,0x110(%ebx)
  403b5b:	83 f8 ff             	cmp    $0xffffffff,%eax
  403b5e:	74 dc                	je     403b3c <___mingw_rewinddir+0x2c>
  403b60:	c7 83 14 01 00 00 00 	movl   $0x0,0x114(%ebx)
  403b67:	00 00 00 
  403b6a:	83 c4 18             	add    $0x18,%esp
  403b6d:	5b                   	pop    %ebx
  403b6e:	c3                   	ret    
  403b6f:	90                   	nop

00403b70 <___mingw_telldir>:
  403b70:	83 ec 0c             	sub    $0xc,%esp
  403b73:	8b 44 24 10          	mov    0x10(%esp),%eax
  403b77:	85 c0                	test   %eax,%eax
  403b79:	74 0a                	je     403b85 <___mingw_telldir+0x15>
  403b7b:	8b 80 14 01 00 00    	mov    0x114(%eax),%eax
  403b81:	83 c4 0c             	add    $0xc,%esp
  403b84:	c3                   	ret    
  403b85:	e8 92 03 00 00       	call   403f1c <__errno>
  403b8a:	c7 00 09 00 00 00    	movl   $0x9,(%eax)
  403b90:	b8 ff ff ff ff       	mov    $0xffffffff,%eax
  403b95:	eb ea                	jmp    403b81 <___mingw_telldir+0x11>
  403b97:	8d b4 26 00 00 00 00 	lea    0x0(%esi,%eiz,1),%esi
  403b9e:	66 90                	xchg   %ax,%ax

00403ba0 <___mingw_seekdir>:
  403ba0:	56                   	push   %esi
  403ba1:	53                   	push   %ebx
  403ba2:	83 ec 14             	sub    $0x14,%esp
  403ba5:	8b 74 24 24          	mov    0x24(%esp),%esi
  403ba9:	8b 5c 24 20          	mov    0x20(%esp),%ebx
  403bad:	85 f6                	test   %esi,%esi
  403baf:	78 4f                	js     403c00 <___mingw_seekdir+0x60>
  403bb1:	89 1c 24             	mov    %ebx,(%esp)
  403bb4:	e8 57 ff ff ff       	call   403b10 <___mingw_rewinddir>
  403bb9:	85 f6                	test   %esi,%esi
  403bbb:	74 37                	je     403bf4 <___mingw_seekdir+0x54>
  403bbd:	83 bb 10 01 00 00 ff 	cmpl   $0xffffffff,0x110(%ebx)
  403bc4:	75 1b                	jne    403be1 <___mingw_seekdir+0x41>
  403bc6:	eb 2c                	jmp    403bf4 <___mingw_seekdir+0x54>
  403bc8:	8d b4 26 00 00 00 00 	lea    0x0(%esi,%eiz,1),%esi
  403bcf:	90                   	nop
  403bd0:	8b 83 10 01 00 00    	mov    0x110(%ebx),%eax
  403bd6:	89 da                	mov    %ebx,%edx
  403bd8:	e8 d3 fb ff ff       	call   4037b0 <.text+0xf0>
  403bdd:	85 c0                	test   %eax,%eax
  403bdf:	74 13                	je     403bf4 <___mingw_seekdir+0x54>
  403be1:	8b 83 14 01 00 00    	mov    0x114(%ebx),%eax
  403be7:	83 c0 01             	add    $0x1,%eax
  403bea:	89 83 14 01 00 00    	mov    %eax,0x114(%ebx)
  403bf0:	39 f0                	cmp    %esi,%eax
  403bf2:	7c dc                	jl     403bd0 <___mingw_seekdir+0x30>
  403bf4:	83 c4 14             	add    $0x14,%esp
  403bf7:	5b                   	pop    %ebx
  403bf8:	5e                   	pop    %esi
  403bf9:	c3                   	ret    
  403bfa:	8d b6 00 00 00 00    	lea    0x0(%esi),%esi
  403c00:	e8 17 03 00 00       	call   403f1c <__errno>
  403c05:	c7 00 16 00 00 00    	movl   $0x16,(%eax)
  403c0b:	83 c4 14             	add    $0x14,%esp
  403c0e:	5b                   	pop    %ebx
  403c0f:	5e                   	pop    %esi
  403c10:	c3                   	ret    
  403c11:	90                   	nop
  403c12:	90                   	nop
  403c13:	90                   	nop
  403c14:	90                   	nop
  403c15:	90                   	nop
  403c16:	90                   	nop
  403c17:	90                   	nop
  403c18:	90                   	nop
  403c19:	90                   	nop
  403c1a:	90                   	nop
  403c1b:	90                   	nop
  403c1c:	90                   	nop
  403c1d:	90                   	nop
  403c1e:	90                   	nop
  403c1f:	90                   	nop

00403c20 <___mingw_memalign_base>:
  403c20:	55                   	push   %ebp
  403c21:	57                   	push   %edi
  403c22:	56                   	push   %esi
  403c23:	53                   	push   %ebx
  403c24:	83 ec 08             	sub    $0x8,%esp
  403c27:	8b 44 24 1c          	mov    0x1c(%esp),%eax
  403c2b:	85 c0                	test   %eax,%eax
  403c2d:	0f 84 83 00 00 00    	je     403cb6 <___mingw_memalign_base+0x96>
  403c33:	8b 35 6c 80 40 00    	mov    0x40806c,%esi
  403c39:	85 f6                	test   %esi,%esi
  403c3b:	74 79                	je     403cb6 <___mingw_memalign_base+0x96>
  403c3d:	8d 56 08             	lea    0x8(%esi),%edx
  403c40:	39 c2                	cmp    %eax,%edx
  403c42:	77 72                	ja     403cb6 <___mingw_memalign_base+0x96>
  403c44:	8d 50 fc             	lea    -0x4(%eax),%edx
  403c47:	8b 7c 24 20          	mov    0x20(%esp),%edi
  403c4b:	83 e2 fc             	and    $0xfffffffc,%edx
  403c4e:	8b 12                	mov    (%edx),%edx
  403c50:	89 d3                	mov    %edx,%ebx
  403c52:	89 d1                	mov    %edx,%ecx
  403c54:	83 e3 03             	and    $0x3,%ebx
  403c57:	83 e1 fc             	and    $0xfffffffc,%ecx
  403c5a:	89 5f 04             	mov    %ebx,0x4(%edi)
  403c5d:	89 0f                	mov    %ecx,(%edi)
  403c5f:	39 ce                	cmp    %ecx,%esi
  403c61:	77 53                	ja     403cb6 <___mingw_memalign_base+0x96>
  403c63:	8d 70 f8             	lea    -0x8(%eax),%esi
  403c66:	39 f1                	cmp    %esi,%ecx
  403c68:	77 4c                	ja     403cb6 <___mingw_memalign_base+0x96>
  403c6a:	89 4c 24 04          	mov    %ecx,0x4(%esp)
  403c6e:	f6 c2 01             	test   $0x1,%dl
  403c71:	74 4d                	je     403cc0 <___mingw_memalign_base+0xa0>
  403c73:	8b 39                	mov    (%ecx),%edi
  403c75:	89 fd                	mov    %edi,%ebp
  403c77:	8d 77 07             	lea    0x7(%edi),%esi
  403c7a:	f7 dd                	neg    %ebp
  403c7c:	89 2c 24             	mov    %ebp,(%esp)
  403c7f:	8b 6c 24 20          	mov    0x20(%esp),%ebp
  403c83:	89 7d 08             	mov    %edi,0x8(%ebp)
  403c86:	83 e2 02             	and    $0x2,%edx
  403c89:	74 0b                	je     403c96 <___mingw_memalign_base+0x76>
  403c8b:	8d 53 01             	lea    0x1(%ebx),%edx
  403c8e:	c1 ea 02             	shr    $0x2,%edx
  403c91:	8b 14 91             	mov    (%ecx,%edx,4),%edx
  403c94:	01 d1                	add    %edx,%ecx
  403c96:	8b 6c 24 20          	mov    0x20(%esp),%ebp
  403c9a:	89 55 0c             	mov    %edx,0xc(%ebp)
  403c9d:	83 fb 03             	cmp    $0x3,%ebx
  403ca0:	75 03                	jne    403ca5 <___mingw_memalign_base+0x85>
  403ca2:	8d 77 0b             	lea    0xb(%edi),%esi
  403ca5:	8b 2c 24             	mov    (%esp),%ebp
  403ca8:	01 f1                	add    %esi,%ecx
  403caa:	21 cd                	and    %ecx,%ebp
  403cac:	29 d5                	sub    %edx,%ebp
  403cae:	39 e8                	cmp    %ebp,%eax
  403cb0:	75 04                	jne    403cb6 <___mingw_memalign_base+0x96>
  403cb2:	8b 44 24 04          	mov    0x4(%esp),%eax
  403cb6:	83 c4 08             	add    $0x8,%esp
  403cb9:	5b                   	pop    %ebx
  403cba:	5e                   	pop    %esi
  403cbb:	5f                   	pop    %edi
  403cbc:	5d                   	pop    %ebp
  403cbd:	c3                   	ret    
  403cbe:	66 90                	xchg   %ax,%ax
  403cc0:	c7 04 24 f8 ff ff ff 	movl   $0xfffffff8,(%esp)
  403cc7:	be 0f 00 00 00       	mov    $0xf,%esi
  403ccc:	bf 08 00 00 00       	mov    $0x8,%edi
  403cd1:	eb ac                	jmp    403c7f <___mingw_memalign_base+0x5f>
  403cd3:	90                   	nop
  403cd4:	90                   	nop
  403cd5:	90                   	nop
  403cd6:	90                   	nop
  403cd7:	90                   	nop
  403cd8:	90                   	nop
  403cd9:	90                   	nop
  403cda:	90                   	nop
  403cdb:	90                   	nop
  403cdc:	90                   	nop
  403cdd:	90                   	nop
  403cde:	90                   	nop
  403cdf:	90                   	nop

00403ce0 <___mingw_realloc>:
  403ce0:	57                   	push   %edi
  403ce1:	56                   	push   %esi
  403ce2:	53                   	push   %ebx
  403ce3:	83 ec 20             	sub    $0x20,%esp
  403ce6:	8b 5c 24 30          	mov    0x30(%esp),%ebx
  403cea:	8b 74 24 34          	mov    0x34(%esp),%esi
  403cee:	85 db                	test   %ebx,%ebx
  403cf0:	74 3a                	je     403d2c <___mingw_realloc+0x4c>
  403cf2:	8d 7c 24 10          	lea    0x10(%esp),%edi
  403cf6:	89 1c 24             	mov    %ebx,(%esp)
  403cf9:	89 7c 24 04          	mov    %edi,0x4(%esp)
  403cfd:	e8 1e ff ff ff       	call   403c20 <___mingw_memalign_base>
  403d02:	39 c3                	cmp    %eax,%ebx
  403d04:	74 26                	je     403d2c <___mingw_realloc+0x4c>
  403d06:	85 f6                	test   %esi,%esi
  403d08:	74 1e                	je     403d28 <___mingw_realloc+0x48>
  403d0a:	39 74 24 1c          	cmp    %esi,0x1c(%esp)
  403d0e:	72 30                	jb     403d40 <___mingw_realloc+0x60>
  403d10:	e8 07 02 00 00       	call   403f1c <__errno>
  403d15:	c7 00 16 00 00 00    	movl   $0x16,(%eax)
  403d1b:	83 c4 20             	add    $0x20,%esp
  403d1e:	31 c0                	xor    %eax,%eax
  403d20:	5b                   	pop    %ebx
  403d21:	5e                   	pop    %esi
  403d22:	5f                   	pop    %edi
  403d23:	c3                   	ret    
  403d24:	8d 74 26 00          	lea    0x0(%esi,%eiz,1),%esi
  403d28:	8b 5c 24 10          	mov    0x10(%esp),%ebx
  403d2c:	89 74 24 04          	mov    %esi,0x4(%esp)
  403d30:	89 1c 24             	mov    %ebx,(%esp)
  403d33:	ff 15 54 92 40 00    	call   *0x409254
  403d39:	83 c4 20             	add    $0x20,%esp
  403d3c:	5b                   	pop    %ebx
  403d3d:	5e                   	pop    %esi
  403d3e:	5f                   	pop    %edi
  403d3f:	c3                   	ret    
  403d40:	89 74 24 08          	mov    %esi,0x8(%esp)
  403d44:	89 7c 24 04          	mov    %edi,0x4(%esp)
  403d48:	89 1c 24             	mov    %ebx,(%esp)
  403d4b:	e8 10 00 00 00       	call   403d60 <___mingw_memalign_realloc>
  403d50:	83 c4 20             	add    $0x20,%esp
  403d53:	5b                   	pop    %ebx
  403d54:	5e                   	pop    %esi
  403d55:	5f                   	pop    %edi
  403d56:	c3                   	ret    
  403d57:	90                   	nop
  403d58:	90                   	nop
  403d59:	90                   	nop
  403d5a:	90                   	nop
  403d5b:	90                   	nop
  403d5c:	90                   	nop
  403d5d:	90                   	nop
  403d5e:	90                   	nop
  403d5f:	90                   	nop

00403d60 <___mingw_memalign_realloc>:
  403d60:	55                   	push   %ebp
  403d61:	57                   	push   %edi
  403d62:	56                   	push   %esi
  403d63:	53                   	push   %ebx
  403d64:	83 ec 1c             	sub    $0x1c,%esp
  403d67:	8b 74 24 34          	mov    0x34(%esp),%esi
  403d6b:	8b 06                	mov    (%esi),%eax
  403d6d:	89 04 24             	mov    %eax,(%esp)
  403d70:	e8 8f 01 00 00       	call   403f04 <__msize>
  403d75:	8b 56 08             	mov    0x8(%esi),%edx
  403d78:	89 c7                	mov    %eax,%edi
  403d7a:	8b 46 04             	mov    0x4(%esi),%eax
  403d7d:	8d 5a 07             	lea    0x7(%edx),%ebx
  403d80:	83 e0 03             	and    $0x3,%eax
  403d83:	83 f8 03             	cmp    $0x3,%eax
  403d86:	75 03                	jne    403d8b <___mingw_memalign_realloc+0x2b>
  403d88:	8d 5a 0b             	lea    0xb(%edx),%ebx
  403d8b:	8b 44 24 38          	mov    0x38(%esp),%eax
  403d8f:	01 d8                	add    %ebx,%eax
  403d91:	89 44 24 04          	mov    %eax,0x4(%esp)
  403d95:	8b 06                	mov    (%esi),%eax
  403d97:	89 04 24             	mov    %eax,(%esp)
  403d9a:	ff 15 54 92 40 00    	call   *0x409254
  403da0:	8b 16                	mov    (%esi),%edx
  403da2:	39 c2                	cmp    %eax,%edx
  403da4:	0f 84 86 00 00 00    	je     403e30 <___mingw_memalign_realloc+0xd0>
  403daa:	31 ed                	xor    %ebp,%ebp
  403dac:	85 c0                	test   %eax,%eax
  403dae:	74 59                	je     403e09 <___mingw_memalign_realloc+0xa9>
  403db0:	8b 4c 24 30          	mov    0x30(%esp),%ecx
  403db4:	8b 2d 6c 80 40 00    	mov    0x40806c,%ebp
  403dba:	29 d1                	sub    %edx,%ecx
  403dbc:	85 ed                	test   %ebp,%ebp
  403dbe:	75 58                	jne    403e18 <___mingw_memalign_realloc+0xb8>
  403dc0:	a3 6c 80 40 00       	mov    %eax,0x40806c
  403dc5:	8b 6e 04             	mov    0x4(%esi),%ebp
  403dc8:	03 5e 0c             	add    0xc(%esi),%ebx
  403dcb:	01 c3                	add    %eax,%ebx
  403dcd:	09 c5                	or     %eax,%ebp
  403dcf:	01 c8                	add    %ecx,%eax
  403dd1:	89 2e                	mov    %ebp,(%esi)
  403dd3:	8b 6e 08             	mov    0x8(%esi),%ebp
  403dd6:	f7 dd                	neg    %ebp
  403dd8:	21 eb                	and    %ebp,%ebx
  403dda:	2b 5e 0c             	sub    0xc(%esi),%ebx
  403ddd:	89 dd                	mov    %ebx,%ebp
  403ddf:	39 c3                	cmp    %eax,%ebx
  403de1:	74 1c                	je     403dff <___mingw_memalign_realloc+0x9f>
  403de3:	2b 54 24 30          	sub    0x30(%esp),%edx
  403de7:	01 d7                	add    %edx,%edi
  403de9:	3b 7c 24 38          	cmp    0x38(%esp),%edi
  403ded:	77 31                	ja     403e20 <___mingw_memalign_realloc+0xc0>
  403def:	89 7c 24 08          	mov    %edi,0x8(%esp)
  403df3:	89 44 24 04          	mov    %eax,0x4(%esp)
  403df7:	89 1c 24             	mov    %ebx,(%esp)
  403dfa:	e8 c5 00 00 00       	call   403ec4 <_memmove>
  403dff:	8b 06                	mov    (%esi),%eax
  403e01:	83 eb 04             	sub    $0x4,%ebx
  403e04:	83 e3 fc             	and    $0xfffffffc,%ebx
  403e07:	89 03                	mov    %eax,(%ebx)
  403e09:	83 c4 1c             	add    $0x1c,%esp
  403e0c:	89 e8                	mov    %ebp,%eax
  403e0e:	5b                   	pop    %ebx
  403e0f:	5e                   	pop    %esi
  403e10:	5f                   	pop    %edi
  403e11:	5d                   	pop    %ebp
  403e12:	c3                   	ret    
  403e13:	8d 74 26 00          	lea    0x0(%esi,%eiz,1),%esi
  403e17:	90                   	nop
  403e18:	39 c5                	cmp    %eax,%ebp
  403e1a:	76 a9                	jbe    403dc5 <___mingw_memalign_realloc+0x65>
  403e1c:	eb a2                	jmp    403dc0 <___mingw_memalign_realloc+0x60>
  403e1e:	66 90                	xchg   %ax,%ax
  403e20:	8b 7c 24 38          	mov    0x38(%esp),%edi
  403e24:	eb c9                	jmp    403def <___mingw_memalign_realloc+0x8f>
  403e26:	8d b4 26 00 00 00 00 	lea    0x0(%esi,%eiz,1),%esi
  403e2d:	8d 76 00             	lea    0x0(%esi),%esi
  403e30:	8b 6c 24 30          	mov    0x30(%esp),%ebp
  403e34:	83 c4 1c             	add    $0x1c,%esp
  403e37:	5b                   	pop    %ebx
  403e38:	5e                   	pop    %esi
  403e39:	89 e8                	mov    %ebp,%eax
  403e3b:	5f                   	pop    %edi
  403e3c:	5d                   	pop    %ebp
  403e3d:	c3                   	ret    
  403e3e:	90                   	nop
  403e3f:	90                   	nop

00403e40 <___register_frame_info>:
  403e40:	ff 25 68 92 40 00    	jmp    *0x409268
  403e46:	90                   	nop
  403e47:	90                   	nop

00403e48 <___deregister_frame_info>:
  403e48:	ff 25 64 92 40 00    	jmp    *0x409264
  403e4e:	90                   	nop
  403e4f:	90                   	nop

00403e50 <___chkstk_ms>:
  403e50:	51                   	push   %ecx
  403e51:	50                   	push   %eax
  403e52:	3d 00 10 00 00       	cmp    $0x1000,%eax
  403e57:	8d 4c 24 0c          	lea    0xc(%esp),%ecx
  403e5b:	72 15                	jb     403e72 <___chkstk_ms+0x22>
  403e5d:	81 e9 00 10 00 00    	sub    $0x1000,%ecx
  403e63:	83 09 00             	orl    $0x0,(%ecx)
  403e66:	2d 00 10 00 00       	sub    $0x1000,%eax
  403e6b:	3d 00 10 00 00       	cmp    $0x1000,%eax
  403e70:	77 eb                	ja     403e5d <___chkstk_ms+0xd>
  403e72:	29 c1                	sub    %eax,%ecx
  403e74:	83 09 00             	orl    $0x0,(%ecx)
  403e77:	58                   	pop    %eax
  403e78:	59                   	pop    %ecx
  403e79:	c3                   	ret    
  403e7a:	90                   	nop
  403e7b:	90                   	nop

00403e7c <_stricoll>:
  403e7c:	ff 25 cc 91 40 00    	jmp    *0x4091cc
  403e82:	90                   	nop
  403e83:	90                   	nop

00403e84 <_strdup>:
  403e84:	ff 25 c8 91 40 00    	jmp    *0x4091c8
  403e8a:	90                   	nop
  403e8b:	90                   	nop

00403e8c <_wcstombs>:
  403e8c:	ff 25 4c 92 40 00    	jmp    *0x40924c
  403e92:	90                   	nop
  403e93:	90                   	nop

00403e94 <_vfprintf>:
  403e94:	ff 25 48 92 40 00    	jmp    *0x409248
  403e9a:	90                   	nop
  403e9b:	90                   	nop

00403e9c <_tolower>:
  403e9c:	ff 25 44 92 40 00    	jmp    *0x409244
  403ea2:	90                   	nop
  403ea3:	90                   	nop

00403ea4 <_strlen>:
  403ea4:	ff 25 40 92 40 00    	jmp    *0x409240
  403eaa:	90                   	nop
  403eab:	90                   	nop

00403eac <_strcoll>:
  403eac:	ff 25 3c 92 40 00    	jmp    *0x40923c
  403eb2:	90                   	nop
  403eb3:	90                   	nop

00403eb4 <_signal>:
  403eb4:	ff 25 38 92 40 00    	jmp    *0x409238
  403eba:	90                   	nop
  403ebb:	90                   	nop

00403ebc <_setlocale>:
  403ebc:	ff 25 34 92 40 00    	jmp    *0x409234
  403ec2:	90                   	nop
  403ec3:	90                   	nop

00403ec4 <_memmove>:
  403ec4:	ff 25 30 92 40 00    	jmp    *0x409230
  403eca:	90                   	nop
  403ecb:	90                   	nop

00403ecc <_memcpy>:
  403ecc:	ff 25 2c 92 40 00    	jmp    *0x40922c
  403ed2:	90                   	nop
  403ed3:	90                   	nop

00403ed4 <_mbstowcs>:
  403ed4:	ff 25 28 92 40 00    	jmp    *0x409228
  403eda:	90                   	nop
  403edb:	90                   	nop

00403edc <_malloc>:
  403edc:	ff 25 24 92 40 00    	jmp    *0x409224
  403ee2:	90                   	nop
  403ee3:	90                   	nop

00403ee4 <_fwrite>:
  403ee4:	ff 25 20 92 40 00    	jmp    *0x409220
  403eea:	90                   	nop
  403eeb:	90                   	nop

00403eec <_calloc>:
  403eec:	ff 25 1c 92 40 00    	jmp    *0x40921c
  403ef2:	90                   	nop
  403ef3:	90                   	nop

00403ef4 <_abort>:
  403ef4:	ff 25 14 92 40 00    	jmp    *0x409214
  403efa:	90                   	nop
  403efb:	90                   	nop

00403efc <__setmode>:
  403efc:	ff 25 10 92 40 00    	jmp    *0x409210
  403f02:	90                   	nop
  403f03:	90                   	nop

00403f04 <__msize>:
  403f04:	ff 25 04 92 40 00    	jmp    *0x409204
  403f0a:	90                   	nop
  403f0b:	90                   	nop

00403f0c <__isctype>:
  403f0c:	ff 25 00 92 40 00    	jmp    *0x409200
  403f12:	90                   	nop
  403f13:	90                   	nop

00403f14 <__fullpath>:
  403f14:	ff 25 f8 91 40 00    	jmp    *0x4091f8
  403f1a:	90                   	nop
  403f1b:	90                   	nop

00403f1c <__errno>:
  403f1c:	ff 25 f0 91 40 00    	jmp    *0x4091f0
  403f22:	90                   	nop
  403f23:	90                   	nop

00403f24 <__cexit>:
  403f24:	ff 25 ec 91 40 00    	jmp    *0x4091ec
  403f2a:	90                   	nop
  403f2b:	90                   	nop

00403f2c <___p__pgmptr>:
  403f2c:	ff 25 e4 91 40 00    	jmp    *0x4091e4
  403f32:	90                   	nop
  403f33:	90                   	nop

00403f34 <___p__fmode>:
  403f34:	ff 25 e0 91 40 00    	jmp    *0x4091e0
  403f3a:	90                   	nop
  403f3b:	90                   	nop

00403f3c <___p__environ>:
  403f3c:	ff 25 dc 91 40 00    	jmp    *0x4091dc
  403f42:	90                   	nop
  403f43:	90                   	nop

00403f44 <___getmainargs>:
  403f44:	ff 25 d4 91 40 00    	jmp    *0x4091d4
  403f4a:	90                   	nop
  403f4b:	90                   	nop

00403f4c <_MessageBoxW@16>:
  403f4c:	ff 25 5c 92 40 00    	jmp    *0x40925c
  403f52:	90                   	nop
  403f53:	90                   	nop

00403f54 <_VirtualQuery@12>:
  403f54:	ff 25 c0 91 40 00    	jmp    *0x4091c0
  403f5a:	90                   	nop
  403f5b:	90                   	nop

00403f5c <_VirtualProtect@16>:
  403f5c:	ff 25 bc 91 40 00    	jmp    *0x4091bc
  403f62:	90                   	nop
  403f63:	90                   	nop

00403f64 <_TlsGetValue@4>:
  403f64:	ff 25 b8 91 40 00    	jmp    *0x4091b8
  403f6a:	90                   	nop
  403f6b:	90                   	nop

00403f6c <_SetUnhandledExceptionFilter@4>:
  403f6c:	ff 25 b4 91 40 00    	jmp    *0x4091b4
  403f72:	90                   	nop
  403f73:	90                   	nop

00403f74 <_LoadLibraryA@4>:
  403f74:	ff 25 b0 91 40 00    	jmp    *0x4091b0
  403f7a:	90                   	nop
  403f7b:	90                   	nop

00403f7c <_LeaveCriticalSection@4>:
  403f7c:	ff 25 ac 91 40 00    	jmp    *0x4091ac
  403f82:	90                   	nop
  403f83:	90                   	nop

00403f84 <_InitializeCriticalSection@4>:
  403f84:	ff 25 a8 91 40 00    	jmp    *0x4091a8
  403f8a:	90                   	nop
  403f8b:	90                   	nop

00403f8c <_GetStartupInfoA@4>:
  403f8c:	ff 25 a4 91 40 00    	jmp    *0x4091a4
  403f92:	90                   	nop
  403f93:	90                   	nop

00403f94 <_GetProcAddress@8>:
  403f94:	ff 25 a0 91 40 00    	jmp    *0x4091a0
  403f9a:	90                   	nop
  403f9b:	90                   	nop

00403f9c <_GetModuleHandleA@4>:
  403f9c:	ff 25 9c 91 40 00    	jmp    *0x40919c
  403fa2:	90                   	nop
  403fa3:	90                   	nop

00403fa4 <_GetModuleFileNameA@12>:
  403fa4:	ff 25 98 91 40 00    	jmp    *0x409198
  403faa:	90                   	nop
  403fab:	90                   	nop

00403fac <_GetLastError@0>:
  403fac:	ff 25 94 91 40 00    	jmp    *0x409194
  403fb2:	90                   	nop
  403fb3:	90                   	nop

00403fb4 <_GetCommandLineA@0>:
  403fb4:	ff 25 90 91 40 00    	jmp    *0x409190
  403fba:	90                   	nop
  403fbb:	90                   	nop

00403fbc <_FreeLibrary@4>:
  403fbc:	ff 25 8c 91 40 00    	jmp    *0x40918c
  403fc2:	90                   	nop
  403fc3:	90                   	nop

00403fc4 <_FindNextFileA@8>:
  403fc4:	ff 25 88 91 40 00    	jmp    *0x409188
  403fca:	90                   	nop
  403fcb:	90                   	nop

00403fcc <_FindFirstFileA@8>:
  403fcc:	ff 25 84 91 40 00    	jmp    *0x409184
  403fd2:	90                   	nop
  403fd3:	90                   	nop

00403fd4 <_FindClose@4>:
  403fd4:	ff 25 80 91 40 00    	jmp    *0x409180
  403fda:	90                   	nop
  403fdb:	90                   	nop

00403fdc <_ExitProcess@4>:
  403fdc:	ff 25 7c 91 40 00    	jmp    *0x40917c
  403fe2:	90                   	nop
  403fe3:	90                   	nop

00403fe4 <_EnterCriticalSection@4>:
  403fe4:	ff 25 78 91 40 00    	jmp    *0x409178
  403fea:	90                   	nop
  403feb:	90                   	nop

00403fec <_DeleteCriticalSection@4>:
  403fec:	ff 25 74 91 40 00    	jmp    *0x409174
  403ff2:	90                   	nop
  403ff3:	90                   	nop

00403ff4 <.text>:
  403ff4:	66 90                	xchg   %ax,%ax
  403ff6:	66 90                	xchg   %ax,%ax
  403ff8:	66 90                	xchg   %ax,%ax
  403ffa:	66 90                	xchg   %ax,%ax
  403ffc:	66 90                	xchg   %ax,%ax
  403ffe:	66 90                	xchg   %ax,%ax

00404000 <_main>:
  404000:	8d 4c 24 04          	lea    0x4(%esp),%ecx
  404004:	83 e4 f0             	and    $0xfffffff0,%esp
  404007:	ff 71 fc             	pushl  -0x4(%ecx)
  40400a:	55                   	push   %ebp
  40400b:	89 e5                	mov    %esp,%ebp
  40400d:	56                   	push   %esi
  40400e:	53                   	push   %ebx
  40400f:	51                   	push   %ecx
  404010:	83 ec 6c             	sub    $0x6c,%esp
  404013:	e8 48 da ff ff       	call   401a60 <___main>
  404018:	e8 97 ff ff ff       	call   403fb4 <_GetCommandLineA@0>
  40401d:	89 c3                	mov    %eax,%ebx
  40401f:	8d 45 a4             	lea    -0x5c(%ebp),%eax
  404022:	89 04 24             	mov    %eax,(%esp)
  404025:	e8 62 ff ff ff       	call   403f8c <_GetStartupInfoA@4>
  40402a:	83 ec 04             	sub    $0x4,%esp
  40402d:	85 db                	test   %ebx,%ebx
  40402f:	75 0a                	jne    40403b <_main+0x3b>
  404031:	eb 5b                	jmp    40408e <_main+0x8e>
  404033:	8d 74 26 00          	lea    0x0(%esi,%eiz,1),%esi
  404037:	90                   	nop
  404038:	83 c3 01             	add    $0x1,%ebx
  40403b:	0f b6 03             	movzbl (%ebx),%eax
  40403e:	3c 20                	cmp    $0x20,%al
  404040:	74 f6                	je     404038 <_main+0x38>
  404042:	3c 09                	cmp    $0x9,%al
  404044:	74 f2                	je     404038 <_main+0x38>
  404046:	3c 22                	cmp    $0x22,%al
  404048:	75 2d                	jne    404077 <_main+0x77>
  40404a:	8d b6 00 00 00 00    	lea    0x0(%esi),%esi
  404050:	89 da                	mov    %ebx,%edx
  404052:	0f b6 43 01          	movzbl 0x1(%ebx),%eax
  404056:	83 c3 01             	add    $0x1,%ebx
  404059:	3c 22                	cmp    $0x22,%al
  40405b:	74 08                	je     404065 <_main+0x65>
  40405d:	84 c0                	test   %al,%al
  40405f:	75 ef                	jne    404050 <_main+0x50>
  404061:	3c 22                	cmp    $0x22,%al
  404063:	75 1e                	jne    404083 <_main+0x83>
  404065:	8d 5a 02             	lea    0x2(%edx),%ebx
  404068:	eb 19                	jmp    404083 <_main+0x83>
  40406a:	8d b6 00 00 00 00    	lea    0x0(%esi),%esi
  404070:	3c 09                	cmp    $0x9,%al
  404072:	74 0f                	je     404083 <_main+0x83>
  404074:	83 c3 01             	add    $0x1,%ebx
  404077:	0f b6 03             	movzbl (%ebx),%eax
  40407a:	a8 df                	test   $0xdf,%al
  40407c:	75 f2                	jne    404070 <_main+0x70>
  40407e:	eb 03                	jmp    404083 <_main+0x83>
  404080:	83 c3 01             	add    $0x1,%ebx
  404083:	0f b6 03             	movzbl (%ebx),%eax
  404086:	3c 20                	cmp    $0x20,%al
  404088:	74 f6                	je     404080 <_main+0x80>
  40408a:	3c 09                	cmp    $0x9,%al
  40408c:	74 f2                	je     404080 <_main+0x80>
  40408e:	be 0a 00 00 00       	mov    $0xa,%esi
  404093:	f6 45 d0 01          	testb  $0x1,-0x30(%ebp)
  404097:	74 04                	je     40409d <_main+0x9d>
  404099:	0f b7 75 d4          	movzwl -0x2c(%ebp),%esi
  40409d:	c7 04 24 00 00 00 00 	movl   $0x0,(%esp)
  4040a4:	e8 f3 fe ff ff       	call   403f9c <_GetModuleHandleA@4>
  4040a9:	83 ec 04             	sub    $0x4,%esp
  4040ac:	89 74 24 0c          	mov    %esi,0xc(%esp)
  4040b0:	89 5c 24 08          	mov    %ebx,0x8(%esp)
  4040b4:	c7 44 24 04 00 00 00 	movl   $0x0,0x4(%esp)
  4040bb:	00 
  4040bc:	89 04 24             	mov    %eax,(%esp)
  4040bf:	e8 4c d3 ff ff       	call   401410 <_WinMain@16>
  4040c4:	83 ec 10             	sub    $0x10,%esp
  4040c7:	8d 65 f4             	lea    -0xc(%ebp),%esp
  4040ca:	59                   	pop    %ecx
  4040cb:	5b                   	pop    %ebx
  4040cc:	5e                   	pop    %esi
  4040cd:	5d                   	pop    %ebp
  4040ce:	8d 61 fc             	lea    -0x4(%ecx),%esp
  4040d1:	c3                   	ret    
  4040d2:	90                   	nop
  4040d3:	90                   	nop
  4040d4:	90                   	nop
  4040d5:	90                   	nop
  4040d6:	90                   	nop
  4040d7:	90                   	nop
  4040d8:	90                   	nop
  4040d9:	90                   	nop
  4040da:	90                   	nop
  4040db:	90                   	nop
  4040dc:	90                   	nop
  4040dd:	90                   	nop
  4040de:	90                   	nop
  4040df:	90                   	nop

004040e0 <_register_frame_ctor>:
  4040e0:	e9 4b d2 ff ff       	jmp    401330 <___gcc_register_frame>
  4040e5:	90                   	nop
  4040e6:	90                   	nop
  4040e7:	90                   	nop
  4040e8:	90                   	nop
  4040e9:	90                   	nop
  4040ea:	90                   	nop
  4040eb:	90                   	nop
  4040ec:	90                   	nop
  4040ed:	90                   	nop
  4040ee:	90                   	nop
  4040ef:	90                   	nop

004040f0 <__CTOR_LIST__>:
  4040f0:	ff                   	(bad)  
  4040f1:	ff                   	(bad)  
  4040f2:	ff                   	(bad)  
  4040f3:	ff                 	jmp    *%eax

004040f4 <.ctors.65535>:
  4040f4:	e0 40                	loopne 404136 <__DTOR_LIST__+0x3a>
  4040f6:	40                   	inc    %eax
  4040f7:	00 00                	add    %al,(%eax)
  4040f9:	00 00                	add    %al,(%eax)
	...

004040fc <__DTOR_LIST__>:
  4040fc:	ff                   	(bad)  
  4040fd:	ff                   	(bad)  
  4040fe:	ff                   	(bad)  
  4040ff:	ff 00                	incl   (%eax)
  404101:	00 00                	add    %al,(%eax)
	...

Disassembly of section .data:

00405000 <__data_start__>:
  405000:	00 00                	add    %al,(%eax)
	...

00405004 <__CRT_glob>:
  405004:	02 00                	add    (%eax),%al
	...

00405008 <__CRT_fenv>:
  405008:	fd                   	std    
  405009:	ff                   	(bad)  
  40500a:	ff                   	(bad)  
  40500b:	ff                 	incl   (%eax)

0040500c <__fmode>:
  40500c:	00 40 00             	add    %al,0x0(%eax)
	...

00405010 <.data>:
  405010:	00 41 40             	add    %al,0x40(%ecx)
	...

00405014 <.data>:
  405014:	ff                   	(bad)  
  405015:	ff                   	(bad)  
  405016:	ff                   	(bad)  
  405017:	ff                   	.byte 0xff

Disassembly of section .rdata:

00406000 <.rdata>:
  406000:	6c                   	insb   (%dx),%es:(%edi)
  406001:	69 62 67 63 63 5f 73 	imul   $0x735f6363,0x67(%edx),%esp
  406008:	5f                   	pop    %edi
  406009:	64 77 32             	fs ja  40603e <.rdata+0x3e>
  40600c:	2d 31 2e 64 6c       	sub    $0x6c642e31,%eax
  406011:	6c                   	insb   (%dx),%es:(%edi)
  406012:	00 5f 5f             	add    %bl,0x5f(%edi)
  406015:	72 65                	jb     40607c <.rdata+0x38>
  406017:	67 69 73 74 65 72 5f 	imul   $0x665f7265,0x74(%bp,%di),%esi
  40601e:	66 
  40601f:	72 61                	jb     406082 <.rdata+0x3e>
  406021:	6d                   	insl   (%dx),%es:(%edi)
  406022:	65 5f                	gs pop %edi
  406024:	69 6e 66 6f 00 5f 5f 	imul   $0x5f5f006f,0x66(%esi),%ebp
  40602b:	64 65 72 65          	fs gs jb 406094 <.rdata>
  40602f:	67 69 73 74 65 72 5f 	imul   $0x665f7265,0x74(%bp,%di),%esi
  406036:	66 
  406037:	72 61                	jb     40609a <.rdata+0x6>
  406039:	6d                   	insl   (%dx),%es:(%edi)
  40603a:	65 5f                	gs pop %edi
  40603c:	69 6e 66 6f 00 00 00 	imul   $0x6f,0x66(%esi),%ebp
	...

00406044 <.rdata>:
  406044:	54                   	push   %esp
  406045:	00 ed                	add    %ch,%ch
  406047:	00 74 00 75          	add    %dh,0x75(%eax,%eax,1)
  40604b:	00 6c 00 6f          	add    %ch,0x6f(%eax,%eax,1)
  40604f:	00 20                	add    %ah,(%eax)
  406051:	00 64 00 65          	add    %ah,0x65(%eax,%eax,1)
  406055:	00 6c 00 20          	add    %ch,0x20(%eax,%eax,1)
  406059:	00 4d 00             	add    %cl,0x0(%ebp)
  40605c:	65 00 6e 00          	add    %ch,%gs:0x0(%esi)
  406060:	73 00                	jae    406062 <.rdata+0x1e>
  406062:	61                   	popa   
  406063:	00 6a 00             	add    %ch,0x0(%edx)
  406066:	65 00 00             	add    %al,%gs:(%eax)
  406069:	00 00                	add    %al,(%eax)
  40606b:	00 45 00             	add    %al,0x0(%ebp)
  40606e:	73 00                	jae    406070 <.rdata+0x2c>
  406070:	74 00                	je     406072 <.rdata+0x2e>
  406072:	65 00 20             	add    %ah,%gs:(%eax)
  406075:	00 65 00             	add    %ah,0x0(%ebp)
  406078:	73 00                	jae    40607a <.rdata+0x36>
  40607a:	20 00                	and    %al,(%eax)
  40607c:	74 00                	je     40607e <.rdata+0x3a>
  40607e:	75 00                	jne    406080 <.rdata+0x3c>
  406080:	20 00                	and    %al,(%eax)
  406082:	6d                   	insl   (%dx),%es:(%edi)
  406083:	00 65 00             	add    %ah,0x0(%ebp)
  406086:	6e                   	outsb  %ds:(%esi),(%dx)
  406087:	00 73 00             	add    %dh,0x0(%ebx)
  40608a:	61                   	popa   
  40608b:	00 6a 00             	add    %ch,0x0(%edx)
  40608e:	65 00 00             	add    %al,%gs:(%eax)
  406091:	00 00                	add    %al,(%eax)
	...

00406094 <.rdata>:
  406094:	a4                   	movsb  %ds:(%esi),%es:(%edi)
  406095:	17                   	pop    %ss
  406096:	40                   	inc    %eax
  406097:	00 0a                	add    %cl,(%edx)
  406099:	15 40 00 0a 15       	adc    $0x150a0040,%eax
  40609e:	40                   	inc    %eax
  40609f:	00 0a                	add    %cl,(%edx)
  4060a1:	15 40 00 0a 15       	adc    $0x150a0040,%eax
  4060a6:	40                   	inc    %eax
  4060a7:	00 50 17             	add    %dl,0x17(%eax)
  4060aa:	40                   	inc    %eax
  4060ab:	00 0a                	add    %cl,(%edx)
  4060ad:	15 40 00 0a 15       	adc    $0x150a0040,%eax
  4060b2:	40                   	inc    %eax
  4060b3:	00 06                	add    %al,(%esi)
  4060b5:	17                   	pop    %ss
  4060b6:	40                   	inc    %eax
  4060b7:	00 0a                	add    %cl,(%edx)
  4060b9:	15 40 00 06 17       	adc    $0x17060040,%eax
  4060be:	40                   	inc    %eax
  4060bf:	00 0a                	add    %cl,(%edx)
  4060c1:	15 40 00 0a 15       	adc    $0x150a0040,%eax
  4060c6:	40                   	inc    %eax
  4060c7:	00 0a                	add    %cl,(%edx)
  4060c9:	15 40 00 0a 15       	adc    $0x150a0040,%eax
  4060ce:	40                   	inc    %eax
  4060cf:	00 0a                	add    %cl,(%edx)
  4060d1:	15 40 00 0a 15       	adc    $0x150a0040,%eax
  4060d6:	40                   	inc    %eax
  4060d7:	00 0a                	add    %cl,(%edx)
  4060d9:	15 40 00 0a 15       	adc    $0x150a0040,%eax
  4060de:	40                   	inc    %eax
  4060df:	00 0a                	add    %cl,(%edx)
  4060e1:	15 40 00 0a 15       	adc    $0x150a0040,%eax
  4060e6:	40                   	inc    %eax
  4060e7:	00 0a                	add    %cl,(%edx)
  4060e9:	15 40 00 0a 15       	adc    $0x150a0040,%eax
  4060ee:	40                   	inc    %eax
  4060ef:	00 0a                	add    %cl,(%edx)
  4060f1:	15 40 00 0a 15       	adc    $0x150a0040,%eax
  4060f6:	40                   	inc    %eax
  4060f7:	00 0a                	add    %cl,(%edx)
  4060f9:	15 40 00 0a 15       	adc    $0x150a0040,%eax
  4060fe:	40                   	inc    %eax
  4060ff:	00 0a                	add    %cl,(%edx)
  406101:	15 40 00 0a 15       	adc    $0x150a0040,%eax
  406106:	40                   	inc    %eax
  406107:	00 06                	add    %al,(%esi)
  406109:	17                   	pop    %ss
  40610a:	40                   	inc    %eax
  40610b:	00 18                	add    %bl,(%eax)
  40610d:	18 40 00             	sbb    %al,0x0(%eax)
  406110:	07                   	pop    %es
  406111:	18 40 00             	sbb    %al,0x0(%eax)
  406114:	0a 15 40 00 0a 15    	or     0x150a0040,%dl
  40611a:	40                   	inc    %eax
  40611b:	00 0a                	add    %cl,(%edx)
  40611d:	15 40 00 0a 15       	adc    $0x150a0040,%eax
  406122:	40                   	inc    %eax
  406123:	00 0a                	add    %cl,(%edx)
  406125:	15 40 00 0a 15       	adc    $0x150a0040,%eax
  40612a:	40                   	inc    %eax
  40612b:	00 0a                	add    %cl,(%edx)
  40612d:	15 40 00 0a 15       	adc    $0x150a0040,%eax
  406132:	40                   	inc    %eax
  406133:	00 0a                	add    %cl,(%edx)
  406135:	15 40 00 0a 15       	adc    $0x150a0040,%eax
  40613a:	40                   	inc    %eax
  40613b:	00 0a                	add    %cl,(%edx)
  40613d:	15 40 00 0a 15       	adc    $0x150a0040,%eax
  406142:	40                   	inc    %eax
  406143:	00 0a                	add    %cl,(%edx)
  406145:	15 40 00 0a 15       	adc    $0x150a0040,%eax
  40614a:	40                   	inc    %eax
  40614b:	00 0a                	add    %cl,(%edx)
  40614d:	15 40 00 0a 15       	adc    $0x150a0040,%eax
  406152:	40                   	inc    %eax
  406153:	00 0a                	add    %cl,(%edx)
  406155:	15 40 00 0a 15       	adc    $0x150a0040,%eax
  40615a:	40                   	inc    %eax
  40615b:	00 0a                	add    %cl,(%edx)
  40615d:	15 40 00 0a 15       	adc    $0x150a0040,%eax
  406162:	40                   	inc    %eax
  406163:	00 0a                	add    %cl,(%edx)
  406165:	15 40 00 0a 15       	adc    $0x150a0040,%eax
  40616a:	40                   	inc    %eax
  40616b:	00 0a                	add    %cl,(%edx)
  40616d:	15 40 00 0a 15       	adc    $0x150a0040,%eax
  406172:	40                   	inc    %eax
  406173:	00 0a                	add    %cl,(%edx)
  406175:	15 40 00 0a 15       	adc    $0x150a0040,%eax
  40617a:	40                   	inc    %eax
  40617b:	00 0a                	add    %cl,(%edx)
  40617d:	15 40 00 0a 15       	adc    $0x150a0040,%eax
  406182:	40                   	inc    %eax
  406183:	00 0a                	add    %cl,(%edx)
  406185:	15 40 00 0a 15       	adc    $0x150a0040,%eax
  40618a:	40                   	inc    %eax
  40618b:	00 06                	add    %al,(%esi)
  40618d:	17                   	pop    %ss
  40618e:	40                   	inc    %eax
  40618f:	00 0a                	add    %cl,(%edx)
  406191:	15 40 00 06 17       	adc    $0x17060040,%eax
  406196:	40                   	inc    %eax
  406197:	00 0a                	add    %cl,(%edx)
  406199:	15 40 00 06 17       	adc    $0x17060040,%eax
  40619e:	40                   	inc    %eax
	...

004061a0 <___dyn_tls_init_callback>:
  4061a0:	d0 1a                	rcrb   (%edx)
  4061a2:	40                   	inc    %eax
	...

004061a4 <.rdata>:
  4061a4:	4d                   	dec    %ebp
  4061a5:	69 6e 67 77 20 72 75 	imul   $0x75722077,0x67(%esi),%ebp
  4061ac:	6e                   	outsb  %ds:(%esi),(%dx)
  4061ad:	74 69                	je     406218 <.rdata+0x74>
  4061af:	6d                   	insl   (%dx),%es:(%edi)
  4061b0:	65 20 66 61          	and    %ah,%gs:0x61(%esi)
  4061b4:	69 6c 75 72 65 3a 0a 	imul   $0xa3a65,0x72(%ebp,%esi,2),%ebp
  4061bb:	00 
  4061bc:	20 20                	and    %ah,(%eax)
  4061be:	56                   	push   %esi
  4061bf:	69 72 74 75 61 6c 51 	imul   $0x516c6175,0x74(%edx),%esi
  4061c6:	75 65                	jne    40622d <.rdata+0x89>
  4061c8:	72 79                	jb     406243 <.rdata+0x9f>
  4061ca:	20 66 61             	and    %ah,0x61(%esi)
  4061cd:	69 6c 65 64 20 66 6f 	imul   $0x726f6620,0x64(%ebp,%eiz,2),%ebp
  4061d4:	72 
  4061d5:	20 25 64 20 62 79    	and    %ah,0x79622064
  4061db:	74 65                	je     406242 <.rdata+0x9e>
  4061dd:	73 20                	jae    4061ff <.rdata+0x5b>
  4061df:	61                   	popa   
  4061e0:	74 20                	je     406202 <.rdata+0x5e>
  4061e2:	61                   	popa   
  4061e3:	64 64 72 65          	fs fs jb 40624c <.rdata+0xa8>
  4061e7:	73 73                	jae    40625c <.rdata+0xc>
  4061e9:	20 25 70 00 00 00    	and    %ah,0x70
  4061ef:	00 20                	add    %ah,(%eax)
  4061f1:	20 55 6e             	and    %dl,0x6e(%ebp)
  4061f4:	6b 6e 6f 77          	imul   $0x77,0x6f(%esi),%ebp
  4061f8:	6e                   	outsb  %ds:(%esi),(%dx)
  4061f9:	20 70 73             	and    %dh,0x73(%eax)
  4061fc:	65 75 64             	gs jne 406263 <.rdata+0x13>
  4061ff:	6f                   	outsl  %ds:(%esi),(%dx)
  406200:	20 72 65             	and    %dh,0x65(%edx)
  406203:	6c                   	insb   (%dx),%es:(%edi)
  406204:	6f                   	outsl  %ds:(%esi),(%dx)
  406205:	63 61 74             	arpl   %sp,0x74(%ecx)
  406208:	69 6f 6e 20 70 72 6f 	imul   $0x6f727020,0x6e(%edi),%ebp
  40620f:	74 6f                	je     406280 <.rdata+0x1c>
  406211:	63 6f 6c             	arpl   %bp,0x6c(%edi)
  406214:	20 76 65             	and    %dh,0x65(%esi)
  406217:	72 73                	jb     40628c <.rdata+0x28>
  406219:	69 6f 6e 20 25 64 2e 	imul   $0x2e642520,0x6e(%edi),%ebp
  406220:	0a 00                	or     (%eax),%al
  406222:	00 00                	add    %al,(%eax)
  406224:	20 20                	and    %ah,(%eax)
  406226:	55                   	push   %ebp
  406227:	6e                   	outsb  %ds:(%esi),(%dx)
  406228:	6b 6e 6f 77          	imul   $0x77,0x6f(%esi),%ebp
  40622c:	6e                   	outsb  %ds:(%esi),(%dx)
  40622d:	20 70 73             	and    %dh,0x73(%eax)
  406230:	65 75 64             	gs jne 406297 <.rdata+0x33>
  406233:	6f                   	outsl  %ds:(%esi),(%dx)
  406234:	20 72 65             	and    %dh,0x65(%edx)
  406237:	6c                   	insb   (%dx),%es:(%edi)
  406238:	6f                   	outsl  %ds:(%esi),(%dx)
  406239:	63 61 74             	arpl   %sp,0x74(%ecx)
  40623c:	69 6f 6e 20 62 69 74 	imul   $0x74696220,0x6e(%edi),%ebp
  406243:	20 73 69             	and    %dh,0x69(%ebx)
  406246:	7a 65                	jp     4062ad <.rdata$zzz+0xd>
  406248:	20 25 64 2e 0a 00    	and    %ah,0xa2e64
	...

00406250 <.rdata>:
  406250:	67 6c                	insb   (%dx),%es:(%di)
  406252:	6f                   	outsl  %ds:(%esi),(%dx)
  406253:	62 2d 31 2e 30 2d    	bound  %ebp,0x2d302e31
  406259:	6d                   	insl   (%dx),%es:(%edi)
  40625a:	69 6e 67 77 33 32 00 	imul   $0x323377,0x67(%esi),%ebp
  406261:	00 00                	add    %al,(%eax)
	...

00406264 <.rdata>:
  406264:	00 00                	add    %al,(%eax)
  406266:	2e 00 00             	add    %al,%cs:(%eax)
  406269:	00 00                	add    %al,(%eax)
  40626b:	00 47 43             	add    %al,0x43(%edi)
  40626e:	43                   	inc    %ebx
  40626f:	3a 20                	cmp    (%eax),%ah
  406271:	28 4d 69             	sub    %cl,0x69(%ebp)
  406274:	6e                   	outsb  %ds:(%esi),(%dx)
  406275:	47                   	inc    %edi
  406276:	57                   	push   %edi
  406277:	2e 6f                	outsl  %cs:(%esi),(%dx)
  406279:	72 67                	jb     4062e2 <.rdata$zzz+0xe>
  40627b:	20 43 72             	and    %al,0x72(%ebx)
  40627e:	6f                   	outsl  %ds:(%esi),(%dx)
  40627f:	73 73                	jae    4062f4 <.rdata$zzz+0x20>
  406281:	2d 47 43 43 20       	sub    $0x20434347,%eax
  406286:	42                   	inc    %edx
  406287:	75 69                	jne    4062f2 <.rdata$zzz+0x1e>
  406289:	6c                   	insb   (%dx),%es:(%edi)
  40628a:	64 2d 32 30 32 30    	fs sub $0x30323032,%eax
  406290:	30 35 33 31 2d 31    	xor    %dh,0x312d3133
  406296:	29 20                	sub    %esp,(%eax)
  406298:	39 2e                	cmp    %ebp,(%esi)
  40629a:	32 2e                	xor    (%esi),%ch
  40629c:	30 00                	xor    %al,(%eax)
	...

004062a0 <.rdata$zzz>:
  4062a0:	47                   	inc    %edi
  4062a1:	43                   	inc    %ebx
  4062a2:	43                   	inc    %ebx
  4062a3:	3a 20                	cmp    (%eax),%ah
  4062a5:	28 4d 69             	sub    %cl,0x69(%ebp)
  4062a8:	6e                   	outsb  %ds:(%esi),(%dx)
  4062a9:	47                   	inc    %edi
  4062aa:	57                   	push   %edi
  4062ab:	2e 6f                	outsl  %cs:(%esi),(%dx)
  4062ad:	72 67                	jb     406316 <.rdata$zzz+0x42>
  4062af:	20 43 72             	and    %al,0x72(%ebx)
  4062b2:	6f                   	outsl  %ds:(%esi),(%dx)
  4062b3:	73 73                	jae    406328 <.rdata$zzz+0x54>
  4062b5:	2d 47 43 43 20       	sub    $0x20434347,%eax
  4062ba:	42                   	inc    %edx
  4062bb:	75 69                	jne    406326 <.rdata$zzz+0x52>
  4062bd:	6c                   	insb   (%dx),%es:(%edi)
  4062be:	64 2d 32 30 32 30    	fs sub $0x30323032,%eax
  4062c4:	30 35 33 31 2d 31    	xor    %dh,0x312d3133
  4062ca:	29 20                	sub    %esp,(%eax)
  4062cc:	39 2e                	cmp    %ebp,(%esi)
  4062ce:	32 2e                	xor    (%esi),%ch
  4062d0:	30 00                	xor    %al,(%eax)
	...

004062d4 <.rdata$zzz>:
  4062d4:	47                   	inc    %edi
  4062d5:	43                   	inc    %ebx
  4062d6:	43                   	inc    %ebx
  4062d7:	3a 20                	cmp    (%eax),%ah
  4062d9:	28 4d 69             	sub    %cl,0x69(%ebp)
  4062dc:	6e                   	outsb  %ds:(%esi),(%dx)
  4062dd:	47                   	inc    %edi
  4062de:	57                   	push   %edi
  4062df:	2e 6f                	outsl  %cs:(%esi),(%dx)
  4062e1:	72 67                	jb     40634a <.rdata$zzz+0x76>
  4062e3:	20 47 43             	and    %al,0x43(%edi)
  4062e6:	43                   	inc    %ebx
  4062e7:	20 42 75             	and    %al,0x75(%edx)
  4062ea:	69 6c 64 2d 32 29 20 	imul   $0x39202932,0x2d(%esp,%eiz,2),%ebp
  4062f1:	39 
  4062f2:	2e 32 2e             	xor    %cs:(%esi),%ch
  4062f5:	30 00                	xor    %al,(%eax)
  4062f7:	00 47 43             	add    %al,0x43(%edi)
  4062fa:	43                   	inc    %ebx
  4062fb:	3a 20                	cmp    (%eax),%ah
  4062fd:	28 4d 69             	sub    %cl,0x69(%ebp)
  406300:	6e                   	outsb  %ds:(%esi),(%dx)
  406301:	47                   	inc    %edi
  406302:	57                   	push   %edi
  406303:	2e 6f                	outsl  %cs:(%esi),(%dx)
  406305:	72 67                	jb     40636e <.rdata$zzz+0x9a>
  406307:	20 43 72             	and    %al,0x72(%ebx)
  40630a:	6f                   	outsl  %ds:(%esi),(%dx)
  40630b:	73 73                	jae    406380 <.rdata$zzz+0xac>
  40630d:	2d 47 43 43 20       	sub    $0x20434347,%eax
  406312:	42                   	inc    %edx
  406313:	75 69                	jne    40637e <.rdata$zzz+0xaa>
  406315:	6c                   	insb   (%dx),%es:(%edi)
  406316:	64 2d 32 30 32 30    	fs sub $0x30323032,%eax
  40631c:	30 35 33 31 2d 31    	xor    %dh,0x312d3133
  406322:	29 20                	sub    %esp,(%eax)
  406324:	39 2e                	cmp    %ebp,(%esi)
  406326:	32 2e                	xor    (%esi),%ch
  406328:	30 00                	xor    %al,(%eax)
  40632a:	00 00                	add    %al,(%eax)
  40632c:	47                   	inc    %edi
  40632d:	43                   	inc    %ebx
  40632e:	43                   	inc    %ebx
  40632f:	3a 20                	cmp    (%eax),%ah
  406331:	28 4d 69             	sub    %cl,0x69(%ebp)
  406334:	6e                   	outsb  %ds:(%esi),(%dx)
  406335:	47                   	inc    %edi
  406336:	57                   	push   %edi
  406337:	2e 6f                	outsl  %cs:(%esi),(%dx)
  406339:	72 67                	jb     4063a2 <.rdata$zzz+0xce>
  40633b:	20 43 72             	and    %al,0x72(%ebx)
  40633e:	6f                   	outsl  %ds:(%esi),(%dx)
  40633f:	73 73                	jae    4063b4 <.rdata$zzz+0xe0>
  406341:	2d 47 43 43 20       	sub    $0x20434347,%eax
  406346:	42                   	inc    %edx
  406347:	75 69                	jne    4063b2 <.rdata$zzz+0xde>
  406349:	6c                   	insb   (%dx),%es:(%edi)
  40634a:	64 2d 32 30 32 30    	fs sub $0x30323032,%eax
  406350:	30 35 33 31 2d 31    	xor    %dh,0x312d3133
  406356:	29 20                	sub    %esp,(%eax)
  406358:	39 2e                	cmp    %ebp,(%esi)
  40635a:	32 2e                	xor    (%esi),%ch
  40635c:	30 00                	xor    %al,(%eax)
  40635e:	00 00                	add    %al,(%eax)
  406360:	47                   	inc    %edi
  406361:	43                   	inc    %ebx
  406362:	43                   	inc    %ebx
  406363:	3a 20                	cmp    (%eax),%ah
  406365:	28 4d 69             	sub    %cl,0x69(%ebp)
  406368:	6e                   	outsb  %ds:(%esi),(%dx)
  406369:	47                   	inc    %edi
  40636a:	57                   	push   %edi
  40636b:	2e 6f                	outsl  %cs:(%esi),(%dx)
  40636d:	72 67                	jb     4063d6 <.rdata$zzz+0x102>
  40636f:	20 43 72             	and    %al,0x72(%ebx)
  406372:	6f                   	outsl  %ds:(%esi),(%dx)
  406373:	73 73                	jae    4063e8 <.rdata$zzz+0x114>
  406375:	2d 47 43 43 20       	sub    $0x20434347,%eax
  40637a:	42                   	inc    %edx
  40637b:	75 69                	jne    4063e6 <.rdata$zzz+0x112>
  40637d:	6c                   	insb   (%dx),%es:(%edi)
  40637e:	64 2d 32 30 32 30    	fs sub $0x30323032,%eax
  406384:	30 35 33 31 2d 31    	xor    %dh,0x312d3133
  40638a:	29 20                	sub    %esp,(%eax)
  40638c:	39 2e                	cmp    %ebp,(%esi)
  40638e:	32 2e                	xor    (%esi),%ch
  406390:	30 00                	xor    %al,(%eax)
  406392:	00 00                	add    %al,(%eax)
  406394:	47                   	inc    %edi
  406395:	43                   	inc    %ebx
  406396:	43                   	inc    %ebx
  406397:	3a 20                	cmp    (%eax),%ah
  406399:	28 4d 69             	sub    %cl,0x69(%ebp)
  40639c:	6e                   	outsb  %ds:(%esi),(%dx)
  40639d:	47                   	inc    %edi
  40639e:	57                   	push   %edi
  40639f:	2e 6f                	outsl  %cs:(%esi),(%dx)
  4063a1:	72 67                	jb     40640a <.rdata$zzz+0x136>
  4063a3:	20 43 72             	and    %al,0x72(%ebx)
  4063a6:	6f                   	outsl  %ds:(%esi),(%dx)
  4063a7:	73 73                	jae    40641c <.rdata$zzz+0x148>
  4063a9:	2d 47 43 43 20       	sub    $0x20434347,%eax
  4063ae:	42                   	inc    %edx
  4063af:	75 69                	jne    40641a <.rdata$zzz+0x146>
  4063b1:	6c                   	insb   (%dx),%es:(%edi)
  4063b2:	64 2d 32 30 32 30    	fs sub $0x30323032,%eax
  4063b8:	30 35 33 31 2d 31    	xor    %dh,0x312d3133
  4063be:	29 20                	sub    %esp,(%eax)
  4063c0:	39 2e                	cmp    %ebp,(%esi)
  4063c2:	32 2e                	xor    (%esi),%ch
  4063c4:	30 00                	xor    %al,(%eax)
  4063c6:	00 00                	add    %al,(%eax)
  4063c8:	47                   	inc    %edi
  4063c9:	43                   	inc    %ebx
  4063ca:	43                   	inc    %ebx
  4063cb:	3a 20                	cmp    (%eax),%ah
  4063cd:	28 4d 69             	sub    %cl,0x69(%ebp)
  4063d0:	6e                   	outsb  %ds:(%esi),(%dx)
  4063d1:	47                   	inc    %edi
  4063d2:	57                   	push   %edi
  4063d3:	2e 6f                	outsl  %cs:(%esi),(%dx)
  4063d5:	72 67                	jb     40643e <.rdata$zzz+0x16a>
  4063d7:	20 43 72             	and    %al,0x72(%ebx)
  4063da:	6f                   	outsl  %ds:(%esi),(%dx)
  4063db:	73 73                	jae    406450 <.rdata$zzz+0x17c>
  4063dd:	2d 47 43 43 20       	sub    $0x20434347,%eax
  4063e2:	42                   	inc    %edx
  4063e3:	75 69                	jne    40644e <.rdata$zzz+0x17a>
  4063e5:	6c                   	insb   (%dx),%es:(%edi)
  4063e6:	64 2d 32 30 32 30    	fs sub $0x30323032,%eax
  4063ec:	30 35 33 31 2d 31    	xor    %dh,0x312d3133
  4063f2:	29 20                	sub    %esp,(%eax)
  4063f4:	39 2e                	cmp    %ebp,(%esi)
  4063f6:	32 2e                	xor    (%esi),%ch
  4063f8:	30 00                	xor    %al,(%eax)
  4063fa:	00 00                	add    %al,(%eax)
  4063fc:	47                   	inc    %edi
  4063fd:	43                   	inc    %ebx
  4063fe:	43                   	inc    %ebx
  4063ff:	3a 20                	cmp    (%eax),%ah
  406401:	28 4d 69             	sub    %cl,0x69(%ebp)
  406404:	6e                   	outsb  %ds:(%esi),(%dx)
  406405:	47                   	inc    %edi
  406406:	57                   	push   %edi
  406407:	2e 6f                	outsl  %cs:(%esi),(%dx)
  406409:	72 67                	jb     406472 <.rdata$zzz+0x19e>
  40640b:	20 43 72             	and    %al,0x72(%ebx)
  40640e:	6f                   	outsl  %ds:(%esi),(%dx)
  40640f:	73 73                	jae    406484 <.rdata$zzz+0x1b0>
  406411:	2d 47 43 43 20       	sub    $0x20434347,%eax
  406416:	42                   	inc    %edx
  406417:	75 69                	jne    406482 <.rdata$zzz+0x1ae>
  406419:	6c                   	insb   (%dx),%es:(%edi)
  40641a:	64 2d 32 30 32 30    	fs sub $0x30323032,%eax
  406420:	30 35 33 31 2d 31    	xor    %dh,0x312d3133
  406426:	29 20                	sub    %esp,(%eax)
  406428:	39 2e                	cmp    %ebp,(%esi)
  40642a:	32 2e                	xor    (%esi),%ch
  40642c:	30 00                	xor    %al,(%eax)
  40642e:	00 00                	add    %al,(%eax)
  406430:	47                   	inc    %edi
  406431:	43                   	inc    %ebx
  406432:	43                   	inc    %ebx
  406433:	3a 20                	cmp    (%eax),%ah
  406435:	28 4d 69             	sub    %cl,0x69(%ebp)
  406438:	6e                   	outsb  %ds:(%esi),(%dx)
  406439:	47                   	inc    %edi
  40643a:	57                   	push   %edi
  40643b:	2e 6f                	outsl  %cs:(%esi),(%dx)
  40643d:	72 67                	jb     4064a6 <.rdata$zzz+0x1d2>
  40643f:	20 43 72             	and    %al,0x72(%ebx)
  406442:	6f                   	outsl  %ds:(%esi),(%dx)
  406443:	73 73                	jae    4064b8 <.rdata$zzz+0x1e4>
  406445:	2d 47 43 43 20       	sub    $0x20434347,%eax
  40644a:	42                   	inc    %edx
  40644b:	75 69                	jne    4064b6 <.rdata$zzz+0x1e2>
  40644d:	6c                   	insb   (%dx),%es:(%edi)
  40644e:	64 2d 32 30 32 30    	fs sub $0x30323032,%eax
  406454:	30 35 33 31 2d 31    	xor    %dh,0x312d3133
  40645a:	29 20                	sub    %esp,(%eax)
  40645c:	39 2e                	cmp    %ebp,(%esi)
  40645e:	32 2e                	xor    (%esi),%ch
  406460:	30 00                	xor    %al,(%eax)
  406462:	00 00                	add    %al,(%eax)
  406464:	47                   	inc    %edi
  406465:	43                   	inc    %ebx
  406466:	43                   	inc    %ebx
  406467:	3a 20                	cmp    (%eax),%ah
  406469:	28 4d 69             	sub    %cl,0x69(%ebp)
  40646c:	6e                   	outsb  %ds:(%esi),(%dx)
  40646d:	47                   	inc    %edi
  40646e:	57                   	push   %edi
  40646f:	2e 6f                	outsl  %cs:(%esi),(%dx)
  406471:	72 67                	jb     4064da <.rdata$zzz+0x206>
  406473:	20 43 72             	and    %al,0x72(%ebx)
  406476:	6f                   	outsl  %ds:(%esi),(%dx)
  406477:	73 73                	jae    4064ec <.rdata$zzz+0x218>
  406479:	2d 47 43 43 20       	sub    $0x20434347,%eax
  40647e:	42                   	inc    %edx
  40647f:	75 69                	jne    4064ea <.rdata$zzz+0x216>
  406481:	6c                   	insb   (%dx),%es:(%edi)
  406482:	64 2d 32 30 32 30    	fs sub $0x30323032,%eax
  406488:	30 35 33 31 2d 31    	xor    %dh,0x312d3133
  40648e:	29 20                	sub    %esp,(%eax)
  406490:	39 2e                	cmp    %ebp,(%esi)
  406492:	32 2e                	xor    (%esi),%ch
  406494:	30 00                	xor    %al,(%eax)
  406496:	00 00                	add    %al,(%eax)
  406498:	47                   	inc    %edi
  406499:	43                   	inc    %ebx
  40649a:	43                   	inc    %ebx
  40649b:	3a 20                	cmp    (%eax),%ah
  40649d:	28 4d 69             	sub    %cl,0x69(%ebp)
  4064a0:	6e                   	outsb  %ds:(%esi),(%dx)
  4064a1:	47                   	inc    %edi
  4064a2:	57                   	push   %edi
  4064a3:	2e 6f                	outsl  %cs:(%esi),(%dx)
  4064a5:	72 67                	jb     40650e <.rdata$zzz+0x23a>
  4064a7:	20 43 72             	and    %al,0x72(%ebx)
  4064aa:	6f                   	outsl  %ds:(%esi),(%dx)
  4064ab:	73 73                	jae    406520 <.rdata$zzz+0x24c>
  4064ad:	2d 47 43 43 20       	sub    $0x20434347,%eax
  4064b2:	42                   	inc    %edx
  4064b3:	75 69                	jne    40651e <.rdata$zzz+0x24a>
  4064b5:	6c                   	insb   (%dx),%es:(%edi)
  4064b6:	64 2d 32 30 32 30    	fs sub $0x30323032,%eax
  4064bc:	30 35 33 31 2d 31    	xor    %dh,0x312d3133
  4064c2:	29 20                	sub    %esp,(%eax)
  4064c4:	39 2e                	cmp    %ebp,(%esi)
  4064c6:	32 2e                	xor    (%esi),%ch
  4064c8:	30 00                	xor    %al,(%eax)
  4064ca:	00 00                	add    %al,(%eax)
  4064cc:	47                   	inc    %edi
  4064cd:	43                   	inc    %ebx
  4064ce:	43                   	inc    %ebx
  4064cf:	3a 20                	cmp    (%eax),%ah
  4064d1:	28 4d 69             	sub    %cl,0x69(%ebp)
  4064d4:	6e                   	outsb  %ds:(%esi),(%dx)
  4064d5:	47                   	inc    %edi
  4064d6:	57                   	push   %edi
  4064d7:	2e 6f                	outsl  %cs:(%esi),(%dx)
  4064d9:	72 67                	jb     406542 <.rdata$zzz+0x26e>
  4064db:	20 43 72             	and    %al,0x72(%ebx)
  4064de:	6f                   	outsl  %ds:(%esi),(%dx)
  4064df:	73 73                	jae    406554 <.rdata$zzz+0x280>
  4064e1:	2d 47 43 43 20       	sub    $0x20434347,%eax
  4064e6:	42                   	inc    %edx
  4064e7:	75 69                	jne    406552 <.rdata$zzz+0x27e>
  4064e9:	6c                   	insb   (%dx),%es:(%edi)
  4064ea:	64 2d 32 30 32 30    	fs sub $0x30323032,%eax
  4064f0:	30 35 33 31 2d 31    	xor    %dh,0x312d3133
  4064f6:	29 20                	sub    %esp,(%eax)
  4064f8:	39 2e                	cmp    %ebp,(%esi)
  4064fa:	32 2e                	xor    (%esi),%ch
  4064fc:	30 00                	xor    %al,(%eax)
  4064fe:	00 00                	add    %al,(%eax)
  406500:	47                   	inc    %edi
  406501:	43                   	inc    %ebx
  406502:	43                   	inc    %ebx
  406503:	3a 20                	cmp    (%eax),%ah
  406505:	28 4d 69             	sub    %cl,0x69(%ebp)
  406508:	6e                   	outsb  %ds:(%esi),(%dx)
  406509:	47                   	inc    %edi
  40650a:	57                   	push   %edi
  40650b:	2e 6f                	outsl  %cs:(%esi),(%dx)
  40650d:	72 67                	jb     406576 <.rdata$zzz+0x2a2>
  40650f:	20 43 72             	and    %al,0x72(%ebx)
  406512:	6f                   	outsl  %ds:(%esi),(%dx)
  406513:	73 73                	jae    406588 <.rdata$zzz+0x2b4>
  406515:	2d 47 43 43 20       	sub    $0x20434347,%eax
  40651a:	42                   	inc    %edx
  40651b:	75 69                	jne    406586 <.rdata$zzz+0x2b2>
  40651d:	6c                   	insb   (%dx),%es:(%edi)
  40651e:	64 2d 32 30 32 30    	fs sub $0x30323032,%eax
  406524:	30 35 33 31 2d 31    	xor    %dh,0x312d3133
  40652a:	29 20                	sub    %esp,(%eax)
  40652c:	39 2e                	cmp    %ebp,(%esi)
  40652e:	32 2e                	xor    (%esi),%ch
  406530:	30 00                	xor    %al,(%eax)
  406532:	00 00                	add    %al,(%eax)
  406534:	47                   	inc    %edi
  406535:	43                   	inc    %ebx
  406536:	43                   	inc    %ebx
  406537:	3a 20                	cmp    (%eax),%ah
  406539:	28 4d 69             	sub    %cl,0x69(%ebp)
  40653c:	6e                   	outsb  %ds:(%esi),(%dx)
  40653d:	47                   	inc    %edi
  40653e:	57                   	push   %edi
  40653f:	2e 6f                	outsl  %cs:(%esi),(%dx)
  406541:	72 67                	jb     4065aa <.rdata$zzz+0x2d6>
  406543:	20 43 72             	and    %al,0x72(%ebx)
  406546:	6f                   	outsl  %ds:(%esi),(%dx)
  406547:	73 73                	jae    4065bc <.rdata$zzz+0x2e8>
  406549:	2d 47 43 43 20       	sub    $0x20434347,%eax
  40654e:	42                   	inc    %edx
  40654f:	75 69                	jne    4065ba <.rdata$zzz+0x2e6>
  406551:	6c                   	insb   (%dx),%es:(%edi)
  406552:	64 2d 32 30 32 30    	fs sub $0x30323032,%eax
  406558:	30 35 33 31 2d 31    	xor    %dh,0x312d3133
  40655e:	29 20                	sub    %esp,(%eax)
  406560:	39 2e                	cmp    %ebp,(%esi)
  406562:	32 2e                	xor    (%esi),%ch
  406564:	30 00                	xor    %al,(%eax)
  406566:	00 00                	add    %al,(%eax)
  406568:	47                   	inc    %edi
  406569:	43                   	inc    %ebx
  40656a:	43                   	inc    %ebx
  40656b:	3a 20                	cmp    (%eax),%ah
  40656d:	28 4d 69             	sub    %cl,0x69(%ebp)
  406570:	6e                   	outsb  %ds:(%esi),(%dx)
  406571:	47                   	inc    %edi
  406572:	57                   	push   %edi
  406573:	2e 6f                	outsl  %cs:(%esi),(%dx)
  406575:	72 67                	jb     4065de <.rdata$zzz+0x30a>
  406577:	20 43 72             	and    %al,0x72(%ebx)
  40657a:	6f                   	outsl  %ds:(%esi),(%dx)
  40657b:	73 73                	jae    4065f0 <.rdata$zzz+0x31c>
  40657d:	2d 47 43 43 20       	sub    $0x20434347,%eax
  406582:	42                   	inc    %edx
  406583:	75 69                	jne    4065ee <.rdata$zzz+0x31a>
  406585:	6c                   	insb   (%dx),%es:(%edi)
  406586:	64 2d 32 30 32 30    	fs sub $0x30323032,%eax
  40658c:	30 35 33 31 2d 31    	xor    %dh,0x312d3133
  406592:	29 20                	sub    %esp,(%eax)
  406594:	39 2e                	cmp    %ebp,(%esi)
  406596:	32 2e                	xor    (%esi),%ch
  406598:	30 00                	xor    %al,(%eax)
  40659a:	00 00                	add    %al,(%eax)
  40659c:	47                   	inc    %edi
  40659d:	43                   	inc    %ebx
  40659e:	43                   	inc    %ebx
  40659f:	3a 20                	cmp    (%eax),%ah
  4065a1:	28 4d 69             	sub    %cl,0x69(%ebp)
  4065a4:	6e                   	outsb  %ds:(%esi),(%dx)
  4065a5:	47                   	inc    %edi
  4065a6:	57                   	push   %edi
  4065a7:	2e 6f                	outsl  %cs:(%esi),(%dx)
  4065a9:	72 67                	jb     406612 <.rdata$zzz+0x33e>
  4065ab:	20 43 72             	and    %al,0x72(%ebx)
  4065ae:	6f                   	outsl  %ds:(%esi),(%dx)
  4065af:	73 73                	jae    406624 <.rdata$zzz+0x350>
  4065b1:	2d 47 43 43 20       	sub    $0x20434347,%eax
  4065b6:	42                   	inc    %edx
  4065b7:	75 69                	jne    406622 <.rdata$zzz+0x34e>
  4065b9:	6c                   	insb   (%dx),%es:(%edi)
  4065ba:	64 2d 32 30 32 30    	fs sub $0x30323032,%eax
  4065c0:	30 35 33 31 2d 31    	xor    %dh,0x312d3133
  4065c6:	29 20                	sub    %esp,(%eax)
  4065c8:	39 2e                	cmp    %ebp,(%esi)
  4065ca:	32 2e                	xor    (%esi),%ch
  4065cc:	30 00                	xor    %al,(%eax)
  4065ce:	00 00                	add    %al,(%eax)
  4065d0:	47                   	inc    %edi
  4065d1:	43                   	inc    %ebx
  4065d2:	43                   	inc    %ebx
  4065d3:	3a 20                	cmp    (%eax),%ah
  4065d5:	28 4d 69             	sub    %cl,0x69(%ebp)
  4065d8:	6e                   	outsb  %ds:(%esi),(%dx)
  4065d9:	47                   	inc    %edi
  4065da:	57                   	push   %edi
  4065db:	2e 6f                	outsl  %cs:(%esi),(%dx)
  4065dd:	72 67                	jb     406646 <.rdata$zzz+0x372>
  4065df:	20 43 72             	and    %al,0x72(%ebx)
  4065e2:	6f                   	outsl  %ds:(%esi),(%dx)
  4065e3:	73 73                	jae    406658 <.rdata$zzz+0x384>
  4065e5:	2d 47 43 43 20       	sub    $0x20434347,%eax
  4065ea:	42                   	inc    %edx
  4065eb:	75 69                	jne    406656 <.rdata$zzz+0x382>
  4065ed:	6c                   	insb   (%dx),%es:(%edi)
  4065ee:	64 2d 32 30 32 30    	fs sub $0x30323032,%eax
  4065f4:	30 35 33 31 2d 31    	xor    %dh,0x312d3133
  4065fa:	29 20                	sub    %esp,(%eax)
  4065fc:	39 2e                	cmp    %ebp,(%esi)
  4065fe:	32 2e                	xor    (%esi),%ch
  406600:	30 00                	xor    %al,(%eax)
  406602:	00 00                	add    %al,(%eax)
  406604:	47                   	inc    %edi
  406605:	43                   	inc    %ebx
  406606:	43                   	inc    %ebx
  406607:	3a 20                	cmp    (%eax),%ah
  406609:	28 4d 69             	sub    %cl,0x69(%ebp)
  40660c:	6e                   	outsb  %ds:(%esi),(%dx)
  40660d:	47                   	inc    %edi
  40660e:	57                   	push   %edi
  40660f:	2e 6f                	outsl  %cs:(%esi),(%dx)
  406611:	72 67                	jb     40667a <.rdata$zzz+0x3a6>
  406613:	20 43 72             	and    %al,0x72(%ebx)
  406616:	6f                   	outsl  %ds:(%esi),(%dx)
  406617:	73 73                	jae    40668c <.rdata$zzz+0x3b8>
  406619:	2d 47 43 43 20       	sub    $0x20434347,%eax
  40661e:	42                   	inc    %edx
  40661f:	75 69                	jne    40668a <.rdata$zzz+0x3b6>
  406621:	6c                   	insb   (%dx),%es:(%edi)
  406622:	64 2d 32 30 32 30    	fs sub $0x30323032,%eax
  406628:	30 35 33 31 2d 31    	xor    %dh,0x312d3133
  40662e:	29 20                	sub    %esp,(%eax)
  406630:	39 2e                	cmp    %ebp,(%esi)
  406632:	32 2e                	xor    (%esi),%ch
  406634:	30 00                	xor    %al,(%eax)
  406636:	00 00                	add    %al,(%eax)
  406638:	47                   	inc    %edi
  406639:	43                   	inc    %ebx
  40663a:	43                   	inc    %ebx
  40663b:	3a 20                	cmp    (%eax),%ah
  40663d:	28 4d 69             	sub    %cl,0x69(%ebp)
  406640:	6e                   	outsb  %ds:(%esi),(%dx)
  406641:	47                   	inc    %edi
  406642:	57                   	push   %edi
  406643:	2e 6f                	outsl  %cs:(%esi),(%dx)
  406645:	72 67                	jb     4066ae <.rdata$zzz+0x3da>
  406647:	20 43 72             	and    %al,0x72(%ebx)
  40664a:	6f                   	outsl  %ds:(%esi),(%dx)
  40664b:	73 73                	jae    4066c0 <.rdata$zzz+0x3ec>
  40664d:	2d 47 43 43 20       	sub    $0x20434347,%eax
  406652:	42                   	inc    %edx
  406653:	75 69                	jne    4066be <.rdata$zzz+0x3ea>
  406655:	6c                   	insb   (%dx),%es:(%edi)
  406656:	64 2d 32 30 32 30    	fs sub $0x30323032,%eax
  40665c:	30 35 33 31 2d 31    	xor    %dh,0x312d3133
  406662:	29 20                	sub    %esp,(%eax)
  406664:	39 2e                	cmp    %ebp,(%esi)
  406666:	32 2e                	xor    (%esi),%ch
  406668:	30 00                	xor    %al,(%eax)
  40666a:	00 00                	add    %al,(%eax)
  40666c:	47                   	inc    %edi
  40666d:	43                   	inc    %ebx
  40666e:	43                   	inc    %ebx
  40666f:	3a 20                	cmp    (%eax),%ah
  406671:	28 4d 69             	sub    %cl,0x69(%ebp)
  406674:	6e                   	outsb  %ds:(%esi),(%dx)
  406675:	47                   	inc    %edi
  406676:	57                   	push   %edi
  406677:	2e 6f                	outsl  %cs:(%esi),(%dx)
  406679:	72 67                	jb     4066e2 <.rdata$zzz+0x40e>
  40667b:	20 43 72             	and    %al,0x72(%ebx)
  40667e:	6f                   	outsl  %ds:(%esi),(%dx)
  40667f:	73 73                	jae    4066f4 <.rdata$zzz+0x420>
  406681:	2d 47 43 43 20       	sub    $0x20434347,%eax
  406686:	42                   	inc    %edx
  406687:	75 69                	jne    4066f2 <.rdata$zzz+0x41e>
  406689:	6c                   	insb   (%dx),%es:(%edi)
  40668a:	64 2d 32 30 32 30    	fs sub $0x30323032,%eax
  406690:	30 35 33 31 2d 31    	xor    %dh,0x312d3133
  406696:	29 20                	sub    %esp,(%eax)
  406698:	39 2e                	cmp    %ebp,(%esi)
  40669a:	32 2e                	xor    (%esi),%ch
  40669c:	30 00                	xor    %al,(%eax)
  40669e:	00 00                	add    %al,(%eax)
  4066a0:	47                   	inc    %edi
  4066a1:	43                   	inc    %ebx
  4066a2:	43                   	inc    %ebx
  4066a3:	3a 20                	cmp    (%eax),%ah
  4066a5:	28 4d 69             	sub    %cl,0x69(%ebp)
  4066a8:	6e                   	outsb  %ds:(%esi),(%dx)
  4066a9:	47                   	inc    %edi
  4066aa:	57                   	push   %edi
  4066ab:	2e 6f                	outsl  %cs:(%esi),(%dx)
  4066ad:	72 67                	jb     406716 <.rdata$zzz+0x442>
  4066af:	20 43 72             	and    %al,0x72(%ebx)
  4066b2:	6f                   	outsl  %ds:(%esi),(%dx)
  4066b3:	73 73                	jae    406728 <.rdata$zzz+0x454>
  4066b5:	2d 47 43 43 20       	sub    $0x20434347,%eax
  4066ba:	42                   	inc    %edx
  4066bb:	75 69                	jne    406726 <.rdata$zzz+0x452>
  4066bd:	6c                   	insb   (%dx),%es:(%edi)
  4066be:	64 2d 32 30 32 30    	fs sub $0x30323032,%eax
  4066c4:	30 35 33 31 2d 31    	xor    %dh,0x312d3133
  4066ca:	29 20                	sub    %esp,(%eax)
  4066cc:	39 2e                	cmp    %ebp,(%esi)
  4066ce:	32 2e                	xor    (%esi),%ch
  4066d0:	30 00                	xor    %al,(%eax)
  4066d2:	00 00                	add    %al,(%eax)
  4066d4:	47                   	inc    %edi
  4066d5:	43                   	inc    %ebx
  4066d6:	43                   	inc    %ebx
  4066d7:	3a 20                	cmp    (%eax),%ah
  4066d9:	28 4d 69             	sub    %cl,0x69(%ebp)
  4066dc:	6e                   	outsb  %ds:(%esi),(%dx)
  4066dd:	47                   	inc    %edi
  4066de:	57                   	push   %edi
  4066df:	2e 6f                	outsl  %cs:(%esi),(%dx)
  4066e1:	72 67                	jb     40674a <.rdata$zzz+0xe>
  4066e3:	20 43 72             	and    %al,0x72(%ebx)
  4066e6:	6f                   	outsl  %ds:(%esi),(%dx)
  4066e7:	73 73                	jae    40675c <.rdata$zzz+0x20>
  4066e9:	2d 47 43 43 20       	sub    $0x20434347,%eax
  4066ee:	42                   	inc    %edx
  4066ef:	75 69                	jne    40675a <.rdata$zzz+0x1e>
  4066f1:	6c                   	insb   (%dx),%es:(%edi)
  4066f2:	64 2d 32 30 32 30    	fs sub $0x30323032,%eax
  4066f8:	30 35 33 31 2d 31    	xor    %dh,0x312d3133
  4066fe:	29 20                	sub    %esp,(%eax)
  406700:	39 2e                	cmp    %ebp,(%esi)
  406702:	32 2e                	xor    (%esi),%ch
  406704:	30 00                	xor    %al,(%eax)
  406706:	00 00                	add    %al,(%eax)
  406708:	47                   	inc    %edi
  406709:	43                   	inc    %ebx
  40670a:	43                   	inc    %ebx
  40670b:	3a 20                	cmp    (%eax),%ah
  40670d:	28 4d 69             	sub    %cl,0x69(%ebp)
  406710:	6e                   	outsb  %ds:(%esi),(%dx)
  406711:	47                   	inc    %edi
  406712:	57                   	push   %edi
  406713:	2e 6f                	outsl  %cs:(%esi),(%dx)
  406715:	72 67                	jb     40677e <.rdata$zzz+0xe>
  406717:	20 43 72             	and    %al,0x72(%ebx)
  40671a:	6f                   	outsl  %ds:(%esi),(%dx)
  40671b:	73 73                	jae    406790 <.rdata$zzz+0x20>
  40671d:	2d 47 43 43 20       	sub    $0x20434347,%eax
  406722:	42                   	inc    %edx
  406723:	75 69                	jne    40678e <.rdata$zzz+0x1e>
  406725:	6c                   	insb   (%dx),%es:(%edi)
  406726:	64 2d 32 30 32 30    	fs sub $0x30323032,%eax
  40672c:	30 35 33 31 2d 31    	xor    %dh,0x312d3133
  406732:	29 20                	sub    %esp,(%eax)
  406734:	39 2e                	cmp    %ebp,(%esi)
  406736:	32 2e                	xor    (%esi),%ch
  406738:	30 00                	xor    %al,(%eax)
	...

0040673c <.rdata$zzz>:
  40673c:	47                   	inc    %edi
  40673d:	43                   	inc    %ebx
  40673e:	43                   	inc    %ebx
  40673f:	3a 20                	cmp    (%eax),%ah
  406741:	28 4d 69             	sub    %cl,0x69(%ebp)
  406744:	6e                   	outsb  %ds:(%esi),(%dx)
  406745:	47                   	inc    %edi
  406746:	57                   	push   %edi
  406747:	2e 6f                	outsl  %cs:(%esi),(%dx)
  406749:	72 67                	jb     4067b2 <__RUNTIME_PSEUDO_RELOC_LIST_END__+0xe>
  40674b:	20 43 72             	and    %al,0x72(%ebx)
  40674e:	6f                   	outsl  %ds:(%esi),(%dx)
  40674f:	73 73                	jae    4067c4 <__RUNTIME_PSEUDO_RELOC_LIST_END__+0x20>
  406751:	2d 47 43 43 20       	sub    $0x20434347,%eax
  406756:	42                   	inc    %edx
  406757:	75 69                	jne    4067c2 <__RUNTIME_PSEUDO_RELOC_LIST_END__+0x1e>
  406759:	6c                   	insb   (%dx),%es:(%edi)
  40675a:	64 2d 32 30 32 30    	fs sub $0x30323032,%eax
  406760:	30 35 33 31 2d 31    	xor    %dh,0x312d3133
  406766:	29 20                	sub    %esp,(%eax)
  406768:	39 2e                	cmp    %ebp,(%esi)
  40676a:	32 2e                	xor    (%esi),%ch
  40676c:	30 00                	xor    %al,(%eax)
	...

00406770 <.rdata$zzz>:
  406770:	47                   	inc    %edi
  406771:	43                   	inc    %ebx
  406772:	43                   	inc    %ebx
  406773:	3a 20                	cmp    (%eax),%ah
  406775:	28 4d 69             	sub    %cl,0x69(%ebp)
  406778:	6e                   	outsb  %ds:(%esi),(%dx)
  406779:	47                   	inc    %edi
  40677a:	57                   	push   %edi
  40677b:	2e 6f                	outsl  %cs:(%esi),(%dx)
  40677d:	72 67                	jb     4067e6 <__RUNTIME_PSEUDO_RELOC_LIST_END__+0x42>
  40677f:	20 43 72             	and    %al,0x72(%ebx)
  406782:	6f                   	outsl  %ds:(%esi),(%dx)
  406783:	73 73                	jae    4067f8 <__RUNTIME_PSEUDO_RELOC_LIST_END__+0x54>
  406785:	2d 47 43 43 20       	sub    $0x20434347,%eax
  40678a:	42                   	inc    %edx
  40678b:	75 69                	jne    4067f6 <__RUNTIME_PSEUDO_RELOC_LIST_END__+0x52>
  40678d:	6c                   	insb   (%dx),%es:(%edi)
  40678e:	64 2d 32 30 32 30    	fs sub $0x30323032,%eax
  406794:	30 35 33 31 2d 31    	xor    %dh,0x312d3133
  40679a:	29 20                	sub    %esp,(%eax)
  40679c:	39 2e                	cmp    %ebp,(%esi)
  40679e:	32 2e                	xor    (%esi),%ch
  4067a0:	30 00                	xor    %al,(%eax)
	...

Disassembly of section .eh_frame:

00407000 <___EH_FRAME_BEGIN__-0xc8>:
  407000:	14 00                	adc    $0x0,%al
  407002:	00 00                	add    %al,(%eax)
  407004:	00 00                	add    %al,(%eax)
  407006:	00 00                	add    %al,(%eax)
  407008:	01 7a 52             	add    %edi,0x52(%edx)
  40700b:	00 01                	add    %al,(%ecx)
  40700d:	7c 08                	jl     407017 <__RUNTIME_PSEUDO_RELOC_LIST_END__+0x873>
  40700f:	01 1b                	add    %ebx,(%ebx)
  407011:	0c 04                	or     $0x4,%al
  407013:	04 88                	add    $0x88,%al
  407015:	01 00                	add    %eax,(%eax)
  407017:	00 18                	add    %bl,(%eax)
  407019:	00 00                	add    %al,(%eax)
  40701b:	00 1c 00             	add    %bl,(%eax,%eax,1)
  40701e:	00 00                	add    %al,(%eax)
  407020:	e0 9f                	loopne 406fc1 <__RUNTIME_PSEUDO_RELOC_LIST_END__+0x81d>
  407022:	ff                   	(bad)  
  407023:	ff 9b 01 00 00 00    	lcall  *0x1(%ebx)
  407029:	43                   	inc    %ebx
  40702a:	0e                   	push   %cs
  40702b:	20 02                	and    %al,(%edx)
  40702d:	56                   	push   %esi
  40702e:	0a 0e                	or     (%esi),%cl
  407030:	04 47                	add    $0x47,%al
  407032:	0b 00                	or     (%eax),%eax
  407034:	28 00                	sub    %al,(%eax)
  407036:	00 00                	add    %al,(%eax)
  407038:	38 00                	cmp    %al,(%eax)
  40703a:	00 00                	add    %al,(%eax)
  40703c:	64 a1 ff ff e9 00    	mov    %fs:0xe9ffff,%eax
  407042:	00 00                	add    %al,(%eax)
  407044:	00 41 0e             	add    %al,0xe(%ecx)
  407047:	08 83 02 43 0e 20    	or     %al,0x200e4302(%ebx)
  40704d:	62 0e                	bound  %ecx,(%esi)
  40704f:	14 43                	adc    $0x43,%al
  407051:	0e                   	push   %cs
  407052:	20 4c 0e 1c          	and    %cl,0x1c(%esi,%ecx,1)
  407056:	43                   	inc    %ebx
  407057:	0e                   	push   %cs
  407058:	20 02                	and    %al,(%edx)
  40705a:	6a 0a                	push   $0xa
  40705c:	0e                   	push   %cs
  40705d:	1c 0b                	sbb    $0xb,%al
  40705f:	00 14 00             	add    %dl,(%eax,%eax,1)
  407062:	00 00                	add    %al,(%eax)
  407064:	64 00 00             	add    %al,%fs:(%eax)
  407067:	00 28                	add    %ch,(%eax)
  407069:	a2 ff ff 3f 00       	mov    %al,0x3fffff
  40706e:	00 00                	add    %al,(%eax)
  407070:	00 43 0e             	add    %al,0xe(%ebx)
  407073:	40                   	inc    %eax
  407074:	7b 0e                	jnp    407084 <__RUNTIME_PSEUDO_RELOC_LIST_END__+0x8e0>
  407076:	04 00                	add    $0x0,%al
  407078:	10 00                	adc    %al,(%eax)
  40707a:	00 00                	add    %al,(%eax)
  40707c:	7c 00                	jl     40707e <__RUNTIME_PSEUDO_RELOC_LIST_END__+0x8da>
  40707e:	00 00                	add    %al,(%eax)
  407080:	50                   	push   %eax
  407081:	a2 ff ff 15 00       	mov    %al,0x15ffff
  407086:	00 00                	add    %al,(%eax)
  407088:	00 43 0e             	add    %al,0xe(%ebx)
  40708b:	20 10                	and    %dl,(%eax)
  40708d:	00 00                	add    %al,(%eax)
  40708f:	00 90 00 00 00 5c    	add    %dl,0x5c000000(%eax)
  407095:	a2 ff ff 15 00       	mov    %al,0x15ffff
  40709a:	00 00                	add    %al,(%eax)
  40709c:	00 43 0e             	add    %al,0xe(%ebx)
  40709f:	20 10                	and    %dl,(%eax)
  4070a1:	00 00                	add    %al,(%eax)
  4070a3:	00 a4 00 00 00 68 a2 	add    %ah,-0x5d980000(%eax,%eax,1)
  4070aa:	ff                   	(bad)  
  4070ab:	ff 06                	incl   (%esi)
  4070ad:	00 00                	add    %al,(%eax)
  4070af:	00 00                	add    %al,(%eax)
  4070b1:	00 00                	add    %al,(%eax)
  4070b3:	00 10                	add    %dl,(%eax)
  4070b5:	00 00                	add    %al,(%eax)
  4070b7:	00 b8 00 00 00 64    	add    %bh,0x64000000(%eax)
  4070bd:	a2 ff ff 06 00       	mov    %al,0x6ffff
  4070c2:	00 00                	add    %al,(%eax)
  4070c4:	00 00                	add    %al,(%eax)
	...

004070c8 <___EH_FRAME_BEGIN__>:
  4070c8:	14 00                	adc    $0x0,%al
  4070ca:	00 00                	add    %al,(%eax)
  4070cc:	00 00                	add    %al,(%eax)
  4070ce:	00 00                	add    %al,(%eax)
  4070d0:	01 7a 52             	add    %edi,0x52(%edx)
  4070d3:	00 01                	add    %al,(%ecx)
  4070d5:	7c 08                	jl     4070df <___EH_FRAME_BEGIN__+0x17>
  4070d7:	01 1b                	add    %ebx,(%ebx)
  4070d9:	0c 04                	or     $0x4,%al
  4070db:	04 88                	add    $0x88,%al
  4070dd:	01 00                	add    %eax,(%eax)
  4070df:	00 28                	add    %ch,(%eax)
  4070e1:	00 00                	add    %al,(%eax)
  4070e3:	00 1c 00             	add    %bl,(%eax,%eax,1)
  4070e6:	00 00                	add    %al,(%eax)
  4070e8:	48                   	dec    %eax
  4070e9:	a2 ff ff a1 00       	mov    %al,0xa1ffff
  4070ee:	00 00                	add    %al,(%eax)
  4070f0:	00 41 0e             	add    %al,0xe(%ecx)
  4070f3:	08 85 02 42 0d 05    	or     %al,0x50d4202(%ebp)
  4070f9:	45                   	inc    %ebp
  4070fa:	86 03                	xchg   %al,(%ebx)
  4070fc:	83 04 02 7b          	addl   $0x7b,(%edx,%eax,1)
  407100:	0a c3                	or     %bl,%al
  407102:	41                   	inc    %ecx
  407103:	c6 41 c5 0c          	movb   $0xc,-0x3b(%ecx)
  407107:	04 04                	add    $0x4,%al
  407109:	4b                   	dec    %ebx
  40710a:	0b 00                	or     (%eax),%eax
  40710c:	1c 00                	sbb    $0x0,%al
  40710e:	00 00                	add    %al,(%eax)
  407110:	48                   	dec    %eax
  407111:	00 00                	add    %al,(%eax)
  407113:	00 cc                	add    %cl,%ah
  407115:	a2 ff ff 2e 00       	mov    %al,0x2effff
  40711a:	00 00                	add    %al,(%eax)
  40711c:	00 41 0e             	add    %al,0xe(%ecx)
  40711f:	08 85 02 42 0d 05    	or     %al,0x50d4202(%ebp)
  407125:	6a c5                	push   $0xffffffc5
  407127:	0c 04                	or     $0x4,%al
  407129:	04 00                	add    $0x0,%al
	...

0040712c <.eh_frame>:
  40712c:	14 00                	adc    $0x0,%al
  40712e:	00 00                	add    %al,(%eax)
  407130:	00 00                	add    %al,(%eax)
  407132:	00 00                	add    %al,(%eax)
  407134:	01 7a 52             	add    %edi,0x52(%edx)
  407137:	00 01                	add    %al,(%ecx)
  407139:	7c 08                	jl     407143 <.eh_frame+0x17>
  40713b:	01 1b                	add    %ebx,(%ebx)
  40713d:	0c 04                	or     $0x4,%al
  40713f:	04 88                	add    $0x88,%al
  407141:	01 00                	add    %eax,(%eax)
  407143:	00 1c 00             	add    %bl,(%eax,%eax,1)
  407146:	00 00                	add    %al,(%eax)
  407148:	1c 00                	sbb    $0x0,%al
  40714a:	00 00                	add    %al,(%eax)
  40714c:	c4 a2 ff ff 36 00    	les    0x36ffff(%edx),%esp
  407152:	00 00                	add    %al,(%eax)
  407154:	00 41 0e             	add    %al,0xe(%ecx)
  407157:	08 85 02 42 0d 05    	or     %al,0x50d4202(%ebp)
  40715d:	70 c5                	jo     407124 <___EH_FRAME_BEGIN__+0x5c>
  40715f:	0c 04                	or     $0x4,%al
  407161:	04 00                	add    $0x0,%al
  407163:	00 14 00             	add    %dl,(%eax,%eax,1)
  407166:	00 00                	add    %al,(%eax)
  407168:	00 00                	add    %al,(%eax)
  40716a:	00 00                	add    %al,(%eax)
  40716c:	01 7a 52             	add    %edi,0x52(%edx)
  40716f:	00 01                	add    %al,(%ecx)
  407171:	7c 08                	jl     40717b <.eh_frame+0x4f>
  407173:	01 1b                	add    %ebx,(%ebx)
  407175:	0c 04                	or     $0x4,%al
  407177:	04 88                	add    $0x88,%al
  407179:	01 00                	add    %eax,(%eax)
  40717b:	00 2c 00             	add    %ch,(%eax,%eax,1)
  40717e:	00 00                	add    %al,(%eax)
  407180:	1c 00                	sbb    $0x0,%al
  407182:	00 00                	add    %al,(%eax)
  407184:	cc                   	int3   
  407185:	a2 ff ff 51 04       	mov    %al,0x451ffff
  40718a:	00 00                	add    %al,(%eax)
  40718c:	00 41 0e             	add    %al,0xe(%ecx)
  40718f:	08 85 02 42 0d 05    	or     %al,0x50d4202(%ebp)
  407195:	49                   	dec    %ecx
  407196:	87 03                	xchg   %eax,(%ebx)
  407198:	86 04 83             	xchg   %al,(%ebx,%eax,4)
  40719b:	05 52 0a c3 41       	add    $0x41c30a52,%eax
  4071a0:	c6 41 c7 41          	movb   $0x41,-0x39(%ecx)
  4071a4:	c5 0c 04             	lds    (%esp,%eax,1),%ecx
  4071a7:	04 47                	add    $0x47,%al
  4071a9:	0b 00                	or     (%eax),%eax
  4071ab:	00 14 00             	add    %dl,(%eax,%eax,1)
  4071ae:	00 00                	add    %al,(%eax)
  4071b0:	00 00                	add    %al,(%eax)
  4071b2:	00 00                	add    %al,(%eax)
  4071b4:	01 7a 52             	add    %edi,0x52(%edx)
  4071b7:	00 01                	add    %al,(%ecx)
  4071b9:	7c 08                	jl     4071c3 <.eh_frame+0x97>
  4071bb:	01 1b                	add    %ebx,(%ebx)
  4071bd:	0c 04                	or     $0x4,%al
  4071bf:	04 88                	add    $0x88,%al
  4071c1:	01 00                	add    %eax,(%eax)
  4071c3:	00 24 00             	add    %ah,(%eax,%eax,1)
  4071c6:	00 00                	add    %al,(%eax)
  4071c8:	1c 00                	sbb    $0x0,%al
  4071ca:	00 00                	add    %al,(%eax)
  4071cc:	e4 a6                	in     $0xa6,%al
  4071ce:	ff                   	(bad)  
  4071cf:	ff 07                	incl   (%edi)
  4071d1:	01 00                	add    %eax,(%eax)
  4071d3:	00 00                	add    %al,(%eax)
  4071d5:	5d                   	pop    %ebp
  4071d6:	0e                   	push   %cs
  4071d7:	08 83 02 02 48 0c    	or     %al,0xc480202(%ebx)
  4071dd:	05 0c 85 03 02       	add    $0x203850c,%eax
  4071e2:	41                   	inc    %ecx
  4071e3:	c5 0c 04             	lds    (%esp,%eax,1),%ecx
  4071e6:	08 02                	or     %al,(%edx)
  4071e8:	5f                   	pop    %edi
  4071e9:	c3                   	ret    
  4071ea:	0e                   	push   %cs
  4071eb:	04 14                	add    $0x14,%al
  4071ed:	00 00                	add    %al,(%eax)
  4071ef:	00 00                	add    %al,(%eax)
  4071f1:	00 00                	add    %al,(%eax)
  4071f3:	00 01                	add    %al,(%ecx)
  4071f5:	7a 52                	jp     407249 <.eh_frame+0x11d>
  4071f7:	00 01                	add    %al,(%ecx)
  4071f9:	7c 08                	jl     407203 <.eh_frame+0xd7>
  4071fb:	01 1b                	add    %ebx,(%ebx)
  4071fd:	0c 04                	or     $0x4,%al
  4071ff:	04 88                	add    $0x88,%al
  407201:	01 00                	add    %eax,(%eax)
  407203:	00 38                	add    %bh,(%eax)
  407205:	00 00                	add    %al,(%eax)
  407207:	00 1c 00             	add    %bl,(%eax,%eax,1)
  40720a:	00 00                	add    %al,(%eax)
  40720c:	f4                   	hlt    
  40720d:	cd ff                	int    $0xff
  40720f:	ff d2                	call   *%edx
  407211:	00 00                	add    %al,(%eax)
  407213:	00 00                	add    %al,(%eax)
  407215:	44                   	inc    %esp
  407216:	0c 01                	or     $0x1,%al
  407218:	00 47 10             	add    %al,0x10(%edi)
  40721b:	05 02 75 00 45       	add    $0x45007502,%eax
  407220:	0f 03 75 74          	lsl    0x74(%ebp),%esi
  407224:	06                   	push   %es
  407225:	10 06                	adc    %al,(%esi)
  407227:	02 75 7c             	add    0x7c(%ebp),%dh
  40722a:	10 03                	adc    %al,(%ebx)
  40722c:	02 75 78             	add    0x78(%ebp),%dh
  40722f:	02 bb c1 0c 01 00    	add    0x10cc1(%ebx),%bh
  407235:	41                   	inc    %ecx
  407236:	c3                   	ret    
  407237:	41                   	inc    %ecx
  407238:	c6 41 c5 43          	movb   $0x43,-0x3b(%ecx)
  40723c:	0c 04                	or     $0x4,%al
  40723e:	04 00                	add    $0x0,%al
  407240:	14 00                	adc    $0x0,%al
  407242:	00 00                	add    %al,(%eax)
  407244:	00 00                	add    %al,(%eax)
  407246:	00 00                	add    %al,(%eax)
  407248:	01 7a 52             	add    %edi,0x52(%edx)
  40724b:	00 01                	add    %al,(%ecx)
  40724d:	7c 08                	jl     407257 <.eh_frame+0x12b>
  40724f:	01 1b                	add    %ebx,(%ebx)
  407251:	0c 04                	or     $0x4,%al
  407253:	04 88                	add    $0x88,%al
  407255:	01 00                	add    %eax,(%eax)
  407257:	00 14 00             	add    %dl,(%eax,%eax,1)
  40725a:	00 00                	add    %al,(%eax)
  40725c:	1c 00                	sbb    $0x0,%al
  40725e:	00 00                	add    %al,(%eax)
  407260:	60                   	pusha  
  407261:	a7                   	cmpsl  %es:(%edi),%ds:(%esi)
  407262:	ff                   	(bad)  
  407263:	ff 31                	pushl  (%ecx)
  407265:	00 00                	add    %al,(%eax)
  407267:	00 00                	add    %al,(%eax)
  407269:	4e                   	dec    %esi
  40726a:	0e                   	push   %cs
  40726b:	10 5c 0e 04          	adc    %bl,0x4(%esi,%ecx,1)
  40726f:	00 20                	add    %ah,(%eax)
  407271:	00 00                	add    %al,(%eax)
  407273:	00 34 00             	add    %dh,(%eax,%eax,1)
  407276:	00 00                	add    %al,(%eax)
  407278:	88 a7 ff ff 52 00    	mov    %ah,0x52ffff(%edi)
  40727e:	00 00                	add    %al,(%eax)
  407280:	00 41 0e             	add    %al,0xe(%ecx)
  407283:	08 83 02 43 0e 20    	or     %al,0x200e4302(%ebx)
  407289:	6f                   	outsl  %ds:(%esi),(%dx)
  40728a:	0a 0e                	or     (%esi),%cl
  40728c:	08 41 c3             	or     %al,-0x3d(%ecx)
  40728f:	0e                   	push   %cs
  407290:	04 44                	add    $0x44,%al
  407292:	0b 00                	or     (%eax),%eax
  407294:	10 00                	adc    %al,(%eax)
  407296:	00 00                	add    %al,(%eax)
  407298:	58                   	pop    %eax
  407299:	00 00                	add    %al,(%eax)
  40729b:	00 c4                	add    %al,%ah
  40729d:	a7                   	cmpsl  %es:(%edi),%ds:(%esi)
  40729e:	ff                   	(bad)  
  40729f:	ff 1c 00             	lcall  *(%eax,%eax,1)
  4072a2:	00 00                	add    %al,(%eax)
  4072a4:	00 00                	add    %al,(%eax)
  4072a6:	00 00                	add    %al,(%eax)
  4072a8:	14 00                	adc    $0x0,%al
  4072aa:	00 00                	add    %al,(%eax)
  4072ac:	00 00                	add    %al,(%eax)
  4072ae:	00 00                	add    %al,(%eax)
  4072b0:	01 7a 52             	add    %edi,0x52(%edx)
  4072b3:	00 01                	add    %al,(%ecx)
  4072b5:	7c 08                	jl     4072bf <.eh_frame+0x193>
  4072b7:	01 1b                	add    %ebx,(%ebx)
  4072b9:	0c 04                	or     $0x4,%al
  4072bb:	04 88                	add    $0x88,%al
  4072bd:	01 00                	add    %eax,(%eax)
  4072bf:	00 1c 00             	add    %bl,(%eax,%eax,1)
  4072c2:	00 00                	add    %al,(%eax)
  4072c4:	1c 00                	sbb    $0x0,%al
  4072c6:	00 00                	add    %al,(%eax)
  4072c8:	b8 a7 ff ff 43       	mov    $0x43ffffa7,%eax
  4072cd:	00 00                	add    %al,(%eax)
  4072cf:	00 00                	add    %al,(%eax)
  4072d1:	43                   	inc    %ebx
  4072d2:	0e                   	push   %cs
  4072d3:	20 55 0a             	and    %dl,0xa(%ebp)
  4072d6:	0e                   	push   %cs
  4072d7:	04 48                	add    $0x48,%al
  4072d9:	0b 60 0e             	or     0xe(%eax),%esp
  4072dc:	04 00                	add    $0x0,%al
  4072de:	00 00                	add    %al,(%eax)
  4072e0:	44                   	inc    %esp
  4072e1:	00 00                	add    %al,(%eax)
  4072e3:	00 3c 00             	add    %bh,(%eax,%eax,1)
  4072e6:	00 00                	add    %al,(%eax)
  4072e8:	e8 a7 ff ff a1       	call   a2407294 <.debug_str+0xa1ff5294>
  4072ed:	00 00                	add    %al,(%eax)
  4072ef:	00 00                	add    %al,(%eax)
  4072f1:	41                   	inc    %ecx
  4072f2:	0e                   	push   %cs
  4072f3:	08 86 02 41 0e 0c    	or     %al,0xc0e4102(%esi)
  4072f9:	83 03 43             	addl   $0x43,(%ebx)
  4072fc:	0e                   	push   %cs
  4072fd:	20 64 0a 0e          	and    %ah,0xe(%edx,%ecx,1)
  407301:	0c 46                	or     $0x46,%al
  407303:	c3                   	ret    
  407304:	0e                   	push   %cs
  407305:	08 41 c6             	or     %al,-0x3a(%ecx)
  407308:	0e                   	push   %cs
  407309:	04 48                	add    $0x48,%al
  40730b:	0b 6f 0a             	or     0xa(%edi),%ebp
  40730e:	0e                   	push   %cs
  40730f:	0c 46                	or     $0x46,%al
  407311:	c3                   	ret    
  407312:	0e                   	push   %cs
  407313:	08 41 c6             	or     %al,-0x3a(%ecx)
  407316:	0e                   	push   %cs
  407317:	04 4a                	add    $0x4a,%al
  407319:	0b 5f 0e             	or     0xe(%edi),%ebx
  40731c:	0c 46                	or     $0x46,%al
  40731e:	c3                   	ret    
  40731f:	0e                   	push   %cs
  407320:	08 41 c6             	or     %al,-0x3a(%ecx)
  407323:	0e                   	push   %cs
  407324:	04 00                	add    $0x0,%al
  407326:	00 00                	add    %al,(%eax)
  407328:	10 00                	adc    %al,(%eax)
  40732a:	00 00                	add    %al,(%eax)
  40732c:	84 00                	test   %al,(%eax)
  40732e:	00 00                	add    %al,(%eax)
  407330:	50                   	push   %eax
  407331:	a8 ff                	test   $0xff,%al
  407333:	ff 03                	incl   (%ebx)
  407335:	00 00                	add    %al,(%eax)
  407337:	00 00                	add    %al,(%eax)
  407339:	00 00                	add    %al,(%eax)
  40733b:	00 14 00             	add    %dl,(%eax,%eax,1)
  40733e:	00 00                	add    %al,(%eax)
  407340:	00 00                	add    %al,(%eax)
  407342:	00 00                	add    %al,(%eax)
  407344:	01 7a 52             	add    %edi,0x52(%edx)
  407347:	00 01                	add    %al,(%ecx)
  407349:	7c 08                	jl     407353 <.eh_frame+0x227>
  40734b:	01 1b                	add    %ebx,(%ebx)
  40734d:	0c 04                	or     $0x4,%al
  40734f:	04 88                	add    $0x88,%al
  407351:	01 00                	add    %eax,(%eax)
  407353:	00 38                	add    %bh,(%eax)
  407355:	00 00                	add    %al,(%eax)
  407357:	00 1c 00             	add    %bl,(%eax,%eax,1)
  40735a:	00 00                	add    %al,(%eax)
  40735c:	34 a8                	xor    $0xa8,%al
  40735e:	ff                   	(bad)  
  40735f:	ff 60 00             	jmp    *0x0(%eax)
  407362:	00 00                	add    %al,(%eax)
  407364:	00 41 0e             	add    %al,0xe(%ecx)
  407367:	08 86 02 41 0e 0c    	or     %al,0xc0e4102(%esi)
  40736d:	83 03 43             	addl   $0x43,(%ebx)
  407370:	0e                   	push   %cs
  407371:	20 4c 0e 1c          	and    %cl,0x1c(%esi,%ecx,1)
  407375:	49                   	dec    %ecx
  407376:	0e                   	push   %cs
  407377:	20 50 0e             	and    %dl,0xe(%eax)
  40737a:	1c 43                	sbb    $0x43,%al
  40737c:	0e                   	push   %cs
  40737d:	20 6a 0e             	and    %ch,0xe(%edx)
  407380:	1c 43                	sbb    $0x43,%al
  407382:	0e                   	push   %cs
  407383:	20 43 0e             	and    %al,0xe(%ebx)
  407386:	0c 41                	or     $0x41,%al
  407388:	c3                   	ret    
  407389:	0e                   	push   %cs
  40738a:	08 41 c6             	or     %al,-0x3a(%ecx)
  40738d:	0e                   	push   %cs
  40738e:	04 00                	add    $0x0,%al
  407390:	2c 00                	sub    $0x0,%al
  407392:	00 00                	add    %al,(%eax)
  407394:	58                   	pop    %eax
  407395:	00 00                	add    %al,(%eax)
  407397:	00 58 a8             	add    %bl,-0x58(%eax)
  40739a:	ff                   	(bad)  
  40739b:	ff 73 00             	pushl  0x0(%ebx)
  40739e:	00 00                	add    %al,(%eax)
  4073a0:	00 51 0e             	add    %dl,0xe(%ecx)
  4073a3:	08 83 02 43 0e 20    	or     %al,0x200e4302(%ebx)
  4073a9:	73 0e                	jae    4073b9 <.eh_frame+0x28d>
  4073ab:	1c 4e                	sbb    $0x4e,%al
  4073ad:	0e                   	push   %cs
  4073ae:	20 4f 0e             	and    %cl,0xe(%edi)
  4073b1:	1c 45                	sbb    $0x45,%al
  4073b3:	0e                   	push   %cs
  4073b4:	20 43 0a             	and    %al,0xa(%ebx)
  4073b7:	0e                   	push   %cs
  4073b8:	08 41 c3             	or     %al,-0x3d(%ecx)
  4073bb:	0e                   	push   %cs
  4073bc:	04 41                	add    $0x41,%al
  4073be:	0b 00                	or     (%eax),%eax
  4073c0:	38 00                	cmp    %al,(%eax)
  4073c2:	00 00                	add    %al,(%eax)
  4073c4:	88 00                	mov    %al,(%eax)
  4073c6:	00 00                	add    %al,(%eax)
  4073c8:	a8 a8                	test   $0xa8,%al
  4073ca:	ff                   	(bad)  
  4073cb:	ff 88 00 00 00 00    	decl   0x0(%eax)
  4073d1:	41                   	inc    %ecx
  4073d2:	0e                   	push   %cs
  4073d3:	08 83 02 43 0e 20    	or     %al,0x200e4302(%ebx)
  4073d9:	50                   	push   %eax
  4073da:	0a 0e                	or     (%esi),%cl
  4073dc:	08 43 c3             	or     %al,-0x3d(%ebx)
  4073df:	0e                   	push   %cs
  4073e0:	04 49                	add    $0x49,%al
  4073e2:	0b 4c 0e 1c          	or     0x1c(%esi,%ecx,1),%ecx
  4073e6:	48                   	dec    %eax
  4073e7:	0e                   	push   %cs
  4073e8:	20 78 0e             	and    %bh,0xe(%eax)
  4073eb:	1c 45                	sbb    $0x45,%al
  4073ed:	0e                   	push   %cs
  4073ee:	20 43 0a             	and    %al,0xa(%ebx)
  4073f1:	0e                   	push   %cs
  4073f2:	08 41 c3             	or     %al,-0x3d(%ecx)
  4073f5:	0e                   	push   %cs
  4073f6:	04 4b                	add    $0x4b,%al
  4073f8:	0b 00                	or     (%eax),%eax
  4073fa:	00 00                	add    %al,(%eax)
  4073fc:	30 00                	xor    %al,(%eax)
  4073fe:	00 00                	add    %al,(%eax)
  407400:	c4 00                	les    (%eax),%eax
  407402:	00 00                	add    %al,(%eax)
  407404:	fc                   	cld    
  407405:	a8 ff                	test   $0xff,%al
  407407:	ff                   	(bad)  
  407408:	bc 00 00 00 00       	mov    $0x0,%esp
  40740d:	43                   	inc    %ebx
  40740e:	0e                   	push   %cs
  40740f:	20 5a 0a             	and    %bl,0xa(%edx)
  407412:	0e                   	push   %cs
  407413:	04 43                	add    $0x43,%al
  407415:	0b 5b 0a             	or     0xa(%ebx),%ebx
  407418:	0e                   	push   %cs
  407419:	04 45                	add    $0x45,%al
  40741b:	0b 69 0e             	or     0xe(%ecx),%ebp
  40741e:	1c 43                	sbb    $0x43,%al
  407420:	0e                   	push   %cs
  407421:	20 5a 0a             	and    %bl,0xa(%edx)
  407424:	0e                   	push   %cs
  407425:	04 4a                	add    $0x4a,%al
  407427:	0b 64 0e 1c          	or     0x1c(%esi,%ecx,1),%esp
  40742b:	43                   	inc    %ebx
  40742c:	0e                   	push   %cs
  40742d:	20 00                	and    %al,(%eax)
  40742f:	00 14 00             	add    %dl,(%eax,%eax,1)
  407432:	00 00                	add    %al,(%eax)
  407434:	00 00                	add    %al,(%eax)
  407436:	00 00                	add    %al,(%eax)
  407438:	01 7a 52             	add    %edi,0x52(%edx)
  40743b:	00 01                	add    %al,(%ecx)
  40743d:	7c 08                	jl     407447 <.eh_frame+0x31b>
  40743f:	01 1b                	add    %ebx,(%ebx)
  407441:	0c 04                	or     $0x4,%al
  407443:	04 88                	add    $0x88,%al
  407445:	01 00                	add    %eax,(%eax)
  407447:	00 1c 00             	add    %bl,(%eax,%eax,1)
  40744a:	00 00                	add    %al,(%eax)
  40744c:	1c 00                	sbb    $0x0,%al
  40744e:	00 00                	add    %al,(%eax)
  407450:	70 a9                	jo     4073fb <.eh_frame+0x2cf>
  407452:	ff                   	(bad)  
  407453:	ff 4a 00             	decl   0x0(%edx)
  407456:	00 00                	add    %al,(%eax)
  407458:	00 41 0e             	add    %al,0xe(%ecx)
  40745b:	08 86 02 41 0e 0c    	or     %al,0xc0e4102(%esi)
  407461:	83 03 43             	addl   $0x43,(%ebx)
  407464:	0e                   	push   %cs
  407465:	20 00                	and    %al,(%eax)
  407467:	00 64 00 00          	add    %ah,0x0(%eax,%eax,1)
  40746b:	00 3c 00             	add    %bh,(%eax,%eax,1)
  40746e:	00 00                	add    %al,(%eax)
  407470:	a0 a9 ff ff ec       	mov    0xecffffa9,%al
  407475:	00 00                	add    %al,(%eax)
  407477:	00 00                	add    %al,(%eax)
  407479:	41                   	inc    %ecx
  40747a:	0e                   	push   %cs
  40747b:	08 85 02 41 0e 0c    	or     %al,0xc0e4102(%ebp)
  407481:	87 03                	xchg   %eax,(%ebx)
  407483:	43                   	inc    %ebx
  407484:	0e                   	push   %cs
  407485:	10 86 04 43 0e 14    	adc    %al,0x140e4304(%esi)
  40748b:	83 05 45 0e 50 58 0e 	addl   $0xe,0x58500e45
  407492:	44                   	inc    %esp
  407493:	43                   	inc    %ebx
  407494:	0e                   	push   %cs
  407495:	50                   	push   %eax
  407496:	6d                   	insl   (%dx),%es:(%edi)
  407497:	0a 0e                	or     (%esi),%cl
  407499:	14 41                	adc    $0x41,%al
  40749b:	c3                   	ret    
  40749c:	0e                   	push   %cs
  40749d:	10 41 c6             	adc    %al,-0x3a(%ecx)
  4074a0:	0e                   	push   %cs
  4074a1:	0c 41                	or     $0x41,%al
  4074a3:	c7                   	(bad)  
  4074a4:	0e                   	push   %cs
  4074a5:	08 41 c5             	or     %al,-0x3b(%ecx)
  4074a8:	0e                   	push   %cs
  4074a9:	04 47                	add    $0x47,%al
  4074ab:	0b 64 0e 40          	or     0x40(%esi,%ecx,1),%esp
  4074af:	43                   	inc    %ebx
  4074b0:	0e                   	push   %cs
  4074b1:	50                   	push   %eax
  4074b2:	02 42 0e             	add    0xe(%edx),%al
  4074b5:	40                   	inc    %eax
  4074b6:	43                   	inc    %ebx
  4074b7:	0e                   	push   %cs
  4074b8:	50                   	push   %eax
  4074b9:	43                   	inc    %ebx
  4074ba:	0a 0e                	or     (%esi),%cl
  4074bc:	14 41                	adc    $0x41,%al
  4074be:	c3                   	ret    
  4074bf:	0e                   	push   %cs
  4074c0:	10 41 c6             	adc    %al,-0x3a(%ecx)
  4074c3:	0e                   	push   %cs
  4074c4:	0c 41                	or     $0x41,%al
  4074c6:	c7                   	(bad)  
  4074c7:	0e                   	push   %cs
  4074c8:	08 41 c5             	or     %al,-0x3b(%ecx)
  4074cb:	0e                   	push   %cs
  4074cc:	04 41                	add    $0x41,%al
  4074ce:	0b 00                	or     (%eax),%eax
  4074d0:	48                   	dec    %eax
  4074d1:	00 00                	add    %al,(%eax)
  4074d3:	00 a4 00 00 00 28 aa 	add    %ah,-0x55d80000(%eax,%eax,1)
  4074da:	ff                   	(bad)  
  4074db:	ff                   	(bad)  
  4074dc:	ea 01 00 00 00 6a 0e 	ljmp   $0xe6a,$0x1
  4074e3:	08 87 02 41 0e 0c    	or     %al,0xc0e4102(%edi)
  4074e9:	86 03                	xchg   %al,(%ebx)
  4074eb:	41                   	inc    %ecx
  4074ec:	0e                   	push   %cs
  4074ed:	10 83 04 43 0e 30    	adc    %al,0x300e4304(%ebx)
  4074f3:	02 93 0a 0e 10 41    	add    0x41100e0a(%ebx),%dl
  4074f9:	c3                   	ret    
  4074fa:	0e                   	push   %cs
  4074fb:	0c 41                	or     $0x41,%al
  4074fd:	c6                   	(bad)  
  4074fe:	0e                   	push   %cs
  4074ff:	08 41 c7             	or     %al,-0x39(%ecx)
  407502:	0e                   	push   %cs
  407503:	04 4b                	add    $0x4b,%al
  407505:	0b 02                	or     (%edx),%eax
  407507:	fb                   	sti    
  407508:	0a 0e                	or     (%esi),%cl
  40750a:	10 41 c3             	adc    %al,-0x3d(%ecx)
  40750d:	0e                   	push   %cs
  40750e:	0c 41                	or     $0x41,%al
  407510:	c6                   	(bad)  
  407511:	0e                   	push   %cs
  407512:	08 41 c7             	or     %al,-0x39(%ecx)
  407515:	0e                   	push   %cs
  407516:	04 42                	add    $0x42,%al
  407518:	0b 00                	or     (%eax),%eax
  40751a:	00 00                	add    %al,(%eax)
  40751c:	14 00                	adc    $0x0,%al
  40751e:	00 00                	add    %al,(%eax)
  407520:	00 00                	add    %al,(%eax)
  407522:	00 00                	add    %al,(%eax)
  407524:	01 7a 52             	add    %edi,0x52(%edx)
  407527:	00 01                	add    %al,(%ecx)
  407529:	7c 08                	jl     407533 <.eh_frame+0x407>
  40752b:	01 1b                	add    %ebx,(%ebx)
  40752d:	0c 04                	or     $0x4,%al
  40752f:	04 88                	add    $0x88,%al
  407531:	01 00                	add    %eax,(%eax)
  407533:	00 18                	add    %bl,(%eax)
  407535:	00 00                	add    %al,(%eax)
  407537:	00 1c 00             	add    %bl,(%eax,%eax,1)
  40753a:	00 00                	add    %al,(%eax)
  40753c:	b4 ab                	mov    $0xab,%ah
  40753e:	ff                   	(bad)  
  40753f:	ff 77 00             	pushl  0x0(%edi)
  407542:	00 00                	add    %al,(%eax)
  407544:	00 43 0e             	add    %al,0xe(%ebx)
  407547:	20 02                	and    %al,(%edx)
  407549:	41                   	inc    %ecx
  40754a:	0a 0e                	or     (%esi),%cl
  40754c:	04 44                	add    $0x44,%al
  40754e:	0b 00                	or     (%eax),%eax
  407550:	14 00                	adc    $0x0,%al
  407552:	00 00                	add    %al,(%eax)
  407554:	00 00                	add    %al,(%eax)
  407556:	00 00                	add    %al,(%eax)
  407558:	01 7a 52             	add    %edi,0x52(%edx)
  40755b:	00 01                	add    %al,(%ecx)
  40755d:	7c 08                	jl     407567 <.eh_frame+0x43b>
  40755f:	01 1b                	add    %ebx,(%ebx)
  407561:	0c 04                	or     $0x4,%al
  407563:	04 88                	add    $0x88,%al
  407565:	01 00                	add    %eax,(%eax)
  407567:	00 14 00             	add    %dl,(%eax,%eax,1)
  40756a:	00 00                	add    %al,(%eax)
  40756c:	1c 00                	sbb    $0x0,%al
  40756e:	00 00                	add    %al,(%eax)
  407570:	00 ac ff ff 24 00 00 	add    %ch,0x24ff(%edi,%edi,8)
  407577:	00 00                	add    %al,(%eax)
  407579:	43                   	inc    %ebx
  40757a:	0e                   	push   %cs
  40757b:	30 60 0e             	xor    %ah,0xe(%eax)
  40757e:	04 00                	add    $0x0,%al
  407580:	14 00                	adc    $0x0,%al
  407582:	00 00                	add    %al,(%eax)
  407584:	00 00                	add    %al,(%eax)
  407586:	00 00                	add    %al,(%eax)
  407588:	01 7a 52             	add    %edi,0x52(%edx)
  40758b:	00 01                	add    %al,(%ecx)
  40758d:	7c 08                	jl     407597 <.eh_frame+0x46b>
  40758f:	01 1b                	add    %ebx,(%ebx)
  407591:	0c 04                	or     $0x4,%al
  407593:	04 88                	add    $0x88,%al
  407595:	01 00                	add    %eax,(%eax)
  407597:	00 3c 00             	add    %bh,(%eax,%eax,1)
  40759a:	00 00                	add    %al,(%eax)
  40759c:	1c 00                	sbb    $0x0,%al
  40759e:	00 00                	add    %al,(%eax)
  4075a0:	00 ac ff ff 27 03 00 	add    %ch,0x327ff(%edi,%edi,8)
  4075a7:	00 00                	add    %al,(%eax)
  4075a9:	41                   	inc    %ecx
  4075aa:	0e                   	push   %cs
  4075ab:	08 85 02 41 0e 0c    	or     %al,0xc0e4102(%ebp)
  4075b1:	87 03                	xchg   %eax,(%ebx)
  4075b3:	41                   	inc    %ecx
  4075b4:	0e                   	push   %cs
  4075b5:	10 86 04 41 0e 14    	adc    %al,0x140e4104(%esi)
  4075bb:	83 05 43 0e 50 03 26 	addl   $0x26,0x3500e43
  4075c2:	01 0a                	add    %ecx,(%edx)
  4075c4:	0e                   	push   %cs
  4075c5:	14 41                	adc    $0x41,%al
  4075c7:	c3                   	ret    
  4075c8:	0e                   	push   %cs
  4075c9:	10 41 c6             	adc    %al,-0x3a(%ecx)
  4075cc:	0e                   	push   %cs
  4075cd:	0c 41                	or     $0x41,%al
  4075cf:	c7                   	(bad)  
  4075d0:	0e                   	push   %cs
  4075d1:	08 41 c5             	or     %al,-0x3b(%ecx)
  4075d4:	0e                   	push   %cs
  4075d5:	04 47                	add    $0x47,%al
  4075d7:	0b 3c 00             	or     (%eax,%eax,1),%edi
  4075da:	00 00                	add    %al,(%eax)
  4075dc:	5c                   	pop    %esp
  4075dd:	00 00                	add    %al,(%eax)
  4075df:	00 f0                	add    %dh,%al
  4075e1:	ae                   	scas   %es:(%edi),%al
  4075e2:	ff                   	(bad)  
  4075e3:	ff 27                	jmp    *(%edi)
  4075e5:	02 00                	add    (%eax),%al
  4075e7:	00 00                	add    %al,(%eax)
  4075e9:	41                   	inc    %ecx
  4075ea:	0e                   	push   %cs
  4075eb:	08 85 02 43 0e 0c    	or     %al,0xc0e4302(%ebp)
  4075f1:	87 03                	xchg   %eax,(%ebx)
  4075f3:	41                   	inc    %ecx
  4075f4:	0e                   	push   %cs
  4075f5:	10 86 04 43 0e 14    	adc    %al,0x140e4304(%esi)
  4075fb:	83 05 43 0e 40 02 ca 	addl   $0xffffffca,0x2400e43
  407602:	0a 0e                	or     (%esi),%cl
  407604:	14 43                	adc    $0x43,%al
  407606:	c3                   	ret    
  407607:	0e                   	push   %cs
  407608:	10 41 c6             	adc    %al,-0x3a(%ecx)
  40760b:	0e                   	push   %cs
  40760c:	0c 41                	or     $0x41,%al
  40760e:	c7                   	(bad)  
  40760f:	0e                   	push   %cs
  407610:	08 41 c5             	or     %al,-0x3b(%ecx)
  407613:	0e                   	push   %cs
  407614:	04 45                	add    $0x45,%al
  407616:	0b 00                	or     (%eax),%eax
  407618:	3c 00                	cmp    $0x0,%al
  40761a:	00 00                	add    %al,(%eax)
  40761c:	9c                   	pushf  
  40761d:	00 00                	add    %al,(%eax)
  40761f:	00 e0                	add    %ah,%al
  407621:	b0 ff                	mov    $0xff,%al
  407623:	ff 9d 00 00 00 00    	lcall  *0x0(%ebp)
  407629:	41                   	inc    %ecx
  40762a:	0e                   	push   %cs
  40762b:	08 87 02 44 0e 0c    	or     %al,0xc0e4402(%edi)
  407631:	86 03                	xchg   %al,(%ebx)
  407633:	41                   	inc    %ecx
  407634:	0e                   	push   %cs
  407635:	10 83 04 02 6b 0a    	adc    %al,0xa6b0204(%ebx)
  40763b:	c3                   	ret    
  40763c:	0e                   	push   %cs
  40763d:	0c 41                	or     $0x41,%al
  40763f:	c6                   	(bad)  
  407640:	0e                   	push   %cs
  407641:	08 41 c7             	or     %al,-0x39(%ecx)
  407644:	0e                   	push   %cs
  407645:	04 45                	add    $0x45,%al
  407647:	0b 59 0a             	or     0xa(%ecx),%ebx
  40764a:	c3                   	ret    
  40764b:	0e                   	push   %cs
  40764c:	0c 46                	or     $0x46,%al
  40764e:	c6                   	(bad)  
  40764f:	0e                   	push   %cs
  407650:	08 41 c7             	or     %al,-0x39(%ecx)
  407653:	0e                   	push   %cs
  407654:	04 41                	add    $0x41,%al
  407656:	0b 00                	or     (%eax),%eax
  407658:	44                   	inc    %esp
  407659:	00 00                	add    %al,(%eax)
  40765b:	00 dc                	add    %bl,%ah
  40765d:	00 00                	add    %al,(%eax)
  40765f:	00 40 b1             	add    %al,-0x4f(%eax)
  407662:	ff                   	(bad)  
  407663:	ff 5c 00 00          	lcall  *0x0(%eax,%eax,1)
  407667:	00 00                	add    %al,(%eax)
  407669:	41                   	inc    %ecx
  40766a:	0e                   	push   %cs
  40766b:	08 87 02 41 0e 0c    	or     %al,0xc0e4102(%edi)
  407671:	86 03                	xchg   %al,(%ebx)
  407673:	43                   	inc    %ebx
  407674:	0e                   	push   %cs
  407675:	10 83 04 45 0e 20    	adc    %al,0x200e4504(%ebx)
  40767b:	02 40 0a             	add    0xa(%eax),%al
  40767e:	0e                   	push   %cs
  40767f:	10 43 c3             	adc    %al,-0x3d(%ebx)
  407682:	0e                   	push   %cs
  407683:	0c 41                	or     $0x41,%al
  407685:	c6                   	(bad)  
  407686:	0e                   	push   %cs
  407687:	08 41 c7             	or     %al,-0x39(%ecx)
  40768a:	0e                   	push   %cs
  40768b:	04 41                	add    $0x41,%al
  40768d:	0b 43 0e             	or     0xe(%ebx),%eax
  407690:	10 46 c3             	adc    %al,-0x3d(%esi)
  407693:	0e                   	push   %cs
  407694:	0c 41                	or     $0x41,%al
  407696:	c6                   	(bad)  
  407697:	0e                   	push   %cs
  407698:	08 41 c7             	or     %al,-0x39(%ecx)
  40769b:	0e                   	push   %cs
  40769c:	04 00                	add    $0x0,%al
  40769e:	00 00                	add    %al,(%eax)
  4076a0:	28 00                	sub    %al,(%eax)
  4076a2:	00 00                	add    %al,(%eax)
  4076a4:	24 01                	and    $0x1,%al
  4076a6:	00 00                	add    %al,(%eax)
  4076a8:	58                   	pop    %eax
  4076a9:	b1 ff                	mov    $0xff,%cl
  4076ab:	ff 49 00             	decl   0x0(%ecx)
  4076ae:	00 00                	add    %al,(%eax)
  4076b0:	00 41 0e             	add    %al,0xe(%ecx)
  4076b3:	08 86 02 43 0e 0c    	or     %al,0xc0e4302(%esi)
  4076b9:	83 03 45             	addl   $0x45,(%ebx)
  4076bc:	0e                   	push   %cs
  4076bd:	20 6f 0a             	and    %ch,0xa(%edi)
  4076c0:	0e                   	push   %cs
  4076c1:	0c 41                	or     $0x41,%al
  4076c3:	c3                   	ret    
  4076c4:	0e                   	push   %cs
  4076c5:	08 41 c6             	or     %al,-0x3a(%ecx)
  4076c8:	0e                   	push   %cs
  4076c9:	04 46                	add    $0x46,%al
  4076cb:	0b 28                	or     (%eax),%ebp
  4076cd:	00 00                	add    %al,(%eax)
  4076cf:	00 50 01             	add    %dl,0x1(%eax)
  4076d2:	00 00                	add    %al,(%eax)
  4076d4:	7c b1                	jl     407687 <.eh_frame+0x55b>
  4076d6:	ff                   	(bad)  
  4076d7:	ff 4b 00             	decl   0x0(%ebx)
  4076da:	00 00                	add    %al,(%eax)
  4076dc:	00 41 0e             	add    %al,0xe(%ecx)
  4076df:	08 86 02 43 0e 0c    	or     %al,0xc0e4302(%esi)
  4076e5:	83 03 43             	addl   $0x43,(%ebx)
  4076e8:	0e                   	push   %cs
  4076e9:	20 7a 0a             	and    %bh,0xa(%edx)
  4076ec:	0e                   	push   %cs
  4076ed:	0c 41                	or     $0x41,%al
  4076ef:	c3                   	ret    
  4076f0:	0e                   	push   %cs
  4076f1:	08 41 c6             	or     %al,-0x3a(%ecx)
  4076f4:	0e                   	push   %cs
  4076f5:	04 41                	add    $0x41,%al
  4076f7:	0b 3c 00             	or     (%eax,%eax,1),%edi
  4076fa:	00 00                	add    %al,(%eax)
  4076fc:	7c 01                	jl     4076ff <.eh_frame+0x5d3>
  4076fe:	00 00                	add    %al,(%eax)
  407700:	a0 b1 ff ff 92       	mov    0x92ffffb1,%al
  407705:	08 00                	or     %al,(%eax)
  407707:	00 00                	add    %al,(%eax)
  407709:	41                   	inc    %ecx
  40770a:	0e                   	push   %cs
  40770b:	08 85 02 42 0d 05    	or     %al,0x50d4202(%ebp)
  407711:	46                   	inc    %esi
  407712:	87 03                	xchg   %eax,(%ebx)
  407714:	86 04 83             	xchg   %al,(%ebx,%eax,4)
  407717:	05 03 c9 02 0a       	add    $0xa02c903,%eax
  40771c:	c3                   	ret    
  40771d:	41                   	inc    %ecx
  40771e:	c6 41 c7 41          	movb   $0x41,-0x39(%ecx)
  407722:	c5 0c 04             	lds    (%esp,%eax,1),%ecx
  407725:	04 4b                	add    $0x4b,%al
  407727:	0b 03                	or     (%ebx),%eax
  407729:	22 01                	and    (%ecx),%al
  40772b:	0a c3                	or     %bl,%al
  40772d:	41                   	inc    %ecx
  40772e:	c6 41 c7 41          	movb   $0x41,-0x39(%ecx)
  407732:	c5 0c 04             	lds    (%esp,%eax,1),%ecx
  407735:	04 4b                	add    $0x4b,%al
  407737:	0b 2c 00             	or     (%eax,%eax,1),%ebp
  40773a:	00 00                	add    %al,(%eax)
  40773c:	bc 01 00 00 00       	mov    $0x1,%esp
  407741:	ba ff ff f5 00       	mov    $0xf5ffff,%edx
  407746:	00 00                	add    %al,(%eax)
  407748:	00 41 0e             	add    %al,0xe(%ecx)
  40774b:	08 85 02 42 0d 05    	or     %al,0x50d4202(%ebp)
  407751:	46                   	inc    %esi
  407752:	87 03                	xchg   %eax,(%ebx)
  407754:	86 04 83             	xchg   %al,(%ebx,%eax,4)
  407757:	05 02 46 0a c3       	add    $0xc30a4602,%eax
  40775c:	41                   	inc    %ecx
  40775d:	c6 41 c7 41          	movb   $0x41,-0x39(%ecx)
  407761:	c5 0c 04             	lds    (%esp,%eax,1),%ecx
  407764:	04 46                	add    $0x46,%al
  407766:	0b 00                	or     (%eax),%eax
  407768:	40                   	inc    %eax
  407769:	00 00                	add    %al,(%eax)
  40776b:	00 ec                	add    %ch,%ah
  40776d:	01 00                	add    %eax,(%eax)
  40776f:	00 d0                	add    %dl,%al
  407771:	ba ff ff 57 00       	mov    $0x57ffff,%edx
  407776:	00 00                	add    %al,(%eax)
  407778:	00 41 0e             	add    %al,0xe(%ecx)
  40777b:	08 87 02 41 0e 0c    	or     %al,0xc0e4102(%edi)
  407781:	86 03                	xchg   %al,(%ebx)
  407783:	41                   	inc    %ecx
  407784:	0e                   	push   %cs
  407785:	10 83 04 43 0e 20    	adc    %al,0x200e4304(%ebx)
  40778b:	4f                   	dec    %edi
  40778c:	0a 0e                	or     (%esi),%cl
  40778e:	10 41 c3             	adc    %al,-0x3d(%ecx)
  407791:	0e                   	push   %cs
  407792:	0c 41                	or     $0x41,%al
  407794:	c6                   	(bad)  
  407795:	0e                   	push   %cs
  407796:	08 41 c7             	or     %al,-0x39(%ecx)
  407799:	0e                   	push   %cs
  40779a:	04 48                	add    $0x48,%al
  40779c:	0b 6f 0e             	or     0xe(%edi),%ebp
  40779f:	10 41 c3             	adc    %al,-0x3d(%ecx)
  4077a2:	0e                   	push   %cs
  4077a3:	0c 41                	or     $0x41,%al
  4077a5:	c6                   	(bad)  
  4077a6:	0e                   	push   %cs
  4077a7:	08 41 c7             	or     %al,-0x39(%ecx)
  4077aa:	0e                   	push   %cs
  4077ab:	04 14                	add    $0x14,%al
  4077ad:	00 00                	add    %al,(%eax)
  4077af:	00 00                	add    %al,(%eax)
  4077b1:	00 00                	add    %al,(%eax)
  4077b3:	00 01                	add    %al,(%ecx)
  4077b5:	7a 52                	jp     407809 <.eh_frame+0x6dd>
  4077b7:	00 01                	add    %al,(%ecx)
  4077b9:	7c 08                	jl     4077c3 <.eh_frame+0x697>
  4077bb:	01 1b                	add    %ebx,(%ebx)
  4077bd:	0c 04                	or     $0x4,%al
  4077bf:	04 88                	add    $0x88,%al
  4077c1:	01 00                	add    %eax,(%eax)
  4077c3:	00 2c 00             	add    %ch,(%eax,%eax,1)
  4077c6:	00 00                	add    %al,(%eax)
  4077c8:	1c 00                	sbb    $0x0,%al
  4077ca:	00 00                	add    %al,(%eax)
  4077cc:	d4 ba                	aam    $0xba
  4077ce:	ff                   	(bad)  
  4077cf:	ff 12                	call   *(%edx)
  4077d1:	04 00                	add    $0x0,%al
  4077d3:	00 00                	add    %al,(%eax)
  4077d5:	41                   	inc    %ecx
  4077d6:	0e                   	push   %cs
  4077d7:	08 85 02 42 0d 05    	or     %al,0x50d4202(%ebp)
  4077dd:	46                   	inc    %esi
  4077de:	87 03                	xchg   %eax,(%ebx)
  4077e0:	86 04 83             	xchg   %al,(%ebx,%eax,4)
  4077e3:	05 02 b4 0a c3       	add    $0xc30ab402,%eax
  4077e8:	41                   	inc    %ecx
  4077e9:	c6 41 c7 41          	movb   $0x41,-0x39(%ecx)
  4077ed:	c5 0c 04             	lds    (%esp,%eax,1),%ecx
  4077f0:	04 48                	add    $0x48,%al
  4077f2:	0b 00                	or     (%eax),%eax
  4077f4:	14 00                	adc    $0x0,%al
  4077f6:	00 00                	add    %al,(%eax)
  4077f8:	00 00                	add    %al,(%eax)
  4077fa:	00 00                	add    %al,(%eax)
  4077fc:	01 7a 52             	add    %edi,0x52(%edx)
  4077ff:	00 01                	add    %al,(%ecx)
  407801:	7c 08                	jl     40780b <.eh_frame+0x6df>
  407803:	01 1b                	add    %ebx,(%ebx)
  407805:	0c 04                	or     $0x4,%al
  407807:	04 88                	add    $0x88,%al
  407809:	01 00                	add    %eax,(%eax)
  40780b:	00 40 00             	add    %al,0x0(%eax)
  40780e:	00 00                	add    %al,(%eax)
  407810:	1c 00                	sbb    $0x0,%al
  407812:	00 00                	add    %al,(%eax)
  407814:	ac                   	lods   %ds:(%esi),%al
  407815:	be ff ff e9 00       	mov    $0xe9ffff,%esi
  40781a:	00 00                	add    %al,(%eax)
  40781c:	00 41 0e             	add    %al,0xe(%ecx)
  40781f:	08 86 02 41 0e 0c    	or     %al,0xc0e4102(%esi)
  407825:	83 03 48             	addl   $0x48,(%ebx)
  407828:	0e                   	push   %cs
  407829:	e0 02                	loopne 40782d <.eh_frame+0x701>
  40782b:	50                   	push   %eax
  40782c:	0e                   	push   %cs
  40782d:	d8 02                	fadds  (%edx)
  40782f:	43                   	inc    %ebx
  407830:	0e                   	push   %cs
  407831:	e0 02                	loopne 407835 <.eh_frame+0x709>
  407833:	02 57 0a             	add    0xa(%edi),%dl
  407836:	0e                   	push   %cs
  407837:	0c 43                	or     $0x43,%al
  407839:	c3                   	ret    
  40783a:	0e                   	push   %cs
  40783b:	08 41 c6             	or     %al,-0x3a(%ecx)
  40783e:	0e                   	push   %cs
  40783f:	04 48                	add    $0x48,%al
  407841:	0b 4d 0a             	or     0xa(%ebp),%ecx
  407844:	0e                   	push   %cs
  407845:	0c 43                	or     $0x43,%al
  407847:	c3                   	ret    
  407848:	0e                   	push   %cs
  407849:	08 41 c6             	or     %al,-0x3a(%ecx)
  40784c:	0e                   	push   %cs
  40784d:	04 47                	add    $0x47,%al
  40784f:	0b 4c 00 00          	or     0x0(%eax,%eax,1),%ecx
  407853:	00 60 00             	add    %ah,0x0(%eax)
  407856:	00 00                	add    %al,(%eax)
  407858:	58                   	pop    %eax
  407859:	bf ff ff b8 00       	mov    $0xb8ffff,%edi
  40785e:	00 00                	add    %al,(%eax)
  407860:	00 41 0e             	add    %al,0xe(%ecx)
  407863:	08 86 02 41 0e 0c    	or     %al,0xc0e4102(%esi)
  407869:	83 03 48             	addl   $0x48,(%ebx)
  40786c:	0e                   	push   %cs
  40786d:	e0 02                	loopne 407871 <.eh_frame+0x745>
  40786f:	50                   	push   %eax
  407870:	0e                   	push   %cs
  407871:	d8 02                	fadds  (%edx)
  407873:	43                   	inc    %ebx
  407874:	0e                   	push   %cs
  407875:	e0 02                	loopne 407879 <.eh_frame+0x74d>
  407877:	02 57 0a             	add    0xa(%edi),%dl
  40787a:	0e                   	push   %cs
  40787b:	0c 43                	or     $0x43,%al
  40787d:	c3                   	ret    
  40787e:	0e                   	push   %cs
  40787f:	08 41 c6             	or     %al,-0x3a(%ecx)
  407882:	0e                   	push   %cs
  407883:	04 48                	add    $0x48,%al
  407885:	0b 4d 0a             	or     0xa(%ebp),%ecx
  407888:	0e                   	push   %cs
  407889:	0c 43                	or     $0x43,%al
  40788b:	c3                   	ret    
  40788c:	0e                   	push   %cs
  40788d:	08 41 c6             	or     %al,-0x3a(%ecx)
  407890:	0e                   	push   %cs
  407891:	04 47                	add    $0x47,%al
  407893:	0b 5b 0e             	or     0xe(%ebx),%ebx
  407896:	0c 43                	or     $0x43,%al
  407898:	c3                   	ret    
  407899:	0e                   	push   %cs
  40789a:	08 41 c6             	or     %al,-0x3a(%ecx)
  40789d:	0e                   	push   %cs
  40789e:	04 00                	add    $0x0,%al
  4078a0:	54                   	push   %esp
  4078a1:	00 00                	add    %al,(%eax)
  4078a3:	00 b0 00 00 00 c8    	add    %dh,-0x38000000(%eax)
  4078a9:	bf ff ff ff 01       	mov    $0x1ffffff,%edi
  4078ae:	00 00                	add    %al,(%eax)
  4078b0:	00 41 0e             	add    %al,0xe(%ecx)
  4078b3:	08 85 02 41 0e 0c    	or     %al,0xc0e4102(%ebp)
  4078b9:	87 03                	xchg   %eax,(%ebx)
  4078bb:	41                   	inc    %ecx
  4078bc:	0e                   	push   %cs
  4078bd:	10 86 04 41 0e 14    	adc    %al,0x140e4104(%esi)
  4078c3:	83 05 46 0e c0 02 03 	addl   $0x3,0x2c00e46
  4078ca:	53                   	push   %ebx
  4078cb:	01 0a                	add    %ecx,(%edx)
  4078cd:	0e                   	push   %cs
  4078ce:	14 43                	adc    $0x43,%al
  4078d0:	c3                   	ret    
  4078d1:	0e                   	push   %cs
  4078d2:	10 41 c6             	adc    %al,-0x3a(%ecx)
  4078d5:	0e                   	push   %cs
  4078d6:	0c 41                	or     $0x41,%al
  4078d8:	c7                   	(bad)  
  4078d9:	0e                   	push   %cs
  4078da:	08 41 c5             	or     %al,-0x3b(%ecx)
  4078dd:	0e                   	push   %cs
  4078de:	04 45                	add    $0x45,%al
  4078e0:	0b 02                	or     (%edx),%eax
  4078e2:	53                   	push   %ebx
  4078e3:	0a 0e                	or     (%esi),%cl
  4078e5:	14 43                	adc    $0x43,%al
  4078e7:	c3                   	ret    
  4078e8:	0e                   	push   %cs
  4078e9:	10 41 c6             	adc    %al,-0x3a(%ecx)
  4078ec:	0e                   	push   %cs
  4078ed:	0c 41                	or     $0x41,%al
  4078ef:	c7                   	(bad)  
  4078f0:	0e                   	push   %cs
  4078f1:	08 41 c5             	or     %al,-0x3b(%ecx)
  4078f4:	0e                   	push   %cs
  4078f5:	04 47                	add    $0x47,%al
  4078f7:	0b 20                	or     (%eax),%esp
  4078f9:	00 00                	add    %al,(%eax)
  4078fb:	00 08                	add    %cl,(%eax)
  4078fd:	01 00                	add    %eax,(%eax)
  4078ff:	00 70 c1             	add    %dh,-0x3f(%eax)
  407902:	ff                   	(bad)  
  407903:	ff 4f 00             	decl   0x0(%edi)
  407906:	00 00                	add    %al,(%eax)
  407908:	00 41 0e             	add    %al,0xe(%ecx)
  40790b:	08 83 02 43 0e 10    	or     %al,0x100e4302(%ebx)
  407911:	76 0a                	jbe    40791d <.eh_frame+0x7f1>
  407913:	0e                   	push   %cs
  407914:	08 43 c3             	or     %al,-0x3d(%ebx)
  407917:	0e                   	push   %cs
  407918:	04 43                	add    $0x43,%al
  40791a:	0b 00                	or     (%eax),%eax
  40791c:	28 00                	sub    %al,(%eax)
  40791e:	00 00                	add    %al,(%eax)
  407920:	2c 01                	sub    $0x1,%al
  407922:	00 00                	add    %al,(%eax)
  407924:	9c                   	pushf  
  407925:	c1 ff ff             	sar    $0xff,%edi
  407928:	42                   	inc    %edx
  407929:	00 00                	add    %al,(%eax)
  40792b:	00 00                	add    %al,(%eax)
  40792d:	41                   	inc    %ecx
  40792e:	0e                   	push   %cs
  40792f:	08 83 02 43 0e 20    	or     %al,0x200e4302(%ebx)
  407935:	56                   	push   %esi
  407936:	0e                   	push   %cs
  407937:	1c 43                	sbb    $0x43,%al
  407939:	0e                   	push   %cs
  40793a:	20 51 0a             	and    %dl,0xa(%ecx)
  40793d:	0e                   	push   %cs
  40793e:	08 41 c3             	or     %al,-0x3d(%ecx)
  407941:	0e                   	push   %cs
  407942:	04 41                	add    $0x41,%al
  407944:	0b 00                	or     (%eax),%eax
  407946:	00 00                	add    %al,(%eax)
  407948:	2c 00                	sub    $0x0,%al
  40794a:	00 00                	add    %al,(%eax)
  40794c:	58                   	pop    %eax
  40794d:	01 00                	add    %eax,(%eax)
  40794f:	00 c0                	add    %al,%al
  407951:	c1 ff ff             	sar    $0xff,%edi
  407954:	5f                   	pop    %edi
  407955:	00 00                	add    %al,(%eax)
  407957:	00 00                	add    %al,(%eax)
  407959:	41                   	inc    %ecx
  40795a:	0e                   	push   %cs
  40795b:	08 83 02 43 0e 20    	or     %al,0x200e4302(%ebx)
  407961:	56                   	push   %esi
  407962:	0e                   	push   %cs
  407963:	1c 43                	sbb    $0x43,%al
  407965:	0e                   	push   %cs
  407966:	20 52 0a             	and    %dl,0xa(%edx)
  407969:	0e                   	push   %cs
  40796a:	08 41 c3             	or     %al,-0x3d(%ecx)
  40796d:	0e                   	push   %cs
  40796e:	04 48                	add    $0x48,%al
  407970:	0b 65 0e             	or     0xe(%ebp),%esp
  407973:	08 41 c3             	or     %al,-0x3d(%ecx)
  407976:	0e                   	push   %cs
  407977:	04 18                	add    $0x18,%al
  407979:	00 00                	add    %al,(%eax)
  40797b:	00 88 01 00 00 f0    	add    %cl,-0xfffffff(%eax)
  407981:	c1 ff ff             	sar    $0xff,%edi
  407984:	27                   	daa    
  407985:	00 00                	add    %al,(%eax)
  407987:	00 00                	add    %al,(%eax)
  407989:	43                   	inc    %ebx
  40798a:	0e                   	push   %cs
  40798b:	10 51 0a             	adc    %dl,0xa(%ecx)
  40798e:	0e                   	push   %cs
  40798f:	04 41                	add    $0x41,%al
  407991:	0b 00                	or     (%eax),%eax
  407993:	00 34 00             	add    %dh,(%eax,%eax,1)
  407996:	00 00                	add    %al,(%eax)
  407998:	a4                   	movsb  %ds:(%esi),%es:(%edi)
  407999:	01 00                	add    %eax,(%eax)
  40799b:	00 04 c2             	add    %al,(%edx,%eax,8)
  40799e:	ff                   	(bad)  
  40799f:	ff 71 00             	pushl  0x0(%ecx)
  4079a2:	00 00                	add    %al,(%eax)
  4079a4:	00 41 0e             	add    %al,0xe(%ecx)
  4079a7:	08 86 02 41 0e 0c    	or     %al,0xc0e4102(%esi)
  4079ad:	83 03 43             	addl   $0x43,(%ebx)
  4079b0:	0e                   	push   %cs
  4079b1:	20 02                	and    %al,(%edx)
  4079b3:	52                   	push   %edx
  4079b4:	0a 0e                	or     (%esi),%cl
  4079b6:	0c 41                	or     $0x41,%al
  4079b8:	c3                   	ret    
  4079b9:	0e                   	push   %cs
  4079ba:	08 41 c6             	or     %al,-0x3a(%ecx)
  4079bd:	0e                   	push   %cs
  4079be:	04 47                	add    $0x47,%al
  4079c0:	0b 4e 0e             	or     0xe(%esi),%ecx
  4079c3:	0c 41                	or     $0x41,%al
  4079c5:	c3                   	ret    
  4079c6:	0e                   	push   %cs
  4079c7:	08 41 c6             	or     %al,-0x3a(%ecx)
  4079ca:	0e                   	push   %cs
  4079cb:	04 14                	add    $0x14,%al
  4079cd:	00 00                	add    %al,(%eax)
  4079cf:	00 00                	add    %al,(%eax)
  4079d1:	00 00                	add    %al,(%eax)
  4079d3:	00 01                	add    %al,(%ecx)
  4079d5:	7a 52                	jp     407a29 <.eh_frame+0x8fd>
  4079d7:	00 01                	add    %al,(%ecx)
  4079d9:	7c 08                	jl     4079e3 <.eh_frame+0x8b7>
  4079db:	01 1b                	add    %ebx,(%ebx)
  4079dd:	0c 04                	or     $0x4,%al
  4079df:	04 88                	add    $0x88,%al
  4079e1:	01 00                	add    %eax,(%eax)
  4079e3:	00 3c 00             	add    %bh,(%eax,%eax,1)
  4079e6:	00 00                	add    %al,(%eax)
  4079e8:	1c 00                	sbb    $0x0,%al
  4079ea:	00 00                	add    %al,(%eax)
  4079ec:	34 c2                	xor    $0xc2,%al
  4079ee:	ff                   	(bad)  
  4079ef:	ff b3 00 00 00 00    	pushl  0x0(%ebx)
  4079f5:	41                   	inc    %ecx
  4079f6:	0e                   	push   %cs
  4079f7:	08 85 02 41 0e 0c    	or     %al,0xc0e4102(%ebp)
  4079fd:	87 03                	xchg   %eax,(%ebx)
  4079ff:	41                   	inc    %ecx
  407a00:	0e                   	push   %cs
  407a01:	10 86 04 41 0e 14    	adc    %al,0x140e4104(%esi)
  407a07:	83 05 43 0e 1c 02 92 	addl   $0xffffff92,0x21c0e43
  407a0e:	0a 0e                	or     (%esi),%cl
  407a10:	14 41                	adc    $0x41,%al
  407a12:	c3                   	ret    
  407a13:	0e                   	push   %cs
  407a14:	10 41 c6             	adc    %al,-0x3a(%ecx)
  407a17:	0e                   	push   %cs
  407a18:	0c 41                	or     $0x41,%al
  407a1a:	c7                   	(bad)  
  407a1b:	0e                   	push   %cs
  407a1c:	08 41 c5             	or     %al,-0x3b(%ecx)
  407a1f:	0e                   	push   %cs
  407a20:	04 43                	add    $0x43,%al
  407a22:	0b 00                	or     (%eax),%eax
  407a24:	14 00                	adc    $0x0,%al
  407a26:	00 00                	add    %al,(%eax)
  407a28:	00 00                	add    %al,(%eax)
  407a2a:	00 00                	add    %al,(%eax)
  407a2c:	01 7a 52             	add    %edi,0x52(%edx)
  407a2f:	00 01                	add    %al,(%ecx)
  407a31:	7c 08                	jl     407a3b <.eh_frame+0x90f>
  407a33:	01 1b                	add    %ebx,(%ebx)
  407a35:	0c 04                	or     $0x4,%al
  407a37:	04 88                	add    $0x88,%al
  407a39:	01 00                	add    %eax,(%eax)
  407a3b:	00 54 00 00          	add    %dl,0x0(%eax,%eax,1)
  407a3f:	00 1c 00             	add    %bl,(%eax,%eax,1)
  407a42:	00 00                	add    %al,(%eax)
  407a44:	9c                   	pushf  
  407a45:	c2 ff ff             	ret    $0xffff
  407a48:	77 00                	ja     407a4a <.eh_frame+0x91e>
  407a4a:	00 00                	add    %al,(%eax)
  407a4c:	00 41 0e             	add    %al,0xe(%ecx)
  407a4f:	08 87 02 41 0e 0c    	or     %al,0xc0e4102(%edi)
  407a55:	86 03                	xchg   %al,(%ebx)
  407a57:	41                   	inc    %ecx
  407a58:	0e                   	push   %cs
  407a59:	10 83 04 43 0e 30    	adc    %al,0x300e4304(%ebx)
  407a5f:	78 0a                	js     407a6b <.eh_frame+0x93f>
  407a61:	0e                   	push   %cs
  407a62:	10 43 c3             	adc    %al,-0x3d(%ebx)
  407a65:	0e                   	push   %cs
  407a66:	0c 41                	or     $0x41,%al
  407a68:	c6                   	(bad)  
  407a69:	0e                   	push   %cs
  407a6a:	08 41 c7             	or     %al,-0x39(%ecx)
  407a6d:	0e                   	push   %cs
  407a6e:	04 45                	add    $0x45,%al
  407a70:	0b 54 0a 0e          	or     0xe(%edx,%ecx,1),%edx
  407a74:	10 41 c3             	adc    %al,-0x3d(%ecx)
  407a77:	0e                   	push   %cs
  407a78:	0c 41                	or     $0x41,%al
  407a7a:	c6                   	(bad)  
  407a7b:	0e                   	push   %cs
  407a7c:	08 41 c7             	or     %al,-0x39(%ecx)
  407a7f:	0e                   	push   %cs
  407a80:	04 41                	add    $0x41,%al
  407a82:	0b 53 0e             	or     0xe(%ebx),%edx
  407a85:	10 41 c3             	adc    %al,-0x3d(%ecx)
  407a88:	0e                   	push   %cs
  407a89:	0c 41                	or     $0x41,%al
  407a8b:	c6                   	(bad)  
  407a8c:	0e                   	push   %cs
  407a8d:	08 41 c7             	or     %al,-0x39(%ecx)
  407a90:	0e                   	push   %cs
  407a91:	04 00                	add    $0x0,%al
  407a93:	00 14 00             	add    %dl,(%eax,%eax,1)
  407a96:	00 00                	add    %al,(%eax)
  407a98:	00 00                	add    %al,(%eax)
  407a9a:	00 00                	add    %al,(%eax)
  407a9c:	01 7a 52             	add    %edi,0x52(%edx)
  407a9f:	00 01                	add    %al,(%ecx)
  407aa1:	7c 08                	jl     407aab <.eh_frame+0x97f>
  407aa3:	01 1b                	add    %ebx,(%ebx)
  407aa5:	0c 04                	or     $0x4,%al
  407aa7:	04 88                	add    $0x88,%al
  407aa9:	01 00                	add    %eax,(%eax)
  407aab:	00 50 00             	add    %dl,0x0(%eax)
  407aae:	00 00                	add    %al,(%eax)
  407ab0:	1c 00                	sbb    $0x0,%al
  407ab2:	00 00                	add    %al,(%eax)
  407ab4:	ac                   	lods   %ds:(%esi),%al
  407ab5:	c2 ff ff             	ret    $0xffff
  407ab8:	de 00                	fiadds (%eax)
  407aba:	00 00                	add    %al,(%eax)
  407abc:	00 41 0e             	add    %al,0xe(%ecx)
  407abf:	08 85 02 41 0e 0c    	or     %al,0xc0e4102(%ebp)
  407ac5:	87 03                	xchg   %eax,(%ebx)
  407ac7:	41                   	inc    %ecx
  407ac8:	0e                   	push   %cs
  407ac9:	10 86 04 41 0e 14    	adc    %al,0x140e4104(%esi)
  407acf:	83 05 43 0e 30 02 a5 	addl   $0xffffffa5,0x2300e43
  407ad6:	0a 0e                	or     (%esi),%cl
  407ad8:	14 43                	adc    $0x43,%al
  407ada:	c3                   	ret    
  407adb:	0e                   	push   %cs
  407adc:	10 41 c6             	adc    %al,-0x3a(%ecx)
  407adf:	0e                   	push   %cs
  407ae0:	0c 41                	or     $0x41,%al
  407ae2:	c7                   	(bad)  
  407ae3:	0e                   	push   %cs
  407ae4:	08 41 c5             	or     %al,-0x3b(%ecx)
  407ae7:	0e                   	push   %cs
  407ae8:	04 46                	add    $0x46,%al
  407aea:	0b 5f 0e             	or     0xe(%edi),%ebx
  407aed:	14 41                	adc    $0x41,%al
  407aef:	c3                   	ret    
  407af0:	0e                   	push   %cs
  407af1:	10 41 c6             	adc    %al,-0x3a(%ecx)
  407af4:	0e                   	push   %cs
  407af5:	0c 43                	or     $0x43,%al
  407af7:	c7                   	(bad)  
  407af8:	0e                   	push   %cs
  407af9:	08 41 c5             	or     %al,-0x3b(%ecx)
  407afc:	0e                   	push   %cs
  407afd:	04 00                	add    $0x0,%al
	...

00407b00 <___FRAME_END__>:
  407b00:	00 00                	add    %al,(%eax)
  407b02:	00 00                	add    %al,(%eax)
  407b04:	14 00                	adc    $0x0,%al
  407b06:	00 00                	add    %al,(%eax)
  407b08:	00 00                	add    %al,(%eax)
  407b0a:	00 00                	add    %al,(%eax)
  407b0c:	01 7a 52             	add    %edi,0x52(%edx)
  407b0f:	00 01                	add    %al,(%ecx)
  407b11:	7c 08                	jl     407b1b <___FRAME_END__+0x1b>
  407b13:	01 1b                	add    %ebx,(%ebx)
  407b15:	0c 04                	or     $0x4,%al
  407b17:	04 88                	add    $0x88,%al
  407b19:	01 00                	add    %eax,(%eax)
  407b1b:	00 10                	add    %dl,(%eax)
  407b1d:	00 00                	add    %al,(%eax)
  407b1f:	00 1c 00             	add    %bl,(%eax,%eax,1)
  407b22:	00 00                	add    %al,(%eax)
  407b24:	bc c5 ff ff 05       	mov    $0x5ffffc5,%esp
  407b29:	00 00                	add    %al,(%eax)
  407b2b:	00 00                	add    %al,(%eax)
  407b2d:	00 00                	add    %al,(%eax)
	...

Disassembly of section .bss:

00408000 <__argv>:
  408000:	00 00                	add    %al,(%eax)
	...

00408004 <__argc>:
  408004:	00 00                	add    %al,(%eax)
	...

00408008 <_obj>:
	...

00408020 <__CRT_fmode>:
  408020:	00 00                	add    %al,(%eax)
	...

00408024 <___cpu_features>:
  408024:	00 00                	add    %al,(%eax)
	...

00408028 <.bss>:
  408028:	00 00                	add    %al,(%eax)
	...

0040802c <_mingw_initltssuo_force>:
  40802c:	00 00                	add    %al,(%eax)
	...

00408030 <_mingw_initltsdyn_force>:
  408030:	00 00                	add    %al,(%eax)
	...

00408034 <_mingw_initltsdrot_force>:
  408034:	00 00                	add    %al,(%eax)
	...

00408038 <__tls_index>:
  408038:	00 00                	add    %al,(%eax)
	...

0040803c <.bss>:
	...

0040805c <.bss>:
	...

00408064 <__CRT_MT>:
  408064:	00 00                	add    %al,(%eax)
	...

00408068 <.bss>:
  408068:	00 00                	add    %al,(%eax)
	...

0040806c <___mingw_memalign_lwm>:
  40806c:	00 00                	add    %al,(%eax)
	...

00408070 <_hmod_libgcc>:
  408070:	00 00                	add    %al,(%eax)
	...

Disassembly of section .idata:

00409000 <__head_libkernel32_a>:
  409000:	78 90                	js     408f92 <__bss_end__+0xf1e>
	...
  40900a:	00 00                	add    %al,(%eax)
  40900c:	0c 96                	or     $0x96,%al
  40900e:	00 00                	add    %al,(%eax)
  409010:	74 91                	je     408fa3 <__bss_end__+0xf2f>
	...

00409014 <__head_libmoldname_a>:
  409014:	cc                   	int3   
  409015:	90                   	nop
	...
  40901e:	00 00                	add    %al,(%eax)
  409020:	24 96                	and    $0x96,%al
  409022:	00 00                	add    %al,(%eax)
  409024:	c8 91 00 00          	enter  $0x91,$0x0

00409028 <__head_libmsvcrt_a>:
  409028:	d8 90 00 00 00 00    	fcoms  0x0(%eax)
  40902e:	00 00                	add    %al,(%eax)
  409030:	00 00                	add    %al,(%eax)
  409032:	00 00                	add    %al,(%eax)
  409034:	b4 96                	mov    $0x96,%ah
  409036:	00 00                	add    %al,(%eax)
  409038:	d4 91                	aam    $0x91
	...

0040903c <__head_libuser32_a>:
  40903c:	60                   	pusha  
  40903d:	91                   	xchg   %eax,%ecx
	...
  409046:	00 00                	add    %al,(%eax)
  409048:	c4 96 00 00 5c 92    	les    -0x6da40000(%esi),%edx
	...

00409050 <__head_libgcc_s_dw2_1_dll>:
  409050:	68 91 00 00 00       	push   $0x91
  409055:	00 00                	add    %al,(%eax)
  409057:	00 00                	add    %al,(%eax)
  409059:	00 00                	add    %al,(%eax)
  40905b:	00 d8                	add    %bl,%al
  40905d:	96                   	xchg   %eax,%esi
  40905e:	00 00                	add    %al,(%eax)
  409060:	64 92                	fs xchg %eax,%edx
	...

00409078 <.idata$4>:
  409078:	70 92                	jo     40900c <__head_libkernel32_a+0xc>
  40907a:	00 00                	add    %al,(%eax)
  40907c:	88 92 00 00 a0 92    	mov    %dl,-0x6d600000(%edx)
  409082:	00 00                	add    %al,(%eax)
  409084:	ae                   	scas   %es:(%edi),%al
  409085:	92                   	xchg   %eax,%edx
  409086:	00 00                	add    %al,(%eax)
  409088:	ba 92 00 00 cc       	mov    $0xcc000092,%edx
  40908d:	92                   	xchg   %eax,%edx
  40908e:	00 00                	add    %al,(%eax)
  409090:	dc 92 00 00 ea 92    	fcoml  -0x6d160000(%edx)
  409096:	00 00                	add    %al,(%eax)
  409098:	fc                   	cld    
  409099:	92                   	xchg   %eax,%edx
  40909a:	00 00                	add    %al,(%eax)
  40909c:	0c 93                	or     $0x93,%al
  40909e:	00 00                	add    %al,(%eax)
  4090a0:	22 93 00 00 36 93    	and    -0x6cca0000(%ebx),%dl
  4090a6:	00 00                	add    %al,(%eax)
  4090a8:	48                   	dec    %eax
  4090a9:	93                   	xchg   %eax,%ebx
  4090aa:	00 00                	add    %al,(%eax)
  4090ac:	5a                   	pop    %edx
  4090ad:	93                   	xchg   %eax,%ebx
  4090ae:	00 00                	add    %al,(%eax)
  4090b0:	76 93                	jbe    409045 <__head_libuser32_a+0x9>
  4090b2:	00 00                	add    %al,(%eax)
  4090b4:	8e 93 00 00 9e 93    	mov    -0x6c620000(%ebx),%ss
  4090ba:	00 00                	add    %al,(%eax)
  4090bc:	bc 93 00 00 ca       	mov    $0xca000093,%esp
  4090c1:	93                   	xchg   %eax,%ebx
  4090c2:	00 00                	add    %al,(%eax)
  4090c4:	dc 93 00 00 00 00    	fcoml  0x0(%ebx)
	...

004090cc <.idata$4>:
  4090cc:	ec                   	in     (%dx),%al
  4090cd:	93                   	xchg   %eax,%ebx
  4090ce:	00 00                	add    %al,(%eax)
  4090d0:	f6 93 00 00 00 00    	notb   0x0(%ebx)
	...

004090d8 <.idata$4>:
  4090d8:	02 94 00 00 12 94 00 	add    0x941200(%eax,%eax,1),%dl
  4090df:	00 22                	add    %ah,(%edx)
  4090e1:	94                   	xchg   %eax,%esp
  4090e2:	00 00                	add    %al,(%eax)
  4090e4:	32 94 00 00 40 94 00 	xor    0x944000(%eax,%eax,1),%dl
  4090eb:	00 4e 94             	add    %cl,-0x6c(%esi)
  4090ee:	00 00                	add    %al,(%eax)
  4090f0:	60                   	pusha  
  4090f1:	94                   	xchg   %eax,%esp
  4090f2:	00 00                	add    %al,(%eax)
  4090f4:	6a 94                	push   $0xffffff94
  4090f6:	00 00                	add    %al,(%eax)
  4090f8:	74 94                	je     40908e <.idata$4+0x16>
  4090fa:	00 00                	add    %al,(%eax)
  4090fc:	80 94 00 00 8c 94 00 	adcb   $0x0,0x948c00(%eax,%eax,1)
  409103:	00 
  409104:	94                   	xchg   %eax,%esp
  409105:	94                   	xchg   %eax,%esp
  409106:	00 00                	add    %al,(%eax)
  409108:	a0 94 00 00 aa       	mov    0xaa000094,%al
  40910d:	94                   	xchg   %eax,%esp
  40910e:	00 00                	add    %al,(%eax)
  409110:	b4 94                	mov    $0x94,%ah
  409112:	00 00                	add    %al,(%eax)
  409114:	be 94 00 00 ca       	mov    $0xca000094,%esi
  409119:	94                   	xchg   %eax,%esp
  40911a:	00 00                	add    %al,(%eax)
  40911c:	d2 94 00 00 dc 94 00 	rclb   %cl,0x94dc00(%eax,%eax,1)
  409123:	00 e6                	add    %ah,%dh
  409125:	94                   	xchg   %eax,%esp
  409126:	00 00                	add    %al,(%eax)
  409128:	f0 94                	lock xchg %eax,%esp
  40912a:	00 00                	add    %al,(%eax)
  40912c:	fa                   	cli    
  40912d:	94                   	xchg   %eax,%esp
  40912e:	00 00                	add    %al,(%eax)
  409130:	06                   	push   %es
  409131:	95                   	xchg   %eax,%ebp
  409132:	00 00                	add    %al,(%eax)
  409134:	10 95 00 00 1a 95    	adc    %dl,-0x6ae60000(%ebp)
  40913a:	00 00                	add    %al,(%eax)
  40913c:	26 95                	es xchg %eax,%ebp
  40913e:	00 00                	add    %al,(%eax)
  409140:	30 95 00 00 3a 95    	xor    %dl,-0x6ac60000(%ebp)
  409146:	00 00                	add    %al,(%eax)
  409148:	44                   	inc    %esp
  409149:	95                   	xchg   %eax,%ebp
  40914a:	00 00                	add    %al,(%eax)
  40914c:	4e                   	dec    %esi
  40914d:	95                   	xchg   %eax,%ebp
  40914e:	00 00                	add    %al,(%eax)
  409150:	5a                   	pop    %edx
  409151:	95                   	xchg   %eax,%ebp
  409152:	00 00                	add    %al,(%eax)
  409154:	66 95                	xchg   %ax,%bp
  409156:	00 00                	add    %al,(%eax)
  409158:	6e                   	outsb  %ds:(%esi),(%dx)
  409159:	95                   	xchg   %eax,%ebp
  40915a:	00 00                	add    %al,(%eax)
  40915c:	00 00                	add    %al,(%eax)
	...

00409160 <.idata$4>:
  409160:	78 95                	js     4090f7 <.idata$4+0x1f>
  409162:	00 00                	add    %al,(%eax)
  409164:	00 00                	add    %al,(%eax)
	...

00409168 <.idata$4>:
  409168:	88 95 00 00      	mov    %dl,-0x6a5c0000(%ebp)

0040916c <.idata$4>:
  40916c:	a4                   	movsb  %ds:(%esi),%es:(%edi)
  40916d:	95                   	xchg   %eax,%ebp
	...

00409170 <.idata$4>:
  409170:	00 00                	add    %al,(%eax)
	...

00409174 <__IAT_start__>:
  409174:	70 92                	jo     409108 <.idata$4+0x30>
	...

00409178 <__imp__EnterCriticalSection@4>:
  409178:	88 92 00 00      	mov    %dl,-0x6d600000(%edx)

0040917c <__imp__ExitProcess@4>:
  40917c:	a0 92 00 00        	mov    0xae000092,%al

00409180 <__imp__FindClose@4>:
  409180:	ae                   	scas   %es:(%edi),%al
  409181:	92                   	xchg   %eax,%edx
	...

00409184 <__imp__FindFirstFileA@8>:
  409184:	ba 92 00 00        	mov    $0xcc000092,%edx

00409188 <__imp__FindNextFileA@8>:
  409188:	cc                   	int3   
  409189:	92                   	xchg   %eax,%edx
	...

0040918c <__imp__FreeLibrary@4>:
  40918c:	dc 92 00 00      	fcoml  -0x6d160000(%edx)

00409190 <__imp__GetCommandLineA@0>:
  409190:	ea 92 00 00    	ljmp   $0x92,$0xfc000092

00409194 <__imp__GetLastError@0>:
  409194:	fc                   	cld    
  409195:	92                   	xchg   %eax,%edx
	...

00409198 <__imp__GetModuleFileNameA@12>:
  409198:	0c 93                	or     $0x93,%al
	...

0040919c <__imp__GetModuleHandleA@4>:
  40919c:	22 93 00 00      	and    -0x6cca0000(%ebx),%dl

004091a0 <__imp__GetProcAddress@8>:
  4091a0:	36 93                	ss xchg %eax,%ebx
	...

004091a4 <__imp__GetStartupInfoA@4>:
  4091a4:	48                   	dec    %eax
  4091a5:	93                   	xchg   %eax,%ebx
	...

004091a8 <__imp__InitializeCriticalSection@4>:
  4091a8:	5a                   	pop    %edx
  4091a9:	93                   	xchg   %eax,%ebx
	...

004091ac <__imp__LeaveCriticalSection@4>:
  4091ac:	76 93                	jbe    409141 <.idata$4+0x69>
	...

004091b0 <__imp__LoadLibraryA@4>:
  4091b0:	8e 93 00 00      	mov    -0x6c620000(%ebx),%ss

004091b4 <__imp__SetUnhandledExceptionFilter@4>:
  4091b4:	9e                   	sahf   
  4091b5:	93                   	xchg   %eax,%ebx
	...

004091b8 <__imp__TlsGetValue@4>:
  4091b8:	bc 93 00 00        	mov    $0xca000093,%esp

004091bc <__imp__VirtualProtect@16>:
  4091bc:	ca 93 00             	lret   $0x93
	...

004091c0 <__imp__VirtualQuery@12>:
  4091c0:	dc 93 00 00 00 00    	fcoml  0x0(%ebx)
	...

004091c8 <__imp__strdup>:
  4091c8:	ec                   	in     (%dx),%al
  4091c9:	93                   	xchg   %eax,%ebx
	...

004091cc <__imp__stricoll>:
  4091cc:	f6 93 00 00 00 00    	notb   0x0(%ebx)
	...

004091d4 <__imp____getmainargs>:
  4091d4:	02 94 00 00    	add    0x941200(%eax,%eax,1),%dl

004091d8 <__imp____mb_cur_max>:
  4091d8:	12 94 00 00    	adc    0x942200(%eax,%eax,1),%dl

004091dc <__imp____p__environ>:
  4091dc:	22 94 00 00    	and    0x943200(%eax,%eax,1),%dl

004091e0 <__imp____p__fmode>:
  4091e0:	32 94 00 00    	xor    0x944000(%eax,%eax,1),%dl

004091e4 <__imp____p__pgmptr>:
  4091e4:	40                   	inc    %eax
  4091e5:	94                   	xchg   %eax,%esp
	...

004091e8 <__imp____set_app_type>:
  4091e8:	4e                   	dec    %esi
  4091e9:	94                   	xchg   %eax,%esp
	...

004091ec <__imp___cexit>:
  4091ec:	60                   	pusha  
  4091ed:	94                   	xchg   %eax,%esp
	...

004091f0 <__imp___errno>:
  4091f0:	6a 94                	push   $0xffffff94
	...

004091f4 <__imp___fpreset>:
  4091f4:	74 94                	je     40918a <__imp__FindNextFileA@8+0x2>
	...

004091f8 <__imp___fullpath>:
  4091f8:	80 94 00 00    	adcb   $0x0,0x948c00(%eax,%eax,1)
  4091ff:	 

004091fc <__imp___iob>:
  4091fc:	8c 94 00 00    	mov    %ss,0x949400(%eax,%eax,1)

00409200 <__imp___isctype>:
  409200:	94                   	xchg   %eax,%esp
  409201:	94                   	xchg   %eax,%esp
	...

00409204 <__imp___msize>:
  409204:	a0 94 00 00        	mov    0xaa000094,%al

00409208 <__imp___onexit>:
  409208:	aa                   	stos   %al,%es:(%edi)
  409209:	94                   	xchg   %eax,%esp
	...

0040920c <__imp___pctype>:
  40920c:	b4 94                	mov    $0x94,%ah
	...

00409210 <__imp___setmode>:
  409210:	be 94 00 00        	mov    $0xca000094,%esi

00409214 <__imp__abort>:
  409214:	ca 94 00             	lret   $0x94
	...

00409218 <__imp__atexit>:
  409218:	d2 94 00 00    	rclb   %cl,0x94dc00(%eax,%eax,1)

0040921c <__imp__calloc>:
  40921c:	dc 94 00 00    	fcoml  0x94e600(%eax,%eax,1)

00409220 <__imp__fwrite>:
  409220:	e6 94                	out    %al,$0x94
	...

00409224 <__imp__malloc>:
  409224:	f0 94                	lock xchg %eax,%esp
	...

00409228 <__imp__mbstowcs>:
  409228:	fa                   	cli    
  409229:	94                   	xchg   %eax,%esp
	...

0040922c <__imp__memcpy>:
  40922c:	06                   	push   %es
  40922d:	95                   	xchg   %eax,%ebp
	...

00409230 <__imp__memmove>:
  409230:	10 95 00 00      	adc    %dl,-0x6ae60000(%ebp)

00409234 <__imp__setlocale>:
  409234:	1a 95 00 00      	sbb    -0x6ada0000(%ebp),%dl

00409238 <__imp__signal>:
  409238:	26 95                	es xchg %eax,%ebp
	...

0040923c <__imp__strcoll>:
  40923c:	30 95 00 00      	xor    %dl,-0x6ac60000(%ebp)

00409240 <__imp__strlen>:
  409240:	3a 95 00 00      	cmp    -0x6abc0000(%ebp),%dl

00409244 <__imp__tolower>:
  409244:	44                   	inc    %esp
  409245:	95                   	xchg   %eax,%ebp
	...

00409248 <__imp__vfprintf>:
  409248:	4e                   	dec    %esi
  409249:	95                   	xchg   %eax,%ebp
	...

0040924c <__imp__wcstombs>:
  40924c:	5a                   	pop    %edx
  40924d:	95                   	xchg   %eax,%ebp
	...

00409250 <__imp____msvcrt_free>:
  409250:	66 95                	xchg   %ax,%bp
	...

00409254 <__imp____msvcrt_realloc>:
  409254:	6e                   	outsb  %ds:(%esi),(%dx)
  409255:	95                   	xchg   %eax,%ebp
  409256:	00 00                	add    %al,(%eax)
  409258:	00 00                	add    %al,(%eax)
	...

0040925c <__imp__MessageBoxW@16>:
  40925c:	78 95                	js     4091f3 <__imp___errno+0x3>
  40925e:	00 00                	add    %al,(%eax)
  409260:	00 00                	add    %al,(%eax)
	...

00409264 <__imp____deregister_frame_info>:
  409264:	88 95 00 00      	mov    %dl,-0x6a5c0000(%ebp)

00409268 <__imp____register_frame_info>:
  409268:	a4                   	movsb  %ds:(%esi),%es:(%edi)
  409269:	95                   	xchg   %eax,%ebp
	...

0040926c <.idata$5>:
  40926c:	00 00                	add    %al,(%eax)
	...

00409270 <__IAT_end__>:
  409270:	d0 00                	rolb   (%eax)
  409272:	44                   	inc    %esp
  409273:	65 6c                	gs insb (%dx),%es:(%edi)
  409275:	65 74 65             	gs je  4092dd <.idata$6+0x1>
  409278:	43                   	inc    %ebx
  409279:	72 69                	jb     4092e4 <.idata$6+0x8>
  40927b:	74 69                	je     4092e6 <.idata$6+0xa>
  40927d:	63 61 6c             	arpl   %sp,0x6c(%ecx)
  409280:	53                   	push   %ebx
  409281:	65 63 74 69 6f       	arpl   %si,%gs:0x6f(%ecx,%ebp,2)
  409286:	6e                   	outsb  %ds:(%esi),(%dx)
	...

00409288 <.idata$6>:
  409288:	ed                   	in     (%dx),%eax
  409289:	00 45 6e             	add    %al,0x6e(%ebp)
  40928c:	74 65                	je     4092f3 <.idata$6+0x9>
  40928e:	72 43                	jb     4092d3 <.idata$6+0x7>
  409290:	72 69                	jb     4092fb <.idata$6+0x11>
  409292:	74 69                	je     4092fd <.idata$6+0x1>
  409294:	63 61 6c             	arpl   %sp,0x6c(%ecx)
  409297:	53                   	push   %ebx
  409298:	65 63 74 69 6f       	arpl   %si,%gs:0x6f(%ecx,%ebp,2)
  40929d:	6e                   	outsb  %ds:(%esi),(%dx)
	...

004092a0 <.idata$6>:
  4092a0:	18 01                	sbb    %al,(%ecx)
  4092a2:	45                   	inc    %ebp
  4092a3:	78 69                	js     40930e <.idata$6+0x2>
  4092a5:	74 50                	je     4092f7 <.idata$6+0xd>
  4092a7:	72 6f                	jb     409318 <.idata$6+0xc>
  4092a9:	63 65 73             	arpl   %sp,0x73(%ebp)
  4092ac:	73 00                	jae    4092ae <.idata$6>

004092ae <.idata$6>:
  4092ae:	2d 01 46 69 6e       	sub    $0x6e694601,%eax
  4092b3:	64 43                	fs inc %ebx
  4092b5:	6c                   	insb   (%dx),%es:(%edi)
  4092b6:	6f                   	outsl  %ds:(%esi),(%dx)
  4092b7:	73 65                	jae    40931e <.idata$6+0x12>
	...

004092ba <.idata$6>:
  4092ba:	31 01                	xor    %eax,(%ecx)
  4092bc:	46                   	inc    %esi
  4092bd:	69 6e 64 46 69 72 73 	imul   $0x73726946,0x64(%esi),%ebp
  4092c4:	74 46                	je     40930c <.idata$6>
  4092c6:	69 6c 65 41 00 00  	imul   $0x1420000,0x41(%ebp,%eiz,2),%ebp
  4092cd:	 

004092cc <.idata$6>:
  4092cc:	42                   	inc    %edx
  4092cd:	01 46 69             	add    %eax,0x69(%esi)
  4092d0:	6e                   	outsb  %ds:(%esi),(%dx)
  4092d1:	64 4e                	fs dec %esi
  4092d3:	65 78 74             	gs js  40934a <.idata$6+0x2>
  4092d6:	46                   	inc    %esi
  4092d7:	69 6c 65 41 00   	imul   $0x46016100,0x41(%ebp,%eiz,2),%ebp
  4092de:	 

004092dc <.idata$6>:
  4092dc:	61                   	popa   
  4092dd:	01 46 72             	add    %eax,0x72(%esi)
  4092e0:	65 65 4c             	gs gs dec %esp
  4092e3:	69 62 72 61 72 79 00 	imul   $0x797261,0x72(%edx),%esp

004092ea <.idata$6>:
  4092ea:	85 01                	test   %eax,(%ecx)
  4092ec:	47                   	inc    %edi
  4092ed:	65 74 43             	gs je  409333 <.idata$6+0x11>
  4092f0:	6f                   	outsl  %ds:(%esi),(%dx)
  4092f1:	6d                   	insl   (%dx),%es:(%edi)
  4092f2:	6d                   	insl   (%dx),%es:(%edi)
  4092f3:	61                   	popa   
  4092f4:	6e                   	outsb  %ds:(%esi),(%dx)
  4092f5:	64 4c                	fs dec %esp
  4092f7:	69 6e 65 41 00   	imul   $0x1ff0041,0x65(%esi),%ebp

004092fc <.idata$6>:
  4092fc:	ff 01                	incl   (%ecx)
  4092fe:	47                   	inc    %edi
  4092ff:	65 74 4c             	gs je  40934e <.idata$6+0x6>
  409302:	61                   	popa   
  409303:	73 74                	jae    409379 <.idata$6+0x3>
  409305:	45                   	inc    %ebp
  409306:	72 72                	jb     40937a <.idata$6+0x4>
  409308:	6f                   	outsl  %ds:(%esi),(%dx)
  409309:	72 00                	jb     40930b <.idata$6+0xf>
	...

0040930c <.idata$6>:
  40930c:	10 02                	adc    %al,(%edx)
  40930e:	47                   	inc    %edi
  40930f:	65 74 4d             	gs je  40935f <.idata$6+0x5>
  409312:	6f                   	outsl  %ds:(%esi),(%dx)
  409313:	64 75 6c             	fs jne 409382 <.idata$6+0xc>
  409316:	65 46                	gs inc %esi
  409318:	69 6c 65 4e 61 6d 65 	imul   $0x41656d61,0x4e(%ebp,%eiz,2),%ebp
  40931f:	41 
	...

00409322 <.idata$6>:
  409322:	12 02                	adc    (%edx),%al
  409324:	47                   	inc    %edi
  409325:	65 74 4d             	gs je  409375 <.idata$6+0x1b>
  409328:	6f                   	outsl  %ds:(%esi),(%dx)
  409329:	64 75 6c             	fs jne 409398 <.idata$6+0xa>
  40932c:	65 48                	gs dec %eax
  40932e:	61                   	popa   
  40932f:	6e                   	outsb  %ds:(%esi),(%dx)
  409330:	64 6c                	fs insb (%dx),%es:(%edi)
  409332:	65 41                	gs inc %ecx
	...

00409336 <.idata$6>:
  409336:	42                   	inc    %edx
  409337:	02 47 65             	add    0x65(%edi),%al
  40933a:	74 50                	je     40938c <.idata$6+0x16>
  40933c:	72 6f                	jb     4093ad <.idata$6+0xf>
  40933e:	63 41 64             	arpl   %ax,0x64(%ecx)
  409341:	64 72 65             	fs jb  4093a9 <.idata$6+0xb>
  409344:	73 73                	jae    4093b9 <.idata$6+0x1b>
	...

00409348 <.idata$6>:
  409348:	5f                   	pop    %edi
  409349:	02 47 65             	add    0x65(%edi),%al
  40934c:	74 53                	je     4093a1 <.idata$6+0x3>
  40934e:	74 61                	je     4093b1 <.idata$6+0x13>
  409350:	72 74                	jb     4093c6 <.idata$6+0xa>
  409352:	75 70                	jne    4093c4 <.idata$6+0x8>
  409354:	49                   	dec    %ecx
  409355:	6e                   	outsb  %ds:(%esi),(%dx)
  409356:	66 6f                	outsw  %ds:(%esi),(%dx)
  409358:	41                   	inc    %ecx
	...

0040935a <.idata$6>:
  40935a:	df 02                	filds  (%edx)
  40935c:	49                   	dec    %ecx
  40935d:	6e                   	outsb  %ds:(%esi),(%dx)
  40935e:	69 74 69 61 6c 69 7a 	imul   $0x657a696c,0x61(%ecx,%ebp,2),%esi
  409365:	65 
  409366:	43                   	inc    %ebx
  409367:	72 69                	jb     4093d2 <.idata$6+0x8>
  409369:	74 69                	je     4093d4 <.idata$6+0xa>
  40936b:	63 61 6c             	arpl   %sp,0x6c(%ecx)
  40936e:	53                   	push   %ebx
  40936f:	65 63 74 69 6f       	arpl   %si,%gs:0x6f(%ecx,%ebp,2)
  409374:	6e                   	outsb  %ds:(%esi),(%dx)
	...

00409376 <.idata$6>:
  409376:	2f                   	das    
  409377:	03 4c 65 61          	add    0x61(%ebp,%eiz,2),%ecx
  40937b:	76 65                	jbe    4093e2 <.idata$6+0x6>
  40937d:	43                   	inc    %ebx
  40937e:	72 69                	jb     4093e9 <.idata$6+0xd>
  409380:	74 69                	je     4093eb <.idata$6+0xf>
  409382:	63 61 6c             	arpl   %sp,0x6c(%ecx)
  409385:	53                   	push   %ebx
  409386:	65 63 74 69 6f       	arpl   %si,%gs:0x6f(%ecx,%ebp,2)
  40938b:	6e                   	outsb  %ds:(%esi),(%dx)
	...

0040938e <.idata$6>:
  40938e:	32 03                	xor    (%ebx),%al
  409390:	4c                   	dec    %esp
  409391:	6f                   	outsl  %ds:(%esi),(%dx)
  409392:	61                   	popa   
  409393:	64 4c                	fs dec %esp
  409395:	69 62 72 61 72 79 41 	imul   $0x41797261,0x72(%edx),%esp
	...

0040939e <.idata$6>:
  40939e:	6c                   	insb   (%dx),%es:(%edi)
  40939f:	04 53                	add    $0x53,%al
  4093a1:	65 74 55             	gs je  4093f9 <.idata$6+0x3>
  4093a4:	6e                   	outsb  %ds:(%esi),(%dx)
  4093a5:	68 61 6e 64 6c       	push   $0x6c646e61
  4093aa:	65 64 45             	gs fs inc %ebp
  4093ad:	78 63                	js     409412 <.idata$6>
  4093af:	65 70 74             	gs jo  409426 <.idata$6+0x4>
  4093b2:	69 6f 6e 46 69 6c 74 	imul   $0x746c6946,0x6e(%edi),%ebp
  4093b9:	65 72 00             	gs jb  4093bc <.idata$6>

004093bc <.idata$6>:
  4093bc:	8d 04 54             	lea    (%esp,%edx,2),%eax
  4093bf:	6c                   	insb   (%dx),%es:(%edi)
  4093c0:	73 47                	jae    409409 <.idata$6+0x7>
  4093c2:	65 74 56             	gs je  40941b <.idata$6+0x9>
  4093c5:	61                   	popa   
  4093c6:	6c                   	insb   (%dx),%es:(%edi)
  4093c7:	75 65                	jne    40942e <.idata$6+0xc>
	...

004093ca <.idata$6>:
  4093ca:	b5 04                	mov    $0x4,%ch
  4093cc:	56                   	push   %esi
  4093cd:	69 72 74 75 61 6c 50 	imul   $0x506c6175,0x74(%edx),%esi
  4093d4:	72 6f                	jb     409445 <.idata$6+0x5>
  4093d6:	74 65                	je     40943d <.idata$6+0xb>
  4093d8:	63 74 00 00          	arpl   %si,0x0(%eax,%eax,1)

004093dc <.idata$6>:
  4093dc:	b7 04                	mov    $0x4,%bh
  4093de:	56                   	push   %esi
  4093df:	69 72 74 75 61 6c 51 	imul   $0x516c6175,0x74(%edx),%esi
  4093e6:	75 65                	jne    40944d <.idata$6+0xd>
  4093e8:	72 79                	jb     409463 <.idata$6+0x3>
	...

004093ec <.idata$6>:
  4093ec:	51                   	push   %ecx
  4093ed:	00 5f 73             	add    %bl,0x73(%edi)
  4093f0:	74 72                	je     409464 <.idata$6+0x4>
  4093f2:	64 75 70             	fs jne 409465 <.idata$6+0x5>
	...

004093f6 <.idata$6>:
  4093f6:	53                   	push   %ebx
  4093f7:	00 5f 73             	add    %bl,0x73(%edi)
  4093fa:	74 72                	je     40946e <.idata$6+0x4>
  4093fc:	69 63 6f 6c 6c 00  	imul   $0x59006c6c,0x6f(%ebx),%esp

00409402 <.idata$6>:
  409402:	59                   	pop    %ecx
  409403:	00 5f 5f             	add    %bl,0x5f(%edi)
  409406:	67 65 74 6d          	addr16 gs je 409477 <.idata$6+0x3>
  40940a:	61                   	popa   
  40940b:	69 6e 61 72 67 73 00 	imul   $0x736772,0x61(%esi),%ebp

00409412 <.idata$6>:
  409412:	78 00                	js     409414 <.idata$6+0x2>
  409414:	5f                   	pop    %edi
  409415:	5f                   	pop    %edi
  409416:	6d                   	insl   (%dx),%es:(%edi)
  409417:	62 5f 63             	bound  %ebx,0x63(%edi)
  40941a:	75 72                	jne    40948e <.idata$6+0x2>
  40941c:	5f                   	pop    %edi
  40941d:	6d                   	insl   (%dx),%es:(%edi)
  40941e:	61                   	popa   
  40941f:	78 00                	js     409421 <.idata$6+0xf>
	...

00409422 <.idata$6>:
  409422:	84 00                	test   %al,(%eax)
  409424:	5f                   	pop    %edi
  409425:	5f                   	pop    %edi
  409426:	70 5f                	jo     409487 <.idata$6+0x7>
  409428:	5f                   	pop    %edi
  409429:	65 6e                	outsb  %gs:(%esi),(%dx)
  40942b:	76 69                	jbe    409496 <.idata$6+0x2>
  40942d:	72 6f                	jb     40949e <.idata$6+0xa>
  40942f:	6e                   	outsb  %ds:(%esi),(%dx)
	...

00409432 <.idata$6>:
  409432:	86 00                	xchg   %al,(%eax)
  409434:	5f                   	pop    %edi
  409435:	5f                   	pop    %edi
  409436:	70 5f                	jo     409497 <.idata$6+0x3>
  409438:	5f                   	pop    %edi
  409439:	66 6d                	insw   (%dx),%es:(%edi)
  40943b:	6f                   	outsl  %ds:(%esi),(%dx)
  40943c:	64 65 00 00          	fs add %al,%gs:(%eax)

00409440 <.idata$6>:
  409440:	8c 00                	mov    %es,(%eax)
  409442:	5f                   	pop    %edi
  409443:	5f                   	pop    %edi
  409444:	70 5f                	jo     4094a5 <.idata$6+0x5>
  409446:	5f                   	pop    %edi
  409447:	70 67                	jo     4094b0 <.idata$6+0x6>
  409449:	6d                   	insl   (%dx),%es:(%edi)
  40944a:	70 74                	jo     4094c0 <.idata$6+0x2>
  40944c:	72 00                	jb     40944e <.idata$6>

0040944e <.idata$6>:
  40944e:	9a 00 5f 5f 73 65 74 	lcall  $0x7465,$0x735f5f00
  409455:	5f                   	pop    %edi
  409456:	61                   	popa   
  409457:	70 70                	jo     4094c9 <.idata$6+0xb>
  409459:	5f                   	pop    %edi
  40945a:	74 79                	je     4094d5 <.idata$6+0x3>
  40945c:	70 65                	jo     4094c3 <.idata$6+0x5>
	...

00409460 <.idata$6>:
  409460:	d7                   	xlat   %ds:(%ebx)
  409461:	00 5f 63             	add    %bl,0x63(%edi)
  409464:	65 78 69             	gs js  4094d0 <.idata$6+0x6>
  409467:	74 00                	je     409469 <.idata$6+0x9>
	...

0040946a <.idata$6>:
  40946a:	18 01                	sbb    %al,(%ecx)
  40946c:	5f                   	pop    %edi
  40946d:	65 72 72             	gs jb  4094e2 <.idata$6+0x6>
  409470:	6e                   	outsb  %ds:(%esi),(%dx)
  409471:	6f                   	outsl  %ds:(%esi),(%dx)
	...

00409474 <.idata$6>:
  409474:	3f                   	aas    
  409475:	01 5f 66             	add    %ebx,0x66(%edi)
  409478:	70 72                	jo     4094ec <.idata$6+0x6>
  40947a:	65 73 65             	gs jae 4094e2 <.idata$6+0x6>
  40947d:	74 00                	je     40947f <.idata$6+0xb>
	...

00409480 <.idata$6>:
  409480:	59                   	pop    %ecx
  409481:	01 5f 66             	add    %ebx,0x66(%edi)
  409484:	75 6c                	jne    4094f2 <.idata$6+0x2>
  409486:	6c                   	insb   (%dx),%es:(%edi)
  409487:	70 61                	jo     4094ea <.idata$6+0x4>
  409489:	74 68                	je     4094f3 <.idata$6+0x3>
	...

0040948c <.idata$6>:
  40948c:	9c                   	pushf  
  40948d:	01 5f 69             	add    %ebx,0x69(%edi)
  409490:	6f                   	outsl  %ds:(%esi),(%dx)
  409491:	62 00                	bound  %eax,(%eax)
	...

00409494 <.idata$6>:
  409494:	a1 01 5f 69 73       	mov    0x73695f01,%eax
  409499:	63 74 79 70          	arpl   %si,0x70(%ecx,%edi,2)
  40949d:	65 00 00             	add    %al,%gs:(%eax)

004094a0 <.idata$6>:
  4094a0:	a9 02 5f 6d 73       	test   $0x736d5f02,%eax
  4094a5:	69 7a 65 00 00   	imul   $0x2ac0000,0x65(%edx),%edi

004094aa <.idata$6>:
  4094aa:	ac                   	lods   %ds:(%esi),%al
  4094ab:	02 5f 6f             	add    0x6f(%edi),%bl
  4094ae:	6e                   	outsb  %ds:(%esi),(%dx)
  4094af:	65 78 69             	gs js  40951b <.idata$6+0x1>
  4094b2:	74 00                	je     4094b4 <.idata$6>

004094b4 <.idata$6>:
  4094b4:	b5 02                	mov    $0x2,%ch
  4094b6:	5f                   	pop    %edi
  4094b7:	70 63                	jo     40951c <.idata$6+0x2>
  4094b9:	74 79                	je     409534 <.idata$6+0x4>
  4094bb:	70 65                	jo     409522 <.idata$6+0x8>
	...

004094be <.idata$6>:
  4094be:	ec                   	in     (%dx),%al
  4094bf:	02 5f 73             	add    0x73(%edi),%bl
  4094c2:	65 74 6d             	gs je  409532 <.idata$6+0x2>
  4094c5:	6f                   	outsl  %ds:(%esi),(%dx)
  4094c6:	64 65 00 00          	fs add %al,%gs:(%eax)

004094ca <.idata$6>:
  4094ca:	36 04 61             	ss add $0x61,%al
  4094cd:	62 6f 72             	bound  %ebp,0x72(%edi)
  4094d0:	74 00                	je     4094d2 <.idata$6>

004094d2 <.idata$6>:
  4094d2:	3e 04 61             	ds add $0x61,%al
  4094d5:	74 65                	je     40953c <.idata$6+0x2>
  4094d7:	78 69                	js     409542 <.idata$6+0x8>
  4094d9:	74 00                	je     4094db <.idata$6+0x9>
	...

004094dc <.idata$6>:
  4094dc:	45                   	inc    %ebp
  4094dd:	04 63                	add    $0x63,%al
  4094df:	61                   	popa   
  4094e0:	6c                   	insb   (%dx),%es:(%edi)
  4094e1:	6c                   	insb   (%dx),%es:(%edi)
  4094e2:	6f                   	outsl  %ds:(%esi),(%dx)
  4094e3:	63 00                	arpl   %ax,(%eax)
	...

004094e6 <.idata$6>:
  4094e6:	71 04                	jno    4094ec <.idata$6+0x6>
  4094e8:	66 77 72             	data16 ja 40955d <.idata$6+0x3>
  4094eb:	69 74 65 00 00   	imul   $0x6d049e00,0x0(%ebp,%eiz,2),%esi
  4094f2:	 

004094f0 <.idata$6>:
  4094f0:	9e                   	sahf   
  4094f1:	04 6d                	add    $0x6d,%al
  4094f3:	61                   	popa   
  4094f4:	6c                   	insb   (%dx),%es:(%edi)
  4094f5:	6c                   	insb   (%dx),%es:(%edi)
  4094f6:	6f                   	outsl  %ds:(%esi),(%dx)
  4094f7:	63 00                	arpl   %ax,(%eax)
	...

004094fa <.idata$6>:
  4094fa:	a5                   	movsl  %ds:(%esi),%es:(%edi)
  4094fb:	04 6d                	add    $0x6d,%al
  4094fd:	62 73 74             	bound  %esi,0x74(%ebx)
  409500:	6f                   	outsl  %ds:(%esi),(%dx)
  409501:	77 63                	ja     409566 <.idata$6>
  409503:	73 00                	jae    409505 <.idata$6+0xb>
	...

00409506 <.idata$6>:
  409506:	aa                   	stos   %al,%es:(%edi)
  409507:	04 6d                	add    $0x6d,%al
  409509:	65 6d                	gs insl (%dx),%es:(%edi)
  40950b:	63 70 79             	arpl   %si,0x79(%eax)
	...

00409510 <.idata$6>:
  409510:	ac                   	lods   %ds:(%esi),%al
  409511:	04 6d                	add    $0x6d,%al
  409513:	65 6d                	gs insl (%dx),%es:(%edi)
  409515:	6d                   	insl   (%dx),%es:(%edi)
  409516:	6f                   	outsl  %ds:(%esi),(%dx)
  409517:	76 65                	jbe    40957e <.idata$6+0x6>
	...

0040951a <.idata$6>:
  40951a:	c6 04 73 65          	movb   $0x65,(%ebx,%esi,2)
  40951e:	74 6c                	je     40958c <.idata$6+0x4>
  409520:	6f                   	outsl  %ds:(%esi),(%dx)
  409521:	63 61 6c             	arpl   %sp,0x6c(%ecx)
  409524:	65 00              	gs add %cl,%al

00409526 <.idata$6>:
  409526:	c8 04 73 69          	enter  $0x7304,$0x69
  40952a:	67 6e                	outsb  %ds:(%si),(%dx)
  40952c:	61                   	popa   
  40952d:	6c                   	insb   (%dx),%es:(%edi)
	...

00409530 <.idata$6>:
  409530:	d5 04                	aad    $0x4
  409532:	73 74                	jae    4095a8 <.idata$6+0x4>
  409534:	72 63                	jb     409599 <.idata$6+0x11>
  409536:	6f                   	outsl  %ds:(%esi),(%dx)
  409537:	6c                   	insb   (%dx),%es:(%edi)
  409538:	6c                   	insb   (%dx),%es:(%edi)
	...

0040953a <.idata$6>:
  40953a:	dc 04 73             	faddl  (%ebx,%esi,2)
  40953d:	74 72                	je     4095b1 <.idata$6+0xd>
  40953f:	6c                   	insb   (%dx),%es:(%edi)
  409540:	65 6e                	outsb  %gs:(%esi),(%dx)
	...

00409544 <.idata$6>:
  409544:	f8                   	clc    
  409545:	04 74                	add    $0x74,%al
  409547:	6f                   	outsl  %ds:(%esi),(%dx)
  409548:	6c                   	insb   (%dx),%es:(%edi)
  409549:	6f                   	outsl  %ds:(%esi),(%dx)
  40954a:	77 65                	ja     4095b1 <.idata$6+0xd>
  40954c:	72 00                	jb     40954e <.idata$6>

0040954e <.idata$6>:
  40954e:	ff 04 76             	incl   (%esi,%esi,2)
  409551:	66 70 72             	data16 jo 4095c6 <.idata$6+0x22>
  409554:	69 6e 74 66 00 00  	imul   $0x28000066,0x74(%esi),%ebp

0040955a <.idata$6>:
  40955a:	28 05 77 63 73 74    	sub    %al,0x74736377
  409560:	6f                   	outsl  %ds:(%esi),(%dx)
  409561:	6d                   	insl   (%dx),%es:(%edi)
  409562:	62 73 00             	bound  %esi,0x0(%ebx)
	...

00409566 <.idata$6>:
  409566:	66 04 66             	data16 add $0x66,%al
  409569:	72 65                	jb     4095d0 <.idata$6+0x2c>
  40956b:	65 00 00             	add    %al,%gs:(%eax)

0040956e <.idata$6>:
  40956e:	bf 04 72 65 61       	mov    $0x61657204,%edi
  409573:	6c                   	insb   (%dx),%es:(%edi)
  409574:	6c                   	insb   (%dx),%es:(%edi)
  409575:	6f                   	outsl  %ds:(%esi),(%dx)
  409576:	63 00                	arpl   %ax,(%eax)

00409578 <.idata$6>:
  409578:	b8 01 4d 65 73       	mov    $0x73654d01,%eax
  40957d:	73 61                	jae    4095e0 <.idata$6+0x3c>
  40957f:	67 65 42             	addr16 gs inc %edx
  409582:	6f                   	outsl  %ds:(%esi),(%dx)
  409583:	78 57                	js     4095dc <.idata$6+0x38>
  409585:	00 00                	add    %al,(%eax)
	...

00409588 <.idata$6>:
  409588:	25 00 5f 5f 64       	and    $0x645f5f00,%eax
  40958d:	65 72 65             	gs jb  4095f5 <.idata$6+0x51>
  409590:	67 69 73 74 65 72 5f 	imul   $0x665f7265,0x74(%bp,%di),%esi
  409597:	66 
  409598:	72 61                	jb     4095fb <.idata$6+0x57>
  40959a:	6d                   	insl   (%dx),%es:(%edi)
  40959b:	65 5f                	gs pop %edi
  40959d:	69 6e 66 6f 00 00 00 	imul   $0x6f,0x66(%esi),%ebp

004095a4 <.idata$6>:
  4095a4:	6b 00 5f             	imul   $0x5f,(%eax),%eax
  4095a7:	5f                   	pop    %edi
  4095a8:	72 65                	jb     40960f <__libkernel32_a_iname+0x3>
  4095aa:	67 69 73 74 65 72 5f 	imul   $0x665f7265,0x74(%bp,%di),%esi
  4095b1:	66 
  4095b2:	72 61                	jb     409615 <__libkernel32_a_iname+0x9>
  4095b4:	6d                   	insl   (%dx),%es:(%edi)
  4095b5:	65 5f                	gs pop %edi
  4095b7:	69 6e 66 6f 00 00 90 	imul   $0x9000006f,0x66(%esi),%ebp
  4095be:	00 00                	add    %al,(%eax)
  4095c0:	00 90 00 00 00 90    	add    %dl,-0x70000000(%eax)
  4095c6:	00 00                	add    %al,(%eax)
  4095c8:	00 90 00 00 00 90    	add    %dl,-0x70000000(%eax)
  4095ce:	00 00                	add    %al,(%eax)
  4095d0:	00 90 00 00 00 90    	add    %dl,-0x70000000(%eax)
  4095d6:	00 00                	add    %al,(%eax)
  4095d8:	00 90 00 00 00 90    	add    %dl,-0x70000000(%eax)
  4095de:	00 00                	add    %al,(%eax)
  4095e0:	00 90 00 00 00 90    	add    %dl,-0x70000000(%eax)
  4095e6:	00 00                	add    %al,(%eax)
  4095e8:	00 90 00 00 00 90    	add    %dl,-0x70000000(%eax)
  4095ee:	00 00                	add    %al,(%eax)
  4095f0:	00 90 00 00 00 90    	add    %dl,-0x70000000(%eax)
  4095f6:	00 00                	add    %al,(%eax)
  4095f8:	00 90 00 00 00 90    	add    %dl,-0x70000000(%eax)
  4095fe:	00 00                	add    %al,(%eax)
  409600:	00 90 00 00 00 90    	add    %dl,-0x70000000(%eax)
  409606:	00 00                	add    %al,(%eax)
  409608:	00 90 00 00      	add    %dl,0x454b0000(%eax)

0040960c <__libkernel32_a_iname>:
  40960c:	4b                   	dec    %ebx
  40960d:	45                   	inc    %ebp
  40960e:	52                   	push   %edx
  40960f:	4e                   	dec    %esi
  409610:	45                   	inc    %ebp
  409611:	4c                   	dec    %esp
  409612:	33 32                	xor    (%edx),%esi
  409614:	2e 64 6c             	cs fs insb (%dx),%es:(%edi)
  409617:	6c                   	insb   (%dx),%es:(%edi)
  409618:	00 00                	add    %al,(%eax)
  40961a:	00 00                	add    %al,(%eax)
  40961c:	14 90                	adc    $0x90,%al
  40961e:	00 00                	add    %al,(%eax)
  409620:	14 90                	adc    $0x90,%al
	...

00409624 <__libmoldname_a_iname>:
  409624:	6d                   	insl   (%dx),%es:(%edi)
  409625:	73 76                	jae    40969d <__libmoldname_a_iname+0x79>
  409627:	63 72 74             	arpl   %si,0x74(%edx)
  40962a:	2e 64 6c             	cs fs insb (%dx),%es:(%edi)
  40962d:	6c                   	insb   (%dx),%es:(%edi)
  40962e:	00 00                	add    %al,(%eax)
  409630:	28 90 00 00 28 90    	sub    %dl,-0x6fd80000(%eax)
  409636:	00 00                	add    %al,(%eax)
  409638:	28 90 00 00 28 90    	sub    %dl,-0x6fd80000(%eax)
  40963e:	00 00                	add    %al,(%eax)
  409640:	28 90 00 00 28 90    	sub    %dl,-0x6fd80000(%eax)
  409646:	00 00                	add    %al,(%eax)
  409648:	28 90 00 00 28 90    	sub    %dl,-0x6fd80000(%eax)
  40964e:	00 00                	add    %al,(%eax)
  409650:	28 90 00 00 28 90    	sub    %dl,-0x6fd80000(%eax)
  409656:	00 00                	add    %al,(%eax)
  409658:	28 90 00 00 28 90    	sub    %dl,-0x6fd80000(%eax)
  40965e:	00 00                	add    %al,(%eax)
  409660:	28 90 00 00 28 90    	sub    %dl,-0x6fd80000(%eax)
  409666:	00 00                	add    %al,(%eax)
  409668:	28 90 00 00 28 90    	sub    %dl,-0x6fd80000(%eax)
  40966e:	00 00                	add    %al,(%eax)
  409670:	28 90 00 00 28 90    	sub    %dl,-0x6fd80000(%eax)
  409676:	00 00                	add    %al,(%eax)
  409678:	28 90 00 00 28 90    	sub    %dl,-0x6fd80000(%eax)
  40967e:	00 00                	add    %al,(%eax)
  409680:	28 90 00 00 28 90    	sub    %dl,-0x6fd80000(%eax)
  409686:	00 00                	add    %al,(%eax)
  409688:	28 90 00 00 28 90    	sub    %dl,-0x6fd80000(%eax)
  40968e:	00 00                	add    %al,(%eax)
  409690:	28 90 00 00 28 90    	sub    %dl,-0x6fd80000(%eax)
  409696:	00 00                	add    %al,(%eax)
  409698:	28 90 00 00 28 90    	sub    %dl,-0x6fd80000(%eax)
  40969e:	00 00                	add    %al,(%eax)
  4096a0:	28 90 00 00 28 90    	sub    %dl,-0x6fd80000(%eax)
  4096a6:	00 00                	add    %al,(%eax)
  4096a8:	28 90 00 00 28 90    	sub    %dl,-0x6fd80000(%eax)
  4096ae:	00 00                	add    %al,(%eax)
  4096b0:	28 90 00 00      	sub    %dl,0x736d0000(%eax)

004096b4 <__libmsvcrt_a_iname>:
  4096b4:	6d                   	insl   (%dx),%es:(%edi)
  4096b5:	73 76                	jae    40972d <_libgcc_s_dw2_1_dll_iname+0x55>
  4096b7:	63 72 74             	arpl   %si,0x74(%edx)
  4096ba:	2e 64 6c             	cs fs insb (%dx),%es:(%edi)
  4096bd:	6c                   	insb   (%dx),%es:(%edi)
  4096be:	00 00                	add    %al,(%eax)
  4096c0:	3c 90                	cmp    $0x90,%al
	...

004096c4 <__libuser32_a_iname>:
  4096c4:	55                   	push   %ebp
  4096c5:	53                   	push   %ebx
  4096c6:	45                   	inc    %ebp
  4096c7:	52                   	push   %edx
  4096c8:	33 32                	xor    (%edx),%esi
  4096ca:	2e 64 6c             	cs fs insb (%dx),%es:(%edi)
  4096cd:	6c                   	insb   (%dx),%es:(%edi)
	...

004096d0 <.idata$7>:
  4096d0:	50                   	push   %eax
  4096d1:	90                   	nop
	...

004096d4 <.idata$7>:
  4096d4:	50                   	push   %eax
  4096d5:	90                   	nop
	...

004096d8 <_libgcc_s_dw2_1_dll_iname>:
  4096d8:	6c                   	insb   (%dx),%es:(%edi)
  4096d9:	69 62 67 63 63 5f 73 	imul   $0x735f6363,0x67(%edx),%esp
  4096e0:	5f                   	pop    %edi
  4096e1:	64 77 32             	fs ja  409716 <_libgcc_s_dw2_1_dll_iname+0x3e>
  4096e4:	2d 31 2e 64 6c       	sub    $0x6c642e31,%eax
  4096e9:	6c                   	insb   (%dx),%es:(%edi)
	...

Disassembly of section .CRT:

0040a000 <___crt_xc_end__>:
  40a000:	00 00                	add    %al,(%eax)
	...

0040a004 <___xl_c>:
  40a004:	d0 1a                	rcrb   (%edx)
  40a006:	40                   	inc    %eax
	...

0040a008 <___xl_d>:
  40a008:	80 1a 40             	sbbb   $0x40,(%edx)
	...

0040a00c <___xl_z>:
  40a00c:	00 00                	add    %al,(%eax)
	...

0040a010 <___crt_xp_end__>:
  40a010:	00 00                	add    %al,(%eax)
	...

0040a014 <.CRT$XDZ>:
  40a014:	00 00                	add    %al,(%eax)
	...

Disassembly of section .tls:

0040b000 <___tls_start__>:
  40b000:	00 00                	add    %al,(%eax)
	...

0040b004 <__tls_used>:
  40b004:	01 b0 40 00 1c b0    	add    %esi,-0x4fe3ffc0(%eax)
  40b00a:	40                   	inc    %eax
  40b00b:	00 38                	add    %bh,(%eax)
  40b00d:	80 40 00 04          	addb   $0x4,0x0(%eax)
  40b011:	a0 40 00 00 00       	mov    0x40,%al
  40b016:	00 00                	add    %al,(%eax)
  40b018:	00 00                	add    %al,(%eax)
	...

0040b01c <__tls_end>:
  40b01c:	00 00                	add    %al,(%eax)
	...

Disassembly of section .debug_aranges:

0040c000 <.debug_aranges>:
  40c000:	1c 00                	sbb    $0x0,%al
  40c002:	00 00                	add    %al,(%eax)
  40c004:	02 00                	add    (%eax),%al
  40c006:	00 00                	add    %al,(%eax)
  40c008:	00 00                	add    %al,(%eax)
  40c00a:	04 00                	add    $0x0,%al
  40c00c:	00 00                	add    %al,(%eax)
  40c00e:	00 00                	add    %al,(%eax)
  40c010:	50                   	push   %eax
  40c011:	3e 40                	ds inc %eax
  40c013:	00 2a                	add    %ch,(%edx)
	...

0040c020 <.debug_aranges>:
  40c020:	14 00                	adc    $0x0,%al
  40c022:	00 00                	add    %al,(%eax)
  40c024:	02 00                	add    (%eax),%al
  40c026:	26 00 00             	add    %al,%es:(%eax)
  40c029:	00 04 00             	add    %al,(%eax,%eax,1)
	...

Disassembly of section .debug_info:

0040d000 <.debug_info>:
  40d000:	22 00                	and    (%eax),%al
  40d002:	00 00                	add    %al,(%eax)
  40d004:	02 00                	add    (%eax),%al
  40d006:	00 00                	add    %al,(%eax)
  40d008:	00 00                	add    %al,(%eax)
  40d00a:	04 01                	add    $0x1,%al
  40d00c:	00 00                	add    %al,(%eax)
  40d00e:	00 00                	add    %al,(%eax)
  40d010:	50                   	push   %eax
  40d011:	3e 40                	ds inc %eax
  40d013:	00 7a 3e             	add    %bh,0x3e(%edx)
  40d016:	40                   	inc    %eax
  40d017:	00 00                	add    %al,(%eax)
  40d019:	00 00                	add    %al,(%eax)
  40d01b:	00 33                	add    %dh,(%ebx)
  40d01d:	00 00                	add    %al,(%eax)
  40d01f:	00 7a 00             	add    %bh,0x0(%edx)
  40d022:	00 00                	add    %al,(%eax)
  40d024:	01 80        	add    %eax,0x1ea2(%eax)

0040d026 <.debug_info>:
  40d026:	a2 1e 00 00 04       	mov    %al,0x400001e
  40d02b:	00 14 00             	add    %dl,(%eax,%eax,1)
  40d02e:	00 00                	add    %al,(%eax)
  40d030:	04 01                	add    $0x1,%al
  40d032:	47                   	inc    %edi
  40d033:	4e                   	dec    %esi
  40d034:	55                   	push   %ebp
  40d035:	20 43 31             	and    %al,0x31(%ebx)
  40d038:	37                   	aaa    
  40d039:	20 39                	and    %bh,(%ecx)
  40d03b:	2e 32 2e             	xor    %cs:(%esi),%ch
  40d03e:	30 20                	xor    %ah,(%eax)
  40d040:	2d 6d 74 75 6e       	sub    $0x6e75746d,%eax
  40d045:	65 3d 67 65 6e 65    	gs cmp $0x656e6567,%eax
  40d04b:	72 69                	jb     40d0b6 <.debug_info+0x90>
  40d04d:	63 20                	arpl   %sp,(%eax)
  40d04f:	2d 6d 61 72 63       	sub    $0x6372616d,%eax
  40d054:	68 3d 69 35 38       	push   $0x3835693d
  40d059:	36 20 2d 67 20 2d 67 	and    %ch,%ss:0x672d2067
  40d060:	20 2d 67 20 2d 4f    	and    %ch,0x4f2d2067
  40d066:	32 20                	xor    (%eax),%ah
  40d068:	2d 4f 32 20 2d       	sub    $0x2d20324f,%eax
  40d06d:	4f                   	dec    %edi
  40d06e:	32 20                	xor    (%eax),%ah
  40d070:	2d 66 62 75 69       	sub    $0x69756266,%eax
  40d075:	6c                   	insb   (%dx),%es:(%edi)
  40d076:	64 69 6e 67 2d 6c 69 	imul   $0x62696c2d,%fs:0x67(%esi),%ebp
  40d07d:	62 
  40d07e:	67 63 63 20          	arpl   %sp,0x20(%bp,%di)
  40d082:	2d 66 6e 6f 2d       	sub    $0x2d6f6e66,%eax
  40d087:	73 74                	jae    40d0fd <.debug_info+0xd7>
  40d089:	61                   	popa   
  40d08a:	63 6b 2d             	arpl   %bp,0x2d(%ebx)
  40d08d:	70 72                	jo     40d101 <.debug_info+0xdb>
  40d08f:	6f                   	outsl  %ds:(%esi),(%dx)
  40d090:	74 65                	je     40d0f7 <.debug_info+0xd1>
  40d092:	63 74 6f 72          	arpl   %si,0x72(%edi,%ebp,2)
  40d096:	00 0c 2e             	add    %cl,(%esi,%ebp,1)
  40d099:	2e 2f                	cs das 
  40d09b:	2e 2e 2f             	cs cs das 
  40d09e:	2e 2e 2f             	cs cs das 
  40d0a1:	73 72                	jae    40d115 <.debug_info+0xef>
  40d0a3:	63 2f                	arpl   %bp,(%edi)
  40d0a5:	67 63 63 2d          	arpl   %sp,0x2d(%bp,%di)
  40d0a9:	39 2e                	cmp    %ebp,(%esi)
  40d0ab:	32 2e                	xor    (%esi),%ch
  40d0ad:	30 2f                	xor    %ch,(%edi)
  40d0af:	6c                   	insb   (%dx),%es:(%edi)
  40d0b0:	69 62 67 63 63 2f 6c 	imul   $0x6c2f6363,0x67(%edx),%esp
  40d0b7:	69 62 67 63 63 32 2e 	imul   $0x2e326363,0x67(%edx),%esp
  40d0be:	63 00                	arpl   %ax,(%eax)
  40d0c0:	2f                   	das    
  40d0c1:	68 6f 6d 65 2f       	push   $0x2f656d6f
  40d0c6:	6b 65 69 74          	imul   $0x74,0x69(%ebp),%esp
  40d0ca:	68 2f 62 75 69       	push   $0x6975622f
  40d0cf:	6c                   	insb   (%dx),%es:(%edi)
  40d0d0:	64 73 2f             	fs jae 40d102 <.debug_info+0xdc>
  40d0d3:	6d                   	insl   (%dx),%es:(%edi)
  40d0d4:	69 6e 67 77 2f 67 63 	imul   $0x63672f77,0x67(%esi),%ebp
  40d0db:	63 2d 39 2e 32 2e    	arpl   %bp,0x2e322e39
  40d0e1:	30 2d 6d 69 6e 67    	xor    %ch,0x676e696d
  40d0e7:	77 33                	ja     40d11c <.debug_info+0xf6>
  40d0e9:	32 2d 63 72 6f 73    	xor    0x736f7263,%ch
  40d0ef:	73 2d                	jae    40d11e <.debug_info+0xf8>
  40d0f1:	6e                   	outsb  %ds:(%esi),(%dx)
  40d0f2:	61                   	popa   
  40d0f3:	74 69                	je     40d15e <.debug_info+0x138>
  40d0f5:	76 65                	jbe    40d15c <.debug_info+0x136>
  40d0f7:	2f                   	das    
  40d0f8:	6d                   	insl   (%dx),%es:(%edi)
  40d0f9:	69 6e 67 77 33 32 2f 	imul   $0x2f323377,0x67(%esi),%ebp
  40d100:	6c                   	insb   (%dx),%es:(%edi)
  40d101:	69 62 67 63 63 00 71 	imul   $0x71006363,0x67(%edx),%esp
  40d108:	00 00                	add    %al,(%eax)
  40d10a:	00 02                	add    %al,(%edx)
  40d10c:	04 05                	add    $0x5,%al
  40d10e:	69 6e 74 00 03 e5 00 	imul   $0xe50300,0x74(%esi),%ebp
  40d115:	00 00                	add    %al,(%eax)
  40d117:	02 04 07             	add    (%edi,%eax,1),%al
  40d11a:	75 6e                	jne    40d18a <.debug_info+0x164>
  40d11c:	73 69                	jae    40d187 <.debug_info+0x161>
  40d11e:	67 6e                	outsb  %ds:(%si),(%dx)
  40d120:	65 64 20 69 6e       	gs and %ch,%fs:0x6e(%ecx)
  40d125:	74 00                	je     40d127 <.debug_info+0x101>
  40d127:	02 02                	add    (%edx),%al
  40d129:	07                   	pop    %es
  40d12a:	73 68                	jae    40d194 <.debug_info+0x16e>
  40d12c:	6f                   	outsl  %ds:(%esi),(%dx)
  40d12d:	72 74                	jb     40d1a3 <.debug_info+0x17d>
  40d12f:	20 75 6e             	and    %dh,0x6e(%ebp)
  40d132:	73 69                	jae    40d19d <.debug_info+0x177>
  40d134:	67 6e                	outsb  %ds:(%si),(%dx)
  40d136:	65 64 20 69 6e       	gs and %ch,%fs:0x6e(%ecx)
  40d13b:	74 00                	je     40d13d <.debug_info+0x117>
  40d13d:	02 08                	add    (%eax),%cl
  40d13f:	05 6c 6f 6e 67       	add    $0x676e6f6c,%eax
  40d144:	20 6c 6f 6e          	and    %ch,0x6e(%edi,%ebp,2)
  40d148:	67 20 69 6e          	and    %ch,0x6e(%bx,%di)
  40d14c:	74 00                	je     40d14e <.debug_info+0x128>
  40d14e:	02 0c 04             	add    (%esp,%eax,1),%cl
  40d151:	6c                   	insb   (%dx),%es:(%edi)
  40d152:	6f                   	outsl  %ds:(%esi),(%dx)
  40d153:	6e                   	outsb  %ds:(%esi),(%dx)
  40d154:	67 20 64 6f          	and    %ah,0x6f(%si)
  40d158:	75 62                	jne    40d1bc <.debug_info+0x196>
  40d15a:	6c                   	insb   (%dx),%es:(%edi)
  40d15b:	65 00 02             	add    %al,%gs:(%edx)
  40d15e:	10 04 5f             	adc    %al,(%edi,%ebx,2)
  40d161:	46                   	inc    %esi
  40d162:	6c                   	insb   (%dx),%es:(%edi)
  40d163:	6f                   	outsl  %ds:(%esi),(%dx)
  40d164:	61                   	popa   
  40d165:	74 31                	je     40d198 <.debug_info+0x172>
  40d167:	32 38                	xor    (%eax),%bh
  40d169:	00 02                	add    %al,(%edx)
  40d16b:	01 06                	add    %eax,(%esi)
  40d16d:	63 68 61             	arpl   %bp,0x61(%eax)
  40d170:	72 00                	jb     40d172 <.debug_info+0x14c>
  40d172:	03 44 01 00          	add    0x0(%ecx,%eax,1),%eax
  40d176:	00 02                	add    %al,(%edx)
  40d178:	04 05                	add    $0x5,%al
  40d17a:	6c                   	insb   (%dx),%es:(%edi)
  40d17b:	6f                   	outsl  %ds:(%esi),(%dx)
  40d17c:	6e                   	outsb  %ds:(%esi),(%dx)
  40d17d:	67 20 69 6e          	and    %ch,0x6e(%bx,%di)
  40d181:	74 00                	je     40d183 <.debug_info+0x15d>
  40d183:	04 5f                	add    $0x5f,%al
  40d185:	69 6f 62 75 66 00 20 	imul   $0x20006675,0x62(%edi),%ebp
  40d18c:	01 d2                	add    %edx,%edx
  40d18e:	10 ed                	adc    %ch,%ch
  40d190:	01 00                	add    %eax,(%eax)
  40d192:	00 05 5f 70 74 72    	add    %al,0x7274705f
  40d198:	00 01                	add    %al,(%ecx)
  40d19a:	d4 09                	aam    $0x9
  40d19c:	ed                   	in     (%dx),%eax
  40d19d:	01 00                	add    %eax,(%eax)
  40d19f:	00 00                	add    %al,(%eax)
  40d1a1:	05 5f 63 6e 74       	add    $0x746e635f,%eax
  40d1a6:	00 01                	add    %al,(%ecx)
  40d1a8:	d5 08                	aad    $0x8
  40d1aa:	e5 00                	in     $0x0,%eax
  40d1ac:	00 00                	add    %al,(%eax)
  40d1ae:	04 05                	add    $0x5,%al
  40d1b0:	5f                   	pop    %edi
  40d1b1:	62 61 73             	bound  %esp,0x73(%ecx)
  40d1b4:	65 00 01             	add    %al,%gs:(%ecx)
  40d1b7:	d6                   	(bad)  
  40d1b8:	09 ed                	or     %ebp,%ebp
  40d1ba:	01 00                	add    %eax,(%eax)
  40d1bc:	00 08                	add    %cl,(%eax)
  40d1be:	05 5f 66 6c 61       	add    $0x616c665f,%eax
  40d1c3:	67 00 01             	add    %al,(%bx,%di)
  40d1c6:	d7                   	xlat   %ds:(%ebx)
  40d1c7:	08 e5                	or     %ah,%ch
  40d1c9:	00 00                	add    %al,(%eax)
  40d1cb:	00 0c 05 5f 66 69 6c 	add    %cl,0x6c69665f(,%eax,1)
  40d1d2:	65 00 01             	add    %al,%gs:(%ecx)
  40d1d5:	d8 08                	fmuls  (%eax)
  40d1d7:	e5 00                	in     $0x0,%eax
  40d1d9:	00 00                	add    %al,(%eax)
  40d1db:	10 05 5f 63 68 61    	adc    %al,0x6168635f
  40d1e1:	72 62                	jb     40d245 <.debug_info+0x21f>
  40d1e3:	75 66                	jne    40d24b <.debug_info+0x225>
  40d1e5:	00 01                	add    %al,(%ecx)
  40d1e7:	d9 08                	(bad)  (%eax)
  40d1e9:	e5 00                	in     $0x0,%eax
  40d1eb:	00 00                	add    %al,(%eax)
  40d1ed:	14 05                	adc    $0x5,%al
  40d1ef:	5f                   	pop    %edi
  40d1f0:	62 75 66             	bound  %esi,0x66(%ebp)
  40d1f3:	73 69                	jae    40d25e <.debug_info+0x238>
  40d1f5:	7a 00                	jp     40d1f7 <.debug_info+0x1d1>
  40d1f7:	01 da                	add    %ebx,%edx
  40d1f9:	08 e5                	or     %ah,%ch
  40d1fb:	00 00                	add    %al,(%eax)
  40d1fd:	00 18                	add    %bl,(%eax)
  40d1ff:	05 5f 74 6d 70       	add    $0x706d745f,%eax
  40d204:	66 6e                	data16 outsb %ds:(%esi),(%dx)
  40d206:	61                   	popa   
  40d207:	6d                   	insl   (%dx),%es:(%edi)
  40d208:	65 00 01             	add    %al,%gs:(%ecx)
  40d20b:	db 09                	fisttpl (%ecx)
  40d20d:	ed                   	in     (%dx),%eax
  40d20e:	01 00                	add    %eax,(%eax)
  40d210:	00 1c 00             	add    %bl,(%eax,%eax,1)
  40d213:	06                   	push   %es
  40d214:	04 44                	add    $0x44,%al
  40d216:	01 00                	add    %eax,(%eax)
  40d218:	00 07                	add    %al,(%edi)
  40d21a:	46                   	inc    %esi
  40d21b:	49                   	dec    %ecx
  40d21c:	4c                   	dec    %esp
  40d21d:	45                   	inc    %ebp
  40d21e:	00 01                	add    %al,(%ecx)
  40d220:	dc 03                	faddl  (%ebx)
  40d222:	5d                   	pop    %ebp
  40d223:	01 00                	add    %eax,(%eax)
  40d225:	00 08                	add    %cl,(%eax)
  40d227:	f3 01 00             	repz add %eax,(%eax)
  40d22a:	00 0b                	add    %cl,(%ebx)
  40d22c:	02 00                	add    (%eax),%al
  40d22e:	00 09                	add    %cl,(%ecx)
  40d230:	00 0a                	add    %cl,(%edx)
  40d232:	5f                   	pop    %edi
  40d233:	69 6f 62 00 01 ef 15 	imul   $0x15ef0100,0x62(%edi),%ebp
  40d23a:	00 02                	add    %al,(%edx)
  40d23c:	00 00                	add    %al,(%eax)
  40d23e:	02 02                	add    (%edx),%al
  40d240:	05 73 68 6f 72       	add    $0x726f6873,%eax
  40d245:	74 20                	je     40d267 <.debug_info+0x241>
  40d247:	69 6e 74 00 02 04 07 	imul   $0x7040200,0x74(%esi),%ebp
  40d24e:	6c                   	insb   (%dx),%es:(%edi)
  40d24f:	6f                   	outsl  %ds:(%esi),(%dx)
  40d250:	6e                   	outsb  %ds:(%esi),(%dx)
  40d251:	67 20 75 6e          	and    %dh,0x6e(%di)
  40d255:	73 69                	jae    40d2c0 <.debug_info+0x29a>
  40d257:	67 6e                	outsb  %ds:(%si),(%dx)
  40d259:	65 64 20 69 6e       	gs and %ch,%fs:0x6e(%ecx)
  40d25e:	74 00                	je     40d260 <.debug_info+0x23a>
  40d260:	0a 5f 61             	or     0x61(%edi),%bl
  40d263:	72 67                	jb     40d2cc <.debug_info+0x2a6>
  40d265:	63 00                	arpl   %ax,(%eax)
  40d267:	02 63 10             	add    0x10(%ebx),%ah
  40d26a:	e5 00                	in     $0x0,%eax
  40d26c:	00 00                	add    %al,(%eax)
  40d26e:	0a 5f 61             	or     0x61(%edi),%bl
  40d271:	72 67                	jb     40d2da <.debug_info+0x2b4>
  40d273:	76 00                	jbe    40d275 <.debug_info+0x24f>
  40d275:	02 64 10 56          	add    0x56(%eax,%edx,1),%ah
  40d279:	02 00                	add    (%eax),%al
  40d27b:	00 06                	add    %al,(%esi)
  40d27d:	04 ed                	add    $0xed,%al
  40d27f:	01 00                	add    %eax,(%eax)
  40d281:	00 0a                	add    %cl,(%edx)
  40d283:	5f                   	pop    %edi
  40d284:	5f                   	pop    %edi
  40d285:	6d                   	insl   (%dx),%es:(%edi)
  40d286:	62 5f 63             	bound  %ebx,0x63(%edi)
  40d289:	75 72                	jne    40d2fd <.debug_info+0x2d7>
  40d28b:	5f                   	pop    %edi
  40d28c:	6d                   	insl   (%dx),%es:(%edi)
  40d28d:	61                   	popa   
  40d28e:	78 00                	js     40d290 <.debug_info+0x26a>
  40d290:	02 8e 17 e5 00 00    	add    0xe517(%esi),%cl
  40d296:	00 0a                	add    %cl,(%edx)
  40d298:	5f                   	pop    %edi
  40d299:	73 79                	jae    40d314 <.debug_info+0x2ee>
  40d29b:	73 5f                	jae    40d2fc <.debug_info+0x2d6>
  40d29d:	6e                   	outsb  %ds:(%esi),(%dx)
  40d29e:	65 72 72             	gs jb  40d313 <.debug_info+0x2ed>
  40d2a1:	00 02                	add    %al,(%edx)
  40d2a3:	e5 14                	in     $0x14,%eax
  40d2a5:	e5 00                	in     $0x0,%eax
  40d2a7:	00 00                	add    %al,(%eax)
  40d2a9:	08 ed                	or     %ch,%ch
  40d2ab:	01 00                	add    %eax,(%eax)
  40d2ad:	00 8e 02 00 00 09    	add    %cl,0x9000002(%esi)
  40d2b3:	00 0a                	add    %cl,(%edx)
  40d2b5:	5f                   	pop    %edi
  40d2b6:	73 79                	jae    40d331 <.debug_info+0x30b>
  40d2b8:	73 5f                	jae    40d319 <.debug_info+0x2f3>
  40d2ba:	65 72 72             	gs jb  40d32f <.debug_info+0x309>
  40d2bd:	6c                   	insb   (%dx),%es:(%edi)
  40d2be:	69 73 74 00 02 fe 16 	imul   $0x16fe0200,0x74(%ebx),%esi
  40d2c5:	83 02 00             	addl   $0x0,(%edx)
  40d2c8:	00 0b                	add    %cl,(%ebx)
  40d2ca:	5f                   	pop    %edi
  40d2cb:	6f                   	outsl  %ds:(%esi),(%dx)
  40d2cc:	73 76                	jae    40d344 <.debug_info+0x31e>
  40d2ce:	65 72 00             	gs jb  40d2d1 <.debug_info+0x2ab>
  40d2d1:	02 15 01 1e f1 00    	add    0xf11e01,%dl
  40d2d7:	00 00                	add    %al,(%eax)
  40d2d9:	0b 5f 77             	or     0x77(%edi),%ebx
  40d2dc:	69 6e 76 65 72 00 02 	imul   $0x2007265,0x76(%esi),%ebp
  40d2e3:	16                   	push   %ss
  40d2e4:	01 1e                	add    %ebx,(%esi)
  40d2e6:	f1                   	icebp  
  40d2e7:	00 00                	add    %al,(%eax)
  40d2e9:	00 0b                	add    %cl,(%ebx)
  40d2eb:	5f                   	pop    %edi
  40d2ec:	77 69                	ja     40d357 <.debug_info+0x331>
  40d2ee:	6e                   	outsb  %ds:(%esi),(%dx)
  40d2ef:	6d                   	insl   (%dx),%es:(%edi)
  40d2f0:	61                   	popa   
  40d2f1:	6a 6f                	push   $0x6f
  40d2f3:	72 00                	jb     40d2f5 <.debug_info+0x2cf>
  40d2f5:	02 17                	add    (%edi),%dl
  40d2f7:	01 1e                	add    %ebx,(%esi)
  40d2f9:	f1                   	icebp  
  40d2fa:	00 00                	add    %al,(%eax)
  40d2fc:	00 0b                	add    %cl,(%ebx)
  40d2fe:	5f                   	pop    %edi
  40d2ff:	77 69                	ja     40d36a <.debug_info+0x344>
  40d301:	6e                   	outsb  %ds:(%esi),(%dx)
  40d302:	6d                   	insl   (%dx),%es:(%edi)
  40d303:	69 6e 6f 72 00 02 18 	imul   $0x18020072,0x6f(%esi),%ebp
  40d30a:	01 1e                	add    %ebx,(%esi)
  40d30c:	f1                   	icebp  
  40d30d:	00 00                	add    %al,(%eax)
  40d30f:	00 0b                	add    %cl,(%ebx)
  40d311:	5f                   	pop    %edi
  40d312:	66 6d                	insw   (%dx),%es:(%edi)
  40d314:	6f                   	outsl  %ds:(%esi),(%dx)
  40d315:	64 65 00 02          	fs add %al,%gs:(%edx)
  40d319:	60                   	pusha  
  40d31a:	01 15 e5 00 00 00    	add    %edx,0xe5
  40d320:	0a 6f 70             	or     0x70(%edi),%ch
  40d323:	74 69                	je     40d38e <.debug_info+0x368>
  40d325:	6e                   	outsb  %ds:(%esi),(%dx)
  40d326:	64 00 03             	add    %al,%fs:(%ebx)
  40d329:	3c 0c                	cmp    $0xc,%al
  40d32b:	e5 00                	in     $0x0,%eax
  40d32d:	00 00                	add    %al,(%eax)
  40d32f:	0a 6f 70             	or     0x70(%edi),%ch
  40d332:	74 6f                	je     40d3a3 <.debug_info+0x37d>
  40d334:	70 74                	jo     40d3aa <.debug_info+0x384>
  40d336:	00 03                	add    %al,(%ebx)
  40d338:	3d 0c e5 00 00       	cmp    $0xe50c,%eax
  40d33d:	00 0a                	add    %cl,(%edx)
  40d33f:	6f                   	outsl  %ds:(%esi),(%dx)
  40d340:	70 74                	jo     40d3b6 <.debug_info+0x390>
  40d342:	65 72 72             	gs jb  40d3b7 <.debug_info+0x391>
  40d345:	00 03                	add    %al,(%ebx)
  40d347:	3e 0c e5             	ds or  $0xe5,%al
  40d34a:	00 00                	add    %al,(%eax)
  40d34c:	00 0a                	add    %cl,(%edx)
  40d34e:	6f                   	outsl  %ds:(%esi),(%dx)
  40d34f:	70 74                	jo     40d3c5 <.debug_info+0x39f>
  40d351:	61                   	popa   
  40d352:	72 67                	jb     40d3bb <.debug_info+0x395>
  40d354:	00 03                	add    %al,(%ebx)
  40d356:	41                   	inc    %ecx
  40d357:	0e                   	push   %cs
  40d358:	ed                   	in     (%dx),%eax
  40d359:	01 00                	add    %eax,(%eax)
  40d35b:	00 0b                	add    %cl,(%ebx)
  40d35d:	5f                   	pop    %edi
  40d35e:	64 61                	fs popa 
  40d360:	79 6c                	jns    40d3ce <.debug_info+0x3a8>
  40d362:	69 67 68 74 00 04 5c 	imul   $0x5c040074,0x68(%edi),%esp
  40d369:	01 16                	add    %edx,(%esi)
  40d36b:	e5 00                	in     $0x0,%eax
  40d36d:	00 00                	add    %al,(%eax)
  40d36f:	0b 5f 74             	or     0x74(%edi),%ebx
  40d372:	69 6d 65 7a 6f 6e 65 	imul   $0x656e6f7a,0x65(%ebp),%ebp
  40d379:	00 04 5d 01 16 51 01 	add    %al,0x1511601(,%ebx,2)
  40d380:	00 00                	add    %al,(%eax)
  40d382:	08 ed                	or     %ch,%ch
  40d384:	01 00                	add    %eax,(%eax)
  40d386:	00 6c 03 00          	add    %ch,0x0(%ebx,%eax,1)
  40d38a:	00 0c f1             	add    %cl,(%ecx,%esi,8)
  40d38d:	00 00                	add    %al,(%eax)
  40d38f:	00 01                	add    %al,(%ecx)
  40d391:	00 0b                	add    %cl,(%ebx)
  40d393:	5f                   	pop    %edi
  40d394:	74 7a                	je     40d410 <.debug_info+0x3ea>
  40d396:	6e                   	outsb  %ds:(%esi),(%dx)
  40d397:	61                   	popa   
  40d398:	6d                   	insl   (%dx),%es:(%edi)
  40d399:	65 00 04 5e          	add    %al,%gs:(%esi,%ebx,2)
  40d39d:	01 16                	add    %edx,(%esi)
  40d39f:	5c                   	pop    %esp
  40d3a0:	03 00                	add    (%eax),%eax
  40d3a2:	00 0b                	add    %cl,(%ebx)
  40d3a4:	64 61                	fs popa 
  40d3a6:	79 6c                	jns    40d414 <.debug_info+0x3ee>
  40d3a8:	69 67 68 74 00 04 7d 	imul   $0x7d040074,0x68(%edi),%esp
  40d3af:	01 16                	add    %edx,(%esi)
  40d3b1:	e5 00                	in     $0x0,%eax
  40d3b3:	00 00                	add    %al,(%eax)
  40d3b5:	0b 74 69 6d          	or     0x6d(%ecx,%ebp,2),%esi
  40d3b9:	65 7a 6f             	gs jp  40d42b <.debug_info+0x405>
  40d3bc:	6e                   	outsb  %ds:(%esi),(%dx)
  40d3bd:	65 00 04 7e          	add    %al,%gs:(%esi,%edi,2)
  40d3c1:	01 16                	add    %edx,(%esi)
  40d3c3:	51                   	push   %ecx
  40d3c4:	01 00                	add    %eax,(%eax)
  40d3c6:	00 0b                	add    %cl,(%ebx)
  40d3c8:	74 7a                	je     40d444 <.debug_info+0x41e>
  40d3ca:	6e                   	outsb  %ds:(%esi),(%dx)
  40d3cb:	61                   	popa   
  40d3cc:	6d                   	insl   (%dx),%es:(%edi)
  40d3cd:	65 00 04 7f          	add    %al,%gs:(%edi,%edi,2)
  40d3d1:	01 16                	add    %edx,(%esi)
  40d3d3:	5c                   	pop    %esp
  40d3d4:	03 00                	add    (%eax),%eax
  40d3d6:	00 07                	add    %al,(%edi)
  40d3d8:	68 61 73 68 76       	push   $0x76687361
  40d3dd:	61                   	popa   
  40d3de:	6c                   	insb   (%dx),%es:(%edi)
  40d3df:	5f                   	pop    %edi
  40d3e0:	74 00                	je     40d3e2 <.debug_info+0x3bc>
  40d3e2:	05 2a 16 f1 00       	add    $0xf1162a,%eax
  40d3e7:	00 00                	add    %al,(%eax)
  40d3e9:	07                   	pop    %es
  40d3ea:	68 74 61 62 5f       	push   $0x5f626174
  40d3ef:	68 61 73 68 00       	push   $0x687361
  40d3f4:	05 2f 15 d5 03       	add    $0x3d5152f,%eax
  40d3f9:	00 00                	add    %al,(%eax)
  40d3fb:	06                   	push   %es
  40d3fc:	04 db                	add    $0xdb,%al
  40d3fe:	03 00                	add    (%eax),%eax
  40d400:	00 0d b1 03 00 00    	add    %cl,0x3b1
  40d406:	ea 03 00 00 0e ea 03 	ljmp   $0x3ea,$0xe000003
  40d40d:	00 00                	add    %al,(%eax)
  40d40f:	00 06                	add    %al,(%esi)
  40d411:	04 f0                	add    $0xf0,%al
  40d413:	03 00                	add    (%eax),%eax
  40d415:	00 0f                	add    %cl,(%edi)
  40d417:	07                   	pop    %es
  40d418:	68 74 61 62 5f       	push   $0x5f626174
  40d41d:	65 71 00             	gs jno 40d420 <.debug_info+0x3fa>
  40d420:	05 36 0f 01 04       	add    $0x4010f36,%eax
  40d425:	00 00                	add    %al,(%eax)
  40d427:	06                   	push   %es
  40d428:	04 07                	add    $0x7,%al
  40d42a:	04 00                	add    $0x0,%al
  40d42c:	00 0d e5 00 00 00    	add    %cl,0xe5
  40d432:	1b 04 00             	sbb    (%eax,%eax,1),%eax
  40d435:	00 0e                	add    %cl,(%esi)
  40d437:	ea 03 00 00 0e ea 03 	ljmp   $0x3ea,$0xe000003
  40d43e:	00 00                	add    %al,(%eax)
  40d440:	00 0a                	add    %cl,(%edx)
  40d442:	68 74 61 62 5f       	push   $0x5f626174
  40d447:	68 61 73 68 5f       	push   $0x5f687361
  40d44c:	70 6f                	jo     40d4bd <.debug_info+0x497>
  40d44e:	69 6e 74 65 72 00 05 	imul   $0x5007265,0x74(%esi),%ebp
  40d455:	bb 12 c3 03 00       	mov    $0x3c312,%ebx
  40d45a:	00 0a                	add    %cl,(%edx)
  40d45c:	68 74 61 62 5f       	push   $0x5f626174
  40d461:	65 71 5f             	gs jno 40d4c3 <.debug_info+0x49d>
  40d464:	70 6f                	jo     40d4d5 <.debug_info+0x4af>
  40d466:	69 6e 74 65 72 00 05 	imul   $0x5007265,0x74(%esi),%ebp
  40d46d:	be 10 f1 03 00       	mov    $0x3f110,%esi
  40d472:	00 02                	add    %al,(%edx)
  40d474:	01 08                	add    %ecx,(%eax)
  40d476:	75 6e                	jne    40d4e6 <.debug_info+0x4c0>
  40d478:	73 69                	jae    40d4e3 <.debug_info+0x4bd>
  40d47a:	67 6e                	outsb  %ds:(%si),(%dx)
  40d47c:	65 64 20 63 68       	gs and %ah,%fs:0x68(%ebx)
  40d481:	61                   	popa   
  40d482:	72 00                	jb     40d484 <.debug_info+0x45e>
  40d484:	10 73 74             	adc    %dh,0x74(%ebx)
  40d487:	72 69                	jb     40d4f2 <.debug_info+0x4cc>
  40d489:	6e                   	outsb  %ds:(%esi),(%dx)
  40d48a:	67 6f                	outsl  %ds:(%si),(%dx)
  40d48c:	70 5f                	jo     40d4ed <.debug_info+0x4c7>
  40d48e:	61                   	popa   
  40d48f:	6c                   	insb   (%dx),%es:(%edi)
  40d490:	67 00 07             	add    %al,(%bx)
  40d493:	04 f1                	add    $0xf1,%al
  40d495:	00 00                	add    %al,(%eax)
  40d497:	00 08                	add    %cl,(%eax)
  40d499:	1d 06 0c 05 00       	sbb    $0x50c06,%eax
  40d49e:	00 11                	add    %dl,(%ecx)
  40d4a0:	6e                   	outsb  %ds:(%esi),(%dx)
  40d4a1:	6f                   	outsl  %ds:(%esi),(%dx)
  40d4a2:	5f                   	pop    %edi
  40d4a3:	73 74                	jae    40d519 <.debug_info+0x4f3>
  40d4a5:	72 69                	jb     40d510 <.debug_info+0x4ea>
  40d4a7:	6e                   	outsb  %ds:(%esi),(%dx)
  40d4a8:	67 6f                	outsl  %ds:(%si),(%dx)
  40d4aa:	70 00                	jo     40d4ac <.debug_info+0x486>
  40d4ac:	00 11                	add    %dl,(%ecx)
  40d4ae:	6c                   	insb   (%dx),%es:(%edi)
  40d4af:	69 62 63 61 6c 6c 00 	imul   $0x6c6c61,0x63(%edx),%esp
  40d4b6:	01 11                	add    %edx,(%ecx)
  40d4b8:	72 65                	jb     40d51f <.debug_info+0x4f9>
  40d4ba:	70 5f                	jo     40d51b <.debug_info+0x4f5>
  40d4bc:	70 72                	jo     40d530 <.debug_info+0x50a>
  40d4be:	65 66 69 78 5f 31 5f 	imul   $0x5f31,%gs:0x5f(%eax),%di
  40d4c5:	62 79 74             	bound  %edi,0x74(%ecx)
  40d4c8:	65 00 02             	add    %al,%gs:(%edx)
  40d4cb:	11 72 65             	adc    %esi,0x65(%edx)
  40d4ce:	70 5f                	jo     40d52f <.debug_info+0x509>
  40d4d0:	70 72                	jo     40d544 <.debug_info+0x51e>
  40d4d2:	65 66 69 78 5f 34 5f 	imul   $0x5f34,%gs:0x5f(%eax),%di
  40d4d9:	62 79 74             	bound  %edi,0x74(%ecx)
  40d4dc:	65 00 03             	add    %al,%gs:(%ebx)
  40d4df:	11 72 65             	adc    %esi,0x65(%edx)
  40d4e2:	70 5f                	jo     40d543 <.debug_info+0x51d>
  40d4e4:	70 72                	jo     40d558 <.debug_info+0x532>
  40d4e6:	65 66 69 78 5f 38 5f 	imul   $0x5f38,%gs:0x5f(%eax),%di
  40d4ed:	62 79 74             	bound  %edi,0x74(%ecx)
  40d4f0:	65 00 04 11          	add    %al,%gs:(%ecx,%edx,1)
  40d4f4:	6c                   	insb   (%dx),%es:(%edi)
  40d4f5:	6f                   	outsl  %ds:(%esi),(%dx)
  40d4f6:	6f                   	outsl  %ds:(%esi),(%dx)
  40d4f7:	70 5f                	jo     40d558 <.debug_info+0x532>
  40d4f9:	31 5f 62             	xor    %ebx,0x62(%edi)
  40d4fc:	79 74                	jns    40d572 <.debug_info+0x54c>
  40d4fe:	65 00 05 11 6c 6f 6f 	add    %al,%gs:0x6f6f6c11
  40d505:	70 00                	jo     40d507 <.debug_info+0x4e1>
  40d507:	06                   	push   %es
  40d508:	11 75 6e             	adc    %esi,0x6e(%ebp)
  40d50b:	72 6f                	jb     40d57c <.debug_info+0x556>
  40d50d:	6c                   	insb   (%dx),%es:(%edi)
  40d50e:	6c                   	insb   (%dx),%es:(%edi)
  40d50f:	65 64 5f             	gs fs pop %edi
  40d512:	6c                   	insb   (%dx),%es:(%edi)
  40d513:	6f                   	outsl  %ds:(%esi),(%dx)
  40d514:	6f                   	outsl  %ds:(%esi),(%dx)
  40d515:	70 00                	jo     40d517 <.debug_info+0x4f1>
  40d517:	07                   	pop    %es
  40d518:	11 76 65             	adc    %esi,0x65(%esi)
  40d51b:	63 74 6f 72          	arpl   %si,0x72(%edi,%ebp,2)
  40d51f:	5f                   	pop    %edi
  40d520:	6c                   	insb   (%dx),%es:(%edi)
  40d521:	6f                   	outsl  %ds:(%esi),(%dx)
  40d522:	6f                   	outsl  %ds:(%esi),(%dx)
  40d523:	70 00                	jo     40d525 <.debug_info+0x4ff>
  40d525:	08 11                	or     %dl,(%ecx)
  40d527:	6c                   	insb   (%dx),%es:(%edi)
  40d528:	61                   	popa   
  40d529:	73 74                	jae    40d59f <.debug_info+0x579>
  40d52b:	5f                   	pop    %edi
  40d52c:	61                   	popa   
  40d52d:	6c                   	insb   (%dx),%es:(%edi)
  40d52e:	67 00 09             	add    %cl,(%bx,%di)
  40d531:	00 03                	add    %al,(%ebx)
  40d533:	5e                   	pop    %esi
  40d534:	04 00                	add    $0x0,%al
  40d536:	00 08                	add    %cl,(%eax)
  40d538:	27                   	daa    
  40d539:	05 00 00 1c 05       	add    $0x51c0000,%eax
  40d53e:	00 00                	add    %al,(%eax)
  40d540:	09 00                	or     %eax,(%eax)
  40d542:	03 11                	add    (%ecx),%edx
  40d544:	05 00 00 06 04       	add    $0x4060000,%eax
  40d549:	4c                   	dec    %esp
  40d54a:	01 00                	add    %eax,(%eax)
  40d54c:	00 03                	add    %al,(%ebx)
  40d54e:	21 05 00 00 0b 75    	and    %eax,0x750b0000
  40d554:	6e                   	outsb  %ds:(%esi),(%dx)
  40d555:	73 70                	jae    40d5c7 <.debug_info+0x5a1>
  40d557:	65 63 5f 73          	arpl   %bx,%gs:0x73(%edi)
  40d55b:	74 72                	je     40d5cf <.debug_info+0x5a9>
  40d55d:	69 6e 67 73 00 06 4a 	imul   $0x4a060073,0x67(%esi),%ebp
  40d564:	01 1a                	add    %ebx,(%edx)
  40d566:	1c 05                	sbb    $0x5,%al
  40d568:	00 00                	add    %al,(%eax)
  40d56a:	0b 75 6e             	or     0x6e(%ebp),%esi
  40d56d:	73 70                	jae    40d5df <.debug_info+0x5b9>
  40d56f:	65 63 76 5f          	arpl   %si,%gs:0x5f(%esi)
  40d573:	73 74                	jae    40d5e9 <.debug_info+0x5c3>
  40d575:	72 69                	jb     40d5e0 <.debug_info+0x5ba>
  40d577:	6e                   	outsb  %ds:(%esi),(%dx)
  40d578:	67 73 00             	addr16 jae 40d57b <.debug_info+0x555>
  40d57b:	06                   	push   %es
  40d57c:	a6                   	cmpsb  %es:(%edi),%ds:(%esi)
  40d57d:	01 1a                	add    %ebx,(%edx)
  40d57f:	1c 05                	sbb    $0x5,%al
  40d581:	00 00                	add    %al,(%eax)
  40d583:	04 73                	add    $0x73,%al
  40d585:	74 72                	je     40d5f9 <.debug_info+0x5d3>
  40d587:	69 6e 67 6f 70 5f 73 	imul   $0x735f706f,0x67(%esi),%ebp
  40d58e:	74 72                	je     40d602 <.debug_info+0x5dc>
  40d590:	61                   	popa   
  40d591:	74 65                	je     40d5f8 <.debug_info+0x5d2>
  40d593:	67 79 00             	addr16 jns 40d596 <.debug_info+0x570>
  40d596:	0c 07                	or     $0x7,%al
  40d598:	e1 10                	loope  40d5aa <.debug_info+0x584>
  40d59a:	a4                   	movsb  %ds:(%esi),%es:(%edi)
  40d59b:	05 00 00 05 6d       	add    $0x6d050000,%eax
  40d5a0:	61                   	popa   
  40d5a1:	78 00                	js     40d5a3 <.debug_info+0x57d>
  40d5a3:	07                   	pop    %es
  40d5a4:	e2 0f                	loop   40d5b5 <.debug_info+0x58f>
  40d5a6:	ec                   	in     (%dx),%al
  40d5a7:	00 00                	add    %al,(%eax)
  40d5a9:	00 00                	add    %al,(%eax)
  40d5ab:	05 61 6c 67 00       	add    $0x676c61,%eax
  40d5b0:	07                   	pop    %es
  40d5b1:	e3 1d                	jecxz  40d5d0 <.debug_info+0x5aa>
  40d5b3:	0c 05                	or     $0x5,%al
  40d5b5:	00 00                	add    %al,(%eax)
  40d5b7:	04 05                	add    $0x5,%al
  40d5b9:	6e                   	outsb  %ds:(%esi),(%dx)
  40d5ba:	6f                   	outsl  %ds:(%esi),(%dx)
  40d5bb:	61                   	popa   
  40d5bc:	6c                   	insb   (%dx),%es:(%edi)
  40d5bd:	69 67 6e 00 07 e4 09 	imul   $0x9e40700,0x6e(%edi),%esp
  40d5c4:	e5 00                	in     $0x0,%eax
  40d5c6:	00 00                	add    %al,(%eax)
  40d5c8:	08 00                	or     %al,(%eax)
  40d5ca:	03 5d 05             	add    0x5(%ebp),%ebx
  40d5cd:	00 00                	add    %al,(%eax)
  40d5cf:	04 73                	add    $0x73,%al
  40d5d1:	74 72                	je     40d645 <.debug_info+0x61f>
  40d5d3:	69 6e 67 6f 70 5f 61 	imul   $0x615f706f,0x67(%esi),%ebp
  40d5da:	6c                   	insb   (%dx),%es:(%edi)
  40d5db:	67 73 00             	addr16 jae 40d5de <.debug_info+0x5b8>
  40d5de:	34 07                	xor    $0x7,%al
  40d5e0:	de 08                	fimuls (%eax)
  40d5e2:	e5 05                	in     $0x5,%eax
  40d5e4:	00 00                	add    %al,(%eax)
  40d5e6:	05 75 6e 6b 6e       	add    $0x6e6b6e75,%eax
  40d5eb:	6f                   	outsl  %ds:(%esi),(%dx)
  40d5ec:	77 6e                	ja     40d65c <.debug_info+0x636>
  40d5ee:	5f                   	pop    %edi
  40d5ef:	73 69                	jae    40d65a <.debug_info+0x634>
  40d5f1:	7a 65                	jp     40d658 <.debug_info+0x632>
  40d5f3:	00 07                	add    %al,(%edi)
  40d5f5:	e0 1b                	loopne 40d612 <.debug_info+0x5ec>
  40d5f7:	0c 05                	or     $0x5,%al
  40d5f9:	00 00                	add    %al,(%eax)
  40d5fb:	00 05 73 69 7a 65    	add    %al,0x657a6973
  40d601:	00 07                	add    %al,(%edi)
  40d603:	e5 05                	in     $0x5,%eax
  40d605:	f5                   	cmc    
  40d606:	05 00 00 04 00       	add    $0x40000,%eax
  40d60b:	08 a4 05 00 00 f5 05 	or     %ah,0x5f50000(%ebp,%eax,1)
  40d612:	00 00                	add    %al,(%eax)
  40d614:	0c f1                	or     $0xf1,%al
  40d616:	00 00                	add    %al,(%eax)
  40d618:	00 03                	add    %al,(%ebx)
  40d61a:	00 03                	add    %al,(%ebx)
  40d61c:	e5 05                	in     $0x5,%eax
  40d61e:	00 00                	add    %al,(%eax)
  40d620:	12 70 72             	adc    0x72(%eax),%dh
  40d623:	6f                   	outsl  %ds:(%esi),(%dx)
  40d624:	63 65 73             	arpl   %sp,0x73(%ebp)
  40d627:	73 6f                	jae    40d698 <.debug_info+0x672>
  40d629:	72 5f                	jb     40d68a <.debug_info+0x664>
  40d62b:	63 6f 73             	arpl   %bp,0x73(%edi)
  40d62e:	74 73                	je     40d6a3 <.debug_info+0x67d>
  40d630:	00 90 01 07 ea 08    	add    %dl,0x8ea0701(%eax)
  40d636:	71 0b                	jno    40d643 <.debug_info+0x61d>
  40d638:	00 00                	add    %al,(%eax)
  40d63a:	05 61 64 64 00       	add    $0x646461,%eax
  40d63f:	07                   	pop    %es
  40d640:	eb 0d                	jmp    40d64f <.debug_info+0x629>
  40d642:	ec                   	in     (%dx),%al
  40d643:	00 00                	add    %al,(%eax)
  40d645:	00 00                	add    %al,(%eax)
  40d647:	05 6c 65 61 00       	add    $0x61656c,%eax
  40d64c:	07                   	pop    %es
  40d64d:	ec                   	in     (%dx),%al
  40d64e:	0d ec 00 00 00       	or     $0xec,%eax
  40d653:	04 05                	add    $0x5,%al
  40d655:	73 68                	jae    40d6bf <.debug_info+0x699>
  40d657:	69 66 74 5f 76 61 72 	imul   $0x7261765f,0x74(%esi),%esp
  40d65e:	00 07                	add    %al,(%edi)
  40d660:	ed                   	in     (%dx),%eax
  40d661:	0d ec 00 00 00       	or     $0xec,%eax
  40d666:	08 05 73 68 69 66    	or     %al,0x66696873
  40d66c:	74 5f                	je     40d6cd <.debug_info+0x6a7>
  40d66e:	63 6f 6e             	arpl   %bp,0x6e(%edi)
  40d671:	73 74                	jae    40d6e7 <.debug_info+0x6c1>
  40d673:	00 07                	add    %al,(%edi)
  40d675:	ee                   	out    %al,(%dx)
  40d676:	0d ec 00 00 00       	or     $0xec,%eax
  40d67b:	0c 05                	or     $0x5,%al
  40d67d:	6d                   	insl   (%dx),%es:(%edi)
  40d67e:	75 6c                	jne    40d6ec <.debug_info+0x6c6>
  40d680:	74 5f                	je     40d6e1 <.debug_info+0x6bb>
  40d682:	69 6e 69 74 00 07 ef 	imul   $0xef070074,0x69(%esi),%ebp
  40d689:	0d 86 0b 00 00       	or     $0xb86,%eax
  40d68e:	10 05 6d 75 6c 74    	adc    %al,0x746c756d
  40d694:	5f                   	pop    %edi
  40d695:	62 69 74             	bound  %ebp,0x74(%ecx)
  40d698:	00 07                	add    %al,(%edi)
  40d69a:	f1                   	icebp  
  40d69b:	0d ec 00 00 00       	or     $0xec,%eax
  40d6a0:	24 05                	and    $0x5,%al
  40d6a2:	64 69 76 69 64 65 00 	imul   $0x7006564,%fs:0x69(%esi),%esi
  40d6a9:	07 
  40d6aa:	f2 0d 86 0b 00 00    	repnz or $0xb86,%eax
  40d6b0:	28 05 6d 6f 76 73    	sub    %al,0x73766f6d
  40d6b6:	78 00                	js     40d6b8 <.debug_info+0x692>
  40d6b8:	07                   	pop    %es
  40d6b9:	f4                   	hlt    
  40d6ba:	07                   	pop    %es
  40d6bb:	e5 00                	in     $0x0,%eax
  40d6bd:	00 00                	add    %al,(%eax)
  40d6bf:	3c 05                	cmp    $0x5,%al
  40d6c1:	6d                   	insl   (%dx),%es:(%edi)
  40d6c2:	6f                   	outsl  %ds:(%esi),(%dx)
  40d6c3:	76 7a                	jbe    40d73f <.debug_info+0x719>
  40d6c5:	78 00                	js     40d6c7 <.debug_info+0x6a1>
  40d6c7:	07                   	pop    %es
  40d6c8:	f5                   	cmc    
  40d6c9:	07                   	pop    %es
  40d6ca:	e5 00                	in     $0x0,%eax
  40d6cc:	00 00                	add    %al,(%eax)
  40d6ce:	40                   	inc    %eax
  40d6cf:	05 6c 61 72 67       	add    $0x6772616c,%eax
  40d6d4:	65 5f                	gs pop %edi
  40d6d6:	69 6e 73 6e 00 07 f6 	imul   $0xf607006e,0x73(%esi),%ebp
  40d6dd:	0d ec 00 00 00       	or     $0xec,%eax
  40d6e2:	44                   	inc    %esp
  40d6e3:	05 6d 6f 76 65       	add    $0x65766f6d,%eax
  40d6e8:	5f                   	pop    %edi
  40d6e9:	72 61                	jb     40d74c <.debug_info+0x726>
  40d6eb:	74 69                	je     40d756 <.debug_info+0x730>
  40d6ed:	6f                   	outsl  %ds:(%esi),(%dx)
  40d6ee:	00 07                	add    %al,(%edi)
  40d6f0:	f7 0d ec 00 00 00 48 	testl  $0x6f6d0548,0xec
  40d6f7:	05 6d 6f 
  40d6fa:	76 7a                	jbe    40d776 <.debug_info+0x750>
  40d6fc:	62 6c 5f 6c          	bound  %ebp,0x6c(%edi,%ebx,2)
  40d700:	6f                   	outsl  %ds:(%esi),(%dx)
  40d701:	61                   	popa   
  40d702:	64 00 07             	add    %al,%fs:(%edi)
  40d705:	f9                   	stc    
  40d706:	0d ec 00 00 00       	or     $0xec,%eax
  40d70b:	4c                   	dec    %esp
  40d70c:	05 69 6e 74 5f       	add    $0x5f746e69,%eax
  40d711:	6c                   	insb   (%dx),%es:(%edi)
  40d712:	6f                   	outsl  %ds:(%esi),(%dx)
  40d713:	61                   	popa   
  40d714:	64 00 07             	add    %al,%fs:(%edi)
  40d717:	fa                   	cli    
  40d718:	0d 9b 0b 00 00       	or     $0xb9b,%eax
  40d71d:	50                   	push   %eax
  40d71e:	05 69 6e 74 5f       	add    $0x5f746e69,%eax
  40d723:	73 74                	jae    40d799 <.debug_info+0x773>
  40d725:	6f                   	outsl  %ds:(%esi),(%dx)
  40d726:	72 65                	jb     40d78d <.debug_info+0x767>
  40d728:	00 07                	add    %al,(%edi)
  40d72a:	fd                   	std    
  40d72b:	0d 9b 0b 00 00       	or     $0xb9b,%eax
  40d730:	5c                   	pop    %esp
  40d731:	05 66 70 5f 6d       	add    $0x6d5f7066,%eax
  40d736:	6f                   	outsl  %ds:(%esi),(%dx)
  40d737:	76 65                	jbe    40d79e <.debug_info+0x778>
  40d739:	00 07                	add    %al,(%edi)
  40d73b:	ff 0d ec 00 00 00    	decl   0xec
  40d741:	68 13 66 70 5f       	push   $0x5f706613
  40d746:	6c                   	insb   (%dx),%es:(%edi)
  40d747:	6f                   	outsl  %ds:(%esi),(%dx)
  40d748:	61                   	popa   
  40d749:	64 00 07             	add    %al,%fs:(%edi)
  40d74c:	00 01                	add    %al,(%ecx)
  40d74e:	0d 9b 0b 00 00       	or     $0xb9b,%eax
  40d753:	6c                   	insb   (%dx),%es:(%edi)
  40d754:	13 66 70             	adc    0x70(%esi),%esp
  40d757:	5f                   	pop    %edi
  40d758:	73 74                	jae    40d7ce <.debug_info+0x7a8>
  40d75a:	6f                   	outsl  %ds:(%esi),(%dx)
  40d75b:	72 65                	jb     40d7c2 <.debug_info+0x79c>
  40d75d:	00 07                	add    %al,(%edi)
  40d75f:	02 01                	add    (%ecx),%al
  40d761:	0d 9b 0b 00 00       	or     $0xb9b,%eax
  40d766:	78 13                	js     40d77b <.debug_info+0x755>
  40d768:	6d                   	insl   (%dx),%es:(%edi)
  40d769:	6d                   	insl   (%dx),%es:(%edi)
  40d76a:	78 5f                	js     40d7cb <.debug_info+0x7a5>
  40d76c:	6d                   	insl   (%dx),%es:(%edi)
  40d76d:	6f                   	outsl  %ds:(%esi),(%dx)
  40d76e:	76 65                	jbe    40d7d5 <.debug_info+0x7af>
  40d770:	00 07                	add    %al,(%edi)
  40d772:	04 01                	add    $0x1,%al
  40d774:	0d ec 00 00 00       	or     $0xec,%eax
  40d779:	84 13                	test   %dl,(%ebx)
  40d77b:	6d                   	insl   (%dx),%es:(%edi)
  40d77c:	6d                   	insl   (%dx),%es:(%edi)
  40d77d:	78 5f                	js     40d7de <.debug_info+0x7b8>
  40d77f:	6c                   	insb   (%dx),%es:(%edi)
  40d780:	6f                   	outsl  %ds:(%esi),(%dx)
  40d781:	61                   	popa   
  40d782:	64 00 07             	add    %al,%fs:(%edi)
  40d785:	05 01 0d b0 0b       	add    $0xbb00d01,%eax
  40d78a:	00 00                	add    %al,(%eax)
  40d78c:	88 13                	mov    %dl,(%ebx)
  40d78e:	6d                   	insl   (%dx),%es:(%edi)
  40d78f:	6d                   	insl   (%dx),%es:(%edi)
  40d790:	78 5f                	js     40d7f1 <.debug_info+0x7cb>
  40d792:	73 74                	jae    40d808 <.debug_info+0x7e2>
  40d794:	6f                   	outsl  %ds:(%esi),(%dx)
  40d795:	72 65                	jb     40d7fc <.debug_info+0x7d6>
  40d797:	00 07                	add    %al,(%edi)
  40d799:	07                   	pop    %es
  40d79a:	01 0d b0 0b 00 00    	add    %ecx,0xbb0
  40d7a0:	90                   	nop
  40d7a1:	13 78 6d             	adc    0x6d(%eax),%edi
  40d7a4:	6d                   	insl   (%dx),%es:(%edi)
  40d7a5:	5f                   	pop    %edi
  40d7a6:	6d                   	insl   (%dx),%es:(%edi)
  40d7a7:	6f                   	outsl  %ds:(%esi),(%dx)
  40d7a8:	76 65                	jbe    40d80f <.debug_info+0x7e9>
  40d7aa:	00 07                	add    %al,(%edi)
  40d7ac:	09 01                	or     %eax,(%ecx)
  40d7ae:	0d ec 00 00 00       	or     $0xec,%eax
  40d7b3:	98                   	cwtl   
  40d7b4:	13 79 6d             	adc    0x6d(%ecx),%edi
  40d7b7:	6d                   	insl   (%dx),%es:(%edi)
  40d7b8:	5f                   	pop    %edi
  40d7b9:	6d                   	insl   (%dx),%es:(%edi)
  40d7ba:	6f                   	outsl  %ds:(%esi),(%dx)
  40d7bb:	76 65                	jbe    40d822 <.debug_info+0x7fc>
  40d7bd:	00 07                	add    %al,(%edi)
  40d7bf:	09 01                	or     %eax,(%ecx)
  40d7c1:	17                   	pop    %ss
  40d7c2:	ec                   	in     (%dx),%al
  40d7c3:	00 00                	add    %al,(%eax)
  40d7c5:	00 9c 13 7a 6d 6d 5f 	add    %bl,0x5f6d6d7a(%ebx,%edx,1)
  40d7cc:	6d                   	insl   (%dx),%es:(%edi)
  40d7cd:	6f                   	outsl  %ds:(%esi),(%dx)
  40d7ce:	76 65                	jbe    40d835 <.debug_info+0x80f>
  40d7d0:	00 07                	add    %al,(%edi)
  40d7d2:	0a 01                	or     (%ecx),%al
  40d7d4:	06                   	push   %es
  40d7d5:	ec                   	in     (%dx),%al
  40d7d6:	00 00                	add    %al,(%eax)
  40d7d8:	00 a0 13 73 73 65    	add    %ah,0x65737313(%eax)
  40d7de:	5f                   	pop    %edi
  40d7df:	6c                   	insb   (%dx),%es:(%edi)
  40d7e0:	6f                   	outsl  %ds:(%esi),(%dx)
  40d7e1:	61                   	popa   
  40d7e2:	64 00 07             	add    %al,%fs:(%edi)
  40d7e5:	0b 01                	or     (%ecx),%eax
  40d7e7:	0d 86 0b 00 00       	or     $0xb86,%eax
  40d7ec:	a4                   	movsb  %ds:(%esi),%es:(%edi)
  40d7ed:	13 73 73             	adc    0x73(%ebx),%esi
  40d7f0:	65 5f                	gs pop %edi
  40d7f2:	75 6e                	jne    40d862 <.debug_info+0x83c>
  40d7f4:	61                   	popa   
  40d7f5:	6c                   	insb   (%dx),%es:(%edi)
  40d7f6:	69 67 6e 65 64 5f 6c 	imul   $0x6c5f6465,0x6e(%edi),%esp
  40d7fd:	6f                   	outsl  %ds:(%esi),(%dx)
  40d7fe:	61                   	popa   
  40d7ff:	64 00 07             	add    %al,%fs:(%edi)
  40d802:	0d 01 0d 86 0b       	or     $0xb860d01,%eax
  40d807:	00 00                	add    %al,(%eax)
  40d809:	b8 13 73 73 65       	mov    $0x65737313,%eax
  40d80e:	5f                   	pop    %edi
  40d80f:	73 74                	jae    40d885 <.debug_info+0x85f>
  40d811:	6f                   	outsl  %ds:(%esi),(%dx)
  40d812:	72 65                	jb     40d879 <.debug_info+0x853>
  40d814:	00 07                	add    %al,(%edi)
  40d816:	0e                   	push   %cs
  40d817:	01 0d 86 0b 00 00    	add    %ecx,0xb86
  40d81d:	cc                   	int3   
  40d81e:	13 73 73             	adc    0x73(%ebx),%esi
  40d821:	65 5f                	gs pop %edi
  40d823:	75 6e                	jne    40d893 <.debug_info+0x86d>
  40d825:	61                   	popa   
  40d826:	6c                   	insb   (%dx),%es:(%edi)
  40d827:	69 67 6e 65 64 5f 73 	imul   $0x735f6465,0x6e(%edi),%esp
  40d82e:	74 6f                	je     40d89f <.debug_info+0x879>
  40d830:	72 65                	jb     40d897 <.debug_info+0x871>
  40d832:	00 07                	add    %al,(%edi)
  40d834:	10 01                	adc    %al,(%ecx)
  40d836:	0d 86 0b 00 00       	or     $0xb86,%eax
  40d83b:	e0 13                	loopne 40d850 <.debug_info+0x82a>
  40d83d:	6d                   	insl   (%dx),%es:(%edi)
  40d83e:	6d                   	insl   (%dx),%es:(%edi)
  40d83f:	78 73                	js     40d8b4 <.debug_info+0x88e>
  40d841:	73 65                	jae    40d8a8 <.debug_info+0x882>
  40d843:	5f                   	pop    %edi
  40d844:	74 6f                	je     40d8b5 <.debug_info+0x88f>
  40d846:	5f                   	pop    %edi
  40d847:	69 6e 74 65 67 65 72 	imul   $0x72656765,0x74(%esi),%ebp
  40d84e:	00 07                	add    %al,(%edi)
  40d850:	11 01                	adc    %eax,(%ecx)
  40d852:	0d ec 00 00 00       	or     $0xec,%eax
  40d857:	f4                   	hlt    
  40d858:	13 73 73             	adc    0x73(%ebx),%esi
  40d85b:	65 6d                	gs insl (%dx),%es:(%edi)
  40d85d:	6d                   	insl   (%dx),%es:(%edi)
  40d85e:	78 5f                	js     40d8bf <.debug_info+0x899>
  40d860:	74 6f                	je     40d8d1 <.debug_info+0x8ab>
  40d862:	5f                   	pop    %edi
  40d863:	69 6e 74 65 67 65 72 	imul   $0x72656765,0x74(%esi),%ebp
  40d86a:	00 07                	add    %al,(%edi)
  40d86c:	13 01                	adc    (%ecx),%eax
  40d86e:	0d ec 00 00 00       	or     $0xec,%eax
  40d873:	f8                   	clc    
  40d874:	13 67 61             	adc    0x61(%edi),%esp
  40d877:	74 68                	je     40d8e1 <.debug_info+0x8bb>
  40d879:	65 72 5f             	gs jb  40d8db <.debug_info+0x8b5>
  40d87c:	73 74                	jae    40d8f2 <.debug_info+0x8cc>
  40d87e:	61                   	popa   
  40d87f:	74 69                	je     40d8ea <.debug_info+0x8c4>
  40d881:	63 00                	arpl   %ax,(%eax)
  40d883:	07                   	pop    %es
  40d884:	14 01                	adc    $0x1,%al
  40d886:	0d ec 00 00 00       	or     $0xec,%eax
  40d88b:	fc                   	cld    
  40d88c:	14 67                	adc    $0x67,%al
  40d88e:	61                   	popa   
  40d88f:	74 68                	je     40d8f9 <.debug_info+0x8d3>
  40d891:	65 72 5f             	gs jb  40d8f3 <.debug_info+0x8cd>
  40d894:	70 65                	jo     40d8fb <.debug_info+0x8d5>
  40d896:	72 5f                	jb     40d8f7 <.debug_info+0x8d1>
  40d898:	65 6c                	gs insb (%dx),%es:(%edi)
  40d89a:	74 00                	je     40d89c <.debug_info+0x876>
  40d89c:	07                   	pop    %es
  40d89d:	14 01                	adc    $0x1,%al
  40d89f:	1c ec                	sbb    $0xec,%al
  40d8a1:	00 00                	add    %al,(%eax)
  40d8a3:	00 00                	add    %al,(%eax)
  40d8a5:	01 14 73             	add    %edx,(%ebx,%esi,2)
  40d8a8:	63 61 74             	arpl   %sp,0x74(%ecx)
  40d8ab:	74 65                	je     40d912 <.debug_info+0x8ec>
  40d8ad:	72 5f                	jb     40d90e <.debug_info+0x8e8>
  40d8af:	73 74                	jae    40d925 <.debug_info+0x8ff>
  40d8b1:	61                   	popa   
  40d8b2:	74 69                	je     40d91d <.debug_info+0x8f7>
  40d8b4:	63 00                	arpl   %ax,(%eax)
  40d8b6:	07                   	pop    %es
  40d8b7:	16                   	push   %ss
  40d8b8:	01 0d ec 00 00 00    	add    %ecx,0xec
  40d8be:	04 01                	add    $0x1,%al
  40d8c0:	14 73                	adc    $0x73,%al
  40d8c2:	63 61 74             	arpl   %sp,0x74(%ecx)
  40d8c5:	74 65                	je     40d92c <.debug_info+0x906>
  40d8c7:	72 5f                	jb     40d928 <.debug_info+0x902>
  40d8c9:	70 65                	jo     40d930 <.debug_info+0x90a>
  40d8cb:	72 5f                	jb     40d92c <.debug_info+0x906>
  40d8cd:	65 6c                	gs insb (%dx),%es:(%edi)
  40d8cf:	74 00                	je     40d8d1 <.debug_info+0x8ab>
  40d8d1:	07                   	pop    %es
  40d8d2:	16                   	push   %ss
  40d8d3:	01 1d ec 00 00 00    	add    %ebx,0xec
  40d8d9:	08 01                	or     %al,(%ecx)
  40d8db:	14 6c                	adc    $0x6c,%al
  40d8dd:	31 5f 63             	xor    %ebx,0x63(%edi)
  40d8e0:	61                   	popa   
  40d8e1:	63 68 65             	arpl   %bp,0x65(%eax)
  40d8e4:	5f                   	pop    %edi
  40d8e5:	73 69                	jae    40d950 <.debug_info+0x92a>
  40d8e7:	7a 65                	jp     40d94e <.debug_info+0x928>
  40d8e9:	00 07                	add    %al,(%edi)
  40d8eb:	18 01                	sbb    %al,(%ecx)
  40d8ed:	0d ec 00 00 00       	or     $0xec,%eax
  40d8f2:	0c 01                	or     $0x1,%al
  40d8f4:	14 6c                	adc    $0x6c,%al
  40d8f6:	32 5f 63             	xor    0x63(%edi),%bl
  40d8f9:	61                   	popa   
  40d8fa:	63 68 65             	arpl   %bp,0x65(%eax)
  40d8fd:	5f                   	pop    %edi
  40d8fe:	73 69                	jae    40d969 <.debug_info+0x943>
  40d900:	7a 65                	jp     40d967 <.debug_info+0x941>
  40d902:	00 07                	add    %al,(%edi)
  40d904:	19 01                	sbb    %eax,(%ecx)
  40d906:	0d ec 00 00 00       	or     $0xec,%eax
  40d90b:	10 01                	adc    %al,(%ecx)
  40d90d:	14 70                	adc    $0x70,%al
  40d90f:	72 65                	jb     40d976 <.debug_info+0x950>
  40d911:	66 65 74 63          	data16 gs je 40d978 <.debug_info+0x952>
  40d915:	68 5f 62 6c 6f       	push   $0x6f6c625f
  40d91a:	63 6b 00             	arpl   %bp,0x0(%ebx)
  40d91d:	07                   	pop    %es
  40d91e:	1a 01                	sbb    (%ecx),%al
  40d920:	0d ec 00 00 00       	or     $0xec,%eax
  40d925:	14 01                	adc    $0x1,%al
  40d927:	14 73                	adc    $0x73,%al
  40d929:	69 6d 75 6c 74 61 6e 	imul   $0x6e61746c,0x75(%ebp),%ebp
  40d930:	65 6f                	outsl  %gs:(%esi),(%dx)
  40d932:	75 73                	jne    40d9a7 <.debug_info+0x981>
  40d934:	5f                   	pop    %edi
  40d935:	70 72                	jo     40d9a9 <.debug_info+0x983>
  40d937:	65 66 65 74 63       	gs data16 gs je 40d99f <.debug_info+0x979>
  40d93c:	68 65 73 00 07       	push   $0x7007365
  40d941:	1b 01                	sbb    (%ecx),%eax
  40d943:	0d ec 00 00 00       	or     $0xec,%eax
  40d948:	18 01                	sbb    %al,(%ecx)
  40d94a:	14 62                	adc    $0x62,%al
  40d94c:	72 61                	jb     40d9af <.debug_info+0x989>
  40d94e:	6e                   	outsb  %ds:(%esi),(%dx)
  40d94f:	63 68 5f             	arpl   %bp,0x5f(%eax)
  40d952:	63 6f 73             	arpl   %bp,0x73(%edi)
  40d955:	74 00                	je     40d957 <.debug_info+0x931>
  40d957:	07                   	pop    %es
  40d958:	1d 01 0d ec 00       	sbb    $0xec0d01,%eax
  40d95d:	00 00                	add    %al,(%eax)
  40d95f:	1c 01                	sbb    $0x1,%al
  40d961:	14 66                	adc    $0x66,%al
  40d963:	61                   	popa   
  40d964:	64 64 00 07          	fs add %al,%fs:(%edi)
  40d968:	1e                   	push   %ds
  40d969:	01 0d ec 00 00 00    	add    %ecx,0xec
  40d96f:	20 01                	and    %al,(%ecx)
  40d971:	14 66                	adc    $0x66,%al
  40d973:	6d                   	insl   (%dx),%es:(%edi)
  40d974:	75 6c                	jne    40d9e2 <.debug_info+0x9bc>
  40d976:	00 07                	add    %al,(%edi)
  40d978:	1f                   	pop    %ds
  40d979:	01 0d ec 00 00 00    	add    %ecx,0xec
  40d97f:	24 01                	and    $0x1,%al
  40d981:	14 66                	adc    $0x66,%al
  40d983:	64 69 76 00 07 20 01 	imul   $0xd012007,%fs:0x0(%esi),%esi
  40d98a:	0d 
  40d98b:	ec                   	in     (%dx),%al
  40d98c:	00 00                	add    %al,(%eax)
  40d98e:	00 28                	add    %ch,(%eax)
  40d990:	01 14 66             	add    %edx,(%esi,%eiz,2)
  40d993:	61                   	popa   
  40d994:	62 73 00             	bound  %esi,0x0(%ebx)
  40d997:	07                   	pop    %es
  40d998:	21 01                	and    %eax,(%ecx)
  40d99a:	0d ec 00 00 00       	or     $0xec,%eax
  40d99f:	2c 01                	sub    $0x1,%al
  40d9a1:	14 66                	adc    $0x66,%al
  40d9a3:	63 68 73             	arpl   %bp,0x73(%eax)
  40d9a6:	00 07                	add    %al,(%edi)
  40d9a8:	22 01                	and    (%ecx),%al
  40d9aa:	0d ec 00 00 00       	or     $0xec,%eax
  40d9af:	30 01                	xor    %al,(%ecx)
  40d9b1:	14 66                	adc    $0x66,%al
  40d9b3:	73 71                	jae    40da26 <.debug_info+0xa00>
  40d9b5:	72 74                	jb     40da2b <.debug_info+0xa05>
  40d9b7:	00 07                	add    %al,(%edi)
  40d9b9:	23 01                	and    (%ecx),%eax
  40d9bb:	0d ec 00 00 00       	or     $0xec,%eax
  40d9c0:	34 01                	xor    $0x1,%al
  40d9c2:	14 73                	adc    $0x73,%al
  40d9c4:	73 65                	jae    40da2b <.debug_info+0xa05>
  40d9c6:	5f                   	pop    %edi
  40d9c7:	6f                   	outsl  %ds:(%esi),(%dx)
  40d9c8:	70 00                	jo     40d9ca <.debug_info+0x9a4>
  40d9ca:	07                   	pop    %es
  40d9cb:	26 01 0d ec 00 00 00 	add    %ecx,%es:0xec
  40d9d2:	38 01                	cmp    %al,(%ecx)
  40d9d4:	14 61                	adc    $0x61,%al
  40d9d6:	64 64 73 73          	fs fs jae 40da4d <.debug_info+0xa27>
  40d9da:	00 07                	add    %al,(%edi)
  40d9dc:	27                   	daa    
  40d9dd:	01 0d ec 00 00 00    	add    %ecx,0xec
  40d9e3:	3c 01                	cmp    $0x1,%al
  40d9e5:	14 6d                	adc    $0x6d,%al
  40d9e7:	75 6c                	jne    40da55 <.debug_info+0xa2f>
  40d9e9:	73 73                	jae    40da5e <.debug_info+0xa38>
  40d9eb:	00 07                	add    %al,(%edi)
  40d9ed:	28 01                	sub    %al,(%ecx)
  40d9ef:	0d ec 00 00 00       	or     $0xec,%eax
  40d9f4:	40                   	inc    %eax
  40d9f5:	01 14 6d 75 6c 73 64 	add    %edx,0x64736c75(,%ebp,2)
  40d9fc:	00 07                	add    %al,(%edi)
  40d9fe:	29 01                	sub    %eax,(%ecx)
  40da00:	0d ec 00 00 00       	or     $0xec,%eax
  40da05:	44                   	inc    %esp
  40da06:	01 14 66             	add    %edx,(%esi,%eiz,2)
  40da09:	6d                   	insl   (%dx),%es:(%edi)
  40da0a:	61                   	popa   
  40da0b:	73 73                	jae    40da80 <.debug_info+0xa5a>
  40da0d:	00 07                	add    %al,(%edi)
  40da0f:	2a 01                	sub    (%ecx),%al
  40da11:	0d ec 00 00 00       	or     $0xec,%eax
  40da16:	48                   	dec    %eax
  40da17:	01 14 66             	add    %edx,(%esi,%eiz,2)
  40da1a:	6d                   	insl   (%dx),%es:(%edi)
  40da1b:	61                   	popa   
  40da1c:	73 64                	jae    40da82 <.debug_info+0xa5c>
  40da1e:	00 07                	add    %al,(%edi)
  40da20:	2b 01                	sub    (%ecx),%eax
  40da22:	0d ec 00 00 00       	or     $0xec,%eax
  40da27:	4c                   	dec    %esp
  40da28:	01 14 64             	add    %edx,(%esp,%eiz,2)
  40da2b:	69 76 73 73 00 07 2c 	imul   $0x2c070073,0x73(%esi),%esi
  40da32:	01 0d ec 00 00 00    	add    %ecx,0xec
  40da38:	50                   	push   %eax
  40da39:	01 14 64             	add    %edx,(%esp,%eiz,2)
  40da3c:	69 76 73 64 00 07 2d 	imul   $0x2d070064,0x73(%esi),%esi
  40da43:	01 0d ec 00 00 00    	add    %ecx,0xec
  40da49:	54                   	push   %esp
  40da4a:	01 14 73             	add    %edx,(%ebx,%esi,2)
  40da4d:	71 72                	jno    40dac1 <.debug_info+0xa9b>
  40da4f:	74 73                	je     40dac4 <.debug_info+0xa9e>
  40da51:	73 00                	jae    40da53 <.debug_info+0xa2d>
  40da53:	07                   	pop    %es
  40da54:	2e 01 0d ec 00 00 00 	add    %ecx,%cs:0xec
  40da5b:	58                   	pop    %eax
  40da5c:	01 14 73             	add    %edx,(%ebx,%esi,2)
  40da5f:	71 72                	jno    40dad3 <.debug_info+0xaad>
  40da61:	74 73                	je     40dad6 <.debug_info+0xab0>
  40da63:	64 00 07             	add    %al,%fs:(%edi)
  40da66:	2f                   	das    
  40da67:	01 0d ec 00 00 00    	add    %ecx,0xec
  40da6d:	5c                   	pop    %esp
  40da6e:	01 14 72             	add    %edx,(%edx,%esi,2)
  40da71:	65 61                	gs popa 
  40da73:	73 73                	jae    40dae8 <.debug_info+0xac2>
  40da75:	6f                   	outsl  %ds:(%esi),(%dx)
  40da76:	63 5f 69             	arpl   %bx,0x69(%edi)
  40da79:	6e                   	outsb  %ds:(%esi),(%dx)
  40da7a:	74 00                	je     40da7c <.debug_info+0xa56>
  40da7c:	07                   	pop    %es
  40da7d:	30 01                	xor    %al,(%ecx)
  40da7f:	0d ec 00 00 00       	or     $0xec,%eax
  40da84:	60                   	pusha  
  40da85:	01 14 72             	add    %edx,(%edx,%esi,2)
  40da88:	65 61                	gs popa 
  40da8a:	73 73                	jae    40daff <.debug_info+0xad9>
  40da8c:	6f                   	outsl  %ds:(%esi),(%dx)
  40da8d:	63 5f 66             	arpl   %bx,0x66(%edi)
  40da90:	70 00                	jo     40da92 <.debug_info+0xa6c>
  40da92:	07                   	pop    %es
  40da93:	30 01                	xor    %al,(%ecx)
  40da95:	1a ec                	sbb    %ah,%ch
  40da97:	00 00                	add    %al,(%eax)
  40da99:	00 64 01 14          	add    %ah,0x14(%ecx,%eax,1)
  40da9d:	72 65                	jb     40db04 <.debug_info+0xade>
  40da9f:	61                   	popa   
  40daa0:	73 73                	jae    40db15 <.debug_info+0xaef>
  40daa2:	6f                   	outsl  %ds:(%esi),(%dx)
  40daa3:	63 5f 76             	arpl   %bx,0x76(%edi)
  40daa6:	65 63 5f 69          	arpl   %bx,%gs:0x69(%edi)
  40daaa:	6e                   	outsb  %ds:(%esi),(%dx)
  40daab:	74 00                	je     40daad <.debug_info+0xa87>
  40daad:	07                   	pop    %es
  40daae:	30 01                	xor    %al,(%ecx)
  40dab0:	26 ec                	es in  (%dx),%al
  40dab2:	00 00                	add    %al,(%eax)
  40dab4:	00 68 01             	add    %ch,0x1(%eax)
  40dab7:	14 72                	adc    $0x72,%al
  40dab9:	65 61                	gs popa 
  40dabb:	73 73                	jae    40db30 <.debug_info+0xb0a>
  40dabd:	6f                   	outsl  %ds:(%esi),(%dx)
  40dabe:	63 5f 76             	arpl   %bx,0x76(%edi)
  40dac1:	65 63 5f 66          	arpl   %bx,%gs:0x66(%edi)
  40dac5:	70 00                	jo     40dac7 <.debug_info+0xaa1>
  40dac7:	07                   	pop    %es
  40dac8:	30 01                	xor    %al,(%ecx)
  40daca:	37                   	aaa    
  40dacb:	ec                   	in     (%dx),%al
  40dacc:	00 00                	add    %al,(%eax)
  40dace:	00 6c 01 14          	add    %ch,0x14(%ecx,%eax,1)
  40dad2:	6d                   	insl   (%dx),%es:(%edi)
  40dad3:	65 6d                	gs insl (%dx),%es:(%edi)
  40dad5:	63 70 79             	arpl   %si,0x79(%eax)
  40dad8:	00 07                	add    %al,(%edi)
  40dada:	37                   	aaa    
  40dadb:	01 19                	add    %ebx,(%ecx)
  40dadd:	b5 0b                	mov    $0xb,%ch
  40dadf:	00 00                	add    %al,(%eax)
  40dae1:	70 01                	jo     40dae4 <.debug_info+0xabe>
  40dae3:	14 6d                	adc    $0x6d,%al
  40dae5:	65 6d                	gs insl (%dx),%es:(%edi)
  40dae7:	73 65                	jae    40db4e <.debug_info+0xb28>
  40dae9:	74 00                	je     40daeb <.debug_info+0xac5>
  40daeb:	07                   	pop    %es
  40daec:	37                   	aaa    
  40daed:	01 22                	add    %esp,(%edx)
  40daef:	b5 0b                	mov    $0xb,%ch
  40daf1:	00 00                	add    %al,(%eax)
  40daf3:	74 01                	je     40daf6 <.debug_info+0xad0>
  40daf5:	14 63                	adc    $0x63,%al
  40daf7:	6f                   	outsl  %ds:(%esi),(%dx)
  40daf8:	6e                   	outsb  %ds:(%esi),(%dx)
  40daf9:	64 5f                	fs pop %edi
  40dafb:	74 61                	je     40db5e <.debug_info+0xb38>
  40dafd:	6b 65 6e 5f          	imul   $0x5f,0x6e(%ebp),%esp
  40db01:	62 72 61             	bound  %esi,0x61(%edx)
  40db04:	6e                   	outsb  %ds:(%esi),(%dx)
  40db05:	63 68 5f             	arpl   %bp,0x5f(%eax)
  40db08:	63 6f 73             	arpl   %bp,0x73(%edi)
  40db0b:	74 00                	je     40db0d <.debug_info+0xae7>
  40db0d:	07                   	pop    %es
  40db0e:	38 01                	cmp    %al,(%ecx)
  40db10:	0d ec 00 00 00       	or     $0xec,%eax
  40db15:	78 01                	js     40db18 <.debug_info+0xaf2>
  40db17:	14 63                	adc    $0x63,%al
  40db19:	6f                   	outsl  %ds:(%esi),(%dx)
  40db1a:	6e                   	outsb  %ds:(%esi),(%dx)
  40db1b:	64 5f                	fs pop %edi
  40db1d:	6e                   	outsb  %ds:(%esi),(%dx)
  40db1e:	6f                   	outsl  %ds:(%esi),(%dx)
  40db1f:	74 5f                	je     40db80 <.debug_info+0xb5a>
  40db21:	74 61                	je     40db84 <.debug_info+0xb5e>
  40db23:	6b 65 6e 5f          	imul   $0x5f,0x6e(%ebp),%esp
  40db27:	62 72 61             	bound  %esi,0x61(%edx)
  40db2a:	6e                   	outsb  %ds:(%esi),(%dx)
  40db2b:	63 68 5f             	arpl   %bp,0x5f(%eax)
  40db2e:	63 6f 73             	arpl   %bp,0x73(%edi)
  40db31:	74 00                	je     40db33 <.debug_info+0xb0d>
  40db33:	07                   	pop    %es
  40db34:	3a 01                	cmp    (%ecx),%al
  40db36:	0d ec 00 00 00       	or     $0xec,%eax
  40db3b:	7c 01                	jl     40db3e <.debug_info+0xb18>
  40db3d:	14 61                	adc    $0x61,%al
  40db3f:	6c                   	insb   (%dx),%es:(%edi)
  40db40:	69 67 6e 5f 6c 6f 6f 	imul   $0x6f6f6c5f,0x6e(%edi),%esp
  40db47:	70 00                	jo     40db49 <.debug_info+0xb23>
  40db49:	07                   	pop    %es
  40db4a:	40                   	inc    %eax
  40db4b:	01 15 27 05 00 00    	add    %edx,0x527
  40db51:	80 01 14             	addb   $0x14,(%ecx)
  40db54:	61                   	popa   
  40db55:	6c                   	insb   (%dx),%es:(%edi)
  40db56:	69 67 6e 5f 6a 75 6d 	imul   $0x6d756a5f,0x6e(%edi),%esp
  40db5d:	70 00                	jo     40db5f <.debug_info+0xb39>
  40db5f:	07                   	pop    %es
  40db60:	41                   	inc    %ecx
  40db61:	01 15 27 05 00 00    	add    %edx,0x527
  40db67:	84 01                	test   %al,(%ecx)
  40db69:	14 61                	adc    $0x61,%al
  40db6b:	6c                   	insb   (%dx),%es:(%edi)
  40db6c:	69 67 6e 5f 6c 61 62 	imul   $0x62616c5f,0x6e(%edi),%esp
  40db73:	65 6c                	gs insb (%dx),%es:(%edi)
  40db75:	00 07                	add    %al,(%edi)
  40db77:	42                   	inc    %edx
  40db78:	01 15 27 05 00 00    	add    %edx,0x527
  40db7e:	88 01                	mov    %al,(%ecx)
  40db80:	14 61                	adc    $0x61,%al
  40db82:	6c                   	insb   (%dx),%es:(%edi)
  40db83:	69 67 6e 5f 66 75 6e 	imul   $0x6e75665f,0x6e(%edi),%esp
  40db8a:	63 00                	arpl   %ax,(%eax)
  40db8c:	07                   	pop    %es
  40db8d:	43                   	inc    %ebx
  40db8e:	01 15 27 05 00 00    	add    %edx,0x527
  40db94:	8c 01                	mov    %es,(%ecx)
  40db96:	00 03                	add    %al,(%ebx)
  40db98:	fa                   	cli    
  40db99:	05 00 00 08 ec       	add    $0xec080000,%eax
  40db9e:	00 00                	add    %al,(%eax)
  40dba0:	00 86 0b 00 00 0c    	add    %al,0xc00000b(%esi)
  40dba6:	f1                   	icebp  
  40dba7:	00 00                	add    %al,(%eax)
  40dba9:	00 04 00             	add    %al,(%eax,%eax,1)
  40dbac:	03 76 0b             	add    0xb(%esi),%esi
  40dbaf:	00 00                	add    %al,(%eax)
  40dbb1:	08 ec                	or     %ch,%ah
  40dbb3:	00 00                	add    %al,(%eax)
  40dbb5:	00 9b 0b 00 00 0c    	add    %bl,0xc00000b(%ebx)
  40dbbb:	f1                   	icebp  
  40dbbc:	00 00                	add    %al,(%eax)
  40dbbe:	00 02                	add    %al,(%edx)
  40dbc0:	00 03                	add    %al,(%ebx)
  40dbc2:	8b 0b                	mov    (%ebx),%ecx
  40dbc4:	00 00                	add    %al,(%eax)
  40dbc6:	08 ec                	or     %ch,%ah
  40dbc8:	00 00                	add    %al,(%eax)
  40dbca:	00 b0 0b 00 00 0c    	add    %dh,0xc00000b(%eax)
  40dbd0:	f1                   	icebp  
  40dbd1:	00 00                	add    %al,(%eax)
  40dbd3:	00 01                	add    %al,(%ecx)
  40dbd5:	00 03                	add    %al,(%ebx)
  40dbd7:	a0 0b 00 00 06       	mov    0x600000b,%al
  40dbdc:	04 a9                	add    $0xa9,%al
  40dbde:	05 00 00 0b 69       	add    $0x690b0000,%eax
  40dbe3:	78 38                	js     40dc1d <.debug_info+0xbf7>
  40dbe5:	36 5f                	ss pop %edi
  40dbe7:	63 6f 73             	arpl   %bp,0x73(%edi)
  40dbea:	74 00                	je     40dbec <.debug_info+0xbc6>
  40dbec:	07                   	pop    %es
  40dbed:	46                   	inc    %esi
  40dbee:	01 26                	add    %esp,(%esi)
  40dbf0:	ce                   	into   
  40dbf1:	0b 00                	or     (%eax),%eax
  40dbf3:	00 06                	add    %al,(%esi)
  40dbf5:	04 71                	add    $0x71,%al
  40dbf7:	0b 00                	or     (%eax),%eax
  40dbf9:	00 0b                	add    %cl,(%ebx)
  40dbfb:	69 78 38 36 5f 73 69 	imul   $0x69735f36,0x38(%eax),%edi
  40dc02:	7a 65                	jp     40dc69 <.debug_info+0xc43>
  40dc04:	5f                   	pop    %edi
  40dc05:	63 6f 73             	arpl   %bp,0x73(%edi)
  40dc08:	74 00                	je     40dc0a <.debug_info+0xbe4>
  40dc0a:	07                   	pop    %es
  40dc0b:	47                   	inc    %edi
  40dc0c:	01 25 71 0b 00 00    	add    %esp,0xb71
  40dc12:	15 69 78 38 36       	adc    $0x36387869,%eax
  40dc17:	5f                   	pop    %edi
  40dc18:	74 75                	je     40dc8f <.debug_info+0xc69>
  40dc1a:	6e                   	outsb  %ds:(%esi),(%dx)
  40dc1b:	65 5f                	gs pop %edi
  40dc1d:	69 6e 64 69 63 65 73 	imul   $0x73656369,0x64(%esi),%ebp
  40dc24:	00 07                	add    %al,(%edi)
  40dc26:	04 f1                	add    $0xf1,%al
  40dc28:	00 00                	add    %al,(%eax)
  40dc2a:	00 07                	add    %al,(%edi)
  40dc2c:	a8 01                	test   $0x1,%al
  40dc2e:	06                   	push   %es
  40dc2f:	2d 16 00 00 11       	sub    $0x11000016,%eax
  40dc34:	58                   	pop    %eax
  40dc35:	38 36                	cmp    %dh,(%esi)
  40dc37:	5f                   	pop    %edi
  40dc38:	54                   	push   %esp
  40dc39:	55                   	push   %ebp
  40dc3a:	4e                   	dec    %esi
  40dc3b:	45                   	inc    %ebp
  40dc3c:	5f                   	pop    %edi
  40dc3d:	53                   	push   %ebx
  40dc3e:	43                   	inc    %ebx
  40dc3f:	48                   	dec    %eax
  40dc40:	45                   	inc    %ebp
  40dc41:	44                   	inc    %esp
  40dc42:	55                   	push   %ebp
  40dc43:	4c                   	dec    %esp
  40dc44:	45                   	inc    %ebp
  40dc45:	00 00                	add    %al,(%eax)
  40dc47:	11 58 38             	adc    %ebx,0x38(%eax)
  40dc4a:	36 5f                	ss pop %edi
  40dc4c:	54                   	push   %esp
  40dc4d:	55                   	push   %ebp
  40dc4e:	4e                   	dec    %esi
  40dc4f:	45                   	inc    %ebp
  40dc50:	5f                   	pop    %edi
  40dc51:	50                   	push   %eax
  40dc52:	41                   	inc    %ecx
  40dc53:	52                   	push   %edx
  40dc54:	54                   	push   %esp
  40dc55:	49                   	dec    %ecx
  40dc56:	41                   	inc    %ecx
  40dc57:	4c                   	dec    %esp
  40dc58:	5f                   	pop    %edi
  40dc59:	52                   	push   %edx
  40dc5a:	45                   	inc    %ebp
  40dc5b:	47                   	inc    %edi
  40dc5c:	5f                   	pop    %edi
  40dc5d:	44                   	inc    %esp
  40dc5e:	45                   	inc    %ebp
  40dc5f:	50                   	push   %eax
  40dc60:	45                   	inc    %ebp
  40dc61:	4e                   	dec    %esi
  40dc62:	44                   	inc    %esp
  40dc63:	45                   	inc    %ebp
  40dc64:	4e                   	dec    %esi
  40dc65:	43                   	inc    %ebx
  40dc66:	59                   	pop    %ecx
  40dc67:	00 01                	add    %al,(%ecx)
  40dc69:	11 58 38             	adc    %ebx,0x38(%eax)
  40dc6c:	36 5f                	ss pop %edi
  40dc6e:	54                   	push   %esp
  40dc6f:	55                   	push   %ebp
  40dc70:	4e                   	dec    %esi
  40dc71:	45                   	inc    %ebp
  40dc72:	5f                   	pop    %edi
  40dc73:	53                   	push   %ebx
  40dc74:	53                   	push   %ebx
  40dc75:	45                   	inc    %ebp
  40dc76:	5f                   	pop    %edi
  40dc77:	50                   	push   %eax
  40dc78:	41                   	inc    %ecx
  40dc79:	52                   	push   %edx
  40dc7a:	54                   	push   %esp
  40dc7b:	49                   	dec    %ecx
  40dc7c:	41                   	inc    %ecx
  40dc7d:	4c                   	dec    %esp
  40dc7e:	5f                   	pop    %edi
  40dc7f:	52                   	push   %edx
  40dc80:	45                   	inc    %ebp
  40dc81:	47                   	inc    %edi
  40dc82:	5f                   	pop    %edi
  40dc83:	44                   	inc    %esp
  40dc84:	45                   	inc    %ebp
  40dc85:	50                   	push   %eax
  40dc86:	45                   	inc    %ebp
  40dc87:	4e                   	dec    %esi
  40dc88:	44                   	inc    %esp
  40dc89:	45                   	inc    %ebp
  40dc8a:	4e                   	dec    %esi
  40dc8b:	43                   	inc    %ebx
  40dc8c:	59                   	pop    %ecx
  40dc8d:	00 02                	add    %al,(%edx)
  40dc8f:	11 58 38             	adc    %ebx,0x38(%eax)
  40dc92:	36 5f                	ss pop %edi
  40dc94:	54                   	push   %esp
  40dc95:	55                   	push   %ebp
  40dc96:	4e                   	dec    %esi
  40dc97:	45                   	inc    %ebp
  40dc98:	5f                   	pop    %edi
  40dc99:	53                   	push   %ebx
  40dc9a:	53                   	push   %ebx
  40dc9b:	45                   	inc    %ebp
  40dc9c:	5f                   	pop    %edi
  40dc9d:	53                   	push   %ebx
  40dc9e:	50                   	push   %eax
  40dc9f:	4c                   	dec    %esp
  40dca0:	49                   	dec    %ecx
  40dca1:	54                   	push   %esp
  40dca2:	5f                   	pop    %edi
  40dca3:	52                   	push   %edx
  40dca4:	45                   	inc    %ebp
  40dca5:	47                   	inc    %edi
  40dca6:	53                   	push   %ebx
  40dca7:	00 03                	add    %al,(%ebx)
  40dca9:	11 58 38             	adc    %ebx,0x38(%eax)
  40dcac:	36 5f                	ss pop %edi
  40dcae:	54                   	push   %esp
  40dcaf:	55                   	push   %ebp
  40dcb0:	4e                   	dec    %esi
  40dcb1:	45                   	inc    %ebp
  40dcb2:	5f                   	pop    %edi
  40dcb3:	50                   	push   %eax
  40dcb4:	41                   	inc    %ecx
  40dcb5:	52                   	push   %edx
  40dcb6:	54                   	push   %esp
  40dcb7:	49                   	dec    %ecx
  40dcb8:	41                   	inc    %ecx
  40dcb9:	4c                   	dec    %esp
  40dcba:	5f                   	pop    %edi
  40dcbb:	46                   	inc    %esi
  40dcbc:	4c                   	dec    %esp
  40dcbd:	41                   	inc    %ecx
  40dcbe:	47                   	inc    %edi
  40dcbf:	5f                   	pop    %edi
  40dcc0:	52                   	push   %edx
  40dcc1:	45                   	inc    %ebp
  40dcc2:	47                   	inc    %edi
  40dcc3:	5f                   	pop    %edi
  40dcc4:	53                   	push   %ebx
  40dcc5:	54                   	push   %esp
  40dcc6:	41                   	inc    %ecx
  40dcc7:	4c                   	dec    %esp
  40dcc8:	4c                   	dec    %esp
  40dcc9:	00 04 11             	add    %al,(%ecx,%edx,1)
  40dccc:	58                   	pop    %eax
  40dccd:	38 36                	cmp    %dh,(%esi)
  40dccf:	5f                   	pop    %edi
  40dcd0:	54                   	push   %esp
  40dcd1:	55                   	push   %ebp
  40dcd2:	4e                   	dec    %esi
  40dcd3:	45                   	inc    %ebp
  40dcd4:	5f                   	pop    %edi
  40dcd5:	4d                   	dec    %ebp
  40dcd6:	4f                   	dec    %edi
  40dcd7:	56                   	push   %esi
  40dcd8:	58                   	pop    %eax
  40dcd9:	00 05 11 58 38 36    	add    %al,0x36385811
  40dcdf:	5f                   	pop    %edi
  40dce0:	54                   	push   %esp
  40dce1:	55                   	push   %ebp
  40dce2:	4e                   	dec    %esi
  40dce3:	45                   	inc    %ebp
  40dce4:	5f                   	pop    %edi
  40dce5:	4d                   	dec    %ebp
  40dce6:	45                   	inc    %ebp
  40dce7:	4d                   	dec    %ebp
  40dce8:	4f                   	dec    %edi
  40dce9:	52                   	push   %edx
  40dcea:	59                   	pop    %ecx
  40dceb:	5f                   	pop    %edi
  40dcec:	4d                   	dec    %ebp
  40dced:	49                   	dec    %ecx
  40dcee:	53                   	push   %ebx
  40dcef:	4d                   	dec    %ebp
  40dcf0:	41                   	inc    %ecx
  40dcf1:	54                   	push   %esp
  40dcf2:	43                   	inc    %ebx
  40dcf3:	48                   	dec    %eax
  40dcf4:	5f                   	pop    %edi
  40dcf5:	53                   	push   %ebx
  40dcf6:	54                   	push   %esp
  40dcf7:	41                   	inc    %ecx
  40dcf8:	4c                   	dec    %esp
  40dcf9:	4c                   	dec    %esp
  40dcfa:	00 06                	add    %al,(%esi)
  40dcfc:	11 58 38             	adc    %ebx,0x38(%eax)
  40dcff:	36 5f                	ss pop %edi
  40dd01:	54                   	push   %esp
  40dd02:	55                   	push   %ebp
  40dd03:	4e                   	dec    %esi
  40dd04:	45                   	inc    %ebp
  40dd05:	5f                   	pop    %edi
  40dd06:	46                   	inc    %esi
  40dd07:	55                   	push   %ebp
  40dd08:	53                   	push   %ebx
  40dd09:	45                   	inc    %ebp
  40dd0a:	5f                   	pop    %edi
  40dd0b:	43                   	inc    %ebx
  40dd0c:	4d                   	dec    %ebp
  40dd0d:	50                   	push   %eax
  40dd0e:	5f                   	pop    %edi
  40dd0f:	41                   	inc    %ecx
  40dd10:	4e                   	dec    %esi
  40dd11:	44                   	inc    %esp
  40dd12:	5f                   	pop    %edi
  40dd13:	42                   	inc    %edx
  40dd14:	52                   	push   %edx
  40dd15:	41                   	inc    %ecx
  40dd16:	4e                   	dec    %esi
  40dd17:	43                   	inc    %ebx
  40dd18:	48                   	dec    %eax
  40dd19:	5f                   	pop    %edi
  40dd1a:	33 32                	xor    (%edx),%esi
  40dd1c:	00 07                	add    %al,(%edi)
  40dd1e:	11 58 38             	adc    %ebx,0x38(%eax)
  40dd21:	36 5f                	ss pop %edi
  40dd23:	54                   	push   %esp
  40dd24:	55                   	push   %ebp
  40dd25:	4e                   	dec    %esi
  40dd26:	45                   	inc    %ebp
  40dd27:	5f                   	pop    %edi
  40dd28:	46                   	inc    %esi
  40dd29:	55                   	push   %ebp
  40dd2a:	53                   	push   %ebx
  40dd2b:	45                   	inc    %ebp
  40dd2c:	5f                   	pop    %edi
  40dd2d:	43                   	inc    %ebx
  40dd2e:	4d                   	dec    %ebp
  40dd2f:	50                   	push   %eax
  40dd30:	5f                   	pop    %edi
  40dd31:	41                   	inc    %ecx
  40dd32:	4e                   	dec    %esi
  40dd33:	44                   	inc    %esp
  40dd34:	5f                   	pop    %edi
  40dd35:	42                   	inc    %edx
  40dd36:	52                   	push   %edx
  40dd37:	41                   	inc    %ecx
  40dd38:	4e                   	dec    %esi
  40dd39:	43                   	inc    %ebx
  40dd3a:	48                   	dec    %eax
  40dd3b:	5f                   	pop    %edi
  40dd3c:	36 34 00             	ss xor $0x0,%al
  40dd3f:	08 11                	or     %dl,(%ecx)
  40dd41:	58                   	pop    %eax
  40dd42:	38 36                	cmp    %dh,(%esi)
  40dd44:	5f                   	pop    %edi
  40dd45:	54                   	push   %esp
  40dd46:	55                   	push   %ebp
  40dd47:	4e                   	dec    %esi
  40dd48:	45                   	inc    %ebp
  40dd49:	5f                   	pop    %edi
  40dd4a:	46                   	inc    %esi
  40dd4b:	55                   	push   %ebp
  40dd4c:	53                   	push   %ebx
  40dd4d:	45                   	inc    %ebp
  40dd4e:	5f                   	pop    %edi
  40dd4f:	43                   	inc    %ebx
  40dd50:	4d                   	dec    %ebp
  40dd51:	50                   	push   %eax
  40dd52:	5f                   	pop    %edi
  40dd53:	41                   	inc    %ecx
  40dd54:	4e                   	dec    %esi
  40dd55:	44                   	inc    %esp
  40dd56:	5f                   	pop    %edi
  40dd57:	42                   	inc    %edx
  40dd58:	52                   	push   %edx
  40dd59:	41                   	inc    %ecx
  40dd5a:	4e                   	dec    %esi
  40dd5b:	43                   	inc    %ebx
  40dd5c:	48                   	dec    %eax
  40dd5d:	5f                   	pop    %edi
  40dd5e:	53                   	push   %ebx
  40dd5f:	4f                   	dec    %edi
  40dd60:	46                   	inc    %esi
  40dd61:	4c                   	dec    %esp
  40dd62:	41                   	inc    %ecx
  40dd63:	47                   	inc    %edi
  40dd64:	53                   	push   %ebx
  40dd65:	00 09                	add    %cl,(%ecx)
  40dd67:	11 58 38             	adc    %ebx,0x38(%eax)
  40dd6a:	36 5f                	ss pop %edi
  40dd6c:	54                   	push   %esp
  40dd6d:	55                   	push   %ebp
  40dd6e:	4e                   	dec    %esi
  40dd6f:	45                   	inc    %ebp
  40dd70:	5f                   	pop    %edi
  40dd71:	46                   	inc    %esi
  40dd72:	55                   	push   %ebp
  40dd73:	53                   	push   %ebx
  40dd74:	45                   	inc    %ebp
  40dd75:	5f                   	pop    %edi
  40dd76:	41                   	inc    %ecx
  40dd77:	4c                   	dec    %esp
  40dd78:	55                   	push   %ebp
  40dd79:	5f                   	pop    %edi
  40dd7a:	41                   	inc    %ecx
  40dd7b:	4e                   	dec    %esi
  40dd7c:	44                   	inc    %esp
  40dd7d:	5f                   	pop    %edi
  40dd7e:	42                   	inc    %edx
  40dd7f:	52                   	push   %edx
  40dd80:	41                   	inc    %ecx
  40dd81:	4e                   	dec    %esi
  40dd82:	43                   	inc    %ebx
  40dd83:	48                   	dec    %eax
  40dd84:	00 0a                	add    %cl,(%edx)
  40dd86:	11 58 38             	adc    %ebx,0x38(%eax)
  40dd89:	36 5f                	ss pop %edi
  40dd8b:	54                   	push   %esp
  40dd8c:	55                   	push   %ebp
  40dd8d:	4e                   	dec    %esi
  40dd8e:	45                   	inc    %ebp
  40dd8f:	5f                   	pop    %edi
  40dd90:	41                   	inc    %ecx
  40dd91:	43                   	inc    %ebx
  40dd92:	43                   	inc    %ebx
  40dd93:	55                   	push   %ebp
  40dd94:	4d                   	dec    %ebp
  40dd95:	55                   	push   %ebp
  40dd96:	4c                   	dec    %esp
  40dd97:	41                   	inc    %ecx
  40dd98:	54                   	push   %esp
  40dd99:	45                   	inc    %ebp
  40dd9a:	5f                   	pop    %edi
  40dd9b:	4f                   	dec    %edi
  40dd9c:	55                   	push   %ebp
  40dd9d:	54                   	push   %esp
  40dd9e:	47                   	inc    %edi
  40dd9f:	4f                   	dec    %edi
  40dda0:	49                   	dec    %ecx
  40dda1:	4e                   	dec    %esi
  40dda2:	47                   	inc    %edi
  40dda3:	5f                   	pop    %edi
  40dda4:	41                   	inc    %ecx
  40dda5:	52                   	push   %edx
  40dda6:	47                   	inc    %edi
  40dda7:	53                   	push   %ebx
  40dda8:	00 0b                	add    %cl,(%ebx)
  40ddaa:	11 58 38             	adc    %ebx,0x38(%eax)
  40ddad:	36 5f                	ss pop %edi
  40ddaf:	54                   	push   %esp
  40ddb0:	55                   	push   %ebp
  40ddb1:	4e                   	dec    %esi
  40ddb2:	45                   	inc    %ebp
  40ddb3:	5f                   	pop    %edi
  40ddb4:	50                   	push   %eax
  40ddb5:	52                   	push   %edx
  40ddb6:	4f                   	dec    %edi
  40ddb7:	4c                   	dec    %esp
  40ddb8:	4f                   	dec    %edi
  40ddb9:	47                   	inc    %edi
  40ddba:	55                   	push   %ebp
  40ddbb:	45                   	inc    %ebp
  40ddbc:	5f                   	pop    %edi
  40ddbd:	55                   	push   %ebp
  40ddbe:	53                   	push   %ebx
  40ddbf:	49                   	dec    %ecx
  40ddc0:	4e                   	dec    %esi
  40ddc1:	47                   	inc    %edi
  40ddc2:	5f                   	pop    %edi
  40ddc3:	4d                   	dec    %ebp
  40ddc4:	4f                   	dec    %edi
  40ddc5:	56                   	push   %esi
  40ddc6:	45                   	inc    %ebp
  40ddc7:	00 0c 11             	add    %cl,(%ecx,%edx,1)
  40ddca:	58                   	pop    %eax
  40ddcb:	38 36                	cmp    %dh,(%esi)
  40ddcd:	5f                   	pop    %edi
  40ddce:	54                   	push   %esp
  40ddcf:	55                   	push   %ebp
  40ddd0:	4e                   	dec    %esi
  40ddd1:	45                   	inc    %ebp
  40ddd2:	5f                   	pop    %edi
  40ddd3:	45                   	inc    %ebp
  40ddd4:	50                   	push   %eax
  40ddd5:	49                   	dec    %ecx
  40ddd6:	4c                   	dec    %esp
  40ddd7:	4f                   	dec    %edi
  40ddd8:	47                   	inc    %edi
  40ddd9:	55                   	push   %ebp
  40ddda:	45                   	inc    %ebp
  40dddb:	5f                   	pop    %edi
  40dddc:	55                   	push   %ebp
  40dddd:	53                   	push   %ebx
  40ddde:	49                   	dec    %ecx
  40dddf:	4e                   	dec    %esi
  40dde0:	47                   	inc    %edi
  40dde1:	5f                   	pop    %edi
  40dde2:	4d                   	dec    %ebp
  40dde3:	4f                   	dec    %edi
  40dde4:	56                   	push   %esi
  40dde5:	45                   	inc    %ebp
  40dde6:	00 0d 11 58 38 36    	add    %cl,0x36385811
  40ddec:	5f                   	pop    %edi
  40dded:	54                   	push   %esp
  40ddee:	55                   	push   %ebp
  40ddef:	4e                   	dec    %esi
  40ddf0:	45                   	inc    %ebp
  40ddf1:	5f                   	pop    %edi
  40ddf2:	55                   	push   %ebp
  40ddf3:	53                   	push   %ebx
  40ddf4:	45                   	inc    %ebp
  40ddf5:	5f                   	pop    %edi
  40ddf6:	4c                   	dec    %esp
  40ddf7:	45                   	inc    %ebp
  40ddf8:	41                   	inc    %ecx
  40ddf9:	56                   	push   %esi
  40ddfa:	45                   	inc    %ebp
  40ddfb:	00 0e                	add    %cl,(%esi)
  40ddfd:	11 58 38             	adc    %ebx,0x38(%eax)
  40de00:	36 5f                	ss pop %edi
  40de02:	54                   	push   %esp
  40de03:	55                   	push   %ebp
  40de04:	4e                   	dec    %esi
  40de05:	45                   	inc    %ebp
  40de06:	5f                   	pop    %edi
  40de07:	50                   	push   %eax
  40de08:	55                   	push   %ebp
  40de09:	53                   	push   %ebx
  40de0a:	48                   	dec    %eax
  40de0b:	5f                   	pop    %edi
  40de0c:	4d                   	dec    %ebp
  40de0d:	45                   	inc    %ebp
  40de0e:	4d                   	dec    %ebp
  40de0f:	4f                   	dec    %edi
  40de10:	52                   	push   %edx
  40de11:	59                   	pop    %ecx
  40de12:	00 0f                	add    %cl,(%edi)
  40de14:	11 58 38             	adc    %ebx,0x38(%eax)
  40de17:	36 5f                	ss pop %edi
  40de19:	54                   	push   %esp
  40de1a:	55                   	push   %ebp
  40de1b:	4e                   	dec    %esi
  40de1c:	45                   	inc    %ebp
  40de1d:	5f                   	pop    %edi
  40de1e:	53                   	push   %ebx
  40de1f:	49                   	dec    %ecx
  40de20:	4e                   	dec    %esi
  40de21:	47                   	inc    %edi
  40de22:	4c                   	dec    %esp
  40de23:	45                   	inc    %ebp
  40de24:	5f                   	pop    %edi
  40de25:	50                   	push   %eax
  40de26:	55                   	push   %ebp
  40de27:	53                   	push   %ebx
  40de28:	48                   	dec    %eax
  40de29:	00 10                	add    %dl,(%eax)
  40de2b:	11 58 38             	adc    %ebx,0x38(%eax)
  40de2e:	36 5f                	ss pop %edi
  40de30:	54                   	push   %esp
  40de31:	55                   	push   %ebp
  40de32:	4e                   	dec    %esi
  40de33:	45                   	inc    %ebp
  40de34:	5f                   	pop    %edi
  40de35:	44                   	inc    %esp
  40de36:	4f                   	dec    %edi
  40de37:	55                   	push   %ebp
  40de38:	42                   	inc    %edx
  40de39:	4c                   	dec    %esp
  40de3a:	45                   	inc    %ebp
  40de3b:	5f                   	pop    %edi
  40de3c:	50                   	push   %eax
  40de3d:	55                   	push   %ebp
  40de3e:	53                   	push   %ebx
  40de3f:	48                   	dec    %eax
  40de40:	00 11                	add    %dl,(%ecx)
  40de42:	11 58 38             	adc    %ebx,0x38(%eax)
  40de45:	36 5f                	ss pop %edi
  40de47:	54                   	push   %esp
  40de48:	55                   	push   %ebp
  40de49:	4e                   	dec    %esi
  40de4a:	45                   	inc    %ebp
  40de4b:	5f                   	pop    %edi
  40de4c:	53                   	push   %ebx
  40de4d:	49                   	dec    %ecx
  40de4e:	4e                   	dec    %esi
  40de4f:	47                   	inc    %edi
  40de50:	4c                   	dec    %esp
  40de51:	45                   	inc    %ebp
  40de52:	5f                   	pop    %edi
  40de53:	50                   	push   %eax
  40de54:	4f                   	dec    %edi
  40de55:	50                   	push   %eax
  40de56:	00 12                	add    %dl,(%edx)
  40de58:	11 58 38             	adc    %ebx,0x38(%eax)
  40de5b:	36 5f                	ss pop %edi
  40de5d:	54                   	push   %esp
  40de5e:	55                   	push   %ebp
  40de5f:	4e                   	dec    %esi
  40de60:	45                   	inc    %ebp
  40de61:	5f                   	pop    %edi
  40de62:	44                   	inc    %esp
  40de63:	4f                   	dec    %edi
  40de64:	55                   	push   %ebp
  40de65:	42                   	inc    %edx
  40de66:	4c                   	dec    %esp
  40de67:	45                   	inc    %ebp
  40de68:	5f                   	pop    %edi
  40de69:	50                   	push   %eax
  40de6a:	4f                   	dec    %edi
  40de6b:	50                   	push   %eax
  40de6c:	00 13                	add    %dl,(%ebx)
  40de6e:	11 58 38             	adc    %ebx,0x38(%eax)
  40de71:	36 5f                	ss pop %edi
  40de73:	54                   	push   %esp
  40de74:	55                   	push   %ebp
  40de75:	4e                   	dec    %esi
  40de76:	45                   	inc    %ebp
  40de77:	5f                   	pop    %edi
  40de78:	50                   	push   %eax
  40de79:	41                   	inc    %ecx
  40de7a:	44                   	inc    %esp
  40de7b:	5f                   	pop    %edi
  40de7c:	53                   	push   %ebx
  40de7d:	48                   	dec    %eax
  40de7e:	4f                   	dec    %edi
  40de7f:	52                   	push   %edx
  40de80:	54                   	push   %esp
  40de81:	5f                   	pop    %edi
  40de82:	46                   	inc    %esi
  40de83:	55                   	push   %ebp
  40de84:	4e                   	dec    %esi
  40de85:	43                   	inc    %ebx
  40de86:	54                   	push   %esp
  40de87:	49                   	dec    %ecx
  40de88:	4f                   	dec    %edi
  40de89:	4e                   	dec    %esi
  40de8a:	00 14 11             	add    %dl,(%ecx,%edx,1)
  40de8d:	58                   	pop    %eax
  40de8e:	38 36                	cmp    %dh,(%esi)
  40de90:	5f                   	pop    %edi
  40de91:	54                   	push   %esp
  40de92:	55                   	push   %ebp
  40de93:	4e                   	dec    %esi
  40de94:	45                   	inc    %ebp
  40de95:	5f                   	pop    %edi
  40de96:	50                   	push   %eax
  40de97:	41                   	inc    %ecx
  40de98:	44                   	inc    %esp
  40de99:	5f                   	pop    %edi
  40de9a:	52                   	push   %edx
  40de9b:	45                   	inc    %ebp
  40de9c:	54                   	push   %esp
  40de9d:	55                   	push   %ebp
  40de9e:	52                   	push   %edx
  40de9f:	4e                   	dec    %esi
  40dea0:	53                   	push   %ebx
  40dea1:	00 15 11 58 38 36    	add    %dl,0x36385811
  40dea7:	5f                   	pop    %edi
  40dea8:	54                   	push   %esp
  40dea9:	55                   	push   %ebp
  40deaa:	4e                   	dec    %esi
  40deab:	45                   	inc    %ebp
  40deac:	5f                   	pop    %edi
  40dead:	46                   	inc    %esi
  40deae:	4f                   	dec    %edi
  40deaf:	55                   	push   %ebp
  40deb0:	52                   	push   %edx
  40deb1:	5f                   	pop    %edi
  40deb2:	4a                   	dec    %edx
  40deb3:	55                   	push   %ebp
  40deb4:	4d                   	dec    %ebp
  40deb5:	50                   	push   %eax
  40deb6:	5f                   	pop    %edi
  40deb7:	4c                   	dec    %esp
  40deb8:	49                   	dec    %ecx
  40deb9:	4d                   	dec    %ebp
  40deba:	49                   	dec    %ecx
  40debb:	54                   	push   %esp
  40debc:	00 16                	add    %dl,(%esi)
  40debe:	11 58 38             	adc    %ebx,0x38(%eax)
  40dec1:	36 5f                	ss pop %edi
  40dec3:	54                   	push   %esp
  40dec4:	55                   	push   %ebp
  40dec5:	4e                   	dec    %esi
  40dec6:	45                   	inc    %ebp
  40dec7:	5f                   	pop    %edi
  40dec8:	53                   	push   %ebx
  40dec9:	4f                   	dec    %edi
  40deca:	46                   	inc    %esi
  40decb:	54                   	push   %esp
  40decc:	57                   	push   %edi
  40decd:	41                   	inc    %ecx
  40dece:	52                   	push   %edx
  40decf:	45                   	inc    %ebp
  40ded0:	5f                   	pop    %edi
  40ded1:	50                   	push   %eax
  40ded2:	52                   	push   %edx
  40ded3:	45                   	inc    %ebp
  40ded4:	46                   	inc    %esi
  40ded5:	45                   	inc    %ebp
  40ded6:	54                   	push   %esp
  40ded7:	43                   	inc    %ebx
  40ded8:	48                   	dec    %eax
  40ded9:	49                   	dec    %ecx
  40deda:	4e                   	dec    %esi
  40dedb:	47                   	inc    %edi
  40dedc:	5f                   	pop    %edi
  40dedd:	42                   	inc    %edx
  40dede:	45                   	inc    %ebp
  40dedf:	4e                   	dec    %esi
  40dee0:	45                   	inc    %ebp
  40dee1:	46                   	inc    %esi
  40dee2:	49                   	dec    %ecx
  40dee3:	43                   	inc    %ebx
  40dee4:	49                   	dec    %ecx
  40dee5:	41                   	inc    %ecx
  40dee6:	4c                   	dec    %esp
  40dee7:	00 17                	add    %dl,(%edi)
  40dee9:	11 58 38             	adc    %ebx,0x38(%eax)
  40deec:	36 5f                	ss pop %edi
  40deee:	54                   	push   %esp
  40deef:	55                   	push   %ebp
  40def0:	4e                   	dec    %esi
  40def1:	45                   	inc    %ebp
  40def2:	5f                   	pop    %edi
  40def3:	4c                   	dec    %esp
  40def4:	43                   	inc    %ebx
  40def5:	50                   	push   %eax
  40def6:	5f                   	pop    %edi
  40def7:	53                   	push   %ebx
  40def8:	54                   	push   %esp
  40def9:	41                   	inc    %ecx
  40defa:	4c                   	dec    %esp
  40defb:	4c                   	dec    %esp
  40defc:	00 18                	add    %bl,(%eax)
  40defe:	11 58 38             	adc    %ebx,0x38(%eax)
  40df01:	36 5f                	ss pop %edi
  40df03:	54                   	push   %esp
  40df04:	55                   	push   %ebp
  40df05:	4e                   	dec    %esi
  40df06:	45                   	inc    %ebp
  40df07:	5f                   	pop    %edi
  40df08:	52                   	push   %edx
  40df09:	45                   	inc    %ebp
  40df0a:	41                   	inc    %ecx
  40df0b:	44                   	inc    %esp
  40df0c:	5f                   	pop    %edi
  40df0d:	4d                   	dec    %ebp
  40df0e:	4f                   	dec    %edi
  40df0f:	44                   	inc    %esp
  40df10:	49                   	dec    %ecx
  40df11:	46                   	inc    %esi
  40df12:	59                   	pop    %ecx
  40df13:	00 19                	add    %bl,(%ecx)
  40df15:	11 58 38             	adc    %ebx,0x38(%eax)
  40df18:	36 5f                	ss pop %edi
  40df1a:	54                   	push   %esp
  40df1b:	55                   	push   %ebp
  40df1c:	4e                   	dec    %esi
  40df1d:	45                   	inc    %ebp
  40df1e:	5f                   	pop    %edi
  40df1f:	55                   	push   %ebp
  40df20:	53                   	push   %ebx
  40df21:	45                   	inc    %ebp
  40df22:	5f                   	pop    %edi
  40df23:	49                   	dec    %ecx
  40df24:	4e                   	dec    %esi
  40df25:	43                   	inc    %ebx
  40df26:	44                   	inc    %esp
  40df27:	45                   	inc    %ebp
  40df28:	43                   	inc    %ebx
  40df29:	00 1a                	add    %bl,(%edx)
  40df2b:	11 58 38             	adc    %ebx,0x38(%eax)
  40df2e:	36 5f                	ss pop %edi
  40df30:	54                   	push   %esp
  40df31:	55                   	push   %ebp
  40df32:	4e                   	dec    %esi
  40df33:	45                   	inc    %ebp
  40df34:	5f                   	pop    %edi
  40df35:	49                   	dec    %ecx
  40df36:	4e                   	dec    %esi
  40df37:	54                   	push   %esp
  40df38:	45                   	inc    %ebp
  40df39:	47                   	inc    %edi
  40df3a:	45                   	inc    %ebp
  40df3b:	52                   	push   %edx
  40df3c:	5f                   	pop    %edi
  40df3d:	44                   	inc    %esp
  40df3e:	46                   	inc    %esi
  40df3f:	4d                   	dec    %ebp
  40df40:	4f                   	dec    %edi
  40df41:	44                   	inc    %esp
  40df42:	45                   	inc    %ebp
  40df43:	5f                   	pop    %edi
  40df44:	4d                   	dec    %ebp
  40df45:	4f                   	dec    %edi
  40df46:	56                   	push   %esi
  40df47:	45                   	inc    %ebp
  40df48:	53                   	push   %ebx
  40df49:	00 1b                	add    %bl,(%ebx)
  40df4b:	11 58 38             	adc    %ebx,0x38(%eax)
  40df4e:	36 5f                	ss pop %edi
  40df50:	54                   	push   %esp
  40df51:	55                   	push   %ebp
  40df52:	4e                   	dec    %esi
  40df53:	45                   	inc    %ebp
  40df54:	5f                   	pop    %edi
  40df55:	4f                   	dec    %edi
  40df56:	50                   	push   %eax
  40df57:	54                   	push   %esp
  40df58:	5f                   	pop    %edi
  40df59:	41                   	inc    %ecx
  40df5a:	47                   	inc    %edi
  40df5b:	55                   	push   %ebp
  40df5c:	00 1c 11             	add    %bl,(%ecx,%edx,1)
  40df5f:	58                   	pop    %eax
  40df60:	38 36                	cmp    %dh,(%esi)
  40df62:	5f                   	pop    %edi
  40df63:	54                   	push   %esp
  40df64:	55                   	push   %ebp
  40df65:	4e                   	dec    %esi
  40df66:	45                   	inc    %ebp
  40df67:	5f                   	pop    %edi
  40df68:	41                   	inc    %ecx
  40df69:	56                   	push   %esi
  40df6a:	4f                   	dec    %edi
  40df6b:	49                   	dec    %ecx
  40df6c:	44                   	inc    %esp
  40df6d:	5f                   	pop    %edi
  40df6e:	4c                   	dec    %esp
  40df6f:	45                   	inc    %ebp
  40df70:	41                   	inc    %ecx
  40df71:	5f                   	pop    %edi
  40df72:	46                   	inc    %esi
  40df73:	4f                   	dec    %edi
  40df74:	52                   	push   %edx
  40df75:	5f                   	pop    %edi
  40df76:	41                   	inc    %ecx
  40df77:	44                   	inc    %esp
  40df78:	44                   	inc    %esp
  40df79:	52                   	push   %edx
  40df7a:	00 1d 11 58 38 36    	add    %bl,0x36385811
  40df80:	5f                   	pop    %edi
  40df81:	54                   	push   %esp
  40df82:	55                   	push   %ebp
  40df83:	4e                   	dec    %esi
  40df84:	45                   	inc    %ebp
  40df85:	5f                   	pop    %edi
  40df86:	53                   	push   %ebx
  40df87:	4c                   	dec    %esp
  40df88:	4f                   	dec    %edi
  40df89:	57                   	push   %edi
  40df8a:	5f                   	pop    %edi
  40df8b:	49                   	dec    %ecx
  40df8c:	4d                   	dec    %ebp
  40df8d:	55                   	push   %ebp
  40df8e:	4c                   	dec    %esp
  40df8f:	5f                   	pop    %edi
  40df90:	49                   	dec    %ecx
  40df91:	4d                   	dec    %ebp
  40df92:	4d                   	dec    %ebp
  40df93:	33 32                	xor    (%edx),%esi
  40df95:	5f                   	pop    %edi
  40df96:	4d                   	dec    %ebp
  40df97:	45                   	inc    %ebp
  40df98:	4d                   	dec    %ebp
  40df99:	00 1e                	add    %bl,(%esi)
  40df9b:	11 58 38             	adc    %ebx,0x38(%eax)
  40df9e:	36 5f                	ss pop %edi
  40dfa0:	54                   	push   %esp
  40dfa1:	55                   	push   %ebp
  40dfa2:	4e                   	dec    %esi
  40dfa3:	45                   	inc    %ebp
  40dfa4:	5f                   	pop    %edi
  40dfa5:	53                   	push   %ebx
  40dfa6:	4c                   	dec    %esp
  40dfa7:	4f                   	dec    %edi
  40dfa8:	57                   	push   %edi
  40dfa9:	5f                   	pop    %edi
  40dfaa:	49                   	dec    %ecx
  40dfab:	4d                   	dec    %ebp
  40dfac:	55                   	push   %ebp
  40dfad:	4c                   	dec    %esp
  40dfae:	5f                   	pop    %edi
  40dfaf:	49                   	dec    %ecx
  40dfb0:	4d                   	dec    %ebp
  40dfb1:	4d                   	dec    %ebp
  40dfb2:	38 00                	cmp    %al,(%eax)
  40dfb4:	1f                   	pop    %ds
  40dfb5:	11 58 38             	adc    %ebx,0x38(%eax)
  40dfb8:	36 5f                	ss pop %edi
  40dfba:	54                   	push   %esp
  40dfbb:	55                   	push   %ebp
  40dfbc:	4e                   	dec    %esi
  40dfbd:	45                   	inc    %ebp
  40dfbe:	5f                   	pop    %edi
  40dfbf:	41                   	inc    %ecx
  40dfc0:	56                   	push   %esi
  40dfc1:	4f                   	dec    %edi
  40dfc2:	49                   	dec    %ecx
  40dfc3:	44                   	inc    %esp
  40dfc4:	5f                   	pop    %edi
  40dfc5:	4d                   	dec    %ebp
  40dfc6:	45                   	inc    %ebp
  40dfc7:	4d                   	dec    %ebp
  40dfc8:	5f                   	pop    %edi
  40dfc9:	4f                   	dec    %edi
  40dfca:	50                   	push   %eax
  40dfcb:	4e                   	dec    %esi
  40dfcc:	44                   	inc    %esp
  40dfcd:	5f                   	pop    %edi
  40dfce:	46                   	inc    %esi
  40dfcf:	4f                   	dec    %edi
  40dfd0:	52                   	push   %edx
  40dfd1:	5f                   	pop    %edi
  40dfd2:	43                   	inc    %ebx
  40dfd3:	4d                   	dec    %ebp
  40dfd4:	4f                   	dec    %edi
  40dfd5:	56                   	push   %esi
  40dfd6:	45                   	inc    %ebp
  40dfd7:	00 20                	add    %ah,(%eax)
  40dfd9:	11 58 38             	adc    %ebx,0x38(%eax)
  40dfdc:	36 5f                	ss pop %edi
  40dfde:	54                   	push   %esp
  40dfdf:	55                   	push   %ebp
  40dfe0:	4e                   	dec    %esi
  40dfe1:	45                   	inc    %ebp
  40dfe2:	5f                   	pop    %edi
  40dfe3:	53                   	push   %ebx
  40dfe4:	49                   	dec    %ecx
  40dfe5:	4e                   	dec    %esi
  40dfe6:	47                   	inc    %edi
  40dfe7:	4c                   	dec    %esp
  40dfe8:	45                   	inc    %ebp
  40dfe9:	5f                   	pop    %edi
  40dfea:	53                   	push   %ebx
  40dfeb:	54                   	push   %esp
  40dfec:	52                   	push   %edx
  40dfed:	49                   	dec    %ecx
  40dfee:	4e                   	dec    %esi
  40dfef:	47                   	inc    %edi
  40dff0:	4f                   	dec    %edi
  40dff1:	50                   	push   %eax
  40dff2:	00 21                	add    %ah,(%ecx)
  40dff4:	11 58 38             	adc    %ebx,0x38(%eax)
  40dff7:	36 5f                	ss pop %edi
  40dff9:	54                   	push   %esp
  40dffa:	55                   	push   %ebp
  40dffb:	4e                   	dec    %esi
  40dffc:	45                   	inc    %ebp
  40dffd:	5f                   	pop    %edi
  40dffe:	4d                   	dec    %ebp
  40dfff:	49                   	dec    %ecx
  40e000:	53                   	push   %ebx
  40e001:	41                   	inc    %ecx
  40e002:	4c                   	dec    %esp
  40e003:	49                   	dec    %ecx
  40e004:	47                   	inc    %edi
  40e005:	4e                   	dec    %esi
  40e006:	45                   	inc    %ebp
  40e007:	44                   	inc    %esp
  40e008:	5f                   	pop    %edi
  40e009:	4d                   	dec    %ebp
  40e00a:	4f                   	dec    %edi
  40e00b:	56                   	push   %esi
  40e00c:	45                   	inc    %ebp
  40e00d:	5f                   	pop    %edi
  40e00e:	53                   	push   %ebx
  40e00f:	54                   	push   %esp
  40e010:	52                   	push   %edx
  40e011:	49                   	dec    %ecx
  40e012:	4e                   	dec    %esi
  40e013:	47                   	inc    %edi
  40e014:	5f                   	pop    %edi
  40e015:	50                   	push   %eax
  40e016:	52                   	push   %edx
  40e017:	4f                   	dec    %edi
  40e018:	5f                   	pop    %edi
  40e019:	45                   	inc    %ebp
  40e01a:	50                   	push   %eax
  40e01b:	49                   	dec    %ecx
  40e01c:	4c                   	dec    %esp
  40e01d:	4f                   	dec    %edi
  40e01e:	47                   	inc    %edi
  40e01f:	55                   	push   %ebp
  40e020:	45                   	inc    %ebp
  40e021:	53                   	push   %ebx
  40e022:	00 22                	add    %ah,(%edx)
  40e024:	11 58 38             	adc    %ebx,0x38(%eax)
  40e027:	36 5f                	ss pop %edi
  40e029:	54                   	push   %esp
  40e02a:	55                   	push   %ebp
  40e02b:	4e                   	dec    %esi
  40e02c:	45                   	inc    %ebp
  40e02d:	5f                   	pop    %edi
  40e02e:	55                   	push   %ebp
  40e02f:	53                   	push   %ebx
  40e030:	45                   	inc    %ebp
  40e031:	5f                   	pop    %edi
  40e032:	53                   	push   %ebx
  40e033:	41                   	inc    %ecx
  40e034:	48                   	dec    %eax
  40e035:	46                   	inc    %esi
  40e036:	00 23                	add    %ah,(%ebx)
  40e038:	11 58 38             	adc    %ebx,0x38(%eax)
  40e03b:	36 5f                	ss pop %edi
  40e03d:	54                   	push   %esp
  40e03e:	55                   	push   %ebp
  40e03f:	4e                   	dec    %esi
  40e040:	45                   	inc    %ebp
  40e041:	5f                   	pop    %edi
  40e042:	55                   	push   %ebp
  40e043:	53                   	push   %ebx
  40e044:	45                   	inc    %ebp
  40e045:	5f                   	pop    %edi
  40e046:	43                   	inc    %ebx
  40e047:	4c                   	dec    %esp
  40e048:	54                   	push   %esp
  40e049:	44                   	inc    %esp
  40e04a:	00 24 11             	add    %ah,(%ecx,%edx,1)
  40e04d:	58                   	pop    %eax
  40e04e:	38 36                	cmp    %dh,(%esi)
  40e050:	5f                   	pop    %edi
  40e051:	54                   	push   %esp
  40e052:	55                   	push   %ebp
  40e053:	4e                   	dec    %esi
  40e054:	45                   	inc    %ebp
  40e055:	5f                   	pop    %edi
  40e056:	55                   	push   %ebp
  40e057:	53                   	push   %ebx
  40e058:	45                   	inc    %ebp
  40e059:	5f                   	pop    %edi
  40e05a:	42                   	inc    %edx
  40e05b:	54                   	push   %esp
  40e05c:	00 25 11 58 38 36    	add    %ah,0x36385811
  40e062:	5f                   	pop    %edi
  40e063:	54                   	push   %esp
  40e064:	55                   	push   %ebp
  40e065:	4e                   	dec    %esi
  40e066:	45                   	inc    %ebp
  40e067:	5f                   	pop    %edi
  40e068:	41                   	inc    %ecx
  40e069:	56                   	push   %esi
  40e06a:	4f                   	dec    %edi
  40e06b:	49                   	dec    %ecx
  40e06c:	44                   	inc    %esp
  40e06d:	5f                   	pop    %edi
  40e06e:	46                   	inc    %esi
  40e06f:	41                   	inc    %ecx
  40e070:	4c                   	dec    %esp
  40e071:	53                   	push   %ebx
  40e072:	45                   	inc    %ebp
  40e073:	5f                   	pop    %edi
  40e074:	44                   	inc    %esp
  40e075:	45                   	inc    %ebp
  40e076:	50                   	push   %eax
  40e077:	5f                   	pop    %edi
  40e078:	46                   	inc    %esi
  40e079:	4f                   	dec    %edi
  40e07a:	52                   	push   %edx
  40e07b:	5f                   	pop    %edi
  40e07c:	42                   	inc    %edx
  40e07d:	4d                   	dec    %ebp
  40e07e:	49                   	dec    %ecx
  40e07f:	00 26                	add    %ah,(%esi)
  40e081:	11 58 38             	adc    %ebx,0x38(%eax)
  40e084:	36 5f                	ss pop %edi
  40e086:	54                   	push   %esp
  40e087:	55                   	push   %ebp
  40e088:	4e                   	dec    %esi
  40e089:	45                   	inc    %ebp
  40e08a:	5f                   	pop    %edi
  40e08b:	41                   	inc    %ecx
  40e08c:	44                   	inc    %esp
  40e08d:	4a                   	dec    %edx
  40e08e:	55                   	push   %ebp
  40e08f:	53                   	push   %ebx
  40e090:	54                   	push   %esp
  40e091:	5f                   	pop    %edi
  40e092:	55                   	push   %ebp
  40e093:	4e                   	dec    %esi
  40e094:	52                   	push   %edx
  40e095:	4f                   	dec    %edi
  40e096:	4c                   	dec    %esp
  40e097:	4c                   	dec    %esp
  40e098:	00 27                	add    %ah,(%edi)
  40e09a:	11 58 38             	adc    %ebx,0x38(%eax)
  40e09d:	36 5f                	ss pop %edi
  40e09f:	54                   	push   %esp
  40e0a0:	55                   	push   %ebp
  40e0a1:	4e                   	dec    %esi
  40e0a2:	45                   	inc    %ebp
  40e0a3:	5f                   	pop    %edi
  40e0a4:	4f                   	dec    %edi
  40e0a5:	4e                   	dec    %esi
  40e0a6:	45                   	inc    %ebp
  40e0a7:	5f                   	pop    %edi
  40e0a8:	49                   	dec    %ecx
  40e0a9:	46                   	inc    %esi
  40e0aa:	5f                   	pop    %edi
  40e0ab:	43                   	inc    %ebx
  40e0ac:	4f                   	dec    %edi
  40e0ad:	4e                   	dec    %esi
  40e0ae:	56                   	push   %esi
  40e0af:	5f                   	pop    %edi
  40e0b0:	49                   	dec    %ecx
  40e0b1:	4e                   	dec    %esi
  40e0b2:	53                   	push   %ebx
  40e0b3:	4e                   	dec    %esi
  40e0b4:	00 28                	add    %ch,(%eax)
  40e0b6:	11 58 38             	adc    %ebx,0x38(%eax)
  40e0b9:	36 5f                	ss pop %edi
  40e0bb:	54                   	push   %esp
  40e0bc:	55                   	push   %ebp
  40e0bd:	4e                   	dec    %esi
  40e0be:	45                   	inc    %ebp
  40e0bf:	5f                   	pop    %edi
  40e0c0:	55                   	push   %ebp
  40e0c1:	53                   	push   %ebx
  40e0c2:	45                   	inc    %ebp
  40e0c3:	5f                   	pop    %edi
  40e0c4:	48                   	dec    %eax
  40e0c5:	49                   	dec    %ecx
  40e0c6:	4d                   	dec    %ebp
  40e0c7:	4f                   	dec    %edi
  40e0c8:	44                   	inc    %esp
  40e0c9:	45                   	inc    %ebp
  40e0ca:	5f                   	pop    %edi
  40e0cb:	46                   	inc    %esi
  40e0cc:	49                   	dec    %ecx
  40e0cd:	4f                   	dec    %edi
  40e0ce:	50                   	push   %eax
  40e0cf:	00 29                	add    %ch,(%ecx)
  40e0d1:	11 58 38             	adc    %ebx,0x38(%eax)
  40e0d4:	36 5f                	ss pop %edi
  40e0d6:	54                   	push   %esp
  40e0d7:	55                   	push   %ebp
  40e0d8:	4e                   	dec    %esi
  40e0d9:	45                   	inc    %ebp
  40e0da:	5f                   	pop    %edi
  40e0db:	55                   	push   %ebp
  40e0dc:	53                   	push   %ebx
  40e0dd:	45                   	inc    %ebp
  40e0de:	5f                   	pop    %edi
  40e0df:	53                   	push   %ebx
  40e0e0:	49                   	dec    %ecx
  40e0e1:	4d                   	dec    %ebp
  40e0e2:	4f                   	dec    %edi
  40e0e3:	44                   	inc    %esp
  40e0e4:	45                   	inc    %ebp
  40e0e5:	5f                   	pop    %edi
  40e0e6:	46                   	inc    %esi
  40e0e7:	49                   	dec    %ecx
  40e0e8:	4f                   	dec    %edi
  40e0e9:	50                   	push   %eax
  40e0ea:	00 2a                	add    %ch,(%edx)
  40e0ec:	11 58 38             	adc    %ebx,0x38(%eax)
  40e0ef:	36 5f                	ss pop %edi
  40e0f1:	54                   	push   %esp
  40e0f2:	55                   	push   %ebp
  40e0f3:	4e                   	dec    %esi
  40e0f4:	45                   	inc    %ebp
  40e0f5:	5f                   	pop    %edi
  40e0f6:	55                   	push   %ebp
  40e0f7:	53                   	push   %ebx
  40e0f8:	45                   	inc    %ebp
  40e0f9:	5f                   	pop    %edi
  40e0fa:	46                   	inc    %esi
  40e0fb:	46                   	inc    %esi
  40e0fc:	52                   	push   %edx
  40e0fd:	45                   	inc    %ebp
  40e0fe:	45                   	inc    %ebp
  40e0ff:	50                   	push   %eax
  40e100:	00 2b                	add    %ch,(%ebx)
  40e102:	11 58 38             	adc    %ebx,0x38(%eax)
  40e105:	36 5f                	ss pop %edi
  40e107:	54                   	push   %esp
  40e108:	55                   	push   %ebp
  40e109:	4e                   	dec    %esi
  40e10a:	45                   	inc    %ebp
  40e10b:	5f                   	pop    %edi
  40e10c:	45                   	inc    %ebp
  40e10d:	58                   	pop    %eax
  40e10e:	54                   	push   %esp
  40e10f:	5f                   	pop    %edi
  40e110:	38 30                	cmp    %dh,(%eax)
  40e112:	33 38                	xor    (%eax),%edi
  40e114:	37                   	aaa    
  40e115:	5f                   	pop    %edi
  40e116:	43                   	inc    %ebx
  40e117:	4f                   	dec    %edi
  40e118:	4e                   	dec    %esi
  40e119:	53                   	push   %ebx
  40e11a:	54                   	push   %esp
  40e11b:	41                   	inc    %ecx
  40e11c:	4e                   	dec    %esi
  40e11d:	54                   	push   %esp
  40e11e:	53                   	push   %ebx
  40e11f:	00 2c 11             	add    %ch,(%ecx,%edx,1)
  40e122:	58                   	pop    %eax
  40e123:	38 36                	cmp    %dh,(%esi)
  40e125:	5f                   	pop    %edi
  40e126:	54                   	push   %esp
  40e127:	55                   	push   %ebp
  40e128:	4e                   	dec    %esi
  40e129:	45                   	inc    %ebp
  40e12a:	5f                   	pop    %edi
  40e12b:	47                   	inc    %edi
  40e12c:	45                   	inc    %ebp
  40e12d:	4e                   	dec    %esi
  40e12e:	45                   	inc    %ebp
  40e12f:	52                   	push   %edx
  40e130:	41                   	inc    %ecx
  40e131:	4c                   	dec    %esp
  40e132:	5f                   	pop    %edi
  40e133:	52                   	push   %edx
  40e134:	45                   	inc    %ebp
  40e135:	47                   	inc    %edi
  40e136:	53                   	push   %ebx
  40e137:	5f                   	pop    %edi
  40e138:	53                   	push   %ebx
  40e139:	53                   	push   %ebx
  40e13a:	45                   	inc    %ebp
  40e13b:	5f                   	pop    %edi
  40e13c:	53                   	push   %ebx
  40e13d:	50                   	push   %eax
  40e13e:	49                   	dec    %ecx
  40e13f:	4c                   	dec    %esp
  40e140:	4c                   	dec    %esp
  40e141:	00 2d 11 58 38 36    	add    %ch,0x36385811
  40e147:	5f                   	pop    %edi
  40e148:	54                   	push   %esp
  40e149:	55                   	push   %ebp
  40e14a:	4e                   	dec    %esi
  40e14b:	45                   	inc    %ebp
  40e14c:	5f                   	pop    %edi
  40e14d:	53                   	push   %ebx
  40e14e:	53                   	push   %ebx
  40e14f:	45                   	inc    %ebp
  40e150:	5f                   	pop    %edi
  40e151:	55                   	push   %ebp
  40e152:	4e                   	dec    %esi
  40e153:	41                   	inc    %ecx
  40e154:	4c                   	dec    %esp
  40e155:	49                   	dec    %ecx
  40e156:	47                   	inc    %edi
  40e157:	4e                   	dec    %esi
  40e158:	45                   	inc    %ebp
  40e159:	44                   	inc    %esp
  40e15a:	5f                   	pop    %edi
  40e15b:	4c                   	dec    %esp
  40e15c:	4f                   	dec    %edi
  40e15d:	41                   	inc    %ecx
  40e15e:	44                   	inc    %esp
  40e15f:	5f                   	pop    %edi
  40e160:	4f                   	dec    %edi
  40e161:	50                   	push   %eax
  40e162:	54                   	push   %esp
  40e163:	49                   	dec    %ecx
  40e164:	4d                   	dec    %ebp
  40e165:	41                   	inc    %ecx
  40e166:	4c                   	dec    %esp
  40e167:	00 2e                	add    %ch,(%esi)
  40e169:	11 58 38             	adc    %ebx,0x38(%eax)
  40e16c:	36 5f                	ss pop %edi
  40e16e:	54                   	push   %esp
  40e16f:	55                   	push   %ebp
  40e170:	4e                   	dec    %esi
  40e171:	45                   	inc    %ebp
  40e172:	5f                   	pop    %edi
  40e173:	53                   	push   %ebx
  40e174:	53                   	push   %ebx
  40e175:	45                   	inc    %ebp
  40e176:	5f                   	pop    %edi
  40e177:	55                   	push   %ebp
  40e178:	4e                   	dec    %esi
  40e179:	41                   	inc    %ecx
  40e17a:	4c                   	dec    %esp
  40e17b:	49                   	dec    %ecx
  40e17c:	47                   	inc    %edi
  40e17d:	4e                   	dec    %esi
  40e17e:	45                   	inc    %ebp
  40e17f:	44                   	inc    %esp
  40e180:	5f                   	pop    %edi
  40e181:	53                   	push   %ebx
  40e182:	54                   	push   %esp
  40e183:	4f                   	dec    %edi
  40e184:	52                   	push   %edx
  40e185:	45                   	inc    %ebp
  40e186:	5f                   	pop    %edi
  40e187:	4f                   	dec    %edi
  40e188:	50                   	push   %eax
  40e189:	54                   	push   %esp
  40e18a:	49                   	dec    %ecx
  40e18b:	4d                   	dec    %ebp
  40e18c:	41                   	inc    %ecx
  40e18d:	4c                   	dec    %esp
  40e18e:	00 2f                	add    %ch,(%edi)
  40e190:	11 58 38             	adc    %ebx,0x38(%eax)
  40e193:	36 5f                	ss pop %edi
  40e195:	54                   	push   %esp
  40e196:	55                   	push   %ebp
  40e197:	4e                   	dec    %esi
  40e198:	45                   	inc    %ebp
  40e199:	5f                   	pop    %edi
  40e19a:	53                   	push   %ebx
  40e19b:	53                   	push   %ebx
  40e19c:	45                   	inc    %ebp
  40e19d:	5f                   	pop    %edi
  40e19e:	50                   	push   %eax
  40e19f:	41                   	inc    %ecx
  40e1a0:	43                   	inc    %ebx
  40e1a1:	4b                   	dec    %ebx
  40e1a2:	45                   	inc    %ebp
  40e1a3:	44                   	inc    %esp
  40e1a4:	5f                   	pop    %edi
  40e1a5:	53                   	push   %ebx
  40e1a6:	49                   	dec    %ecx
  40e1a7:	4e                   	dec    %esi
  40e1a8:	47                   	inc    %edi
  40e1a9:	4c                   	dec    %esp
  40e1aa:	45                   	inc    %ebp
  40e1ab:	5f                   	pop    %edi
  40e1ac:	49                   	dec    %ecx
  40e1ad:	4e                   	dec    %esi
  40e1ae:	53                   	push   %ebx
  40e1af:	4e                   	dec    %esi
  40e1b0:	5f                   	pop    %edi
  40e1b1:	4f                   	dec    %edi
  40e1b2:	50                   	push   %eax
  40e1b3:	54                   	push   %esp
  40e1b4:	49                   	dec    %ecx
  40e1b5:	4d                   	dec    %ebp
  40e1b6:	41                   	inc    %ecx
  40e1b7:	4c                   	dec    %esp
  40e1b8:	00 30                	add    %dh,(%eax)
  40e1ba:	11 58 38             	adc    %ebx,0x38(%eax)
  40e1bd:	36 5f                	ss pop %edi
  40e1bf:	54                   	push   %esp
  40e1c0:	55                   	push   %ebp
  40e1c1:	4e                   	dec    %esi
  40e1c2:	45                   	inc    %ebp
  40e1c3:	5f                   	pop    %edi
  40e1c4:	53                   	push   %ebx
  40e1c5:	53                   	push   %ebx
  40e1c6:	45                   	inc    %ebp
  40e1c7:	5f                   	pop    %edi
  40e1c8:	54                   	push   %esp
  40e1c9:	59                   	pop    %ecx
  40e1ca:	50                   	push   %eax
  40e1cb:	45                   	inc    %ebp
  40e1cc:	4c                   	dec    %esp
  40e1cd:	45                   	inc    %ebp
  40e1ce:	53                   	push   %ebx
  40e1cf:	53                   	push   %ebx
  40e1d0:	5f                   	pop    %edi
  40e1d1:	53                   	push   %ebx
  40e1d2:	54                   	push   %esp
  40e1d3:	4f                   	dec    %edi
  40e1d4:	52                   	push   %edx
  40e1d5:	45                   	inc    %ebp
  40e1d6:	53                   	push   %ebx
  40e1d7:	00 31                	add    %dh,(%ecx)
  40e1d9:	11 58 38             	adc    %ebx,0x38(%eax)
  40e1dc:	36 5f                	ss pop %edi
  40e1de:	54                   	push   %esp
  40e1df:	55                   	push   %ebp
  40e1e0:	4e                   	dec    %esi
  40e1e1:	45                   	inc    %ebp
  40e1e2:	5f                   	pop    %edi
  40e1e3:	53                   	push   %ebx
  40e1e4:	53                   	push   %ebx
  40e1e5:	45                   	inc    %ebp
  40e1e6:	5f                   	pop    %edi
  40e1e7:	4c                   	dec    %esp
  40e1e8:	4f                   	dec    %edi
  40e1e9:	41                   	inc    %ecx
  40e1ea:	44                   	inc    %esp
  40e1eb:	30 5f 42             	xor    %bl,0x42(%edi)
  40e1ee:	59                   	pop    %ecx
  40e1ef:	5f                   	pop    %edi
  40e1f0:	50                   	push   %eax
  40e1f1:	58                   	pop    %eax
  40e1f2:	4f                   	dec    %edi
  40e1f3:	52                   	push   %edx
  40e1f4:	00 32                	add    %dh,(%edx)
  40e1f6:	11 58 38             	adc    %ebx,0x38(%eax)
  40e1f9:	36 5f                	ss pop %edi
  40e1fb:	54                   	push   %esp
  40e1fc:	55                   	push   %ebp
  40e1fd:	4e                   	dec    %esi
  40e1fe:	45                   	inc    %ebp
  40e1ff:	5f                   	pop    %edi
  40e200:	49                   	dec    %ecx
  40e201:	4e                   	dec    %esi
  40e202:	54                   	push   %esp
  40e203:	45                   	inc    %ebp
  40e204:	52                   	push   %edx
  40e205:	5f                   	pop    %edi
  40e206:	55                   	push   %ebp
  40e207:	4e                   	dec    %esi
  40e208:	49                   	dec    %ecx
  40e209:	54                   	push   %esp
  40e20a:	5f                   	pop    %edi
  40e20b:	4d                   	dec    %ebp
  40e20c:	4f                   	dec    %edi
  40e20d:	56                   	push   %esi
  40e20e:	45                   	inc    %ebp
  40e20f:	53                   	push   %ebx
  40e210:	5f                   	pop    %edi
  40e211:	54                   	push   %esp
  40e212:	4f                   	dec    %edi
  40e213:	5f                   	pop    %edi
  40e214:	56                   	push   %esi
  40e215:	45                   	inc    %ebp
  40e216:	43                   	inc    %ebx
  40e217:	00 33                	add    %dh,(%ebx)
  40e219:	11 58 38             	adc    %ebx,0x38(%eax)
  40e21c:	36 5f                	ss pop %edi
  40e21e:	54                   	push   %esp
  40e21f:	55                   	push   %ebp
  40e220:	4e                   	dec    %esi
  40e221:	45                   	inc    %ebp
  40e222:	5f                   	pop    %edi
  40e223:	49                   	dec    %ecx
  40e224:	4e                   	dec    %esi
  40e225:	54                   	push   %esp
  40e226:	45                   	inc    %ebp
  40e227:	52                   	push   %edx
  40e228:	5f                   	pop    %edi
  40e229:	55                   	push   %ebp
  40e22a:	4e                   	dec    %esi
  40e22b:	49                   	dec    %ecx
  40e22c:	54                   	push   %esp
  40e22d:	5f                   	pop    %edi
  40e22e:	4d                   	dec    %ebp
  40e22f:	4f                   	dec    %edi
  40e230:	56                   	push   %esi
  40e231:	45                   	inc    %ebp
  40e232:	53                   	push   %ebx
  40e233:	5f                   	pop    %edi
  40e234:	46                   	inc    %esi
  40e235:	52                   	push   %edx
  40e236:	4f                   	dec    %edi
  40e237:	4d                   	dec    %ebp
  40e238:	5f                   	pop    %edi
  40e239:	56                   	push   %esi
  40e23a:	45                   	inc    %ebp
  40e23b:	43                   	inc    %ebx
  40e23c:	00 34 11             	add    %dh,(%ecx,%edx,1)
  40e23f:	58                   	pop    %eax
  40e240:	38 36                	cmp    %dh,(%esi)
  40e242:	5f                   	pop    %edi
  40e243:	54                   	push   %esp
  40e244:	55                   	push   %ebp
  40e245:	4e                   	dec    %esi
  40e246:	45                   	inc    %ebp
  40e247:	5f                   	pop    %edi
  40e248:	49                   	dec    %ecx
  40e249:	4e                   	dec    %esi
  40e24a:	54                   	push   %esp
  40e24b:	45                   	inc    %ebp
  40e24c:	52                   	push   %edx
  40e24d:	5f                   	pop    %edi
  40e24e:	55                   	push   %ebp
  40e24f:	4e                   	dec    %esi
  40e250:	49                   	dec    %ecx
  40e251:	54                   	push   %esp
  40e252:	5f                   	pop    %edi
  40e253:	43                   	inc    %ebx
  40e254:	4f                   	dec    %edi
  40e255:	4e                   	dec    %esi
  40e256:	56                   	push   %esi
  40e257:	45                   	inc    %ebp
  40e258:	52                   	push   %edx
  40e259:	53                   	push   %ebx
  40e25a:	49                   	dec    %ecx
  40e25b:	4f                   	dec    %edi
  40e25c:	4e                   	dec    %esi
  40e25d:	53                   	push   %ebx
  40e25e:	00 35 11 58 38 36    	add    %dh,0x36385811
  40e264:	5f                   	pop    %edi
  40e265:	54                   	push   %esp
  40e266:	55                   	push   %ebp
  40e267:	4e                   	dec    %esi
  40e268:	45                   	inc    %ebp
  40e269:	5f                   	pop    %edi
  40e26a:	53                   	push   %ebx
  40e26b:	50                   	push   %eax
  40e26c:	4c                   	dec    %esp
  40e26d:	49                   	dec    %ecx
  40e26e:	54                   	push   %esp
  40e26f:	5f                   	pop    %edi
  40e270:	4d                   	dec    %ebp
  40e271:	45                   	inc    %ebp
  40e272:	4d                   	dec    %ebp
  40e273:	5f                   	pop    %edi
  40e274:	4f                   	dec    %edi
  40e275:	50                   	push   %eax
  40e276:	4e                   	dec    %esi
  40e277:	44                   	inc    %esp
  40e278:	5f                   	pop    %edi
  40e279:	46                   	inc    %esi
  40e27a:	4f                   	dec    %edi
  40e27b:	52                   	push   %edx
  40e27c:	5f                   	pop    %edi
  40e27d:	46                   	inc    %esi
  40e27e:	50                   	push   %eax
  40e27f:	5f                   	pop    %edi
  40e280:	43                   	inc    %ebx
  40e281:	4f                   	dec    %edi
  40e282:	4e                   	dec    %esi
  40e283:	56                   	push   %esi
  40e284:	45                   	inc    %ebp
  40e285:	52                   	push   %edx
  40e286:	54                   	push   %esp
  40e287:	53                   	push   %ebx
  40e288:	00 36                	add    %dh,(%esi)
  40e28a:	11 58 38             	adc    %ebx,0x38(%eax)
  40e28d:	36 5f                	ss pop %edi
  40e28f:	54                   	push   %esp
  40e290:	55                   	push   %ebp
  40e291:	4e                   	dec    %esi
  40e292:	45                   	inc    %ebp
  40e293:	5f                   	pop    %edi
  40e294:	55                   	push   %ebp
  40e295:	53                   	push   %ebx
  40e296:	45                   	inc    %ebp
  40e297:	5f                   	pop    %edi
  40e298:	56                   	push   %esi
  40e299:	45                   	inc    %ebp
  40e29a:	43                   	inc    %ebx
  40e29b:	54                   	push   %esp
  40e29c:	4f                   	dec    %edi
  40e29d:	52                   	push   %edx
  40e29e:	5f                   	pop    %edi
  40e29f:	46                   	inc    %esi
  40e2a0:	50                   	push   %eax
  40e2a1:	5f                   	pop    %edi
  40e2a2:	43                   	inc    %ebx
  40e2a3:	4f                   	dec    %edi
  40e2a4:	4e                   	dec    %esi
  40e2a5:	56                   	push   %esi
  40e2a6:	45                   	inc    %ebp
  40e2a7:	52                   	push   %edx
  40e2a8:	54                   	push   %esp
  40e2a9:	53                   	push   %ebx
  40e2aa:	00 37                	add    %dh,(%edi)
  40e2ac:	11 58 38             	adc    %ebx,0x38(%eax)
  40e2af:	36 5f                	ss pop %edi
  40e2b1:	54                   	push   %esp
  40e2b2:	55                   	push   %ebp
  40e2b3:	4e                   	dec    %esi
  40e2b4:	45                   	inc    %ebp
  40e2b5:	5f                   	pop    %edi
  40e2b6:	55                   	push   %ebp
  40e2b7:	53                   	push   %ebx
  40e2b8:	45                   	inc    %ebp
  40e2b9:	5f                   	pop    %edi
  40e2ba:	56                   	push   %esi
  40e2bb:	45                   	inc    %ebp
  40e2bc:	43                   	inc    %ebx
  40e2bd:	54                   	push   %esp
  40e2be:	4f                   	dec    %edi
  40e2bf:	52                   	push   %edx
  40e2c0:	5f                   	pop    %edi
  40e2c1:	43                   	inc    %ebx
  40e2c2:	4f                   	dec    %edi
  40e2c3:	4e                   	dec    %esi
  40e2c4:	56                   	push   %esi
  40e2c5:	45                   	inc    %ebp
  40e2c6:	52                   	push   %edx
  40e2c7:	54                   	push   %esp
  40e2c8:	53                   	push   %ebx
  40e2c9:	00 38                	add    %bh,(%eax)
  40e2cb:	11 58 38             	adc    %ebx,0x38(%eax)
  40e2ce:	36 5f                	ss pop %edi
  40e2d0:	54                   	push   %esp
  40e2d1:	55                   	push   %ebp
  40e2d2:	4e                   	dec    %esi
  40e2d3:	45                   	inc    %ebp
  40e2d4:	5f                   	pop    %edi
  40e2d5:	53                   	push   %ebx
  40e2d6:	4c                   	dec    %esp
  40e2d7:	4f                   	dec    %edi
  40e2d8:	57                   	push   %edi
  40e2d9:	5f                   	pop    %edi
  40e2da:	50                   	push   %eax
  40e2db:	53                   	push   %ebx
  40e2dc:	48                   	dec    %eax
  40e2dd:	55                   	push   %ebp
  40e2de:	46                   	inc    %esi
  40e2df:	42                   	inc    %edx
  40e2e0:	00 39                	add    %bh,(%ecx)
  40e2e2:	11 58 38             	adc    %ebx,0x38(%eax)
  40e2e5:	36 5f                	ss pop %edi
  40e2e7:	54                   	push   %esp
  40e2e8:	55                   	push   %ebp
  40e2e9:	4e                   	dec    %esi
  40e2ea:	45                   	inc    %ebp
  40e2eb:	5f                   	pop    %edi
  40e2ec:	41                   	inc    %ecx
  40e2ed:	56                   	push   %esi
  40e2ee:	4f                   	dec    %edi
  40e2ef:	49                   	dec    %ecx
  40e2f0:	44                   	inc    %esp
  40e2f1:	5f                   	pop    %edi
  40e2f2:	34 42                	xor    $0x42,%al
  40e2f4:	59                   	pop    %ecx
  40e2f5:	54                   	push   %esp
  40e2f6:	45                   	inc    %ebp
  40e2f7:	5f                   	pop    %edi
  40e2f8:	50                   	push   %eax
  40e2f9:	52                   	push   %edx
  40e2fa:	45                   	inc    %ebp
  40e2fb:	46                   	inc    %esi
  40e2fc:	49                   	dec    %ecx
  40e2fd:	58                   	pop    %eax
  40e2fe:	45                   	inc    %ebp
  40e2ff:	53                   	push   %ebx
  40e300:	00 3a                	add    %bh,(%edx)
  40e302:	11 58 38             	adc    %ebx,0x38(%eax)
  40e305:	36 5f                	ss pop %edi
  40e307:	54                   	push   %esp
  40e308:	55                   	push   %ebp
  40e309:	4e                   	dec    %esi
  40e30a:	45                   	inc    %ebp
  40e30b:	5f                   	pop    %edi
  40e30c:	55                   	push   %ebp
  40e30d:	53                   	push   %ebx
  40e30e:	45                   	inc    %ebp
  40e30f:	5f                   	pop    %edi
  40e310:	47                   	inc    %edi
  40e311:	41                   	inc    %ecx
  40e312:	54                   	push   %esp
  40e313:	48                   	dec    %eax
  40e314:	45                   	inc    %ebp
  40e315:	52                   	push   %edx
  40e316:	00 3b                	add    %bh,(%ebx)
  40e318:	11 58 38             	adc    %ebx,0x38(%eax)
  40e31b:	36 5f                	ss pop %edi
  40e31d:	54                   	push   %esp
  40e31e:	55                   	push   %ebp
  40e31f:	4e                   	dec    %esi
  40e320:	45                   	inc    %ebp
  40e321:	5f                   	pop    %edi
  40e322:	41                   	inc    %ecx
  40e323:	56                   	push   %esi
  40e324:	4f                   	dec    %edi
  40e325:	49                   	dec    %ecx
  40e326:	44                   	inc    %esp
  40e327:	5f                   	pop    %edi
  40e328:	31 32                	xor    %esi,(%edx)
  40e32a:	38 46 4d             	cmp    %al,0x4d(%esi)
  40e32d:	41                   	inc    %ecx
  40e32e:	5f                   	pop    %edi
  40e32f:	43                   	inc    %ebx
  40e330:	48                   	dec    %eax
  40e331:	41                   	inc    %ecx
  40e332:	49                   	dec    %ecx
  40e333:	4e                   	dec    %esi
  40e334:	53                   	push   %ebx
  40e335:	00 3c 11             	add    %bh,(%ecx,%edx,1)
  40e338:	58                   	pop    %eax
  40e339:	38 36                	cmp    %dh,(%esi)
  40e33b:	5f                   	pop    %edi
  40e33c:	54                   	push   %esp
  40e33d:	55                   	push   %ebp
  40e33e:	4e                   	dec    %esi
  40e33f:	45                   	inc    %ebp
  40e340:	5f                   	pop    %edi
  40e341:	41                   	inc    %ecx
  40e342:	56                   	push   %esi
  40e343:	4f                   	dec    %edi
  40e344:	49                   	dec    %ecx
  40e345:	44                   	inc    %esp
  40e346:	5f                   	pop    %edi
  40e347:	32 35 36 46 4d 41    	xor    0x414d4636,%dh
  40e34d:	5f                   	pop    %edi
  40e34e:	43                   	inc    %ebx
  40e34f:	48                   	dec    %eax
  40e350:	41                   	inc    %ecx
  40e351:	49                   	dec    %ecx
  40e352:	4e                   	dec    %esi
  40e353:	53                   	push   %ebx
  40e354:	00 3d 11 58 38 36    	add    %bh,0x36385811
  40e35a:	5f                   	pop    %edi
  40e35b:	54                   	push   %esp
  40e35c:	55                   	push   %ebp
  40e35d:	4e                   	dec    %esi
  40e35e:	45                   	inc    %ebp
  40e35f:	5f                   	pop    %edi
  40e360:	41                   	inc    %ecx
  40e361:	56                   	push   %esi
  40e362:	58                   	pop    %eax
  40e363:	32 35 36 5f 55 4e    	xor    0x4e555f36,%dh
  40e369:	41                   	inc    %ecx
  40e36a:	4c                   	dec    %esp
  40e36b:	49                   	dec    %ecx
  40e36c:	47                   	inc    %edi
  40e36d:	4e                   	dec    %esi
  40e36e:	45                   	inc    %ebp
  40e36f:	44                   	inc    %esp
  40e370:	5f                   	pop    %edi
  40e371:	4c                   	dec    %esp
  40e372:	4f                   	dec    %edi
  40e373:	41                   	inc    %ecx
  40e374:	44                   	inc    %esp
  40e375:	5f                   	pop    %edi
  40e376:	4f                   	dec    %edi
  40e377:	50                   	push   %eax
  40e378:	54                   	push   %esp
  40e379:	49                   	dec    %ecx
  40e37a:	4d                   	dec    %ebp
  40e37b:	41                   	inc    %ecx
  40e37c:	4c                   	dec    %esp
  40e37d:	00 3e                	add    %bh,(%esi)
  40e37f:	11 58 38             	adc    %ebx,0x38(%eax)
  40e382:	36 5f                	ss pop %edi
  40e384:	54                   	push   %esp
  40e385:	55                   	push   %ebp
  40e386:	4e                   	dec    %esi
  40e387:	45                   	inc    %ebp
  40e388:	5f                   	pop    %edi
  40e389:	41                   	inc    %ecx
  40e38a:	56                   	push   %esi
  40e38b:	58                   	pop    %eax
  40e38c:	32 35 36 5f 55 4e    	xor    0x4e555f36,%dh
  40e392:	41                   	inc    %ecx
  40e393:	4c                   	dec    %esp
  40e394:	49                   	dec    %ecx
  40e395:	47                   	inc    %edi
  40e396:	4e                   	dec    %esi
  40e397:	45                   	inc    %ebp
  40e398:	44                   	inc    %esp
  40e399:	5f                   	pop    %edi
  40e39a:	53                   	push   %ebx
  40e39b:	54                   	push   %esp
  40e39c:	4f                   	dec    %edi
  40e39d:	52                   	push   %edx
  40e39e:	45                   	inc    %ebp
  40e39f:	5f                   	pop    %edi
  40e3a0:	4f                   	dec    %edi
  40e3a1:	50                   	push   %eax
  40e3a2:	54                   	push   %esp
  40e3a3:	49                   	dec    %ecx
  40e3a4:	4d                   	dec    %ebp
  40e3a5:	41                   	inc    %ecx
  40e3a6:	4c                   	dec    %esp
  40e3a7:	00 3f                	add    %bh,(%edi)
  40e3a9:	11 58 38             	adc    %ebx,0x38(%eax)
  40e3ac:	36 5f                	ss pop %edi
  40e3ae:	54                   	push   %esp
  40e3af:	55                   	push   %ebp
  40e3b0:	4e                   	dec    %esi
  40e3b1:	45                   	inc    %ebp
  40e3b2:	5f                   	pop    %edi
  40e3b3:	41                   	inc    %ecx
  40e3b4:	56                   	push   %esi
  40e3b5:	58                   	pop    %eax
  40e3b6:	31 32                	xor    %esi,(%edx)
  40e3b8:	38 5f 4f             	cmp    %bl,0x4f(%edi)
  40e3bb:	50                   	push   %eax
  40e3bc:	54                   	push   %esp
  40e3bd:	49                   	dec    %ecx
  40e3be:	4d                   	dec    %ebp
  40e3bf:	41                   	inc    %ecx
  40e3c0:	4c                   	dec    %esp
  40e3c1:	00 40 11             	add    %al,0x11(%eax)
  40e3c4:	58                   	pop    %eax
  40e3c5:	38 36                	cmp    %dh,(%esi)
  40e3c7:	5f                   	pop    %edi
  40e3c8:	54                   	push   %esp
  40e3c9:	55                   	push   %ebp
  40e3ca:	4e                   	dec    %esi
  40e3cb:	45                   	inc    %ebp
  40e3cc:	5f                   	pop    %edi
  40e3cd:	41                   	inc    %ecx
  40e3ce:	56                   	push   %esi
  40e3cf:	58                   	pop    %eax
  40e3d0:	32 35 36 5f 4f 50    	xor    0x504f5f36,%dh
  40e3d6:	54                   	push   %esp
  40e3d7:	49                   	dec    %ecx
  40e3d8:	4d                   	dec    %ebp
  40e3d9:	41                   	inc    %ecx
  40e3da:	4c                   	dec    %esp
  40e3db:	00 41 11             	add    %al,0x11(%ecx)
  40e3de:	58                   	pop    %eax
  40e3df:	38 36                	cmp    %dh,(%esi)
  40e3e1:	5f                   	pop    %edi
  40e3e2:	54                   	push   %esp
  40e3e3:	55                   	push   %ebp
  40e3e4:	4e                   	dec    %esi
  40e3e5:	45                   	inc    %ebp
  40e3e6:	5f                   	pop    %edi
  40e3e7:	44                   	inc    %esp
  40e3e8:	4f                   	dec    %edi
  40e3e9:	55                   	push   %ebp
  40e3ea:	42                   	inc    %edx
  40e3eb:	4c                   	dec    %esp
  40e3ec:	45                   	inc    %ebp
  40e3ed:	5f                   	pop    %edi
  40e3ee:	57                   	push   %edi
  40e3ef:	49                   	dec    %ecx
  40e3f0:	54                   	push   %esp
  40e3f1:	48                   	dec    %eax
  40e3f2:	5f                   	pop    %edi
  40e3f3:	41                   	inc    %ecx
  40e3f4:	44                   	inc    %esp
  40e3f5:	44                   	inc    %esp
  40e3f6:	00 42 11             	add    %al,0x11(%edx)
  40e3f9:	58                   	pop    %eax
  40e3fa:	38 36                	cmp    %dh,(%esi)
  40e3fc:	5f                   	pop    %edi
  40e3fd:	54                   	push   %esp
  40e3fe:	55                   	push   %ebp
  40e3ff:	4e                   	dec    %esi
  40e400:	45                   	inc    %ebp
  40e401:	5f                   	pop    %edi
  40e402:	41                   	inc    %ecx
  40e403:	4c                   	dec    %esp
  40e404:	57                   	push   %edi
  40e405:	41                   	inc    %ecx
  40e406:	59                   	pop    %ecx
  40e407:	53                   	push   %ebx
  40e408:	5f                   	pop    %edi
  40e409:	46                   	inc    %esi
  40e40a:	41                   	inc    %ecx
  40e40b:	4e                   	dec    %esi
  40e40c:	43                   	inc    %ebx
  40e40d:	59                   	pop    %ecx
  40e40e:	5f                   	pop    %edi
  40e40f:	4d                   	dec    %ebp
  40e410:	41                   	inc    %ecx
  40e411:	54                   	push   %esp
  40e412:	48                   	dec    %eax
  40e413:	5f                   	pop    %edi
  40e414:	33 38                	xor    (%eax),%edi
  40e416:	37                   	aaa    
  40e417:	00 43 11             	add    %al,0x11(%ebx)
  40e41a:	58                   	pop    %eax
  40e41b:	38 36                	cmp    %dh,(%esi)
  40e41d:	5f                   	pop    %edi
  40e41e:	54                   	push   %esp
  40e41f:	55                   	push   %ebp
  40e420:	4e                   	dec    %esi
  40e421:	45                   	inc    %ebp
  40e422:	5f                   	pop    %edi
  40e423:	55                   	push   %ebp
  40e424:	4e                   	dec    %esi
  40e425:	52                   	push   %edx
  40e426:	4f                   	dec    %edi
  40e427:	4c                   	dec    %esp
  40e428:	4c                   	dec    %esp
  40e429:	5f                   	pop    %edi
  40e42a:	53                   	push   %ebx
  40e42b:	54                   	push   %esp
  40e42c:	52                   	push   %edx
  40e42d:	4c                   	dec    %esp
  40e42e:	45                   	inc    %ebp
  40e42f:	4e                   	dec    %esi
  40e430:	00 44 11 58          	add    %al,0x58(%ecx,%edx,1)
  40e434:	38 36                	cmp    %dh,(%esi)
  40e436:	5f                   	pop    %edi
  40e437:	54                   	push   %esp
  40e438:	55                   	push   %ebp
  40e439:	4e                   	dec    %esi
  40e43a:	45                   	inc    %ebp
  40e43b:	5f                   	pop    %edi
  40e43c:	53                   	push   %ebx
  40e43d:	48                   	dec    %eax
  40e43e:	49                   	dec    %ecx
  40e43f:	46                   	inc    %esi
  40e440:	54                   	push   %esp
  40e441:	31 00                	xor    %eax,(%eax)
  40e443:	45                   	inc    %ebp
  40e444:	11 58 38             	adc    %ebx,0x38(%eax)
  40e447:	36 5f                	ss pop %edi
  40e449:	54                   	push   %esp
  40e44a:	55                   	push   %ebp
  40e44b:	4e                   	dec    %esi
  40e44c:	45                   	inc    %ebp
  40e44d:	5f                   	pop    %edi
  40e44e:	5a                   	pop    %edx
  40e44f:	45                   	inc    %ebp
  40e450:	52                   	push   %edx
  40e451:	4f                   	dec    %edi
  40e452:	5f                   	pop    %edi
  40e453:	45                   	inc    %ebp
  40e454:	58                   	pop    %eax
  40e455:	54                   	push   %esp
  40e456:	45                   	inc    %ebp
  40e457:	4e                   	dec    %esi
  40e458:	44                   	inc    %esp
  40e459:	5f                   	pop    %edi
  40e45a:	57                   	push   %edi
  40e45b:	49                   	dec    %ecx
  40e45c:	54                   	push   %esp
  40e45d:	48                   	dec    %eax
  40e45e:	5f                   	pop    %edi
  40e45f:	41                   	inc    %ecx
  40e460:	4e                   	dec    %esi
  40e461:	44                   	inc    %esp
  40e462:	00 46 11             	add    %al,0x11(%esi)
  40e465:	58                   	pop    %eax
  40e466:	38 36                	cmp    %dh,(%esi)
  40e468:	5f                   	pop    %edi
  40e469:	54                   	push   %esp
  40e46a:	55                   	push   %ebp
  40e46b:	4e                   	dec    %esi
  40e46c:	45                   	inc    %ebp
  40e46d:	5f                   	pop    %edi
  40e46e:	50                   	push   %eax
  40e46f:	52                   	push   %edx
  40e470:	4f                   	dec    %edi
  40e471:	4d                   	dec    %ebp
  40e472:	4f                   	dec    %edi
  40e473:	54                   	push   %esp
  40e474:	45                   	inc    %ebp
  40e475:	5f                   	pop    %edi
  40e476:	48                   	dec    %eax
  40e477:	49                   	dec    %ecx
  40e478:	4d                   	dec    %ebp
  40e479:	4f                   	dec    %edi
  40e47a:	44                   	inc    %esp
  40e47b:	45                   	inc    %ebp
  40e47c:	5f                   	pop    %edi
  40e47d:	49                   	dec    %ecx
  40e47e:	4d                   	dec    %ebp
  40e47f:	55                   	push   %ebp
  40e480:	4c                   	dec    %esp
  40e481:	00 47 11             	add    %al,0x11(%edi)
  40e484:	58                   	pop    %eax
  40e485:	38 36                	cmp    %dh,(%esi)
  40e487:	5f                   	pop    %edi
  40e488:	54                   	push   %esp
  40e489:	55                   	push   %ebp
  40e48a:	4e                   	dec    %esi
  40e48b:	45                   	inc    %ebp
  40e48c:	5f                   	pop    %edi
  40e48d:	46                   	inc    %esi
  40e48e:	41                   	inc    %ecx
  40e48f:	53                   	push   %ebx
  40e490:	54                   	push   %esp
  40e491:	5f                   	pop    %edi
  40e492:	50                   	push   %eax
  40e493:	52                   	push   %edx
  40e494:	45                   	inc    %ebp
  40e495:	46                   	inc    %esi
  40e496:	49                   	dec    %ecx
  40e497:	58                   	pop    %eax
  40e498:	00 48 11             	add    %cl,0x11(%eax)
  40e49b:	58                   	pop    %eax
  40e49c:	38 36                	cmp    %dh,(%esi)
  40e49e:	5f                   	pop    %edi
  40e49f:	54                   	push   %esp
  40e4a0:	55                   	push   %ebp
  40e4a1:	4e                   	dec    %esi
  40e4a2:	45                   	inc    %ebp
  40e4a3:	5f                   	pop    %edi
  40e4a4:	52                   	push   %edx
  40e4a5:	45                   	inc    %ebp
  40e4a6:	41                   	inc    %ecx
  40e4a7:	44                   	inc    %esp
  40e4a8:	5f                   	pop    %edi
  40e4a9:	4d                   	dec    %ebp
  40e4aa:	4f                   	dec    %edi
  40e4ab:	44                   	inc    %esp
  40e4ac:	49                   	dec    %ecx
  40e4ad:	46                   	inc    %esi
  40e4ae:	59                   	pop    %ecx
  40e4af:	5f                   	pop    %edi
  40e4b0:	57                   	push   %edi
  40e4b1:	52                   	push   %edx
  40e4b2:	49                   	dec    %ecx
  40e4b3:	54                   	push   %esp
  40e4b4:	45                   	inc    %ebp
  40e4b5:	00 49 11             	add    %cl,0x11(%ecx)
  40e4b8:	58                   	pop    %eax
  40e4b9:	38 36                	cmp    %dh,(%esi)
  40e4bb:	5f                   	pop    %edi
  40e4bc:	54                   	push   %esp
  40e4bd:	55                   	push   %ebp
  40e4be:	4e                   	dec    %esi
  40e4bf:	45                   	inc    %ebp
  40e4c0:	5f                   	pop    %edi
  40e4c1:	4d                   	dec    %ebp
  40e4c2:	4f                   	dec    %edi
  40e4c3:	56                   	push   %esi
  40e4c4:	45                   	inc    %ebp
  40e4c5:	5f                   	pop    %edi
  40e4c6:	4d                   	dec    %ebp
  40e4c7:	31 5f 56             	xor    %ebx,0x56(%edi)
  40e4ca:	49                   	dec    %ecx
  40e4cb:	41                   	inc    %ecx
  40e4cc:	5f                   	pop    %edi
  40e4cd:	4f                   	dec    %edi
  40e4ce:	52                   	push   %edx
  40e4cf:	00 4a 11             	add    %cl,0x11(%edx)
  40e4d2:	58                   	pop    %eax
  40e4d3:	38 36                	cmp    %dh,(%esi)
  40e4d5:	5f                   	pop    %edi
  40e4d6:	54                   	push   %esp
  40e4d7:	55                   	push   %ebp
  40e4d8:	4e                   	dec    %esi
  40e4d9:	45                   	inc    %ebp
  40e4da:	5f                   	pop    %edi
  40e4db:	4e                   	dec    %esi
  40e4dc:	4f                   	dec    %edi
  40e4dd:	54                   	push   %esp
  40e4de:	5f                   	pop    %edi
  40e4df:	55                   	push   %ebp
  40e4e0:	4e                   	dec    %esi
  40e4e1:	50                   	push   %eax
  40e4e2:	41                   	inc    %ecx
  40e4e3:	49                   	dec    %ecx
  40e4e4:	52                   	push   %edx
  40e4e5:	41                   	inc    %ecx
  40e4e6:	42                   	inc    %edx
  40e4e7:	4c                   	dec    %esp
  40e4e8:	45                   	inc    %ebp
  40e4e9:	00 4b 11             	add    %cl,0x11(%ebx)
  40e4ec:	58                   	pop    %eax
  40e4ed:	38 36                	cmp    %dh,(%esi)
  40e4ef:	5f                   	pop    %edi
  40e4f0:	54                   	push   %esp
  40e4f1:	55                   	push   %ebp
  40e4f2:	4e                   	dec    %esi
  40e4f3:	45                   	inc    %ebp
  40e4f4:	5f                   	pop    %edi
  40e4f5:	50                   	push   %eax
  40e4f6:	41                   	inc    %ecx
  40e4f7:	52                   	push   %edx
  40e4f8:	54                   	push   %esp
  40e4f9:	49                   	dec    %ecx
  40e4fa:	41                   	inc    %ecx
  40e4fb:	4c                   	dec    %esp
  40e4fc:	5f                   	pop    %edi
  40e4fd:	52                   	push   %edx
  40e4fe:	45                   	inc    %ebp
  40e4ff:	47                   	inc    %edi
  40e500:	5f                   	pop    %edi
  40e501:	53                   	push   %ebx
  40e502:	54                   	push   %esp
  40e503:	41                   	inc    %ecx
  40e504:	4c                   	dec    %esp
  40e505:	4c                   	dec    %esp
  40e506:	00 4c 11 58          	add    %cl,0x58(%ecx,%edx,1)
  40e50a:	38 36                	cmp    %dh,(%esi)
  40e50c:	5f                   	pop    %edi
  40e50d:	54                   	push   %esp
  40e50e:	55                   	push   %ebp
  40e50f:	4e                   	dec    %esi
  40e510:	45                   	inc    %ebp
  40e511:	5f                   	pop    %edi
  40e512:	50                   	push   %eax
  40e513:	52                   	push   %edx
  40e514:	4f                   	dec    %edi
  40e515:	4d                   	dec    %ebp
  40e516:	4f                   	dec    %edi
  40e517:	54                   	push   %esp
  40e518:	45                   	inc    %ebp
  40e519:	5f                   	pop    %edi
  40e51a:	51                   	push   %ecx
  40e51b:	49                   	dec    %ecx
  40e51c:	4d                   	dec    %ebp
  40e51d:	4f                   	dec    %edi
  40e51e:	44                   	inc    %esp
  40e51f:	45                   	inc    %ebp
  40e520:	00 4d 11             	add    %cl,0x11(%ebp)
  40e523:	58                   	pop    %eax
  40e524:	38 36                	cmp    %dh,(%esi)
  40e526:	5f                   	pop    %edi
  40e527:	54                   	push   %esp
  40e528:	55                   	push   %ebp
  40e529:	4e                   	dec    %esi
  40e52a:	45                   	inc    %ebp
  40e52b:	5f                   	pop    %edi
  40e52c:	50                   	push   %eax
  40e52d:	52                   	push   %edx
  40e52e:	4f                   	dec    %edi
  40e52f:	4d                   	dec    %ebp
  40e530:	4f                   	dec    %edi
  40e531:	54                   	push   %esp
  40e532:	45                   	inc    %ebp
  40e533:	5f                   	pop    %edi
  40e534:	48                   	dec    %eax
  40e535:	49                   	dec    %ecx
  40e536:	5f                   	pop    %edi
  40e537:	52                   	push   %edx
  40e538:	45                   	inc    %ebp
  40e539:	47                   	inc    %edi
  40e53a:	53                   	push   %ebx
  40e53b:	00 4e 11             	add    %cl,0x11(%esi)
  40e53e:	58                   	pop    %eax
  40e53f:	38 36                	cmp    %dh,(%esi)
  40e541:	5f                   	pop    %edi
  40e542:	54                   	push   %esp
  40e543:	55                   	push   %ebp
  40e544:	4e                   	dec    %esi
  40e545:	45                   	inc    %ebp
  40e546:	5f                   	pop    %edi
  40e547:	48                   	dec    %eax
  40e548:	49                   	dec    %ecx
  40e549:	4d                   	dec    %ebp
  40e54a:	4f                   	dec    %edi
  40e54b:	44                   	inc    %esp
  40e54c:	45                   	inc    %ebp
  40e54d:	5f                   	pop    %edi
  40e54e:	4d                   	dec    %ebp
  40e54f:	41                   	inc    %ecx
  40e550:	54                   	push   %esp
  40e551:	48                   	dec    %eax
  40e552:	00 4f 11             	add    %cl,0x11(%edi)
  40e555:	58                   	pop    %eax
  40e556:	38 36                	cmp    %dh,(%esi)
  40e558:	5f                   	pop    %edi
  40e559:	54                   	push   %esp
  40e55a:	55                   	push   %ebp
  40e55b:	4e                   	dec    %esi
  40e55c:	45                   	inc    %ebp
  40e55d:	5f                   	pop    %edi
  40e55e:	53                   	push   %ebx
  40e55f:	50                   	push   %eax
  40e560:	4c                   	dec    %esp
  40e561:	49                   	dec    %ecx
  40e562:	54                   	push   %esp
  40e563:	5f                   	pop    %edi
  40e564:	4c                   	dec    %esp
  40e565:	4f                   	dec    %edi
  40e566:	4e                   	dec    %esi
  40e567:	47                   	inc    %edi
  40e568:	5f                   	pop    %edi
  40e569:	4d                   	dec    %ebp
  40e56a:	4f                   	dec    %edi
  40e56b:	56                   	push   %esi
  40e56c:	45                   	inc    %ebp
  40e56d:	53                   	push   %ebx
  40e56e:	00 50 11             	add    %dl,0x11(%eax)
  40e571:	58                   	pop    %eax
  40e572:	38 36                	cmp    %dh,(%esi)
  40e574:	5f                   	pop    %edi
  40e575:	54                   	push   %esp
  40e576:	55                   	push   %ebp
  40e577:	4e                   	dec    %esi
  40e578:	45                   	inc    %ebp
  40e579:	5f                   	pop    %edi
  40e57a:	55                   	push   %ebp
  40e57b:	53                   	push   %ebx
  40e57c:	45                   	inc    %ebp
  40e57d:	5f                   	pop    %edi
  40e57e:	58                   	pop    %eax
  40e57f:	43                   	inc    %ebx
  40e580:	48                   	dec    %eax
  40e581:	47                   	inc    %edi
  40e582:	42                   	inc    %edx
  40e583:	00 51 11             	add    %dl,0x11(%ecx)
  40e586:	58                   	pop    %eax
  40e587:	38 36                	cmp    %dh,(%esi)
  40e589:	5f                   	pop    %edi
  40e58a:	54                   	push   %esp
  40e58b:	55                   	push   %ebp
  40e58c:	4e                   	dec    %esi
  40e58d:	45                   	inc    %ebp
  40e58e:	5f                   	pop    %edi
  40e58f:	55                   	push   %ebp
  40e590:	53                   	push   %ebx
  40e591:	45                   	inc    %ebp
  40e592:	5f                   	pop    %edi
  40e593:	4d                   	dec    %ebp
  40e594:	4f                   	dec    %edi
  40e595:	56                   	push   %esi
  40e596:	30 00                	xor    %al,(%eax)
  40e598:	52                   	push   %edx
  40e599:	11 58 38             	adc    %ebx,0x38(%eax)
  40e59c:	36 5f                	ss pop %edi
  40e59e:	54                   	push   %esp
  40e59f:	55                   	push   %ebp
  40e5a0:	4e                   	dec    %esi
  40e5a1:	45                   	inc    %ebp
  40e5a2:	5f                   	pop    %edi
  40e5a3:	4e                   	dec    %esi
  40e5a4:	4f                   	dec    %edi
  40e5a5:	54                   	push   %esp
  40e5a6:	5f                   	pop    %edi
  40e5a7:	56                   	push   %esi
  40e5a8:	45                   	inc    %ebp
  40e5a9:	43                   	inc    %ebx
  40e5aa:	54                   	push   %esp
  40e5ab:	4f                   	dec    %edi
  40e5ac:	52                   	push   %edx
  40e5ad:	4d                   	dec    %ebp
  40e5ae:	4f                   	dec    %edi
  40e5af:	44                   	inc    %esp
  40e5b0:	45                   	inc    %ebp
  40e5b1:	00 53 11             	add    %dl,0x11(%ebx)
  40e5b4:	58                   	pop    %eax
  40e5b5:	38 36                	cmp    %dh,(%esi)
  40e5b7:	5f                   	pop    %edi
  40e5b8:	54                   	push   %esp
  40e5b9:	55                   	push   %ebp
  40e5ba:	4e                   	dec    %esi
  40e5bb:	45                   	inc    %ebp
  40e5bc:	5f                   	pop    %edi
  40e5bd:	41                   	inc    %ecx
  40e5be:	56                   	push   %esi
  40e5bf:	4f                   	dec    %edi
  40e5c0:	49                   	dec    %ecx
  40e5c1:	44                   	inc    %esp
  40e5c2:	5f                   	pop    %edi
  40e5c3:	56                   	push   %esi
  40e5c4:	45                   	inc    %ebp
  40e5c5:	43                   	inc    %ebx
  40e5c6:	54                   	push   %esp
  40e5c7:	4f                   	dec    %edi
  40e5c8:	52                   	push   %edx
  40e5c9:	5f                   	pop    %edi
  40e5ca:	44                   	inc    %esp
  40e5cb:	45                   	inc    %ebp
  40e5cc:	43                   	inc    %ebx
  40e5cd:	4f                   	dec    %edi
  40e5ce:	44                   	inc    %esp
  40e5cf:	45                   	inc    %ebp
  40e5d0:	00 54 11 58          	add    %dl,0x58(%ecx,%edx,1)
  40e5d4:	38 36                	cmp    %dh,(%esi)
  40e5d6:	5f                   	pop    %edi
  40e5d7:	54                   	push   %esp
  40e5d8:	55                   	push   %ebp
  40e5d9:	4e                   	dec    %esi
  40e5da:	45                   	inc    %ebp
  40e5db:	5f                   	pop    %edi
  40e5dc:	42                   	inc    %edx
  40e5dd:	52                   	push   %edx
  40e5de:	41                   	inc    %ecx
  40e5df:	4e                   	dec    %esi
  40e5e0:	43                   	inc    %ebx
  40e5e1:	48                   	dec    %eax
  40e5e2:	5f                   	pop    %edi
  40e5e3:	50                   	push   %eax
  40e5e4:	52                   	push   %edx
  40e5e5:	45                   	inc    %ebp
  40e5e6:	44                   	inc    %esp
  40e5e7:	49                   	dec    %ecx
  40e5e8:	43                   	inc    %ebx
  40e5e9:	54                   	push   %esp
  40e5ea:	49                   	dec    %ecx
  40e5eb:	4f                   	dec    %edi
  40e5ec:	4e                   	dec    %esi
  40e5ed:	5f                   	pop    %edi
  40e5ee:	48                   	dec    %eax
  40e5ef:	49                   	dec    %ecx
  40e5f0:	4e                   	dec    %esi
  40e5f1:	54                   	push   %esp
  40e5f2:	53                   	push   %ebx
  40e5f3:	00 55 11             	add    %dl,0x11(%ebp)
  40e5f6:	58                   	pop    %eax
  40e5f7:	38 36                	cmp    %dh,(%esi)
  40e5f9:	5f                   	pop    %edi
  40e5fa:	54                   	push   %esp
  40e5fb:	55                   	push   %ebp
  40e5fc:	4e                   	dec    %esi
  40e5fd:	45                   	inc    %ebp
  40e5fe:	5f                   	pop    %edi
  40e5ff:	51                   	push   %ecx
  40e600:	49                   	dec    %ecx
  40e601:	4d                   	dec    %ebp
  40e602:	4f                   	dec    %edi
  40e603:	44                   	inc    %esp
  40e604:	45                   	inc    %ebp
  40e605:	5f                   	pop    %edi
  40e606:	4d                   	dec    %ebp
  40e607:	41                   	inc    %ecx
  40e608:	54                   	push   %esp
  40e609:	48                   	dec    %eax
  40e60a:	00 56 11             	add    %dl,0x11(%esi)
  40e60d:	58                   	pop    %eax
  40e60e:	38 36                	cmp    %dh,(%esi)
  40e610:	5f                   	pop    %edi
  40e611:	54                   	push   %esp
  40e612:	55                   	push   %ebp
  40e613:	4e                   	dec    %esi
  40e614:	45                   	inc    %ebp
  40e615:	5f                   	pop    %edi
  40e616:	50                   	push   %eax
  40e617:	52                   	push   %edx
  40e618:	4f                   	dec    %edi
  40e619:	4d                   	dec    %ebp
  40e61a:	4f                   	dec    %edi
  40e61b:	54                   	push   %esp
  40e61c:	45                   	inc    %ebp
  40e61d:	5f                   	pop    %edi
  40e61e:	51                   	push   %ecx
  40e61f:	49                   	dec    %ecx
  40e620:	5f                   	pop    %edi
  40e621:	52                   	push   %edx
  40e622:	45                   	inc    %ebp
  40e623:	47                   	inc    %edi
  40e624:	53                   	push   %ebx
  40e625:	00 57 11             	add    %dl,0x11(%edi)
  40e628:	58                   	pop    %eax
  40e629:	38 36                	cmp    %dh,(%esi)
  40e62b:	5f                   	pop    %edi
  40e62c:	54                   	push   %esp
  40e62d:	55                   	push   %ebp
  40e62e:	4e                   	dec    %esi
  40e62f:	45                   	inc    %ebp
  40e630:	5f                   	pop    %edi
  40e631:	45                   	inc    %ebp
  40e632:	4d                   	dec    %ebp
  40e633:	49                   	dec    %ecx
  40e634:	54                   	push   %esp
  40e635:	5f                   	pop    %edi
  40e636:	56                   	push   %esi
  40e637:	5a                   	pop    %edx
  40e638:	45                   	inc    %ebp
  40e639:	52                   	push   %edx
  40e63a:	4f                   	dec    %edi
  40e63b:	55                   	push   %ebp
  40e63c:	50                   	push   %eax
  40e63d:	50                   	push   %eax
  40e63e:	45                   	inc    %ebp
  40e63f:	52                   	push   %edx
  40e640:	00 58 11             	add    %bl,0x11(%eax)
  40e643:	58                   	pop    %eax
  40e644:	38 36                	cmp    %dh,(%esi)
  40e646:	5f                   	pop    %edi
  40e647:	54                   	push   %esp
  40e648:	55                   	push   %ebp
  40e649:	4e                   	dec    %esi
  40e64a:	45                   	inc    %ebp
  40e64b:	5f                   	pop    %edi
  40e64c:	4c                   	dec    %esp
  40e64d:	41                   	inc    %ecx
  40e64e:	53                   	push   %ebx
  40e64f:	54                   	push   %esp
  40e650:	00 59 00             	add    %bl,0x0(%ecx)
  40e653:	08 4d 04             	or     %cl,0x4(%ebp)
  40e656:	00 00                	add    %al,(%eax)
  40e658:	3d 16 00 00 0c       	cmp    $0xc000016,%eax
  40e65d:	f1                   	icebp  
  40e65e:	00 00                	add    %al,(%eax)
  40e660:	00 58 00             	add    %bl,0x0(%eax)
  40e663:	0b 69 78             	or     0x78(%ecx),%ebp
  40e666:	38 36                	cmp    %dh,(%esi)
  40e668:	5f                   	pop    %edi
  40e669:	74 75                	je     40e6e0 <.debug_info+0x16ba>
  40e66b:	6e                   	outsb  %ds:(%esi),(%dx)
  40e66c:	65 5f                	gs pop %edi
  40e66e:	66 65 61             	gs popaw 
  40e671:	74 75                	je     40e6e8 <.debug_info+0x16c2>
  40e673:	72 65                	jb     40e6da <.debug_info+0x16b4>
  40e675:	73 00                	jae    40e677 <.debug_info+0x1651>
  40e677:	07                   	pop    %es
  40e678:	b0 01                	mov    $0x1,%al
  40e67a:	16                   	push   %ss
  40e67b:	2d 16 00 00 15       	sub    $0x15000016,%eax
  40e680:	69 78 38 36 5f 61 72 	imul   $0x72615f36,0x38(%eax),%edi
  40e687:	63 68 5f             	arpl   %bp,0x5f(%eax)
  40e68a:	69 6e 64 69 63 65 73 	imul   $0x73656369,0x64(%esi),%ebp
  40e691:	00 07                	add    %al,(%edi)
  40e693:	04 f1                	add    $0xf1,%al
  40e695:	00 00                	add    %al,(%eax)
  40e697:	00 07                	add    %al,(%edi)
  40e699:	33 02                	xor    (%edx),%eax
  40e69b:	06                   	push   %es
  40e69c:	e4 16                	in     $0x16,%al
  40e69e:	00 00                	add    %al,(%eax)
  40e6a0:	11 58 38             	adc    %ebx,0x38(%eax)
  40e6a3:	36 5f                	ss pop %edi
  40e6a5:	41                   	inc    %ecx
  40e6a6:	52                   	push   %edx
  40e6a7:	43                   	inc    %ebx
  40e6a8:	48                   	dec    %eax
  40e6a9:	5f                   	pop    %edi
  40e6aa:	43                   	inc    %ebx
  40e6ab:	4d                   	dec    %ebp
  40e6ac:	4f                   	dec    %edi
  40e6ad:	56                   	push   %esi
  40e6ae:	00 00                	add    %al,(%eax)
  40e6b0:	11 58 38             	adc    %ebx,0x38(%eax)
  40e6b3:	36 5f                	ss pop %edi
  40e6b5:	41                   	inc    %ecx
  40e6b6:	52                   	push   %edx
  40e6b7:	43                   	inc    %ebx
  40e6b8:	48                   	dec    %eax
  40e6b9:	5f                   	pop    %edi
  40e6ba:	43                   	inc    %ebx
  40e6bb:	4d                   	dec    %ebp
  40e6bc:	50                   	push   %eax
  40e6bd:	58                   	pop    %eax
  40e6be:	43                   	inc    %ebx
  40e6bf:	48                   	dec    %eax
  40e6c0:	47                   	inc    %edi
  40e6c1:	00 01                	add    %al,(%ecx)
  40e6c3:	11 58 38             	adc    %ebx,0x38(%eax)
  40e6c6:	36 5f                	ss pop %edi
  40e6c8:	41                   	inc    %ecx
  40e6c9:	52                   	push   %edx
  40e6ca:	43                   	inc    %ebx
  40e6cb:	48                   	dec    %eax
  40e6cc:	5f                   	pop    %edi
  40e6cd:	43                   	inc    %ebx
  40e6ce:	4d                   	dec    %ebp
  40e6cf:	50                   	push   %eax
  40e6d0:	58                   	pop    %eax
  40e6d1:	43                   	inc    %ebx
  40e6d2:	48                   	dec    %eax
  40e6d3:	47                   	inc    %edi
  40e6d4:	38 42 00             	cmp    %al,0x0(%edx)
  40e6d7:	02 11                	add    (%ecx),%dl
  40e6d9:	58                   	pop    %eax
  40e6da:	38 36                	cmp    %dh,(%esi)
  40e6dc:	5f                   	pop    %edi
  40e6dd:	41                   	inc    %ecx
  40e6de:	52                   	push   %edx
  40e6df:	43                   	inc    %ebx
  40e6e0:	48                   	dec    %eax
  40e6e1:	5f                   	pop    %edi
  40e6e2:	58                   	pop    %eax
  40e6e3:	41                   	inc    %ecx
  40e6e4:	44                   	inc    %esp
  40e6e5:	44                   	inc    %esp
  40e6e6:	00 03                	add    %al,(%ebx)
  40e6e8:	11 58 38             	adc    %ebx,0x38(%eax)
  40e6eb:	36 5f                	ss pop %edi
  40e6ed:	41                   	inc    %ecx
  40e6ee:	52                   	push   %edx
  40e6ef:	43                   	inc    %ebx
  40e6f0:	48                   	dec    %eax
  40e6f1:	5f                   	pop    %edi
  40e6f2:	42                   	inc    %edx
  40e6f3:	53                   	push   %ebx
  40e6f4:	57                   	push   %edi
  40e6f5:	41                   	inc    %ecx
  40e6f6:	50                   	push   %eax
  40e6f7:	00 04 11             	add    %al,(%ecx,%edx,1)
  40e6fa:	58                   	pop    %eax
  40e6fb:	38 36                	cmp    %dh,(%esi)
  40e6fd:	5f                   	pop    %edi
  40e6fe:	41                   	inc    %ecx
  40e6ff:	52                   	push   %edx
  40e700:	43                   	inc    %ebx
  40e701:	48                   	dec    %eax
  40e702:	5f                   	pop    %edi
  40e703:	4c                   	dec    %esp
  40e704:	41                   	inc    %ecx
  40e705:	53                   	push   %ebx
  40e706:	54                   	push   %esp
  40e707:	00 05 00 08 4d 04    	add    %al,0x44d0800
  40e70d:	00 00                	add    %al,(%eax)
  40e70f:	f4                   	hlt    
  40e710:	16                   	push   %ss
  40e711:	00 00                	add    %al,(%eax)
  40e713:	0c f1                	or     $0xf1,%al
  40e715:	00 00                	add    %al,(%eax)
  40e717:	00 04 00             	add    %al,(%eax,%eax,1)
  40e71a:	0b 69 78             	or     0x78(%ecx),%ebp
  40e71d:	38 36                	cmp    %dh,(%esi)
  40e71f:	5f                   	pop    %edi
  40e720:	61                   	popa   
  40e721:	72 63                	jb     40e786 <.debug_info+0x1760>
  40e723:	68 5f 66 65 61       	push   $0x6165665f
  40e728:	74 75                	je     40e79f <.debug_info+0x1779>
  40e72a:	72 65                	jb     40e791 <.debug_info+0x176b>
  40e72c:	73 00                	jae    40e72e <.debug_info+0x1708>
  40e72e:	07                   	pop    %es
  40e72f:	3d 02 16 e4 16       	cmp    $0x16e41602,%eax
  40e734:	00 00                	add    %al,(%eax)
  40e736:	0b 78 38             	or     0x38(%eax),%edi
  40e739:	36 5f                	ss pop %edi
  40e73b:	70 72                	jo     40e7af <.debug_info+0x1789>
  40e73d:	65 66 65 74 63       	gs data16 gs je 40e7a5 <.debug_info+0x177f>
  40e742:	68 5f 73 73 65       	push   $0x6573735f
  40e747:	00 07                	add    %al,(%edi)
  40e749:	4c                   	dec    %esp
  40e74a:	02 16                	add    (%esi),%dl
  40e74c:	4d                   	dec    %ebp
  40e74d:	04 00                	add    $0x0,%al
  40e74f:	00 16                	add    %dl,(%esi)
  40e751:	5f                   	pop    %edi
  40e752:	64 6f                	outsl  %fs:(%esi),(%dx)
  40e754:	6e                   	outsb  %ds:(%esi),(%dx)
  40e755:	74 5f                	je     40e7b6 <.debug_info+0x1790>
  40e757:	75 73                	jne    40e7cc <.debug_info+0x17a6>
  40e759:	65 5f                	gs pop %edi
  40e75b:	74 72                	je     40e7cf <.debug_info+0x17a9>
  40e75d:	65 65 5f             	gs gs pop %edi
  40e760:	68 65 72 65 5f       	push   $0x5f657265
  40e765:	00 0b                	add    %cl,(%ebx)
  40e767:	78 38                	js     40e7a1 <.debug_info+0x177b>
  40e769:	36 5f                	ss pop %edi
  40e76b:	6d                   	insl   (%dx),%es:(%edi)
  40e76c:	66 65 6e             	data16 outsb %gs:(%esi),(%dx)
  40e76f:	63 65 00             	arpl   %sp,0x0(%ebp)
  40e772:	07                   	pop    %es
  40e773:	6a 02                	push   $0x2
  40e775:	0d 54 17 00 00       	or     $0x1754,%eax
  40e77a:	06                   	push   %es
  40e77b:	04 2a                	add    $0x2a,%al
  40e77d:	17                   	pop    %ss
  40e77e:	00 00                	add    %al,(%eax)
  40e780:	15 72 65 67 5f       	adc    $0x5f676572,%eax
  40e785:	63 6c 61 73          	arpl   %bp,0x73(%ecx,%eiz,2)
  40e789:	73 00                	jae    40e78b <.debug_info+0x1765>
  40e78b:	07                   	pop    %es
  40e78c:	04 f1                	add    $0xf1,%al
  40e78e:	00 00                	add    %al,(%eax)
  40e790:	00 07                	add    %al,(%edi)
  40e792:	30 05 06 08 19 00    	xor    %al,0x190806
  40e798:	00 11                	add    %dl,(%ecx)
  40e79a:	4e                   	dec    %esi
  40e79b:	4f                   	dec    %edi
  40e79c:	5f                   	pop    %edi
  40e79d:	52                   	push   %edx
  40e79e:	45                   	inc    %ebp
  40e79f:	47                   	inc    %edi
  40e7a0:	53                   	push   %ebx
  40e7a1:	00 00                	add    %al,(%eax)
  40e7a3:	11 41 52             	adc    %eax,0x52(%ecx)
  40e7a6:	45                   	inc    %ebp
  40e7a7:	47                   	inc    %edi
  40e7a8:	00 01                	add    %al,(%ecx)
  40e7aa:	11 44 52 45          	adc    %eax,0x45(%edx,%edx,2)
  40e7ae:	47                   	inc    %edi
  40e7af:	00 02                	add    %al,(%edx)
  40e7b1:	11 43 52             	adc    %eax,0x52(%ebx)
  40e7b4:	45                   	inc    %ebp
  40e7b5:	47                   	inc    %edi
  40e7b6:	00 03                	add    %al,(%ebx)
  40e7b8:	11 42 52             	adc    %eax,0x52(%edx)
  40e7bb:	45                   	inc    %ebp
  40e7bc:	47                   	inc    %edi
  40e7bd:	00 04 11             	add    %al,(%ecx,%edx,1)
  40e7c0:	53                   	push   %ebx
  40e7c1:	49                   	dec    %ecx
  40e7c2:	52                   	push   %edx
  40e7c3:	45                   	inc    %ebp
  40e7c4:	47                   	inc    %edi
  40e7c5:	00 05 11 44 49 52    	add    %al,0x52494411
  40e7cb:	45                   	inc    %ebp
  40e7cc:	47                   	inc    %edi
  40e7cd:	00 06                	add    %al,(%esi)
  40e7cf:	11 41 44             	adc    %eax,0x44(%ecx)
  40e7d2:	5f                   	pop    %edi
  40e7d3:	52                   	push   %edx
  40e7d4:	45                   	inc    %ebp
  40e7d5:	47                   	inc    %edi
  40e7d6:	53                   	push   %ebx
  40e7d7:	00 07                	add    %al,(%edi)
  40e7d9:	11 43 4c             	adc    %eax,0x4c(%ebx)
  40e7dc:	4f                   	dec    %edi
  40e7dd:	42                   	inc    %edx
  40e7de:	42                   	inc    %edx
  40e7df:	45                   	inc    %ebp
  40e7e0:	52                   	push   %edx
  40e7e1:	45                   	inc    %ebp
  40e7e2:	44                   	inc    %esp
  40e7e3:	5f                   	pop    %edi
  40e7e4:	52                   	push   %edx
  40e7e5:	45                   	inc    %ebp
  40e7e6:	47                   	inc    %edi
  40e7e7:	53                   	push   %ebx
  40e7e8:	00 08                	add    %cl,(%eax)
  40e7ea:	11 51 5f             	adc    %edx,0x5f(%ecx)
  40e7ed:	52                   	push   %edx
  40e7ee:	45                   	inc    %ebp
  40e7ef:	47                   	inc    %edi
  40e7f0:	53                   	push   %ebx
  40e7f1:	00 09                	add    %cl,(%ecx)
  40e7f3:	11 4e 4f             	adc    %ecx,0x4f(%esi)
  40e7f6:	4e                   	dec    %esi
  40e7f7:	5f                   	pop    %edi
  40e7f8:	51                   	push   %ecx
  40e7f9:	5f                   	pop    %edi
  40e7fa:	52                   	push   %edx
  40e7fb:	45                   	inc    %ebp
  40e7fc:	47                   	inc    %edi
  40e7fd:	53                   	push   %ebx
  40e7fe:	00 0a                	add    %cl,(%edx)
  40e800:	11 54 4c 53          	adc    %edx,0x53(%esp,%ecx,2)
  40e804:	5f                   	pop    %edi
  40e805:	47                   	inc    %edi
  40e806:	4f                   	dec    %edi
  40e807:	54                   	push   %esp
  40e808:	42                   	inc    %edx
  40e809:	41                   	inc    %ecx
  40e80a:	53                   	push   %ebx
  40e80b:	45                   	inc    %ebp
  40e80c:	5f                   	pop    %edi
  40e80d:	52                   	push   %edx
  40e80e:	45                   	inc    %ebp
  40e80f:	47                   	inc    %edi
  40e810:	53                   	push   %ebx
  40e811:	00 0b                	add    %cl,(%ebx)
  40e813:	11 49 4e             	adc    %ecx,0x4e(%ecx)
  40e816:	44                   	inc    %esp
  40e817:	45                   	inc    %ebp
  40e818:	58                   	pop    %eax
  40e819:	5f                   	pop    %edi
  40e81a:	52                   	push   %edx
  40e81b:	45                   	inc    %ebp
  40e81c:	47                   	inc    %edi
  40e81d:	53                   	push   %ebx
  40e81e:	00 0c 11             	add    %cl,(%ecx,%edx,1)
  40e821:	4c                   	dec    %esp
  40e822:	45                   	inc    %ebp
  40e823:	47                   	inc    %edi
  40e824:	41                   	inc    %ecx
  40e825:	43                   	inc    %ebx
  40e826:	59                   	pop    %ecx
  40e827:	5f                   	pop    %edi
  40e828:	52                   	push   %edx
  40e829:	45                   	inc    %ebp
  40e82a:	47                   	inc    %edi
  40e82b:	53                   	push   %ebx
  40e82c:	00 0d 11 47 45 4e    	add    %cl,0x4e454711
  40e832:	45                   	inc    %ebp
  40e833:	52                   	push   %edx
  40e834:	41                   	inc    %ecx
  40e835:	4c                   	dec    %esp
  40e836:	5f                   	pop    %edi
  40e837:	52                   	push   %edx
  40e838:	45                   	inc    %ebp
  40e839:	47                   	inc    %edi
  40e83a:	53                   	push   %ebx
  40e83b:	00 0e                	add    %cl,(%esi)
  40e83d:	11 46 50             	adc    %eax,0x50(%esi)
  40e840:	5f                   	pop    %edi
  40e841:	54                   	push   %esp
  40e842:	4f                   	dec    %edi
  40e843:	50                   	push   %eax
  40e844:	5f                   	pop    %edi
  40e845:	52                   	push   %edx
  40e846:	45                   	inc    %ebp
  40e847:	47                   	inc    %edi
  40e848:	00 0f                	add    %cl,(%edi)
  40e84a:	11 46 50             	adc    %eax,0x50(%esi)
  40e84d:	5f                   	pop    %edi
  40e84e:	53                   	push   %ebx
  40e84f:	45                   	inc    %ebp
  40e850:	43                   	inc    %ebx
  40e851:	4f                   	dec    %edi
  40e852:	4e                   	dec    %esi
  40e853:	44                   	inc    %esp
  40e854:	5f                   	pop    %edi
  40e855:	52                   	push   %edx
  40e856:	45                   	inc    %ebp
  40e857:	47                   	inc    %edi
  40e858:	00 10                	add    %dl,(%eax)
  40e85a:	11 46 4c             	adc    %eax,0x4c(%esi)
  40e85d:	4f                   	dec    %edi
  40e85e:	41                   	inc    %ecx
  40e85f:	54                   	push   %esp
  40e860:	5f                   	pop    %edi
  40e861:	52                   	push   %edx
  40e862:	45                   	inc    %ebp
  40e863:	47                   	inc    %edi
  40e864:	53                   	push   %ebx
  40e865:	00 11                	add    %dl,(%ecx)
  40e867:	11 53 53             	adc    %edx,0x53(%ebx)
  40e86a:	45                   	inc    %ebp
  40e86b:	5f                   	pop    %edi
  40e86c:	46                   	inc    %esi
  40e86d:	49                   	dec    %ecx
  40e86e:	52                   	push   %edx
  40e86f:	53                   	push   %ebx
  40e870:	54                   	push   %esp
  40e871:	5f                   	pop    %edi
  40e872:	52                   	push   %edx
  40e873:	45                   	inc    %ebp
  40e874:	47                   	inc    %edi
  40e875:	00 12                	add    %dl,(%edx)
  40e877:	11 4e 4f             	adc    %ecx,0x4f(%esi)
  40e87a:	5f                   	pop    %edi
  40e87b:	52                   	push   %edx
  40e87c:	45                   	inc    %ebp
  40e87d:	58                   	pop    %eax
  40e87e:	5f                   	pop    %edi
  40e87f:	53                   	push   %ebx
  40e880:	53                   	push   %ebx
  40e881:	45                   	inc    %ebp
  40e882:	5f                   	pop    %edi
  40e883:	52                   	push   %edx
  40e884:	45                   	inc    %ebp
  40e885:	47                   	inc    %edi
  40e886:	53                   	push   %ebx
  40e887:	00 13                	add    %dl,(%ebx)
  40e889:	11 53 53             	adc    %edx,0x53(%ebx)
  40e88c:	45                   	inc    %ebp
  40e88d:	5f                   	pop    %edi
  40e88e:	52                   	push   %edx
  40e88f:	45                   	inc    %ebp
  40e890:	47                   	inc    %edi
  40e891:	53                   	push   %ebx
  40e892:	00 14 11             	add    %dl,(%ecx,%edx,1)
  40e895:	41                   	inc    %ecx
  40e896:	4c                   	dec    %esp
  40e897:	4c                   	dec    %esp
  40e898:	5f                   	pop    %edi
  40e899:	53                   	push   %ebx
  40e89a:	53                   	push   %ebx
  40e89b:	45                   	inc    %ebp
  40e89c:	5f                   	pop    %edi
  40e89d:	52                   	push   %edx
  40e89e:	45                   	inc    %ebp
  40e89f:	47                   	inc    %edi
  40e8a0:	53                   	push   %ebx
  40e8a1:	00 15 11 4d 4d 58    	add    %dl,0x584d4d11
  40e8a7:	5f                   	pop    %edi
  40e8a8:	52                   	push   %edx
  40e8a9:	45                   	inc    %ebp
  40e8aa:	47                   	inc    %edi
  40e8ab:	53                   	push   %ebx
  40e8ac:	00 16                	add    %dl,(%esi)
  40e8ae:	11 46 4c             	adc    %eax,0x4c(%esi)
  40e8b1:	4f                   	dec    %edi
  40e8b2:	41                   	inc    %ecx
  40e8b3:	54                   	push   %esp
  40e8b4:	5f                   	pop    %edi
  40e8b5:	53                   	push   %ebx
  40e8b6:	53                   	push   %ebx
  40e8b7:	45                   	inc    %ebp
  40e8b8:	5f                   	pop    %edi
  40e8b9:	52                   	push   %edx
  40e8ba:	45                   	inc    %ebp
  40e8bb:	47                   	inc    %edi
  40e8bc:	53                   	push   %ebx
  40e8bd:	00 17                	add    %dl,(%edi)
  40e8bf:	11 46 4c             	adc    %eax,0x4c(%esi)
  40e8c2:	4f                   	dec    %edi
  40e8c3:	41                   	inc    %ecx
  40e8c4:	54                   	push   %esp
  40e8c5:	5f                   	pop    %edi
  40e8c6:	49                   	dec    %ecx
  40e8c7:	4e                   	dec    %esi
  40e8c8:	54                   	push   %esp
  40e8c9:	5f                   	pop    %edi
  40e8ca:	52                   	push   %edx
  40e8cb:	45                   	inc    %ebp
  40e8cc:	47                   	inc    %edi
  40e8cd:	53                   	push   %ebx
  40e8ce:	00 18                	add    %bl,(%eax)
  40e8d0:	11 49 4e             	adc    %ecx,0x4e(%ecx)
  40e8d3:	54                   	push   %esp
  40e8d4:	5f                   	pop    %edi
  40e8d5:	53                   	push   %ebx
  40e8d6:	53                   	push   %ebx
  40e8d7:	45                   	inc    %ebp
  40e8d8:	5f                   	pop    %edi
  40e8d9:	52                   	push   %edx
  40e8da:	45                   	inc    %ebp
  40e8db:	47                   	inc    %edi
  40e8dc:	53                   	push   %ebx
  40e8dd:	00 19                	add    %bl,(%ecx)
  40e8df:	11 46 4c             	adc    %eax,0x4c(%esi)
  40e8e2:	4f                   	dec    %edi
  40e8e3:	41                   	inc    %ecx
  40e8e4:	54                   	push   %esp
  40e8e5:	5f                   	pop    %edi
  40e8e6:	49                   	dec    %ecx
  40e8e7:	4e                   	dec    %esi
  40e8e8:	54                   	push   %esp
  40e8e9:	5f                   	pop    %edi
  40e8ea:	53                   	push   %ebx
  40e8eb:	53                   	push   %ebx
  40e8ec:	45                   	inc    %ebp
  40e8ed:	5f                   	pop    %edi
  40e8ee:	52                   	push   %edx
  40e8ef:	45                   	inc    %ebp
  40e8f0:	47                   	inc    %edi
  40e8f1:	53                   	push   %ebx
  40e8f2:	00 1a                	add    %bl,(%edx)
  40e8f4:	11 4d 41             	adc    %ecx,0x41(%ebp)
  40e8f7:	53                   	push   %ebx
  40e8f8:	4b                   	dec    %ebx
  40e8f9:	5f                   	pop    %edi
  40e8fa:	52                   	push   %edx
  40e8fb:	45                   	inc    %ebp
  40e8fc:	47                   	inc    %edi
  40e8fd:	53                   	push   %ebx
  40e8fe:	00 1b                	add    %bl,(%ebx)
  40e900:	11 41 4c             	adc    %eax,0x4c(%ecx)
  40e903:	4c                   	dec    %esp
  40e904:	5f                   	pop    %edi
  40e905:	4d                   	dec    %ebp
  40e906:	41                   	inc    %ecx
  40e907:	53                   	push   %ebx
  40e908:	4b                   	dec    %ebx
  40e909:	5f                   	pop    %edi
  40e90a:	52                   	push   %edx
  40e90b:	45                   	inc    %ebp
  40e90c:	47                   	inc    %edi
  40e90d:	53                   	push   %ebx
  40e90e:	00 1c 11             	add    %bl,(%ecx,%edx,1)
  40e911:	41                   	inc    %ecx
  40e912:	4c                   	dec    %esp
  40e913:	4c                   	dec    %esp
  40e914:	5f                   	pop    %edi
  40e915:	52                   	push   %edx
  40e916:	45                   	inc    %ebp
  40e917:	47                   	inc    %edi
  40e918:	53                   	push   %ebx
  40e919:	00 1d 11 4c 49 4d    	add    %bl,0x4d494c11
  40e91f:	5f                   	pop    %edi
  40e920:	52                   	push   %edx
  40e921:	45                   	inc    %ebp
  40e922:	47                   	inc    %edi
  40e923:	5f                   	pop    %edi
  40e924:	43                   	inc    %ebx
  40e925:	4c                   	dec    %esp
  40e926:	41                   	inc    %ecx
  40e927:	53                   	push   %ebx
  40e928:	53                   	push   %ebx
  40e929:	45                   	inc    %ebp
  40e92a:	53                   	push   %ebx
  40e92b:	00 1e                	add    %bl,(%esi)
  40e92d:	00 03                	add    %al,(%ebx)
  40e92f:	5a                   	pop    %edx
  40e930:	17                   	pop    %ss
  40e931:	00 00                	add    %al,(%eax)
  40e933:	08 ec                	or     %ch,%ah
  40e935:	00 00                	add    %al,(%eax)
  40e937:	00 1d 19 00 00 0c    	add    %bl,0xc000019
  40e93d:	f1                   	icebp  
  40e93e:	00 00                	add    %al,(%eax)
  40e940:	00 4b 00             	add    %cl,0x0(%ebx)
  40e943:	03 0d 19 00 00 0b    	add    0xb000019,%ecx
  40e949:	64 62 78 5f          	bound  %edi,%fs:0x5f(%eax)
  40e94d:	72 65                	jb     40e9b4 <.debug_info+0x198e>
  40e94f:	67 69 73 74 65 72 5f 	imul   $0x6d5f7265,0x74(%bp,%di),%esi
  40e956:	6d 
  40e957:	61                   	popa   
  40e958:	70 00                	jo     40e95a <.debug_info+0x1934>
  40e95a:	07                   	pop    %es
  40e95b:	26 08 12             	or     %dl,%es:(%edx)
  40e95e:	1d 19 00 00 0b       	sbb    $0xb000019,%eax
  40e963:	64 62 78 36          	bound  %edi,%fs:0x36(%eax)
  40e967:	34 5f                	xor    $0x5f,%al
  40e969:	72 65                	jb     40e9d0 <.debug_info+0x19aa>
  40e96b:	67 69 73 74 65 72 5f 	imul   $0x6d5f7265,0x74(%bp,%di),%esi
  40e972:	6d 
  40e973:	61                   	popa   
  40e974:	70 00                	jo     40e976 <.debug_info+0x1950>
  40e976:	07                   	pop    %es
  40e977:	27                   	daa    
  40e978:	08 12                	or     %dl,(%edx)
  40e97a:	1d 19 00 00 0b       	sbb    $0xb000019,%eax
  40e97f:	73 76                	jae    40e9f7 <.debug_info+0x19d1>
  40e981:	72 34                	jb     40e9b7 <.debug_info+0x1991>
  40e983:	5f                   	pop    %edi
  40e984:	64 62 78 5f          	bound  %edi,%fs:0x5f(%eax)
  40e988:	72 65                	jb     40e9ef <.debug_info+0x19c9>
  40e98a:	67 69 73 74 65 72 5f 	imul   $0x6d5f7265,0x74(%bp,%di),%esi
  40e991:	6d 
  40e992:	61                   	popa   
  40e993:	70 00                	jo     40e995 <.debug_info+0x196f>
  40e995:	07                   	pop    %es
  40e996:	28 08                	sub    %cl,(%eax)
  40e998:	12 1d 19 00 00 15    	adc    0x15000019,%bl
  40e99e:	70 72                	jo     40ea12 <.debug_info+0x19ec>
  40e9a0:	6f                   	outsl  %ds:(%esi),(%dx)
  40e9a1:	63 65 73             	arpl   %sp,0x73(%ebp)
  40e9a4:	73 6f                	jae    40ea15 <.debug_info+0x19ef>
  40e9a6:	72 5f                	jb     40ea07 <.debug_info+0x19e1>
  40e9a8:	74 79                	je     40ea23 <.debug_info+0x19fd>
  40e9aa:	70 65                	jo     40ea11 <.debug_info+0x19eb>
  40e9ac:	00 07                	add    %al,(%edi)
  40e9ae:	04 f1                	add    $0xf1,%al
  40e9b0:	00 00                	add    %al,(%eax)
  40e9b2:	00 07                	add    %al,(%edi)
  40e9b4:	ba 08 06 ba 1c       	mov    $0x1cba0608,%edx
  40e9b9:	00 00                	add    %al,(%eax)
  40e9bb:	11 50 52             	adc    %edx,0x52(%eax)
  40e9be:	4f                   	dec    %edi
  40e9bf:	43                   	inc    %ebx
  40e9c0:	45                   	inc    %ebp
  40e9c1:	53                   	push   %ebx
  40e9c2:	53                   	push   %ebx
  40e9c3:	4f                   	dec    %edi
  40e9c4:	52                   	push   %edx
  40e9c5:	5f                   	pop    %edi
  40e9c6:	47                   	inc    %edi
  40e9c7:	45                   	inc    %ebp
  40e9c8:	4e                   	dec    %esi
  40e9c9:	45                   	inc    %ebp
  40e9ca:	52                   	push   %edx
  40e9cb:	49                   	dec    %ecx
  40e9cc:	43                   	inc    %ebx
  40e9cd:	00 00                	add    %al,(%eax)
  40e9cf:	11 50 52             	adc    %edx,0x52(%eax)
  40e9d2:	4f                   	dec    %edi
  40e9d3:	43                   	inc    %ebx
  40e9d4:	45                   	inc    %ebp
  40e9d5:	53                   	push   %ebx
  40e9d6:	53                   	push   %ebx
  40e9d7:	4f                   	dec    %edi
  40e9d8:	52                   	push   %edx
  40e9d9:	5f                   	pop    %edi
  40e9da:	49                   	dec    %ecx
  40e9db:	33 38                	xor    (%eax),%edi
  40e9dd:	36 00 01             	add    %al,%ss:(%ecx)
  40e9e0:	11 50 52             	adc    %edx,0x52(%eax)
  40e9e3:	4f                   	dec    %edi
  40e9e4:	43                   	inc    %ebx
  40e9e5:	45                   	inc    %ebp
  40e9e6:	53                   	push   %ebx
  40e9e7:	53                   	push   %ebx
  40e9e8:	4f                   	dec    %edi
  40e9e9:	52                   	push   %edx
  40e9ea:	5f                   	pop    %edi
  40e9eb:	49                   	dec    %ecx
  40e9ec:	34 38                	xor    $0x38,%al
  40e9ee:	36 00 02             	add    %al,%ss:(%edx)
  40e9f1:	11 50 52             	adc    %edx,0x52(%eax)
  40e9f4:	4f                   	dec    %edi
  40e9f5:	43                   	inc    %ebx
  40e9f6:	45                   	inc    %ebp
  40e9f7:	53                   	push   %ebx
  40e9f8:	53                   	push   %ebx
  40e9f9:	4f                   	dec    %edi
  40e9fa:	52                   	push   %edx
  40e9fb:	5f                   	pop    %edi
  40e9fc:	50                   	push   %eax
  40e9fd:	45                   	inc    %ebp
  40e9fe:	4e                   	dec    %esi
  40e9ff:	54                   	push   %esp
  40ea00:	49                   	dec    %ecx
  40ea01:	55                   	push   %ebp
  40ea02:	4d                   	dec    %ebp
  40ea03:	00 03                	add    %al,(%ebx)
  40ea05:	11 50 52             	adc    %edx,0x52(%eax)
  40ea08:	4f                   	dec    %edi
  40ea09:	43                   	inc    %ebx
  40ea0a:	45                   	inc    %ebp
  40ea0b:	53                   	push   %ebx
  40ea0c:	53                   	push   %ebx
  40ea0d:	4f                   	dec    %edi
  40ea0e:	52                   	push   %edx
  40ea0f:	5f                   	pop    %edi
  40ea10:	4c                   	dec    %esp
  40ea11:	41                   	inc    %ecx
  40ea12:	4b                   	dec    %ebx
  40ea13:	45                   	inc    %ebp
  40ea14:	4d                   	dec    %ebp
  40ea15:	4f                   	dec    %edi
  40ea16:	4e                   	dec    %esi
  40ea17:	54                   	push   %esp
  40ea18:	00 04 11             	add    %al,(%ecx,%edx,1)
  40ea1b:	50                   	push   %eax
  40ea1c:	52                   	push   %edx
  40ea1d:	4f                   	dec    %edi
  40ea1e:	43                   	inc    %ebx
  40ea1f:	45                   	inc    %ebp
  40ea20:	53                   	push   %ebx
  40ea21:	53                   	push   %ebx
  40ea22:	4f                   	dec    %edi
  40ea23:	52                   	push   %edx
  40ea24:	5f                   	pop    %edi
  40ea25:	50                   	push   %eax
  40ea26:	45                   	inc    %ebp
  40ea27:	4e                   	dec    %esi
  40ea28:	54                   	push   %esp
  40ea29:	49                   	dec    %ecx
  40ea2a:	55                   	push   %ebp
  40ea2b:	4d                   	dec    %ebp
  40ea2c:	50                   	push   %eax
  40ea2d:	52                   	push   %edx
  40ea2e:	4f                   	dec    %edi
  40ea2f:	00 05 11 50 52 4f    	add    %al,0x4f525011
  40ea35:	43                   	inc    %ebx
  40ea36:	45                   	inc    %ebp
  40ea37:	53                   	push   %ebx
  40ea38:	53                   	push   %ebx
  40ea39:	4f                   	dec    %edi
  40ea3a:	52                   	push   %edx
  40ea3b:	5f                   	pop    %edi
  40ea3c:	50                   	push   %eax
  40ea3d:	45                   	inc    %ebp
  40ea3e:	4e                   	dec    %esi
  40ea3f:	54                   	push   %esp
  40ea40:	49                   	dec    %ecx
  40ea41:	55                   	push   %ebp
  40ea42:	4d                   	dec    %ebp
  40ea43:	34 00                	xor    $0x0,%al
  40ea45:	06                   	push   %es
  40ea46:	11 50 52             	adc    %edx,0x52(%eax)
  40ea49:	4f                   	dec    %edi
  40ea4a:	43                   	inc    %ebx
  40ea4b:	45                   	inc    %ebp
  40ea4c:	53                   	push   %ebx
  40ea4d:	53                   	push   %ebx
  40ea4e:	4f                   	dec    %edi
  40ea4f:	52                   	push   %edx
  40ea50:	5f                   	pop    %edi
  40ea51:	4e                   	dec    %esi
  40ea52:	4f                   	dec    %edi
  40ea53:	43                   	inc    %ebx
  40ea54:	4f                   	dec    %edi
  40ea55:	4e                   	dec    %esi
  40ea56:	41                   	inc    %ecx
  40ea57:	00 07                	add    %al,(%edi)
  40ea59:	11 50 52             	adc    %edx,0x52(%eax)
  40ea5c:	4f                   	dec    %edi
  40ea5d:	43                   	inc    %ebx
  40ea5e:	45                   	inc    %ebp
  40ea5f:	53                   	push   %ebx
  40ea60:	53                   	push   %ebx
  40ea61:	4f                   	dec    %edi
  40ea62:	52                   	push   %edx
  40ea63:	5f                   	pop    %edi
  40ea64:	43                   	inc    %ebx
  40ea65:	4f                   	dec    %edi
  40ea66:	52                   	push   %edx
  40ea67:	45                   	inc    %ebp
  40ea68:	32 00                	xor    (%eax),%al
  40ea6a:	08 11                	or     %dl,(%ecx)
  40ea6c:	50                   	push   %eax
  40ea6d:	52                   	push   %edx
  40ea6e:	4f                   	dec    %edi
  40ea6f:	43                   	inc    %ebx
  40ea70:	45                   	inc    %ebp
  40ea71:	53                   	push   %ebx
  40ea72:	53                   	push   %ebx
  40ea73:	4f                   	dec    %edi
  40ea74:	52                   	push   %edx
  40ea75:	5f                   	pop    %edi
  40ea76:	4e                   	dec    %esi
  40ea77:	45                   	inc    %ebp
  40ea78:	48                   	dec    %eax
  40ea79:	41                   	inc    %ecx
  40ea7a:	4c                   	dec    %esp
  40ea7b:	45                   	inc    %ebp
  40ea7c:	4d                   	dec    %ebp
  40ea7d:	00 09                	add    %cl,(%ecx)
  40ea7f:	11 50 52             	adc    %edx,0x52(%eax)
  40ea82:	4f                   	dec    %edi
  40ea83:	43                   	inc    %ebx
  40ea84:	45                   	inc    %ebp
  40ea85:	53                   	push   %ebx
  40ea86:	53                   	push   %ebx
  40ea87:	4f                   	dec    %edi
  40ea88:	52                   	push   %edx
  40ea89:	5f                   	pop    %edi
  40ea8a:	53                   	push   %ebx
  40ea8b:	41                   	inc    %ecx
  40ea8c:	4e                   	dec    %esi
  40ea8d:	44                   	inc    %esp
  40ea8e:	59                   	pop    %ecx
  40ea8f:	42                   	inc    %edx
  40ea90:	52                   	push   %edx
  40ea91:	49                   	dec    %ecx
  40ea92:	44                   	inc    %esp
  40ea93:	47                   	inc    %edi
  40ea94:	45                   	inc    %ebp
  40ea95:	00 0a                	add    %cl,(%edx)
  40ea97:	11 50 52             	adc    %edx,0x52(%eax)
  40ea9a:	4f                   	dec    %edi
  40ea9b:	43                   	inc    %ebx
  40ea9c:	45                   	inc    %ebp
  40ea9d:	53                   	push   %ebx
  40ea9e:	53                   	push   %ebx
  40ea9f:	4f                   	dec    %edi
  40eaa0:	52                   	push   %edx
  40eaa1:	5f                   	pop    %edi
  40eaa2:	48                   	dec    %eax
  40eaa3:	41                   	inc    %ecx
  40eaa4:	53                   	push   %ebx
  40eaa5:	57                   	push   %edi
  40eaa6:	45                   	inc    %ebp
  40eaa7:	4c                   	dec    %esp
  40eaa8:	4c                   	dec    %esp
  40eaa9:	00 0b                	add    %cl,(%ebx)
  40eaab:	11 50 52             	adc    %edx,0x52(%eax)
  40eaae:	4f                   	dec    %edi
  40eaaf:	43                   	inc    %ebx
  40eab0:	45                   	inc    %ebp
  40eab1:	53                   	push   %ebx
  40eab2:	53                   	push   %ebx
  40eab3:	4f                   	dec    %edi
  40eab4:	52                   	push   %edx
  40eab5:	5f                   	pop    %edi
  40eab6:	42                   	inc    %edx
  40eab7:	4f                   	dec    %edi
  40eab8:	4e                   	dec    %esi
  40eab9:	4e                   	dec    %esi
  40eaba:	45                   	inc    %ebp
  40eabb:	4c                   	dec    %esp
  40eabc:	4c                   	dec    %esp
  40eabd:	00 0c 11             	add    %cl,(%ecx,%edx,1)
  40eac0:	50                   	push   %eax
  40eac1:	52                   	push   %edx
  40eac2:	4f                   	dec    %edi
  40eac3:	43                   	inc    %ebx
  40eac4:	45                   	inc    %ebp
  40eac5:	53                   	push   %ebx
  40eac6:	53                   	push   %ebx
  40eac7:	4f                   	dec    %edi
  40eac8:	52                   	push   %edx
  40eac9:	5f                   	pop    %edi
  40eaca:	53                   	push   %ebx
  40eacb:	49                   	dec    %ecx
  40eacc:	4c                   	dec    %esp
  40eacd:	56                   	push   %esi
  40eace:	45                   	inc    %ebp
  40eacf:	52                   	push   %edx
  40ead0:	4d                   	dec    %ebp
  40ead1:	4f                   	dec    %edi
  40ead2:	4e                   	dec    %esi
  40ead3:	54                   	push   %esp
  40ead4:	00 0d 11 50 52 4f    	add    %cl,0x4f525011
  40eada:	43                   	inc    %ebx
  40eadb:	45                   	inc    %ebp
  40eadc:	53                   	push   %ebx
  40eadd:	53                   	push   %ebx
  40eade:	4f                   	dec    %edi
  40eadf:	52                   	push   %edx
  40eae0:	5f                   	pop    %edi
  40eae1:	47                   	inc    %edi
  40eae2:	4f                   	dec    %edi
  40eae3:	4c                   	dec    %esp
  40eae4:	44                   	inc    %esp
  40eae5:	4d                   	dec    %ebp
  40eae6:	4f                   	dec    %edi
  40eae7:	4e                   	dec    %esi
  40eae8:	54                   	push   %esp
  40eae9:	00 0e                	add    %cl,(%esi)
  40eaeb:	11 50 52             	adc    %edx,0x52(%eax)
  40eaee:	4f                   	dec    %edi
  40eaef:	43                   	inc    %ebx
  40eaf0:	45                   	inc    %ebp
  40eaf1:	53                   	push   %ebx
  40eaf2:	53                   	push   %ebx
  40eaf3:	4f                   	dec    %edi
  40eaf4:	52                   	push   %edx
  40eaf5:	5f                   	pop    %edi
  40eaf6:	47                   	inc    %edi
  40eaf7:	4f                   	dec    %edi
  40eaf8:	4c                   	dec    %esp
  40eaf9:	44                   	inc    %esp
  40eafa:	4d                   	dec    %ebp
  40eafb:	4f                   	dec    %edi
  40eafc:	4e                   	dec    %esi
  40eafd:	54                   	push   %esp
  40eafe:	5f                   	pop    %edi
  40eaff:	50                   	push   %eax
  40eb00:	4c                   	dec    %esp
  40eb01:	55                   	push   %ebp
  40eb02:	53                   	push   %ebx
  40eb03:	00 0f                	add    %cl,(%edi)
  40eb05:	11 50 52             	adc    %edx,0x52(%eax)
  40eb08:	4f                   	dec    %edi
  40eb09:	43                   	inc    %ebx
  40eb0a:	45                   	inc    %ebp
  40eb0b:	53                   	push   %ebx
  40eb0c:	53                   	push   %ebx
  40eb0d:	4f                   	dec    %edi
  40eb0e:	52                   	push   %edx
  40eb0f:	5f                   	pop    %edi
  40eb10:	54                   	push   %esp
  40eb11:	52                   	push   %edx
  40eb12:	45                   	inc    %ebp
  40eb13:	4d                   	dec    %ebp
  40eb14:	4f                   	dec    %edi
  40eb15:	4e                   	dec    %esi
  40eb16:	54                   	push   %esp
  40eb17:	00 10                	add    %dl,(%eax)
  40eb19:	11 50 52             	adc    %edx,0x52(%eax)
  40eb1c:	4f                   	dec    %edi
  40eb1d:	43                   	inc    %ebx
  40eb1e:	45                   	inc    %ebp
  40eb1f:	53                   	push   %ebx
  40eb20:	53                   	push   %ebx
  40eb21:	4f                   	dec    %edi
  40eb22:	52                   	push   %edx
  40eb23:	5f                   	pop    %edi
  40eb24:	4b                   	dec    %ebx
  40eb25:	4e                   	dec    %esi
  40eb26:	4c                   	dec    %esp
  40eb27:	00 11                	add    %dl,(%ecx)
  40eb29:	11 50 52             	adc    %edx,0x52(%eax)
  40eb2c:	4f                   	dec    %edi
  40eb2d:	43                   	inc    %ebx
  40eb2e:	45                   	inc    %ebp
  40eb2f:	53                   	push   %ebx
  40eb30:	53                   	push   %ebx
  40eb31:	4f                   	dec    %edi
  40eb32:	52                   	push   %edx
  40eb33:	5f                   	pop    %edi
  40eb34:	4b                   	dec    %ebx
  40eb35:	4e                   	dec    %esi
  40eb36:	4d                   	dec    %ebp
  40eb37:	00 12                	add    %dl,(%edx)
  40eb39:	11 50 52             	adc    %edx,0x52(%eax)
  40eb3c:	4f                   	dec    %edi
  40eb3d:	43                   	inc    %ebx
  40eb3e:	45                   	inc    %ebp
  40eb3f:	53                   	push   %ebx
  40eb40:	53                   	push   %ebx
  40eb41:	4f                   	dec    %edi
  40eb42:	52                   	push   %edx
  40eb43:	5f                   	pop    %edi
  40eb44:	53                   	push   %ebx
  40eb45:	4b                   	dec    %ebx
  40eb46:	59                   	pop    %ecx
  40eb47:	4c                   	dec    %esp
  40eb48:	41                   	inc    %ecx
  40eb49:	4b                   	dec    %ebx
  40eb4a:	45                   	inc    %ebp
  40eb4b:	00 13                	add    %dl,(%ebx)
  40eb4d:	11 50 52             	adc    %edx,0x52(%eax)
  40eb50:	4f                   	dec    %edi
  40eb51:	43                   	inc    %ebx
  40eb52:	45                   	inc    %ebp
  40eb53:	53                   	push   %ebx
  40eb54:	53                   	push   %ebx
  40eb55:	4f                   	dec    %edi
  40eb56:	52                   	push   %edx
  40eb57:	5f                   	pop    %edi
  40eb58:	53                   	push   %ebx
  40eb59:	4b                   	dec    %ebx
  40eb5a:	59                   	pop    %ecx
  40eb5b:	4c                   	dec    %esp
  40eb5c:	41                   	inc    %ecx
  40eb5d:	4b                   	dec    %ebx
  40eb5e:	45                   	inc    %ebp
  40eb5f:	5f                   	pop    %edi
  40eb60:	41                   	inc    %ecx
  40eb61:	56                   	push   %esi
  40eb62:	58                   	pop    %eax
  40eb63:	35 31 32 00 14       	xor    $0x14003231,%eax
  40eb68:	11 50 52             	adc    %edx,0x52(%eax)
  40eb6b:	4f                   	dec    %edi
  40eb6c:	43                   	inc    %ebx
  40eb6d:	45                   	inc    %ebp
  40eb6e:	53                   	push   %ebx
  40eb6f:	53                   	push   %ebx
  40eb70:	4f                   	dec    %edi
  40eb71:	52                   	push   %edx
  40eb72:	5f                   	pop    %edi
  40eb73:	43                   	inc    %ebx
  40eb74:	41                   	inc    %ecx
  40eb75:	4e                   	dec    %esi
  40eb76:	4e                   	dec    %esi
  40eb77:	4f                   	dec    %edi
  40eb78:	4e                   	dec    %esi
  40eb79:	4c                   	dec    %esp
  40eb7a:	41                   	inc    %ecx
  40eb7b:	4b                   	dec    %ebx
  40eb7c:	45                   	inc    %ebp
  40eb7d:	00 15 11 50 52 4f    	add    %dl,0x4f525011
  40eb83:	43                   	inc    %ebx
  40eb84:	45                   	inc    %ebp
  40eb85:	53                   	push   %ebx
  40eb86:	53                   	push   %ebx
  40eb87:	4f                   	dec    %edi
  40eb88:	52                   	push   %edx
  40eb89:	5f                   	pop    %edi
  40eb8a:	49                   	dec    %ecx
  40eb8b:	43                   	inc    %ebx
  40eb8c:	45                   	inc    %ebp
  40eb8d:	4c                   	dec    %esp
  40eb8e:	41                   	inc    %ecx
  40eb8f:	4b                   	dec    %ebx
  40eb90:	45                   	inc    %ebp
  40eb91:	5f                   	pop    %edi
  40eb92:	43                   	inc    %ebx
  40eb93:	4c                   	dec    %esp
  40eb94:	49                   	dec    %ecx
  40eb95:	45                   	inc    %ebp
  40eb96:	4e                   	dec    %esi
  40eb97:	54                   	push   %esp
  40eb98:	00 16                	add    %dl,(%esi)
  40eb9a:	11 50 52             	adc    %edx,0x52(%eax)
  40eb9d:	4f                   	dec    %edi
  40eb9e:	43                   	inc    %ebx
  40eb9f:	45                   	inc    %ebp
  40eba0:	53                   	push   %ebx
  40eba1:	53                   	push   %ebx
  40eba2:	4f                   	dec    %edi
  40eba3:	52                   	push   %edx
  40eba4:	5f                   	pop    %edi
  40eba5:	49                   	dec    %ecx
  40eba6:	43                   	inc    %ebx
  40eba7:	45                   	inc    %ebp
  40eba8:	4c                   	dec    %esp
  40eba9:	41                   	inc    %ecx
  40ebaa:	4b                   	dec    %ebx
  40ebab:	45                   	inc    %ebp
  40ebac:	5f                   	pop    %edi
  40ebad:	53                   	push   %ebx
  40ebae:	45                   	inc    %ebp
  40ebaf:	52                   	push   %edx
  40ebb0:	56                   	push   %esi
  40ebb1:	45                   	inc    %ebp
  40ebb2:	52                   	push   %edx
  40ebb3:	00 17                	add    %dl,(%edi)
  40ebb5:	11 50 52             	adc    %edx,0x52(%eax)
  40ebb8:	4f                   	dec    %edi
  40ebb9:	43                   	inc    %ebx
  40ebba:	45                   	inc    %ebp
  40ebbb:	53                   	push   %ebx
  40ebbc:	53                   	push   %ebx
  40ebbd:	4f                   	dec    %edi
  40ebbe:	52                   	push   %edx
  40ebbf:	5f                   	pop    %edi
  40ebc0:	43                   	inc    %ebx
  40ebc1:	41                   	inc    %ecx
  40ebc2:	53                   	push   %ebx
  40ebc3:	43                   	inc    %ebx
  40ebc4:	41                   	inc    %ecx
  40ebc5:	44                   	inc    %esp
  40ebc6:	45                   	inc    %ebp
  40ebc7:	4c                   	dec    %esp
  40ebc8:	41                   	inc    %ecx
  40ebc9:	4b                   	dec    %ebx
  40ebca:	45                   	inc    %ebp
  40ebcb:	00 18                	add    %bl,(%eax)
  40ebcd:	11 50 52             	adc    %edx,0x52(%eax)
  40ebd0:	4f                   	dec    %edi
  40ebd1:	43                   	inc    %ebx
  40ebd2:	45                   	inc    %ebp
  40ebd3:	53                   	push   %ebx
  40ebd4:	53                   	push   %ebx
  40ebd5:	4f                   	dec    %edi
  40ebd6:	52                   	push   %edx
  40ebd7:	5f                   	pop    %edi
  40ebd8:	49                   	dec    %ecx
  40ebd9:	4e                   	dec    %esi
  40ebda:	54                   	push   %esp
  40ebdb:	45                   	inc    %ebp
  40ebdc:	4c                   	dec    %esp
  40ebdd:	00 19                	add    %bl,(%ecx)
  40ebdf:	11 50 52             	adc    %edx,0x52(%eax)
  40ebe2:	4f                   	dec    %edi
  40ebe3:	43                   	inc    %ebx
  40ebe4:	45                   	inc    %ebp
  40ebe5:	53                   	push   %ebx
  40ebe6:	53                   	push   %ebx
  40ebe7:	4f                   	dec    %edi
  40ebe8:	52                   	push   %edx
  40ebe9:	5f                   	pop    %edi
  40ebea:	47                   	inc    %edi
  40ebeb:	45                   	inc    %ebp
  40ebec:	4f                   	dec    %edi
  40ebed:	44                   	inc    %esp
  40ebee:	45                   	inc    %ebp
  40ebef:	00 1a                	add    %bl,(%edx)
  40ebf1:	11 50 52             	adc    %edx,0x52(%eax)
  40ebf4:	4f                   	dec    %edi
  40ebf5:	43                   	inc    %ebx
  40ebf6:	45                   	inc    %ebp
  40ebf7:	53                   	push   %ebx
  40ebf8:	53                   	push   %ebx
  40ebf9:	4f                   	dec    %edi
  40ebfa:	52                   	push   %edx
  40ebfb:	5f                   	pop    %edi
  40ebfc:	4b                   	dec    %ebx
  40ebfd:	36 00 1b             	add    %bl,%ss:(%ebx)
  40ec00:	11 50 52             	adc    %edx,0x52(%eax)
  40ec03:	4f                   	dec    %edi
  40ec04:	43                   	inc    %ebx
  40ec05:	45                   	inc    %ebp
  40ec06:	53                   	push   %ebx
  40ec07:	53                   	push   %ebx
  40ec08:	4f                   	dec    %edi
  40ec09:	52                   	push   %edx
  40ec0a:	5f                   	pop    %edi
  40ec0b:	41                   	inc    %ecx
  40ec0c:	54                   	push   %esp
  40ec0d:	48                   	dec    %eax
  40ec0e:	4c                   	dec    %esp
  40ec0f:	4f                   	dec    %edi
  40ec10:	4e                   	dec    %esi
  40ec11:	00 1c 11             	add    %bl,(%ecx,%edx,1)
  40ec14:	50                   	push   %eax
  40ec15:	52                   	push   %edx
  40ec16:	4f                   	dec    %edi
  40ec17:	43                   	inc    %ebx
  40ec18:	45                   	inc    %ebp
  40ec19:	53                   	push   %ebx
  40ec1a:	53                   	push   %ebx
  40ec1b:	4f                   	dec    %edi
  40ec1c:	52                   	push   %edx
  40ec1d:	5f                   	pop    %edi
  40ec1e:	4b                   	dec    %ebx
  40ec1f:	38 00                	cmp    %al,(%eax)
  40ec21:	1d 11 50 52 4f       	sbb    $0x4f525011,%eax
  40ec26:	43                   	inc    %ebx
  40ec27:	45                   	inc    %ebp
  40ec28:	53                   	push   %ebx
  40ec29:	53                   	push   %ebx
  40ec2a:	4f                   	dec    %edi
  40ec2b:	52                   	push   %edx
  40ec2c:	5f                   	pop    %edi
  40ec2d:	41                   	inc    %ecx
  40ec2e:	4d                   	dec    %ebp
  40ec2f:	44                   	inc    %esp
  40ec30:	46                   	inc    %esi
  40ec31:	41                   	inc    %ecx
  40ec32:	4d                   	dec    %ebp
  40ec33:	31 30                	xor    %esi,(%eax)
  40ec35:	00 1e                	add    %bl,(%esi)
  40ec37:	11 50 52             	adc    %edx,0x52(%eax)
  40ec3a:	4f                   	dec    %edi
  40ec3b:	43                   	inc    %ebx
  40ec3c:	45                   	inc    %ebp
  40ec3d:	53                   	push   %ebx
  40ec3e:	53                   	push   %ebx
  40ec3f:	4f                   	dec    %edi
  40ec40:	52                   	push   %edx
  40ec41:	5f                   	pop    %edi
  40ec42:	42                   	inc    %edx
  40ec43:	44                   	inc    %esp
  40ec44:	56                   	push   %esi
  40ec45:	45                   	inc    %ebp
  40ec46:	52                   	push   %edx
  40ec47:	31 00                	xor    %eax,(%eax)
  40ec49:	1f                   	pop    %ds
  40ec4a:	11 50 52             	adc    %edx,0x52(%eax)
  40ec4d:	4f                   	dec    %edi
  40ec4e:	43                   	inc    %ebx
  40ec4f:	45                   	inc    %ebp
  40ec50:	53                   	push   %ebx
  40ec51:	53                   	push   %ebx
  40ec52:	4f                   	dec    %edi
  40ec53:	52                   	push   %edx
  40ec54:	5f                   	pop    %edi
  40ec55:	42                   	inc    %edx
  40ec56:	44                   	inc    %esp
  40ec57:	56                   	push   %esi
  40ec58:	45                   	inc    %ebp
  40ec59:	52                   	push   %edx
  40ec5a:	32 00                	xor    (%eax),%al
  40ec5c:	20 11                	and    %dl,(%ecx)
  40ec5e:	50                   	push   %eax
  40ec5f:	52                   	push   %edx
  40ec60:	4f                   	dec    %edi
  40ec61:	43                   	inc    %ebx
  40ec62:	45                   	inc    %ebp
  40ec63:	53                   	push   %ebx
  40ec64:	53                   	push   %ebx
  40ec65:	4f                   	dec    %edi
  40ec66:	52                   	push   %edx
  40ec67:	5f                   	pop    %edi
  40ec68:	42                   	inc    %edx
  40ec69:	44                   	inc    %esp
  40ec6a:	56                   	push   %esi
  40ec6b:	45                   	inc    %ebp
  40ec6c:	52                   	push   %edx
  40ec6d:	33 00                	xor    (%eax),%eax
  40ec6f:	21 11                	and    %edx,(%ecx)
  40ec71:	50                   	push   %eax
  40ec72:	52                   	push   %edx
  40ec73:	4f                   	dec    %edi
  40ec74:	43                   	inc    %ebx
  40ec75:	45                   	inc    %ebp
  40ec76:	53                   	push   %ebx
  40ec77:	53                   	push   %ebx
  40ec78:	4f                   	dec    %edi
  40ec79:	52                   	push   %edx
  40ec7a:	5f                   	pop    %edi
  40ec7b:	42                   	inc    %edx
  40ec7c:	44                   	inc    %esp
  40ec7d:	56                   	push   %esi
  40ec7e:	45                   	inc    %ebp
  40ec7f:	52                   	push   %edx
  40ec80:	34 00                	xor    $0x0,%al
  40ec82:	22 11                	and    (%ecx),%dl
  40ec84:	50                   	push   %eax
  40ec85:	52                   	push   %edx
  40ec86:	4f                   	dec    %edi
  40ec87:	43                   	inc    %ebx
  40ec88:	45                   	inc    %ebp
  40ec89:	53                   	push   %ebx
  40ec8a:	53                   	push   %ebx
  40ec8b:	4f                   	dec    %edi
  40ec8c:	52                   	push   %edx
  40ec8d:	5f                   	pop    %edi
  40ec8e:	42                   	inc    %edx
  40ec8f:	54                   	push   %esp
  40ec90:	56                   	push   %esi
  40ec91:	45                   	inc    %ebp
  40ec92:	52                   	push   %edx
  40ec93:	31 00                	xor    %eax,(%eax)
  40ec95:	23 11                	and    (%ecx),%edx
  40ec97:	50                   	push   %eax
  40ec98:	52                   	push   %edx
  40ec99:	4f                   	dec    %edi
  40ec9a:	43                   	inc    %ebx
  40ec9b:	45                   	inc    %ebp
  40ec9c:	53                   	push   %ebx
  40ec9d:	53                   	push   %ebx
  40ec9e:	4f                   	dec    %edi
  40ec9f:	52                   	push   %edx
  40eca0:	5f                   	pop    %edi
  40eca1:	42                   	inc    %edx
  40eca2:	54                   	push   %esp
  40eca3:	56                   	push   %esi
  40eca4:	45                   	inc    %ebp
  40eca5:	52                   	push   %edx
  40eca6:	32 00                	xor    (%eax),%al
  40eca8:	24 11                	and    $0x11,%al
  40ecaa:	50                   	push   %eax
  40ecab:	52                   	push   %edx
  40ecac:	4f                   	dec    %edi
  40ecad:	43                   	inc    %ebx
  40ecae:	45                   	inc    %ebp
  40ecaf:	53                   	push   %ebx
  40ecb0:	53                   	push   %ebx
  40ecb1:	4f                   	dec    %edi
  40ecb2:	52                   	push   %edx
  40ecb3:	5f                   	pop    %edi
  40ecb4:	5a                   	pop    %edx
  40ecb5:	4e                   	dec    %esi
  40ecb6:	56                   	push   %esi
  40ecb7:	45                   	inc    %ebp
  40ecb8:	52                   	push   %edx
  40ecb9:	31 00                	xor    %eax,(%eax)
  40ecbb:	25 11 50 52 4f       	and    $0x4f525011,%eax
  40ecc0:	43                   	inc    %ebx
  40ecc1:	45                   	inc    %ebp
  40ecc2:	53                   	push   %ebx
  40ecc3:	53                   	push   %ebx
  40ecc4:	4f                   	dec    %edi
  40ecc5:	52                   	push   %edx
  40ecc6:	5f                   	pop    %edi
  40ecc7:	5a                   	pop    %edx
  40ecc8:	4e                   	dec    %esi
  40ecc9:	56                   	push   %esi
  40ecca:	45                   	inc    %ebp
  40eccb:	52                   	push   %edx
  40eccc:	32 00                	xor    (%eax),%al
  40ecce:	26 11 50 52          	adc    %edx,%es:0x52(%eax)
  40ecd2:	4f                   	dec    %edi
  40ecd3:	43                   	inc    %ebx
  40ecd4:	45                   	inc    %ebp
  40ecd5:	53                   	push   %ebx
  40ecd6:	53                   	push   %ebx
  40ecd7:	4f                   	dec    %edi
  40ecd8:	52                   	push   %edx
  40ecd9:	5f                   	pop    %edi
  40ecda:	6d                   	insl   (%dx),%es:(%edi)
  40ecdb:	61                   	popa   
  40ecdc:	78 00                	js     40ecde <.debug_info+0x1cb8>
  40ecde:	27                   	daa    
  40ecdf:	00 0b                	add    %cl,(%ebx)
  40ece1:	69 78 38 36 5f 74 75 	imul   $0x75745f36,0x38(%eax),%edi
  40ece8:	6e                   	outsb  %ds:(%esi),(%dx)
  40ece9:	65 00 07             	add    %al,%gs:(%edi)
  40ecec:	72 09                	jb     40ecf7 <.debug_info+0x1cd1>
  40ecee:	1c 77                	sbb    $0x77,%al
  40ecf0:	19 00                	sbb    %eax,(%eax)
  40ecf2:	00 0b                	add    %cl,(%ebx)
  40ecf4:	69 78 38 36 5f 61 72 	imul   $0x72615f36,0x38(%eax),%edi
  40ecfb:	63 68 00             	arpl   %bp,0x0(%eax)
  40ecfe:	07                   	pop    %es
  40ecff:	73 09                	jae    40ed0a <.debug_info+0x1ce4>
  40ed01:	1c 77                	sbb    $0x77,%al
  40ed03:	19 00                	sbb    %eax,(%eax)
  40ed05:	00 0b                	add    %cl,(%ebx)
  40ed07:	69 78 38 36 5f 70 72 	imul   $0x72705f36,0x38(%eax),%edi
  40ed0e:	65 66 65 72 72       	gs data16 gs jb 40ed85 <.debug_info+0x1d5f>
  40ed13:	65 64 5f             	gs fs pop %edi
  40ed16:	73 74                	jae    40ed8c <.debug_info+0x1d66>
  40ed18:	61                   	popa   
  40ed19:	63 6b 5f             	arpl   %bp,0x5f(%ebx)
  40ed1c:	62 6f 75             	bound  %ebp,0x75(%edi)
  40ed1f:	6e                   	outsb  %ds:(%esi),(%dx)
  40ed20:	64 61                	fs popa 
  40ed22:	72 79                	jb     40ed9d <.debug_info+0x1d77>
  40ed24:	00 07                	add    %al,(%edi)
  40ed26:	7a 09                	jp     40ed31 <.debug_info+0x1d0b>
  40ed28:	15 f1 00 00 00       	adc    $0xf1,%eax
  40ed2d:	0b 69 78             	or     0x78(%ecx),%ebp
  40ed30:	38 36                	cmp    %dh,(%esi)
  40ed32:	5f                   	pop    %edi
  40ed33:	69 6e 63 6f 6d 69 6e 	imul   $0x6e696d6f,0x63(%esi),%ebp
  40ed3a:	67 5f                	addr16 pop %edi
  40ed3c:	73 74                	jae    40edb2 <.debug_info+0x1d8c>
  40ed3e:	61                   	popa   
  40ed3f:	63 6b 5f             	arpl   %bp,0x5f(%ebx)
  40ed42:	62 6f 75             	bound  %ebp,0x75(%edi)
  40ed45:	6e                   	outsb  %ds:(%esi),(%dx)
  40ed46:	64 61                	fs popa 
  40ed48:	72 79                	jb     40edc3 <.debug_info+0x1d9d>
  40ed4a:	00 07                	add    %al,(%edi)
  40ed4c:	7b 09                	jnp    40ed57 <.debug_info+0x1d31>
  40ed4e:	15 f1 00 00 00       	adc    $0xf1,%eax
  40ed53:	08 08                	or     %cl,(%eax)
  40ed55:	19 00                	sbb    %eax,(%eax)
  40ed57:	00 3d 1d 00 00 0c    	add    %bh,0xc00001d
  40ed5d:	f1                   	icebp  
  40ed5e:	00 00                	add    %al,(%eax)
  40ed60:	00 4b 00             	add    %cl,0x0(%ebx)
  40ed63:	03 2d 1d 00 00 0b    	add    0xb00001d,%ebp
  40ed69:	72 65                	jb     40edd0 <.debug_info+0x1daa>
  40ed6b:	67 63 6c 61          	arpl   %bp,0x61(%si)
  40ed6f:	73 73                	jae    40ede4 <.debug_info+0x1dbe>
  40ed71:	5f                   	pop    %edi
  40ed72:	6d                   	insl   (%dx),%es:(%edi)
  40ed73:	61                   	popa   
  40ed74:	70 00                	jo     40ed76 <.debug_info+0x1d50>
  40ed76:	07                   	pop    %es
  40ed77:	7e 09                	jle    40ed82 <.debug_info+0x1d5c>
  40ed79:	1d 3d 1d 00 00       	sbb    $0x1d3d,%eax
  40ed7e:	02 01                	add    (%ecx),%al
  40ed80:	06                   	push   %es
  40ed81:	73 69                	jae    40edec <.debug_info+0x1dc6>
  40ed83:	67 6e                	outsb  %ds:(%si),(%dx)
  40ed85:	65 64 20 63 68       	gs and %ah,%fs:0x68(%ebx)
  40ed8a:	61                   	popa   
  40ed8b:	72 00                	jb     40ed8d <.debug_info+0x1d67>
  40ed8d:	07                   	pop    %es
  40ed8e:	55                   	push   %ebp
  40ed8f:	51                   	push   %ecx
  40ed90:	49                   	dec    %ecx
  40ed91:	74 79                	je     40ee0c <.debug_info+0x1de6>
  40ed93:	70 65                	jo     40edfa <.debug_info+0x1dd4>
  40ed95:	00 09                	add    %cl,(%ecx)
  40ed97:	7b 16                	jnp    40edaf <.debug_info+0x1d89>
  40ed99:	4d                   	dec    %ebp
  40ed9a:	04 00                	add    $0x0,%al
  40ed9c:	00 03                	add    %al,(%ebx)
  40ed9e:	67 1d 00 00 02 08    	addr16 sbb $0x8020000,%eax
  40eda4:	07                   	pop    %es
  40eda5:	6c                   	insb   (%dx),%es:(%edi)
  40eda6:	6f                   	outsl  %ds:(%esi),(%dx)
  40eda7:	6e                   	outsb  %ds:(%esi),(%dx)
  40eda8:	67 20 6c 6f          	and    %ch,0x6f(%si)
  40edac:	6e                   	outsb  %ds:(%esi),(%dx)
  40edad:	67 20 75 6e          	and    %dh,0x6e(%di)
  40edb1:	73 69                	jae    40ee1c <.debug_info+0x1df6>
  40edb3:	67 6e                	outsb  %ds:(%si),(%dx)
  40edb5:	65 64 20 69 6e       	gs and %ch,%fs:0x6e(%ecx)
  40edba:	74 00                	je     40edbc <.debug_info+0x1d96>
  40edbc:	02 04 04             	add    (%esp,%eax,1),%al
  40edbf:	66 6c                	data16 insb (%dx),%es:(%edi)
  40edc1:	6f                   	outsl  %ds:(%esi),(%dx)
  40edc2:	61                   	popa   
  40edc3:	74 00                	je     40edc5 <.debug_info+0x1d9f>
  40edc5:	02 08                	add    (%eax),%cl
  40edc7:	03 63 6f             	add    0x6f(%ebx),%esp
  40edca:	6d                   	insl   (%dx),%es:(%edi)
  40edcb:	70 6c                	jo     40ee39 <.debug_info+0x1e13>
  40edcd:	65 78 20             	gs js  40edf0 <.debug_info+0x1dca>
  40edd0:	66 6c                	data16 insb (%dx),%es:(%edi)
  40edd2:	6f                   	outsl  %ds:(%esi),(%dx)
  40edd3:	61                   	popa   
  40edd4:	74 00                	je     40edd6 <.debug_info+0x1db0>
  40edd6:	02 08                	add    (%eax),%cl
  40edd8:	04 64                	add    $0x64,%al
  40edda:	6f                   	outsl  %ds:(%esi),(%dx)
  40eddb:	75 62                	jne    40ee3f <.debug_info+0x1e19>
  40eddd:	6c                   	insb   (%dx),%es:(%edi)
  40edde:	65 00 02             	add    %al,%gs:(%edx)
  40ede1:	10 03                	adc    %al,(%ebx)
  40ede3:	63 6f 6d             	arpl   %bp,0x6d(%edi)
  40ede6:	70 6c                	jo     40ee54 <.debug_info+0x1e2e>
  40ede8:	65 78 20             	gs js  40ee0b <.debug_info+0x1de5>
  40edeb:	64 6f                	outsl  %fs:(%esi),(%dx)
  40eded:	75 62                	jne    40ee51 <.debug_info+0x1e2b>
  40edef:	6c                   	insb   (%dx),%es:(%edi)
  40edf0:	65 00 02             	add    %al,%gs:(%edx)
  40edf3:	18 03                	sbb    %al,(%ebx)
  40edf5:	63 6f 6d             	arpl   %bp,0x6d(%edi)
  40edf8:	70 6c                	jo     40ee66 <.debug_info+0x1e40>
  40edfa:	65 78 20             	gs js  40ee1d <.debug_info+0x1df7>
  40edfd:	6c                   	insb   (%dx),%es:(%edi)
  40edfe:	6f                   	outsl  %ds:(%esi),(%dx)
  40edff:	6e                   	outsb  %ds:(%esi),(%dx)
  40ee00:	67 20 64 6f          	and    %ah,0x6f(%si)
  40ee04:	75 62                	jne    40ee68 <.debug_info+0x1e42>
  40ee06:	6c                   	insb   (%dx),%es:(%edi)
  40ee07:	65 00 02             	add    %al,%gs:(%edx)
  40ee0a:	20 03                	and    %al,(%ebx)
  40ee0c:	63 6f 6d             	arpl   %bp,0x6d(%edi)
  40ee0f:	70 6c                	jo     40ee7d <.debug_info+0x1e57>
  40ee11:	65 78 20             	gs js  40ee34 <.debug_info+0x1e0e>
  40ee14:	5f                   	pop    %edi
  40ee15:	46                   	inc    %esi
  40ee16:	6c                   	insb   (%dx),%es:(%edi)
  40ee17:	6f                   	outsl  %ds:(%esi),(%dx)
  40ee18:	61                   	popa   
  40ee19:	74 31                	je     40ee4c <.debug_info+0x1e26>
  40ee1b:	32 38                	xor    (%eax),%bh
  40ee1d:	00 08                	add    %cl,(%eax)
  40ee1f:	77 1d                	ja     40ee3e <.debug_info+0x1e18>
  40ee21:	00 00                	add    %al,(%eax)
  40ee23:	08 1e                	or     %bl,(%esi)
  40ee25:	00 00                	add    %al,(%eax)
  40ee27:	0c f1                	or     $0xf1,%al
  40ee29:	00 00                	add    %al,(%eax)
  40ee2b:	00 ff                	add    %bh,%bh
  40ee2d:	00 03                	add    %al,(%ebx)
  40ee2f:	f8                   	clc    
  40ee30:	1d 00 00 0b 5f       	sbb    $0x5f0b0000,%eax
  40ee35:	5f                   	pop    %edi
  40ee36:	70 6f                	jo     40eea7 <.debug_info+0x1e81>
  40ee38:	70 63                	jo     40ee9d <.debug_info+0x1e77>
  40ee3a:	6f                   	outsl  %ds:(%esi),(%dx)
  40ee3b:	75 6e                	jne    40eeab <.debug_info+0x1e85>
  40ee3d:	74 5f                	je     40ee9e <.debug_info+0x1e78>
  40ee3f:	74 61                	je     40eea2 <.debug_info+0x1e7c>
  40ee41:	62 00                	bound  %eax,(%eax)
  40ee43:	09 fc                	or     %edi,%esp
  40ee45:	01 16                	add    %edx,(%esi)
  40ee47:	08 1e                	or     %bl,(%esi)
  40ee49:	00 00                	add    %al,(%eax)
  40ee4b:	0b 5f 5f             	or     0x5f(%edi),%ebx
  40ee4e:	63 6c 7a 5f          	arpl   %bp,0x5f(%edx,%edi,2)
  40ee52:	74 61                	je     40eeb5 <.debug_info+0x1e8f>
  40ee54:	62 00                	bound  %eax,(%eax)
  40ee56:	09 02                	or     %eax,(%edx)
  40ee58:	02 16                	add    (%esi),%dl
  40ee5a:	08 1e                	or     %bl,(%esi)
  40ee5c:	00 00                	add    %al,(%eax)
  40ee5e:	07                   	pop    %es
  40ee5f:	66 75 6e             	data16 jne 40eed0 <.debug_info+0x1eaa>
  40ee62:	63 5f 70             	arpl   %bx,0x70(%edi)
  40ee65:	74 72                	je     40eed9 <.debug_info+0x1eb3>
  40ee67:	00 0a                	add    %cl,(%edx)
  40ee69:	2a 10                	sub    (%eax),%dl
  40ee6b:	49                   	dec    %ecx
  40ee6c:	1e                   	push   %ds
  40ee6d:	00 00                	add    %al,(%eax)
  40ee6f:	06                   	push   %es
  40ee70:	04 4f                	add    $0x4f,%al
  40ee72:	1e                   	push   %ds
  40ee73:	00 00                	add    %al,(%eax)
  40ee75:	17                   	pop    %ss
  40ee76:	08 38                	or     %bh,(%eax)
  40ee78:	1e                   	push   %ds
  40ee79:	00 00                	add    %al,(%eax)
  40ee7b:	5b                   	pop    %ebx
  40ee7c:	1e                   	push   %ds
  40ee7d:	00 00                	add    %al,(%eax)
  40ee7f:	09 00                	or     %eax,(%eax)
  40ee81:	0a 5f 5f             	or     0x5f(%edi),%bl
  40ee84:	43                   	inc    %ebx
  40ee85:	54                   	push   %esp
  40ee86:	4f                   	dec    %edi
  40ee87:	52                   	push   %edx
  40ee88:	5f                   	pop    %edi
  40ee89:	4c                   	dec    %esp
  40ee8a:	49                   	dec    %ecx
  40ee8b:	53                   	push   %ebx
  40ee8c:	54                   	push   %esp
  40ee8d:	5f                   	pop    %edi
  40ee8e:	5f                   	pop    %edi
  40ee8f:	00 0a                	add    %cl,(%edx)
  40ee91:	2f                   	das    
  40ee92:	11 50 1e             	adc    %edx,0x1e(%eax)
  40ee95:	00 00                	add    %al,(%eax)
  40ee97:	0a 5f 5f             	or     0x5f(%edi),%bl
  40ee9a:	44                   	inc    %esp
  40ee9b:	54                   	push   %esp
  40ee9c:	4f                   	dec    %edi
  40ee9d:	52                   	push   %edx
  40ee9e:	5f                   	pop    %edi
  40ee9f:	4c                   	dec    %esp
  40eea0:	49                   	dec    %ecx
  40eea1:	53                   	push   %ebx
  40eea2:	54                   	push   %esp
  40eea3:	5f                   	pop    %edi
  40eea4:	5f                   	pop    %edi
  40eea5:	00 0a                	add    %cl,(%edx)
  40eea7:	30 11                	xor    %dl,(%ecx)
  40eea9:	50                   	push   %eax
  40eeaa:	1e                   	push   %ds
  40eeab:	00 00                	add    %al,(%eax)
  40eead:	18 5b 1e             	sbb    %bl,0x1e(%ebx)
  40eeb0:	00 00                	add    %al,(%eax)
  40eeb2:	0b 36                	or     (%esi),%esi
  40eeb4:	09 0a                	or     %ecx,(%edx)
  40eeb6:	05 03 f0 40 40       	add    $0x4040f003,%eax
  40eebb:	00 18                	add    %bl,(%eax)
  40eebd:	71 1e                	jno    40eedd <.debug_info+0x1eb7>
  40eebf:	00 00                	add    %al,(%eax)
  40eec1:	0b 37                	or     (%edi),%esi
  40eec3:	09 0a                	or     %ecx,(%edx)
  40eec5:	05 03 fc 40 40       	add    $0x4040fc03,%eax
	...

Disassembly of section .debug_abbrev:

0040f000 <.debug_abbrev>:
  40f000:	01 11                	add    %edx,(%ecx)
  40f002:	00 10                	add    %dl,(%eax)
  40f004:	06                   	push   %es
  40f005:	11 01                	adc    %eax,(%ecx)
  40f007:	12 01                	adc    (%ecx),%al
  40f009:	03 0e                	add    (%esi),%ecx
  40f00b:	1b 0e                	sbb    (%esi),%ecx
  40f00d:	25 0e 13 05 00       	and    $0x5130e,%eax
	...

0040f014 <.debug_abbrev>:
  40f014:	01 11                	add    %edx,(%ecx)
  40f016:	01 25 08 13 0b 03    	add    %esp,0x30b1308
  40f01c:	08 1b                	or     %bl,(%ebx)
  40f01e:	08 10                	or     %dl,(%eax)
  40f020:	17                   	pop    %ss
  40f021:	00 00                	add    %al,(%eax)
  40f023:	02 24 00             	add    (%eax,%eax,1),%ah
  40f026:	0b 0b                	or     (%ebx),%ecx
  40f028:	3e 0b 03             	or     %ds:(%ebx),%eax
  40f02b:	08 00                	or     %al,(%eax)
  40f02d:	00 03                	add    %al,(%ebx)
  40f02f:	26 00 49 13          	add    %cl,%es:0x13(%ecx)
  40f033:	00 00                	add    %al,(%eax)
  40f035:	04 13                	add    $0x13,%al
  40f037:	01 03                	add    %eax,(%ebx)
  40f039:	08 0b                	or     %cl,(%ebx)
  40f03b:	0b 3a                	or     (%edx),%edi
  40f03d:	0b 3b                	or     (%ebx),%edi
  40f03f:	0b 39                	or     (%ecx),%edi
  40f041:	0b 01                	or     (%ecx),%eax
  40f043:	13 00                	adc    (%eax),%eax
  40f045:	00 05 0d 00 03 08    	add    %al,0x803000d
  40f04b:	3a 0b                	cmp    (%ebx),%cl
  40f04d:	3b 0b                	cmp    (%ebx),%ecx
  40f04f:	39 0b                	cmp    %ecx,(%ebx)
  40f051:	49                   	dec    %ecx
  40f052:	13 38                	adc    (%eax),%edi
  40f054:	0b 00                	or     (%eax),%eax
  40f056:	00 06                	add    %al,(%esi)
  40f058:	0f 00 0b             	str    (%ebx)
  40f05b:	0b 49 13             	or     0x13(%ecx),%ecx
  40f05e:	00 00                	add    %al,(%eax)
  40f060:	07                   	pop    %es
  40f061:	16                   	push   %ss
  40f062:	00 03                	add    %al,(%ebx)
  40f064:	08 3a                	or     %bh,(%edx)
  40f066:	0b 3b                	or     (%ebx),%edi
  40f068:	0b 39                	or     (%ecx),%edi
  40f06a:	0b 49 13             	or     0x13(%ecx),%ecx
  40f06d:	00 00                	add    %al,(%eax)
  40f06f:	08 01                	or     %al,(%ecx)
  40f071:	01 49 13             	add    %ecx,0x13(%ecx)
  40f074:	01 13                	add    %edx,(%ebx)
  40f076:	00 00                	add    %al,(%eax)
  40f078:	09 21                	or     %esp,(%ecx)
  40f07a:	00 00                	add    %al,(%eax)
  40f07c:	00 0a                	add    %cl,(%edx)
  40f07e:	34 00                	xor    $0x0,%al
  40f080:	03 08                	add    (%eax),%ecx
  40f082:	3a 0b                	cmp    (%ebx),%cl
  40f084:	3b 0b                	cmp    (%ebx),%ecx
  40f086:	39 0b                	cmp    %ecx,(%ebx)
  40f088:	49                   	dec    %ecx
  40f089:	13 3f                	adc    (%edi),%edi
  40f08b:	19 3c 19             	sbb    %edi,(%ecx,%ebx,1)
  40f08e:	00 00                	add    %al,(%eax)
  40f090:	0b 34 00             	or     (%eax,%eax,1),%esi
  40f093:	03 08                	add    (%eax),%ecx
  40f095:	3a 0b                	cmp    (%ebx),%cl
  40f097:	3b 05 39 0b 49 13    	cmp    0x13490b39,%eax
  40f09d:	3f                   	aas    
  40f09e:	19 3c 19             	sbb    %edi,(%ecx,%ebx,1)
  40f0a1:	00 00                	add    %al,(%eax)
  40f0a3:	0c 21                	or     $0x21,%al
  40f0a5:	00 49 13             	add    %cl,0x13(%ecx)
  40f0a8:	2f                   	das    
  40f0a9:	0b 00                	or     (%eax),%eax
  40f0ab:	00 0d 15 01 27 19    	add    %cl,0x19270115
  40f0b1:	49                   	dec    %ecx
  40f0b2:	13 01                	adc    (%ecx),%eax
  40f0b4:	13 00                	adc    (%eax),%eax
  40f0b6:	00 0e                	add    %cl,(%esi)
  40f0b8:	05 00 49 13 00       	add    $0x134900,%eax
  40f0bd:	00 0f                	add    %cl,(%edi)
  40f0bf:	26 00 00             	add    %al,%es:(%eax)
  40f0c2:	00 10                	add    %dl,(%eax)
  40f0c4:	04 01                	add    $0x1,%al
  40f0c6:	03 08                	add    (%eax),%ecx
  40f0c8:	3e 0b 0b             	or     %ds:(%ebx),%ecx
  40f0cb:	0b 49 13             	or     0x13(%ecx),%ecx
  40f0ce:	3a 0b                	cmp    (%ebx),%cl
  40f0d0:	3b 0b                	cmp    (%ebx),%ecx
  40f0d2:	39 0b                	cmp    %ecx,(%ebx)
  40f0d4:	01 13                	add    %edx,(%ebx)
  40f0d6:	00 00                	add    %al,(%eax)
  40f0d8:	11 28                	adc    %ebp,(%eax)
  40f0da:	00 03                	add    %al,(%ebx)
  40f0dc:	08 1c 0b             	or     %bl,(%ebx,%ecx,1)
  40f0df:	00 00                	add    %al,(%eax)
  40f0e1:	12 13                	adc    (%ebx),%dl
  40f0e3:	01 03                	add    %eax,(%ebx)
  40f0e5:	08 0b                	or     %cl,(%ebx)
  40f0e7:	05 3a 0b 3b 0b       	add    $0xb3b0b3a,%eax
  40f0ec:	39 0b                	cmp    %ecx,(%ebx)
  40f0ee:	01 13                	add    %edx,(%ebx)
  40f0f0:	00 00                	add    %al,(%eax)
  40f0f2:	13 0d 00 03 08 3a    	adc    0x3a080300,%ecx
  40f0f8:	0b 3b                	or     (%ebx),%edi
  40f0fa:	05 39 0b 49 13       	add    $0x13490b39,%eax
  40f0ff:	38 0b                	cmp    %cl,(%ebx)
  40f101:	00 00                	add    %al,(%eax)
  40f103:	14 0d                	adc    $0xd,%al
  40f105:	00 03                	add    %al,(%ebx)
  40f107:	08 3a                	or     %bh,(%edx)
  40f109:	0b 3b                	or     (%ebx),%edi
  40f10b:	05 39 0b 49 13       	add    $0x13490b39,%eax
  40f110:	38 05 00 00 15 04    	cmp    %al,0x4150000
  40f116:	01 03                	add    %eax,(%ebx)
  40f118:	08 3e                	or     %bh,(%esi)
  40f11a:	0b 0b                	or     (%ebx),%ecx
  40f11c:	0b 49 13             	or     0x13(%ecx),%ecx
  40f11f:	3a 0b                	cmp    (%ebx),%cl
  40f121:	3b 05 39 0b 01 13    	cmp    0x13010b39,%eax
  40f127:	00 00                	add    %al,(%eax)
  40f129:	16                   	push   %ss
  40f12a:	17                   	pop    %ss
  40f12b:	00 03                	add    %al,(%ebx)
  40f12d:	08 3c 19             	or     %bh,(%ecx,%ebx,1)
  40f130:	00 00                	add    %al,(%eax)
  40f132:	17                   	pop    %ss
  40f133:	15 00 27 19 00       	adc    $0x192700,%eax
  40f138:	00 18                	add    %bl,(%eax)
  40f13a:	34 00                	xor    $0x0,%al
  40f13c:	47                   	inc    %edi
  40f13d:	13 3a                	adc    (%edx),%edi
  40f13f:	0b 3b                	or     (%ebx),%edi
  40f141:	05 39 0b 02 18       	add    $0x18020b39,%eax
  40f146:	00 00                	add    %al,(%eax)
	...

Disassembly of section .debug_line:

00410000 <.debug_line>:
  410000:	6d                   	insl   (%dx),%es:(%edi)
  410001:	00 00                	add    %al,(%eax)
  410003:	00 03                	add    %al,(%ebx)
  410005:	00 49 00             	add    %cl,0x0(%ecx)
  410008:	00 00                	add    %al,(%eax)
  41000a:	01 01                	add    %eax,(%ecx)
  41000c:	fb                   	sti    
  41000d:	0e                   	push   %cs
  41000e:	0d 00 01 01 01       	or     $0x1010100,%eax
  410013:	01 00                	add    %eax,(%eax)
  410015:	00 00                	add    %al,(%eax)
  410017:	01 00                	add    %eax,(%eax)
  410019:	00 01                	add    %al,(%ecx)
  41001b:	2e 2e 2f             	cs cs das 
  41001e:	2e 2e 2f             	cs cs das 
  410021:	2e 2e 2f             	cs cs das 
  410024:	73 72                	jae    410098 <.debug_line+0x27>
  410026:	63 2f                	arpl   %bp,(%edi)
  410028:	67 63 63 2d          	arpl   %sp,0x2d(%bp,%di)
  41002c:	39 2e                	cmp    %ebp,(%esi)
  41002e:	32 2e                	xor    (%esi),%ch
  410030:	30 2f                	xor    %ch,(%edi)
  410032:	6c                   	insb   (%dx),%es:(%edi)
  410033:	69 62 67 63 63 2f 63 	imul   $0x632f6363,0x67(%edx),%esp
  41003a:	6f                   	outsl  %ds:(%esi),(%dx)
  41003b:	6e                   	outsb  %ds:(%esi),(%dx)
  41003c:	66 69 67 2f 69 33    	imul   $0x3369,0x2f(%edi),%sp
  410042:	38 36                	cmp    %dh,(%esi)
  410044:	00 00                	add    %al,(%eax)
  410046:	63 79 67             	arpl   %di,0x67(%ecx)
  410049:	77 69                	ja     4100b4 <.debug_line+0x43>
  41004b:	6e                   	outsb  %ds:(%esi),(%dx)
  41004c:	2e 53                	cs push %ebx
  41004e:	00 01                	add    %al,(%ecx)
  410050:	00 00                	add    %al,(%eax)
  410052:	00 00                	add    %al,(%eax)
  410054:	05 02 50 3e 40       	add    $0x403e5002,%eax
  410059:	00 03                	add    %al,(%ebx)
  41005b:	8e 01                	mov    (%ecx),%es
  41005d:	01 22                	add    %esp,(%edx)
  41005f:	22 59 4b             	and    0x4b(%ecx),%bl
  410062:	30 67 3d             	xor    %ah,0x3d(%edi)
  410065:	59                   	pop    %ecx
  410066:	59                   	pop    %ecx
  410067:	30 2f                	xor    %ch,(%edi)
  410069:	3e 22 22             	and    %ds:(%edx),%ah
  41006c:	02 01                	add    (%ecx),%al
  41006e:	00 01                	add    %al,(%ecx)
  410070:	01               	add    %edx,0x1(%ebx)

00410071 <.debug_line>:
  410071:	53                   	push   %ebx
  410072:	01 00                	add    %eax,(%eax)
  410074:	00 03                	add    %al,(%ebx)
  410076:	00 4d 01             	add    %cl,0x1(%ebp)
  410079:	00 00                	add    %al,(%eax)
  41007b:	01 01                	add    %eax,(%ecx)
  41007d:	fb                   	sti    
  41007e:	0e                   	push   %cs
  41007f:	0d 00 01 01 01       	or     $0x1010100,%eax
  410084:	01 00                	add    %eax,(%eax)
  410086:	00 00                	add    %al,(%eax)
  410088:	01 00                	add    %eax,(%eax)
  41008a:	00 01                	add    %al,(%ecx)
  41008c:	2f                   	das    
  41008d:	68 6f 6d 65 2f       	push   $0x2f656d6f
  410092:	6b 65 69 74          	imul   $0x74,0x69(%ebp),%esp
  410096:	68 2f 6d 69 6e       	push   $0x6e696d2f
  41009b:	67 77 33             	addr16 ja 4100d1 <.debug_line+0x60>
  41009e:	32 2d 67 63 63 2d    	xor    0x2d636367,%ch
  4100a4:	39 2e                	cmp    %ebp,(%esi)
  4100a6:	32 2e                	xor    (%esi),%ch
  4100a8:	30 2f                	xor    %ch,(%edi)
  4100aa:	69 6e 63 6c 75 64 65 	imul   $0x6564756c,0x63(%esi),%ebp
  4100b1:	00 2e                	add    %ch,(%esi)
  4100b3:	2e 2f                	cs das 
  4100b5:	2e 2e 2f             	cs cs das 
  4100b8:	2e 2e 2f             	cs cs das 
  4100bb:	73 72                	jae    41012f <.debug_line+0xbe>
  4100bd:	63 2f                	arpl   %bp,(%edi)
  4100bf:	67 63 63 2d          	arpl   %sp,0x2d(%bp,%di)
  4100c3:	39 2e                	cmp    %ebp,(%esi)
  4100c5:	32 2e                	xor    (%esi),%ch
  4100c7:	30 2f                	xor    %ch,(%edi)
  4100c9:	6c                   	insb   (%dx),%es:(%edi)
  4100ca:	69 62 67 63 63 2f 2e 	imul   $0x2e2f6363,0x67(%edx),%esp
  4100d1:	2e 2f                	cs das 
  4100d3:	69 6e 63 6c 75 64 65 	imul   $0x6564756c,0x63(%esi),%ebp
  4100da:	00 2e                	add    %ch,(%esi)
  4100dc:	2e 2f                	cs das 
  4100de:	2e 2e 2f             	cs cs das 
  4100e1:	2e 2f                	cs das 
  4100e3:	67 63 63 00          	arpl   %sp,0x0(%bp,%di)
  4100e7:	2e 2e 2f             	cs cs das 
  4100ea:	2e 2e 2f             	cs cs das 
  4100ed:	2e 2e 2f             	cs cs das 
  4100f0:	73 72                	jae    410164 <.debug_line+0xf3>
  4100f2:	63 2f                	arpl   %bp,(%edi)
  4100f4:	67 63 63 2d          	arpl   %sp,0x2d(%bp,%di)
  4100f8:	39 2e                	cmp    %ebp,(%esi)
  4100fa:	32 2e                	xor    (%esi),%ch
  4100fc:	30 2f                	xor    %ch,(%edi)
  4100fe:	6c                   	insb   (%dx),%es:(%edi)
  4100ff:	69 62 67 63 63 2f 2e 	imul   $0x2e2f6363,0x67(%edx),%esp
  410106:	2e 2f                	cs das 
  410108:	67 63 63 2f          	arpl   %sp,0x2f(%bp,%di)
  41010c:	63 6f 6e             	arpl   %bp,0x6e(%edi)
  41010f:	66 69 67 2f 69 33    	imul   $0x3369,0x2f(%edi),%sp
  410115:	38 36                	cmp    %dh,(%esi)
  410117:	00 2e                	add    %ch,(%esi)
  410119:	2e 2f                	cs das 
  41011b:	2e 2e 2f             	cs cs das 
  41011e:	2e 2e 2f             	cs cs das 
  410121:	73 72                	jae    410195 <.debug_line+0x124>
  410123:	63 2f                	arpl   %bp,(%edi)
  410125:	67 63 63 2d          	arpl   %sp,0x2d(%bp,%di)
  410129:	39 2e                	cmp    %ebp,(%esi)
  41012b:	32 2e                	xor    (%esi),%ch
  41012d:	30 2f                	xor    %ch,(%edi)
  41012f:	6c                   	insb   (%dx),%es:(%edi)
  410130:	69 62 67 63 63 00 00 	imul   $0x6363,0x67(%edx),%esp
  410137:	73 74                	jae    4101ad <.debug_line+0x13c>
  410139:	64 69 6f 2e 68 00 01 	imul   $0x10068,%fs:0x2e(%edi),%ebp
  410140:	00 
  410141:	00 73 74             	add    %dh,0x74(%ebx)
  410144:	64 6c                	fs insb (%dx),%es:(%edi)
  410146:	69 62 2e 68 00 01 00 	imul   $0x10068,0x2e(%edx),%esp
  41014d:	00 67 65             	add    %ah,0x65(%edi)
  410150:	74 6f                	je     4101c1 <.debug_line+0x150>
  410152:	70 74                	jo     4101c8 <.debug_line+0x157>
  410154:	2e 68 00 01 00 00    	cs push $0x100
  41015a:	74 69                	je     4101c5 <.debug_line+0x154>
  41015c:	6d                   	insl   (%dx),%es:(%edi)
  41015d:	65 2e 68 00 01 00 00 	gs cs push $0x100
  410164:	68 61 73 68 74       	push   $0x74687361
  410169:	61                   	popa   
  41016a:	62 2e                	bound  %ebp,(%esi)
  41016c:	68 00 02 00 00       	push   $0x200
  410171:	69 6e 73 6e 2d 63 6f 	imul   $0x6f632d6e,0x73(%esi),%ebp
  410178:	6e                   	outsb  %ds:(%esi),(%dx)
  410179:	73 74                	jae    4101ef <.debug_line+0x17e>
  41017b:	61                   	popa   
  41017c:	6e                   	outsb  %ds:(%esi),(%dx)
  41017d:	74 73                	je     4101f2 <.debug_line+0x181>
  41017f:	2e 68 00 03 00 00    	cs push $0x300
  410185:	69 33 38 36 2e 68    	imul   $0x682e3638,(%ebx),%esi
  41018b:	00 04 00             	add    %al,(%eax,%eax,1)
  41018e:	00 69 33             	add    %ch,0x33(%ecx)
  410191:	38 36                	cmp    %dh,(%esi)
  410193:	2d 6f 70 74 73       	sub    $0x7374706f,%eax
  410198:	2e 68 00 04 00 00    	cs push $0x400
  41019e:	6c                   	insb   (%dx),%es:(%edi)
  41019f:	69 62 67 63 63 32 2e 	imul   $0x2e326363,0x67(%edx),%esp
  4101a6:	68 00 05 00 00       	push   $0x500
  4101ab:	67 62 6c 2d          	bound  %ebp,0x2d(%si)
  4101af:	63 74 6f 72          	arpl   %si,0x72(%edi,%ebp,2)
  4101b3:	73 2e                	jae    4101e3 <.debug_line+0x172>
  4101b5:	68 00 05 00 00       	push   $0x500
  4101ba:	6c                   	insb   (%dx),%es:(%edi)
  4101bb:	69 62 67 63 63 32 2e 	imul   $0x2e326363,0x67(%edx),%esp
  4101c2:	63 00                	arpl   %ax,(%eax)
  4101c4:	05                   	.byte 0x5
  4101c5:	00 00                	add    %al,(%eax)
	...

Disassembly of section .debug_frame:

00411000 <.debug_frame>:
  411000:	10 00                	adc    %al,(%eax)
  411002:	00 00                	add    %al,(%eax)
  411004:	ff                   	(bad)  
  411005:	ff                   	(bad)  
  411006:	ff                   	(bad)  
  411007:	ff 01                	incl   (%ecx)
  411009:	00 01                	add    %al,(%ecx)
  41100b:	7c 08                	jl     411015 <.debug_frame+0x15>
  41100d:	0c 04                	or     $0x4,%al
  41100f:	04 88                	add    $0x88,%al
  411011:	01 00                	add    %eax,(%eax)
  411013:	00 20                	add    %ah,(%eax)
  411015:	00 00                	add    %al,(%eax)
  411017:	00 00                	add    %al,(%eax)
  411019:	00 00                	add    %al,(%eax)
  41101b:	00 50 3e             	add    %dl,0x3e(%eax)
  41101e:	40                   	inc    %eax
  41101f:	00 2a                	add    %ch,(%edx)
  411021:	00 00                	add    %al,(%eax)
  411023:	00 41 0e             	add    %al,0xe(%ecx)
  411026:	08 81 02 41 0e 0c    	or     %al,0xc0e4102(%ecx)
  41102c:	80 03 66             	addb   $0x66,(%ebx)
  41102f:	0e                   	push   %cs
  411030:	08 c0                	or     %al,%al
  411032:	41                   	inc    %ecx
  411033:	0e                   	push   %cs
  411034:	04 c1                	add    $0xc1,%al
	...

Disassembly of section .debug_str:

00412000 <.debug_str>:
  412000:	2e 2e 2f             	cs cs das 
  412003:	2e 2e 2f             	cs cs das 
  412006:	2e 2e 2f             	cs cs das 
  412009:	73 72                	jae    41207d <.debug_str+0x7d>
  41200b:	63 2f                	arpl   %bp,(%edi)
  41200d:	67 63 63 2d          	arpl   %sp,0x2d(%bp,%di)
  412011:	39 2e                	cmp    %ebp,(%esi)
  412013:	32 2e                	xor    (%esi),%ch
  412015:	30 2f                	xor    %ch,(%edi)
  412017:	6c                   	insb   (%dx),%es:(%edi)
  412018:	69 62 67 63 63 2f 63 	imul   $0x632f6363,0x67(%edx),%esp
  41201f:	6f                   	outsl  %ds:(%esi),(%dx)
  412020:	6e                   	outsb  %ds:(%esi),(%dx)
  412021:	66 69 67 2f 69 33    	imul   $0x3369,0x2f(%edi),%sp
  412027:	38 36                	cmp    %dh,(%esi)
  412029:	2f                   	das    
  41202a:	63 79 67             	arpl   %di,0x67(%ecx)
  41202d:	77 69                	ja     412098 <.debug_str+0x98>
  41202f:	6e                   	outsb  %ds:(%esi),(%dx)
  412030:	2e 53                	cs push %ebx
  412032:	00 2f                	add    %ch,(%edi)
  412034:	68 6f 6d 65 2f       	push   $0x2f656d6f
  412039:	6b 65 69 74          	imul   $0x74,0x69(%ebp),%esp
  41203d:	68 2f 62 75 69       	push   $0x6975622f
  412042:	6c                   	insb   (%dx),%es:(%edi)
  412043:	64 73 2f             	fs jae 412075 <.debug_str+0x75>
  412046:	6d                   	insl   (%dx),%es:(%edi)
  412047:	69 6e 67 77 2f 67 63 	imul   $0x63672f77,0x67(%esi),%ebp
  41204e:	63 2d 39 2e 32 2e    	arpl   %bp,0x2e322e39
  412054:	30 2d 6d 69 6e 67    	xor    %ch,0x676e696d
  41205a:	77 33                	ja     41208f <.debug_str+0x8f>
  41205c:	32 2d 63 72 6f 73    	xor    0x736f7263,%ch
  412062:	73 2d                	jae    412091 <.debug_str+0x91>
  412064:	6e                   	outsb  %ds:(%esi),(%dx)
  412065:	61                   	popa   
  412066:	74 69                	je     4120d1 <.debug_str+0xd1>
  412068:	76 65                	jbe    4120cf <.debug_str+0xcf>
  41206a:	2f                   	das    
  41206b:	6d                   	insl   (%dx),%es:(%edi)
  41206c:	69 6e 67 77 33 32 2f 	imul   $0x2f323377,0x67(%esi),%ebp
  412073:	6c                   	insb   (%dx),%es:(%edi)
  412074:	69 62 67 63 63 00 47 	imul   $0x47006363,0x67(%edx),%esp
  41207b:	4e                   	dec    %esi
  41207c:	55                   	push   %ebp
  41207d:	20 41 53             	and    %al,0x53(%ecx)
  412080:	20 32                	and    %dh,(%edx)
  412082:	2e 33 32             	xor    %cs:(%edx),%esi
	...
