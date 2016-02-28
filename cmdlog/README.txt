CMDLOG

0.0 Contents
================================================================================
	1.0 Overview
	2.0 Build and Test

1.0 Overview
================================================================================
Command and output logger for red team use. 32-bit only. For details, see:
	http://baileysoriginalirishtech.blogspot.com/2016/02/snooping-on-myself-for
	-change.html

2.0 Build and Test
================================================================================
Prerequisites:
	* Windows SDK or Visual Studio

	* Microsoft Detours Express
	  http://research.microsoft.com/en-us/projects/detours/

To Build:
	Grab the Makefile from Detours' "simple" sample and use nmake.

To Test:
	withdll.exe /d:cmdlog.dll C:\Windows\SysWOW64\cmd.exe
