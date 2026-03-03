@echo off
setlocal enabledelayedexpansion

echo ============================================================
echo  DarkstarDriver Full Build
echo ============================================================
echo.

where cl.exe >nul 2>&1
if errorlevel 1 goto :nocl

if not exist "DarkstarDriver.c" goto :nosrc

:: Build paths using VS environment variables
set "KM_INC=!WindowsSdkDir!Include\!WindowsSDKVersion!km"
set "SHARED_INC=!WindowsSdkDir!Include\!WindowsSDKVersion!shared"
set "KM_LIB=!WindowsSdkDir!Lib\!WindowsSDKVersion!km\x64"

echo [INFO] WindowsSdkDir: !WindowsSdkDir!
echo [INFO] WindowsSDKVersion: !WindowsSDKVersion!
echo [INFO] KM_INC: !KM_INC!
echo [INFO] KM_LIB: !KM_LIB!

if not exist "!KM_INC!\ntddk.h" goto :noheaders
if not exist "!KM_LIB!\ntoskrnl.lib" goto :nolib

echo [INFO] Found ntddk.h and ntoskrnl.lib
if not exist "build_output" mkdir "build_output"

echo.
echo [BUILD] Compiling DarkstarDriver.c ...
echo.

cl.exe /nologo /c /Zi /O2 /Oi /GL /GS- /Gy /W3 /D _AMD64_ /D _WIN64 /D NDEBUG /I "!KM_INC!" /I "!SHARED_INC!" /Fo"build_output\DarkstarDriver.obj" /Fd"build_output\vc143.pdb" /kernel DarkstarDriver.c

if errorlevel 1 goto :compilefail

echo.
echo [BUILD] Compilation succeeded
echo.
echo [BUILD] Linking DarkstarDriver.sys ...
echo.

link.exe /nologo /OUT:"build_output\DarkstarDriver.sys" /MACHINE:X64 /SUBSYSTEM:NATIVE /DRIVER:WDM /ENTRY:DriverEntry /OPT:REF /OPT:ICF /LTCG /LIBPATH:"!KM_LIB!" ntoskrnl.lib ntstrsafe.lib "build_output\DarkstarDriver.obj"

if errorlevel 1 goto :linkfail

echo.
echo ============================================================
echo [SUCCESS] Built: %CD%\build_output\DarkstarDriver.sys
echo ============================================================
echo.
dir "build_output\DarkstarDriver.sys"
goto :done

:nocl
echo [ERROR] cl.exe not found. Run from "x64 Native Tools Command Prompt for VS 2022"
goto :done

:nosrc
echo [ERROR] DarkstarDriver.c not found in %CD%
goto :done

:noheaders
echo [ERROR] ntddk.h not found at: !KM_INC!
echo         WDK kernel headers may not be installed.
goto :done

:nolib
echo [ERROR] ntoskrnl.lib not found at: !KM_LIB!
goto :done

:compilefail
echo [ERROR] Compilation failed.
goto :done

:linkfail
echo [ERROR] Link failed.
goto :done

:done
echo.
pause
