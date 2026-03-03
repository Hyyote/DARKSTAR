@echo off
echo ========================================
echo DARKSTAR - Build Script
echo ========================================
echo.

REM Check if we're in the correct directory
if not exist "DARKSTAR.sln" (
    echo ERROR: DARKSTAR.sln not found!
    echo.
    echo You must run this script from the DARKSTAR folder.
    echo Current directory: %CD%
    echo.
    echo Please:
    echo 1. Navigate to the folder containing DARKSTAR.sln
    echo 2. Run BUILD.bat from that location
    echo.
    echo OR simply double-click BUILD.bat from File Explorer
    pause
    exit /b 1
)

REM Check if dotnet is installed
dotnet --version >nul 2>&1
if errorlevel 1 (
    echo ERROR: .NET SDK is not installed!
    echo Please install .NET 8.0 SDK from: https://dotnet.microsoft.com/download
    pause
    exit /b 1
)

echo .NET SDK found. Building application...
echo.

REM Clean previous builds
if exist "Bin" rmdir /s /q "Bin"
if exist "src\DARKSTAR\obj" rmdir /s /q "src\DARKSTAR\obj"

echo Choose build type:
echo.
echo 1. Self-Contained (70-100 MB, no .NET required on target PC) [RECOMMENDED]
echo 2. Framework-Dependent (5-10 MB, requires .NET 8.0 on target PC)
echo.
set /p choice="Enter your choice (1 or 2): "

if "%choice%"=="1" goto selfcontained
if "%choice%"=="2" goto framework
echo Invalid choice. Defaulting to Self-Contained...

:selfcontained
echo.
echo Building Self-Contained executable...
echo This produces a single .exe that works without .NET installed.
echo.
dotnet publish src\DARKSTAR\DARKSTAR.csproj -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true -p:IncludeNativeLibrariesForSelfExtract=true -p:EnableCompressionInSingleFile=true -o Bin\Release\publish
goto done

:framework
echo.
echo Building Framework-Dependent executable...
echo NOTE: This requires .NET 8.0 runtime on the target machine.
echo.
dotnet publish src\DARKSTAR\DARKSTAR.csproj -c Release -r win-x64 --self-contained false -p:PublishSingleFile=true -o Bin\Release\publish
goto done

:done
if errorlevel 1 (
    echo.
    echo ========================================
    echo BUILD FAILED!
    echo ========================================
    pause
    exit /b 1
)

echo.
echo ========================================
echo BUILD SUCCESSFUL!
echo ========================================
echo.
echo Your executable is located at:
echo   Bin\Release\publish\DARKSTAR.exe
echo.
echo Make sure to copy config.json next to DARKSTAR.exe:
echo   - config.json
echo.
pause
