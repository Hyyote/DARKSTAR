# DARKSTAR

A self-contained game optimizer with intelligent thread detection.

## Features

- **Intelligent Game Thread Detection**: Automatically identifies main game threads, render threads, audio threads, and worker threads
- **Module-based Thread Analysis**: Uses thread start addresses to determine which module spawned each thread
- **Thread Description Parsing**: Analyzes thread descriptions for classification
- **Confidence Scoring**: Assigns confidence scores to thread classifications for reliable optimization

### Self-Contained Deployment
- **No .NET Runtime Required**: The executable includes all dependencies
- **Single File Deployment**: One .exe file + config.json
- **Optimized Size**: Compressed single-file deployment

## Building

### Prerequisites
- .NET 8.0 SDK (for building only, not required on target machine)
- Windows 10/11

### Quick Build

1. Open the `DARKSTAR` folder
2. Double-click `BUILD.bat`
3. Choose option 1 for self-contained build
4. Find your executable at `Bin\Release\publish\DARKSTAR.exe`

## Kernel driver instructions
- **building in case of getting the Spectre Mitigation error**:<br>
Developer Command Prompt for VS 2022<br>
cd path\to\driver<br>
msbuild DarkstarDriver.vcxproj /p:Configuration=Release /p:Platform=x64 /p:SpectreMitigation=false<br>

Register DarkstarDriver.sys as a service, disable Driver Signature Enforcement to start (DSEFix and OSR Driver Loader for ease of use, though DSEFix is certain to cause a BSOD after some time)


### Manual Build (Self-Contained)

```powershell
cd DARKSTAR
dotnet publish src\DARKSTAR\DARKSTAR.csproj -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true -p:IncludeNativeLibrariesForSelfExtract=true -p:EnableCompressionInSingleFile=true -o Bin\Release\publish
```

### Visual Studio 2022

1. Open `DARKSTAR.sln` in Visual Studio 2022
2. Right-click project → **Publish**
3. Configure: Folder → Self-contained → win-x64 → Single file
4. Click Publish

## Configuration

Copy `config.json` next to `DARKSTAR.exe`:

```
DARKSTAR.exe
config.json
```

### Runtime Prompt

On startup, DARKSTAR prompts for the game executable name (e.g. `MyGame.exe`) to ensure the selected game is monitored even without a preexisting entry.
You can keep the `games` list empty and use only this runtime prompt for optimization targeting.

### Window Guard Settings

Add these keys under `settings` in `config.json`:

- `WINBLOCKKEYS` (`true/false`): blocks left/right Windows key while the monitored game window is the active foreground window. Hook is removed immediately when the game loses focus, is minimized, or exits.
- `BLOCKNOGAMINGMONITOR`:
  - `"auto"`: clips cursor to the game monitor only when the active game window is fullscreen/borderless and covers ~95% of that monitor (with a ~4px tolerance).
  - monitor list (`"1,2,3"`): clips cursor only when the game is active and currently on one of those monitors (numbering starts at 1).
  - `"off"`: disables monitor cursor clipping.
- `DPC_CORE0_LOCK` (`true/false`): experimental kernel-driver toggle that tries to lock DPC behavior away from core 0 by writing `KeQuantumEndTimerIncrement`. Only applies when the kernel driver is available and a game session is active.

These settings are backward-compatible with lowercase aliases (`win_block_keys`, `block_no_gaming_monitor`, `enable_dpc_core0_lock`).

## Hotkeys

- **CTRL+SHIFT+V** - Toggle verbose logging
- **CTRL+SHIFT+H** - Show/hide console window
- **CTRL+SHIFT+G** - Force system optimizations

## Intelligent Thread Detection

DARKSTAR uses intelligent thread detection to automatically classify game threads:

| Thread Type | Description | Core Recommendation |
|-------------|-------------|---------------------|
| Main | Primary game logic thread | P-Core (highest priority) |
| Render | Graphics/rendering thread | P-Core |
| Audio | Sound processing thread | Either |
| Network | Networking/socket thread | E-Core |
| Worker | Background task threads | E-Core |
| System | OS/runtime threads | E-Core |

The detector analyzes:
- Thread descriptions (SetThreadDescription API)
- Thread start addresses and parent modules
- Thread priority levels
- Thread state (Running/Waiting)
