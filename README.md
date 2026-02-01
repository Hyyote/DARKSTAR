# DARKSTAR

A self-contained game optimizer with intelligent thread detection.

## Features

### Combined from DARKSTAR
- **Intelligent Game Thread Detection**: Automatically identifies main game threads, render threads, audio threads, and worker threads
- **Module-based Thread Analysis**: Uses thread start addresses to determine which module spawned each thread
- **Thread Description Parsing**: Analyzes thread descriptions for classification
- **Confidence Scoring**: Assigns confidence scores to thread classifications for reliable optimization

### Self-Contained Deployment
- **No .NET Runtime Required**: The executable includes all dependencies
- **Single File Deployment**: One .exe file + config folder
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

Copy the `config` folder next to `DARKSTAR.exe`:

```
DARKSTAR.exe
config/
  ├── GAME_PRIORITY.GCFG     # Game process configurations
  ├── PROC_PRIORITY.GCFG     # System process configurations
  └── DARKSTAR.GCFG          # General settings
```

### Configuration File Format

See the existing `.GCFG` files for format examples.

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

## Credits

Based on advanced game optimization techniques and intelligent thread detection.

## License

MIT License - See LICENSE file for details.
