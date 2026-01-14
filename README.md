# DARKSTAR

A Windows game optimization tool that applies advanced system tweaks to reduce latency, minimize background interference, and maximize gaming performance.

---

## What changed (recent updates)

- The default configuration shipped by the program was updated. A template `darkstar.ini` will be created automatically on first run if none exists.
- Several settings defaults were changed to safer/off values (for example, Explorer termination and idle-state switching default to disabled).
- The configuration is hot-reloaded every update cycle (same behavior as before) and some internal timing/field names were clarified in code (the program enforces a minimum update interval of 50 ms).
- Process / thread rule application logic was made more robust (first-run always applies rules, and rules are re-applied on interval or when monitored processes change).

This README has been updated to reflect the current defaults, examples, and behavior.

---

## Build guide
**Visual Studio**

New project: empty C++  
Add .cpp files to Source files as Existing item  
Add .h files to Header files as Existing item  
Right click project, Set as startup project  
Select Release, build with Win+Shift+B

---

## Features

### Core Optimizations
- Thread affinity management — Pin game and system threads to specific CPU cores using automatic or manual placement
- Priority control — Set process priority classes and thread priorities for optimal scheduling
- Priority boost disable — Eliminate scheduling jitter by disabling Windows priority boost
- CPU frequency locking — Optionally lock CPU to base frequency to reduce EMI/RFI noise from voltage transitions
- Context switch reduction — Smart rule re-application and `applyonce` mode minimize overhead

### System Management
- Explorer termination — Optionally remove `explorer.exe` during gaming to eliminate shell overhead
- Process suspension — Suspend background applications while gaming
- Idle priority demotion — Automatically lower priority of background processes
- CPU idle state control — Optionally disable processor C-states while a game is active
- MMCSS disable — Stop Multimedia Class Scheduler Service for consistent performance

### Input & Display
- Windows key block — Prevent accidental Win key presses during gameplay
- Cursor clamping — Lock cursor to the monitor with the active game

---

## Configuration

DARKSTAR is configured via `darkstar.ini`. On first run the program will create a template `darkstar.ini` in the executable folder. The configuration is hot-reloaded every update cycle, so you can tweak settings without restarting.

### Settings Section

| Setting | Description | Default |
|---------|-------------|---------|
| `UpdateTimeout` | Main loop interval in milliseconds. Higher values reduce churn; program enforces a minimum of `50` ms. | `250` |
| `ExplorerKillTimeout` | Explorer watchdog interval while a game is active (ms). | `60000` |
| `EnableKillExplorer` | Terminate `explorer.exe` during gaming; restore afterwards. | `false` |
| `EnableIdleSwitching` | Toggle CPU idle states (C-states) when games start/stop. | `false` |
| `WinBlockKeys` | Block Windows key during gaming. | `false` |
| `BlockNoGamingMonitor` | Restrict cursor to the monitor with the active game. | `false` |
| `LockCPUFrequency` | Lock CPU to base frequency / disable turbo (optional). | `false` |
| `ThreadRuleReapplyInterval` | Milliseconds between thread rule re-applications. Higher values reduce DARKSTAR overhead. | `30000` |
| `occupied_affinity_cores` | Physical cores to exclude from `[auto]` affinity. Use `auto` for device/E-core exclusions. | `auto` |
| `occupied_ideal_processor_cores` | Physical cores to exclude from `(auto)` ideal processor placement. | `auto` |
| `occupied_weak_cores` | Physical cores treated as "weak" for background work. Use `auto` to let DARKSTAR detect E-cores; an empty value disables auto-weak marking. | `` (empty) |

Notes:
- The program will clamp `UpdateTimeout` to a minimum of 50 ms to avoid excessive CPU churn.
- Internally some fields are tracked as millisecond values (e.g., update and reapply intervals); the README names are the user-facing keys in the INI.

### List Sections

- `[Games]` — Process names (without `.exe`) that trigger game mode
- `[ProcessesToSuspend]` — Background apps to suspend while gaming
- `[SetProcessesToIdlePriority]` — Processes to demote to IDLE priority class
- `[DisableBoost]` — Processes whose threads have priority boost disabled

### Per-Process Thread Rules

Create a section named after the process (without `.exe`). Each line defines either `priority_class=...` or a thread rule:

```ini
module=<module or exe pattern>[*], modifiers...
threaddesc=<thread name pattern>[*], modifiers...
```

#### Pattern Matching
- Trailing `*` marks a "main" thread and prefers the first logical processor of the chosen physical core
- Wildcards accepted at either end of patterns

#### Modifiers (comma-separated)

| Modifier | Description |
|----------|-------------|
| `[auto]` | Hard pin to the first free logical processor on a permitted physical core |
| `[0x...]` | Explicit affinity mask (group 0 only) |
| `(auto)` | Set ideal processor using auto placement rules |
| `(n)` | Set ideal processor to logical index `n` |
| `pcore` | Bias automatic placement toward P-cores |
| `ecore` | Bias automatic placement toward E-cores |
| `-15..15` | Set thread priority (integer) |
| `disableboost` | Disable priority boost for the thread |
| `disableclones` | Apply the rule only to the first matching thread |
| `applyonce` | Apply the rule once per game session (reduces overhead) |
| `300` | Suspend the thread (value is cooldown in seconds) |
| `200` | Terminate the thread (value is cooldown in seconds) |

Priority Classes: `Idle | BelowNormal | Normal | AboveNormal | High | RealTime`

---

## Example Configuration

This example is aligned with the current runtime template and demonstrates common settings:

```ini
[Settings]
# Main loop interval (ms)
UpdateTimeout=1000
# Explorer watchdog interval (ms) while a game is active.
ExplorerKillTimeout=60000
EnableKillExplorer=true
EnableIdleSwitching=true
# Input safeguards
WinBlockKeys=true
BlockNoGamingMonitor=true
# CPU frequency locking to reduce EMI/RFI noise
LockCPUFrequency=true
# Thread rule re-application interval (ms)
ThreadRuleReapplyInterval=30000
# Physical cores reserved from auto affinity / ideal assignment
occupied_affinity_cores=auto
occupied_ideal_processor_cores=auto
occupied_weak_cores=auto

[Games]
# Process names without .exe that trigger game mode
cs2

[ProcessesToSuspend]
# Background utilities to suspend while gaming
explorer

[SetProcessesToIdlePriority]
# Lower priority background tasks during game mode
steam
discord

[DisableBoost]
# Processes whose threads should have priority boost disabled
csrss
audiodg
dwm

[dwm]
module=dwmcore.dll, [auto], pcore, disableboost, disableclones
threaddesc=DWM Frame Update, [auto], pcore, disableboost

[lsass]
module=ntdll.dll, [auto], pcore, disableboost, disableclones
module=lsasrv.dll, [auto], pcore, disableboost, disableclones

[RpcSs]
module=ntdll.dll, [auto], pcore, disableboost, disableclones

[RpcEptMapper]
module=ntdll.dll, [auto], pcore, disableboost, disableclones

[cs2]
module=cs2.exe*, [auto], pcore, disableboost, applyonce
threaddesc=GameThread*, [auto], pcore, applyonce
threaddesc=RenderThread, (auto), pcore
```

Adjust indices and core hints to suit your machine. Use `auto` to respect device/E-core exclusions automatically.

---

## Tuning Tips

1. If you see stutters or microstutters: increase `UpdateTimeout` (for example, 350–500 ms) and raise `ThreadRuleReapplyInterval` (e.g., 60000 ms) to reduce the frequency of rule re-application.
2. Core assignment strategy:
   - Use `[auto]` affinity for latency-sensitive threads (main game thread, render thread).
   - Use `(auto)` ideal processor for helper threads to avoid crowding.
3. Use `applyonce` for static rules (threads that do not need continuous adjustment) to lower runtime overhead.
4. Check the startup log — the log shows a "Core policy" summary that explains how occupied core lists were interpreted and which cores were marked weak/E-cores.
5. Physical core mapping: adjust `occupied_affinity_cores` to exclude cores handling interrupts (USB controller, NIC, GPU). Check BIOS or use vendor tools to map interrupt-to-core affinities.

---

## Usage

1. Place `darkstar.ini` in the same directory as the executable — the program will create a template if missing.
2. Run `DARKSTAR.exe` with Administrator privileges (required for process/thread manipulation).
3. DARKSTAR monitors for configured games and applies optimizations automatically.
4. Logs are written to `DARKSTAR.log` in the executable folder (default log level is INFO).

When no games are configured the program logs a warning. The program will always attempt to re-launch explorer when game mode exits if explorer was terminated by DARKSTAR.

---

## Requirements

- Windows 10/11 (64-bit)
- Administrator privileges
- CPU topology detection requires multi-core support (Windows 7+ for topology APIs)

---

## License

This project is provided as-is for personal use.