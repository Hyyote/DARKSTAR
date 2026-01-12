# DARKSTAR

A Windows game optimization tool that applies advanced system tweaks to reduce latency, minimize background interference, and maximize gaming performance.

---

## Features

### Core Optimizations
- **Thread Affinity Management** — Pin game and system threads to specific CPU cores using automatic or manual placement
- **Priority Control** — Set process priority classes and thread priorities for optimal scheduling
- **Priority Boost Disable** — Eliminate scheduling jitter by disabling Windows priority boost
- **CPU Frequency Locking** — Lock CPU to base frequency to reduce EMI/RFI noise from voltage transitions
- **Context Switch Reduction** — Smart rule re-application and "apply once" mode minimize overhead

### System Management
- **Explorer Termination** — Remove `explorer.exe` during gaming to eliminate shell overhead
- **Process Suspension** — Suspend background applications while gaming
- **Idle Priority Demotion** — Automatically lower priority of background processes
- **CPU Idle State Control** — Disable processor C-states during gaming
- **MMCSS Disable** — Stop Multimedia Class Scheduler Service for consistent performance

### Input & Display
- **Windows Key Block** — Prevent accidental Win key presses during gameplay
- **Cursor Clamping** — Lock cursor to gaming monitor

---

## Configuration

DARKSTAR is configured via `darkstar.ini`. The configuration is hot-reloaded every update cycle, so you can tweak settings without restarting. 

### Settings Section

| Setting | Description | Default |
|---------|-------------|---------|
| `UpdateTimeout` | Main loop interval in milliseconds.  Higher values reduce churn; minimum is 50ms. | `250` |
| `ExplorerKillTimeout` | Explorer watchdog interval while a game is active. | `60000` |
| `EnableKillExplorer` | Terminate `explorer.exe` during gaming; restore afterwards. | `false` |
| `EnableIdleSwitching` | Toggle CPU idle states (C-states) when games start/stop. | `true` |
| `WinBlockKeys` | Block Windows key during gaming. | `false` |
| `BlockNoGamingMonitor` | Restrict cursor to the monitor with the active game. | `false` |
| `LockCPUFrequency` | Lock CPU to base frequency, disable turbo boost.  Reduces EMI/RFI noise. | `false` |
| `ThreadRuleReapplyInterval` | Milliseconds between thread rule re-applications. Higher values reduce DARKSTAR overhead. | `30000` |
| `occupied_affinity_cores` | Physical cores to exclude from `[auto]` affinity. Use `auto` for device/E-core exclusions.  | `auto` |
| `occupied_ideal_processor_cores` | Physical cores to exclude from `(auto)` ideal processor placement. | `auto` |
| `occupied_weak_cores` | Physical cores treated as "weak" for background work. `auto` uses detected E-cores. | `auto` |

### List Sections

- **`[Games]`** — Process names (without `.exe`) that trigger game mode
- **`[ProcessesToSuspend]`** — Background apps to suspend while gaming
- **`[SetProcessesToIdlePriority]`** — Processes to demote to IDLE priority class
- **`[DisableBoost]`** — Processes whose threads have priority boost disabled

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
| `300` | Suspend the thread (with cooldown) |
| `200` | Terminate the thread (with cooldown) |

**Priority Classes:** `Idle|BelowNormal|Normal|AboveNormal|High|RealTime`

---

## Example Configuration

This example is tuned for an i9-10850K with USB on physical core 1, GPU on 5:

```ini
[Settings]
# Main loop interval (ms). Raise this if you see stutter from rapid re-application.
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
# Use "auto" to let DARKSTAR respect device/E-core exclusions automatically.
occupied_affinity_cores=1,5
occupied_ideal_processor_cores=
occupied_weak_cores=6,7,8,9

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
# Add system daemons that occasionally spike the CPU to flatten latency
csrss
audiodg
dwm

# Adjust indices to your machine. Swap [auto]/(auto) and the pcore/ecore hints as needed for each title.

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
module=cs2.exe*, [0], pcore, disableboost, applyonce
threaddesc=GameThread*, [3], pcore, applyonce
threaddesc=RenderThread, (2), pcore

```

---

## Tuning Tips

1. **Stutters or microstutters?** Increase `UpdateTimeout` (e.g., 350-500ms) and `ThreadRuleReapplyInterval` (e.g., 60000ms) to reduce rule re-application frequency.

2. **Core assignment strategy:**
   - Use `[auto]` affinity **only** for critical latency-sensitive threads (main game thread, render thread)
   - Use `(auto)` ideal processor for helper threads
   - This prevents crowding multiple critical threads on the same core

3. **Use `applyonce` for static rules:** If a thread's affinity/priority doesn't need continuous adjustment, add `applyonce` to reduce overhead.

4. **Check the startup log:** The "Core policy" line shows how DARKSTAR interpreted your occupied core lists and which cores were marked as weak/E-cores.

5. **Physical core mapping:** Adjust `occupied_affinity_cores` to exclude cores handling interrupts (USB controller, NIC, GPU). Check your BIOS or use tools like MSI Mode Utility to identify which cores handle device interrupts.

---

## Usage

1. Place `darkstar.ini` in the same directory as the executable
2. Run `DARKSTAR.exe` with **Administrator privileges** (required for process/thread manipulation)
3. DARKSTAR will monitor for configured games and automatically apply optimizations
4. Check `DARKSTAR.log` for detailed operation logs

---

## Requirements

- Windows 10/11 (64-bit)
- Administrator privileges
- CPU topology detection requires Windows 7+ with multi-core processor

---

## License

This project is provided as-is for personal use. 
