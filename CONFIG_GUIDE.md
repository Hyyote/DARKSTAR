# DARKSTAR configuration guide (SECRET-TWEAK style)

This file summarizes how `darkstar.ini` is interpreted so you can express the SECRET-TWEAK rules precisely without guessing. The syntax mirrors the notes in the `Information` folder but removes MSI Afterburner-only options.

## Settings section
- `UpdateTimeout` — loop interval in milliseconds. Higher values reduce churn; lowering below `50` is clamped in code.
- `ExplorerKillTimeout` — how often the explorer watchdog relaunches or terminates it while a game is active.
- `EnableKillExplorer` — close `explorer.exe` while a game is focused; restore afterwards.
- `EnableIdleSwitching` — toggles CPU idle states when games start/stop.
- `WinBlockKeys` — installs the Win-key block hook (runs on its own message loop thread).
- `BlockNoGamingMonitor` — clamp the cursor to the monitor with the active game when enabled.
- `LockCPUFrequency` — locks CPU to base frequency during game mode. Disables turbo boost and sets min/max processor state to 100%. Reduces EMI/RFI noise from voltage/frequency transitions. Default: `false`.
- `ThreadRuleReapplyInterval` — interval in milliseconds between thread rule re-applications. Higher values reduce DARKSTAR's CPU usage and context switching overhead. Game detection still runs every `UpdateTimeout`. Default: `30000`.
- `occupied_affinity_cores` — physical cores to **exclude** from hard affinity when using `[auto]`. Use `auto` to let DARKSTAR respect device/E-core exclusions. Indices are physical cores, not logical.
- `occupied_ideal_processor_cores` — physical cores to exclude from `(auto)` ideal-processor placement. `auto` keeps the dynamic list.
- `occupied_weak_cores` — physical cores treated as “weak” and favored for background work. `auto` means DARKSTAR will treat detected E-cores as weak; leaving it empty uses E-cores when available.

## List sections
- `[Games]` — process names **without** `.exe` that define when game mode is active.
- `[ProcessesToSuspend]` — background apps to suspend while in-game.
- `[SetProcessesToIdlePriority]` — processes to demote to IDLE class while in-game.
- `[DisableBoost]` — processes whose threads have priority boost disabled.

## Per-process thread sections
Create a section named after the process (no `.exe`). Each line is either `priority_class=...` or a rule:

```
module=<module or exe pattern>[*], modifiers...
threaddesc=<thread name pattern>[*], modifiers...
```

- A trailing `*` marks a “main” thread and prefers first logical of the chosen physical core.
- Patterns accept `*` wildcards at either end.
- Modifiers (comma-separated):
  - `[auto]` — hard pin to the first free logical on a permitted physical core.
  - `[0x..]` — explicit affinity mask (group 0 only).
  - `(auto)` — set ideal processor using the same auto rules.
  - `(n)` — set ideal processor to logical index `n`.
  - `pcore` / `ecore` — bias `[auto]` or `(auto)` toward that core type.
  - integer `-15..15` — set thread priority.
  - `disableboost` — disable priority boost for the thread.
  - `disableclones` — copy the first auto assignment to matching clones.
  - `applyonce` — apply the rule only once per game session.
  - `300` / `200` — suspend or terminate the thread (cooldowns apply).

`priority_class=` accepts `Idle|BelowNormal|Normal|AboveNormal|High|RealTime` and is applied once per process when the first rule matches.

## Example tuned for i9-10850K
The example below mirrors the user-provided layout (USB on physical 1, NIC on 4, GPU on 5) and demonstrates CS2/Roblox rules with explicit placements. Adjust the numeric indexes to your physical core map if it differs.

```
[Settings]
UpdateTimeout=250
ExplorerKillTimeout=60000
EnableKillExplorer=true
EnableIdleSwitching=true
WinBlockKeys=true
BlockNoGamingMonitor=true
occupied_affinity_cores=1,4,5
occupied_ideal_processor_cores=0
occupied_weak_cores=auto

[Games]
cs2
RobloxPlayerBeta

[ProcessesToSuspend]
explorer

[SetProcessesToIdlePriority]
steam
discord

[DisableBoost]
dwm
audiodg
csrss
lsass
smss
wininit
winlogon
Registry

[dwm]
module=dwmcore.dll!CKstBase::RunKernelThreadStatic, [auto], pcore, disableboost
module=dwmcore.dll!CMit::RunInputThreadStatic, [auto], pcore, disableboost
module=ntdll.dll!TppWorkerThread, [auto], pcore, disableboost
threaddesc=DWM Frame Update, [auto], pcore, disableboost

[cs2]
module=cs2.exe*, [0], pcore, disableboost
threaddesc=GameThread*, [3], pcore
threaddesc=RenderThread, (2), pcore

[RobloxPlayerBeta]
module=RobloxPlayerBeta.exe*, [0], pcore, disableboost
threaddesc=GameThread*, [3], pcore
threaddesc=RenderThread, (2), pcore
```

### Tuning tips
- If you see stutters, increase `UpdateTimeout` (e.g., `350-500`) so rules are re-applied less frequently.
- Prefer `(auto)` for helper threads and `[auto]` only for the few latency-sensitive threads to avoid crowding the same core.
- When experimenting, watch the startup log for the "Core policy" line—it reflects whether DARKSTAR treated your occupied core lists as manual or auto and which cores were marked weak.
