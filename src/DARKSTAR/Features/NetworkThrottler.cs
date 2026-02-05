using System;
using System.Collections.Generic;
using System.Diagnostics;

namespace DARKSTAR.Features
{
    internal static class NetworkThrottler
    {
        private static bool _enabled;
        private static readonly HashSet<string> _targetProcesses =
            new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        private static readonly Dictionary<int, (ProcessPriorityClass Priority, IntPtr Affinity)> _originalState =
            new Dictionary<int, (ProcessPriorityClass, IntPtr)>();

        private static bool _isThrottled;

        public static void Configure(bool enabled, IEnumerable<string> processNames)
        {
            _enabled = enabled;
            _targetProcesses.Clear();
            _originalState.Clear();
            _isThrottled = false;

            if (!_enabled || processNames == null)
                return;

            foreach (var name in processNames)
            {
                var trimmed = name?.Trim();
                if (!string.IsNullOrEmpty(trimmed))
                    _targetProcesses.Add(trimmed.Replace(".exe", string.Empty, StringComparison.OrdinalIgnoreCase));
            }
        }

        public static void Apply(IntPtr backgroundAffinity)
        {
            if (!_enabled || _isThrottled || _targetProcesses.Count == 0)
                return;

            foreach (var procName in _targetProcesses)
            {
                Process[] processes;
                try
                {
                    processes = Process.GetProcessesByName(procName);
                }
                catch
                {
                    continue;
                }

                foreach (var process in processes)
                {
                    try
                    {
                        if (process.HasExited)
                            continue;

                        if (!_originalState.ContainsKey(process.Id))
                        {
                            var originalPriority = process.PriorityClass;
                            var originalAffinity = process.ProcessorAffinity;
                            _originalState[process.Id] = (originalPriority, originalAffinity);
                        }

                        try
                        {
                            process.PriorityClass = ProcessPriorityClass.BelowNormal;
                        }
                        catch
                        {
                        }

                        if (backgroundAffinity != IntPtr.Zero)
                        {
                            try
                            {
                                process.ProcessorAffinity = backgroundAffinity;
                            }
                            catch
                            {
                            }
                        }
                    }
                    catch
                    {
                    }
                }
            }

            _isThrottled = true;
        }

        public static void Restore()
        {
            if (!_isThrottled)
                return;

            foreach (var kvp in _originalState)
            {
                int pid = kvp.Key;
                var state = kvp.Value;

                try
                {
                    var process = Process.GetProcessById(pid);
                    if (process.HasExited)
                        continue;

                    try
                    {
                        process.PriorityClass = state.Priority;
                    }
                    catch
                    {
                    }

                    try
                    {
                        process.ProcessorAffinity = state.Affinity;
                    }
                    catch
                    {
                    }
                }
                catch
                {
                }
            }

            _originalState.Clear();
            _isThrottled = false;
        }
    }
}
