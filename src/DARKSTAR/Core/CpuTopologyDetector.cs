using System;
using System.Collections.Generic;
using System.Linq;
using System.Management;

namespace DARKSTAR.Core
{
    public static class CpuTopologyDetector
    {
        private static readonly HashSet<int> _pCores = new HashSet<int>();
        private static readonly HashSet<int> _eCores = new HashSet<int>();
        private static bool _detected = false;

        public static HashSet<int> PCores => _pCores;
        public static HashSet<int> ECores => _eCores;
        public static bool IsDetected => _detected;

        public static void Detect()
        {
            try
            {
                _pCores.Clear();
                _eCores.Clear();
                int logicalCores = Environment.ProcessorCount;
                int physicalCores = GetPhysicalCoreCount();
                bool hyperthreading = logicalCores > physicalCores;
                if (IsHybridCpu())
                {
                    DetectHybridCpuTopology(logicalCores);
                }
                else
                {
                    for (int i = 0; i < logicalCores; i++)
                    {
                        _pCores.Add(i);
                    }
                }
                _detected = true;
                string htStatus = hyperthreading ? "HT Enabled" : "HT Disabled";
                Logger.WriteColored($"CPU: {physicalCores}P ({logicalCores} threads {htStatus}) + {_eCores.Count}E cores detected", ConsoleColor.Cyan);
                Logger.WriteLog($"CPU Topology: {physicalCores} physical cores, {logicalCores} logical cores, {_eCores.Count} E-cores");
                if (Logger.VerboseLogging)
                {
                    Logger.WriteVerbose($"P-cores (logical): [{string.Join(", ", _pCores.OrderBy(x => x))}]", ConsoleColor.DarkCyan);
                    if (_eCores.Count > 0)
                    {
                        Logger.WriteVerbose($"E-cores: [{string.Join(", ", _eCores.OrderBy(x => x))}]", ConsoleColor.Cyan);
                    }
                    else
                    {
                        Logger.WriteVerbose("No E-cores detected (non-hybrid CPU)", ConsoleColor.Cyan);
                    }
                }
            }
            catch (Exception ex)
            {
                Logger.WriteColored($"CPU Topology detection failed: {ex.Message}", ConsoleColor.Cyan);
                Logger.WriteLog($"CPU Topology detection failed: {ex.Message}");
                int totalCores = Environment.ProcessorCount;
                for (int i = 0; i < totalCores; i++)
                {
                    _pCores.Add(i);
                }
                Logger.WriteColored($"Fallback: All {totalCores} logical cores treated as P-cores", ConsoleColor.Cyan);
                Logger.WriteLog($"Fallback: All {totalCores} logical cores treated as P-cores");
                _detected = true;
            }
        }

        private static int GetPhysicalCoreCount()
        {
            try
            {
                using (var searcher = new ManagementObjectSearcher("SELECT NumberOfCores FROM Win32_Processor"))
                {
                    foreach (ManagementObject obj in searcher.Get())
                    {
                        return Convert.ToInt32(obj["NumberOfCores"]);
                    }
                }
            }
            catch
            {
                int logical = Environment.ProcessorCount;
                return logical <= 4 ? logical : logical / 2;
            }
            return Environment.ProcessorCount;
        }

        private static bool IsHybridCpu()
        {
            try
            {
                using (var searcher = new ManagementObjectSearcher("SELECT * FROM Win32_Processor"))
                {
                    foreach (ManagementObject obj in searcher.Get())
                    {
                        string name = (obj["Name"]?.ToString() ?? "").ToLower();
                        if (name.Contains("i9-12") || name.Contains("i9-13") || name.Contains("i9-14") ||
                            name.Contains("i7-12") || name.Contains("i7-13") || name.Contains("i7-14") ||
                            name.Contains("i5-12") || name.Contains("i5-13") || name.Contains("i5-14"))
                        {
                            if (name.Contains("12400") || name.Contains("12500") ||
                                name.Contains("12600") && !name.Contains("12600k") && !name.Contains("12600kf"))
                            {
                                return false;
                            }
                            return true;
                        }
                    }
                }
            }
            catch
            {
            }
            return false;
        }

        private static void DetectHybridCpuTopology(int logicalCores)
        {
            if (logicalCores == 24 || logicalCores == 32)
            {
                for (int i = 0; i < 16; i++) _pCores.Add(i);
                for (int i = 16; i < logicalCores; i++) _eCores.Add(i);
                Logger.WriteVerbose($"Detected: 8P (16 threads) + 16E configuration", ConsoleColor.Cyan);
            }
            else if (logicalCores == 20)
            {
                int pCores = logicalCores / 3 * 2;
                for (int i = 0; i < pCores; i++) _pCores.Add(i);
                for (int i = pCores; i < logicalCores; i++) _eCores.Add(i);
                Logger.WriteVerbose($"Detected: Generic hybrid configuration", ConsoleColor.Cyan);
            }
            else if (logicalCores == 16)
            {
                for (int i = 0; i < 12; i++) _pCores.Add(i);
                for (int i = 12; i < logicalCores; i++) _eCores.Add(i);
                Logger.WriteVerbose($"Detected: 6P (12 threads) + 8E configuration", ConsoleColor.Cyan);
            }
            else
            {
                int pCores = (logicalCores * 2) / 3;
                for (int i = 0; i < pCores; i++) _pCores.Add(i);
                for (int i = pCores; i < logicalCores; i++) _eCores.Add(i);
                Logger.WriteVerbose($"Detected: Generic hybrid {pCores}P + {logicalCores - pCores}E", ConsoleColor.Cyan);
            }
        }
    }
}
