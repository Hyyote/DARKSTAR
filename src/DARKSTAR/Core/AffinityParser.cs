using System;
using System.Collections.Generic;
using System.Linq;

namespace DARKSTAR.Core
{
    public static class AffinityParser
    {
        private static IntPtr _cachedAutoAffinity = IntPtr.Zero;
        private static int _cachedCoreCount = 0;

        public static IntPtr Parse(string affinity)
        {
            if (affinity == "ALL")
                return (IntPtr)((1L << Environment.ProcessorCount) - 1);

            if (affinity.Equals("ht on", StringComparison.OrdinalIgnoreCase))
                return (IntPtr)((1L << Environment.ProcessorCount) - 1);
            if (affinity.Equals("ht off", StringComparison.OrdinalIgnoreCase))
                return GetPhysicalCoresOnly();
            if (affinity.Equals("ht only", StringComparison.OrdinalIgnoreCase))
                return GetHyperThreadedCoresOnly();

            if (affinity.Equals("p-core", StringComparison.OrdinalIgnoreCase))
                return ParsePCoreAffinity();
            if (affinity.Equals("e-core", StringComparison.OrdinalIgnoreCase))
                return ParseECoreAffinity();
            if (affinity.Equals("AUTO", StringComparison.OrdinalIgnoreCase))
                return GetAutoAffinity();

            return ParseManualAffinity(affinity);
        }

        private static IntPtr ParsePCoreAffinity()
        {
            if (!CpuTopologyDetector.IsDetected)
                CpuTopologyDetector.Detect();
            if (CpuTopologyDetector.PCores.Count == 0)
            {
                Logger.WriteColored("ERROR: P-core affinity requested but no P-cores detected!", ConsoleColor.Cyan);
                Logger.WriteLog("ERROR: P-core affinity requested but no P-cores detected");
                return (IntPtr)0;
            }
            long mask = 0;
            foreach (int core in CpuTopologyDetector.PCores)
            {
                mask |= (1L << core);
            }
            Logger.WriteVerbose($"Using P-cores only: [{string.Join(", ", CpuTopologyDetector.PCores.OrderBy(x => x))}]", ConsoleColor.DarkCyan);
            Logger.WriteLog($"Using P-cores only: [{string.Join(", ", CpuTopologyDetector.PCores.OrderBy(x => x))}]");
            return (IntPtr)mask;
        }

        private static IntPtr ParseECoreAffinity()
        {
            if (!CpuTopologyDetector.IsDetected)
                CpuTopologyDetector.Detect();
            if (CpuTopologyDetector.ECores.Count == 0)
            {
                Logger.WriteColored("ERROR: E-core affinity requested but no E-cores detected!", ConsoleColor.Cyan);
                Logger.WriteLog("ERROR: E-core affinity requested but no E-cores detected");
                return (IntPtr)0;
            }
            long mask = 0;
            foreach (int core in CpuTopologyDetector.ECores)
            {
                mask |= (1L << core);
            }
            Logger.WriteVerbose($"Using E-cores only: [{string.Join(", ", CpuTopologyDetector.ECores.OrderBy(x => x))}]", ConsoleColor.DarkCyan);
            Logger.WriteLog($"Using E-cores only: [{string.Join(", ", CpuTopologyDetector.ECores.OrderBy(x => x))}]");
            return (IntPtr)mask;
        }

        private static IntPtr GetAutoAffinity()
        {
            int currentCoreCount = Environment.ProcessorCount;
            if (_cachedAutoAffinity == IntPtr.Zero || _cachedCoreCount != currentCoreCount)
            {
                _cachedAutoAffinity = CalculateAutoAffinity();
                _cachedCoreCount = currentCoreCount;
            }
            return _cachedAutoAffinity;
        }

        private static IntPtr ParseManualAffinity(string affinity)
        {
            long manualMask = 0;
            string[] parts = affinity.Split(',');

            foreach (string part in parts)
            {
                string trimmedPart = part.Trim();
                if (trimmedPart.Contains("-"))
                {
                    string[] range = trimmedPart.Split('-');
                    if (range.Length == 2 && int.TryParse(range[0].Trim(), out int start) && int.TryParse(range[1].Trim(), out int end))
                    {
                        for (int i = start; i <= end; i++)
                        {
                            if (i >= 0 && i < 64)
                                manualMask |= (1L << i);
                        }
                    }
                }
                else if (int.TryParse(trimmedPart, out int core))
                {
                    if (core >= 0 && core < 64)
                        manualMask |= (1L << core);
                }
            }

            return (IntPtr)manualMask;
        }

        private static IntPtr GetPhysicalCoresOnly()
        {
            int totalCores = Environment.ProcessorCount;
            long mask = 0;
            for (int i = 0; i < totalCores; i += 2)
            {
                mask |= (1L << i);
            }
            if (totalCores % 2 == 1)
            {
                mask |= (1L << (totalCores - 1));
            }
            Logger.WriteVerbose($"HT Off - Physical cores only: {Convert.ToString(mask, 2).PadLeft(totalCores, '0')}", ConsoleColor.DarkCyan);
            Logger.WriteLog($"HT Off - Physical cores only: {Convert.ToString(mask, 2).PadLeft(totalCores, '0')}");
            return (IntPtr)mask;
        }

        private static IntPtr GetHyperThreadedCoresOnly()
        {
            int totalCores = Environment.ProcessorCount;
            long mask = 0;
            for (int i = 1; i < totalCores; i += 2)
            {
                mask |= (1L << i);
            }
            Logger.WriteVerbose($"HT Only - Hyper-threaded cores only: {Convert.ToString(mask, 2).PadLeft(totalCores, '0')}", ConsoleColor.DarkCyan);
            Logger.WriteLog($"HT Only - Hyper-threaded cores only: {Convert.ToString(mask, 2).PadLeft(totalCores, '0')}");
            return (IntPtr)mask;
        }

        private static IntPtr CalculateAutoAffinity()
        {
            int totalCores = Environment.ProcessorCount;
            long mask = 1L << 0;
            if (totalCores <= 1)
                return (IntPtr)mask;
            if (totalCores <= 4)
            {
                for (int i = 1; i < totalCores; i++)
                {
                    mask |= (1L << i);
                }
                Logger.WriteVerbose($"Small system auto affinity: Core 0=input, {totalCores-1} cores=game", ConsoleColor.DarkCyan);
            }
            else if (totalCores <= 8)
            {
                int gameCores = (totalCores - 1) / 2;
                int systemCores = (totalCores - 1) - gameCores;
                for (int i = 1; i <= gameCores; i++)
                {
                    mask |= (1L << i);
                }
                for (int i = gameCores + 1; i < totalCores; i++)
                {
                    mask |= (1L << i);
                }
                Logger.WriteVerbose($"Medium system auto affinity: 1 input, {gameCores} game, {systemCores} system", ConsoleColor.DarkCyan);
            }
            else
            {
                int remainingCores = totalCores - 1;
                int gameCores = (int)Math.Round(remainingCores * 0.4);
                int renderCores = (int)Math.Round(remainingCores * 0.2);
                int systemCores = remainingCores - gameCores - renderCores;
                if (gameCores < 1) gameCores = 1;
                if (renderCores < 1) renderCores = 1;
                if (systemCores < 1) systemCores = 1;
                int currentCore = 1;
                for (int i = 0; i < gameCores && currentCore < totalCores; i++, currentCore++)
                {
                    mask |= (1L << currentCore);
                }
                for (int i = 0; i < renderCores && currentCore < totalCores; i++, currentCore++)
                {
                    mask |= (1L << currentCore);
                }
                for (int i = 0; i < systemCores && currentCore < totalCores; i++, currentCore++)
                {
                    mask |= (1L << currentCore);
                }
                Logger.WriteVerbose($"Large system auto affinity: 1 input, {gameCores} game, {renderCores} render, {systemCores} system", ConsoleColor.DarkCyan);
            }
            Logger.WriteVerbose($"Auto affinity mask for {totalCores} cores: {Convert.ToString(mask, 2).PadLeft(totalCores, '0')}", ConsoleColor.DarkCyan);
            Logger.WriteLog($"Auto affinity calculated: {totalCores} cores, mask: {Convert.ToString(mask, 2).PadLeft(totalCores, '0')}");
            return (IntPtr)mask;
        }
    }
}
