using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Runtime.InteropServices;

namespace DARKSTAR.UI.WinForms.Native
{
    internal static class CpuTopologyNative
    {

        internal sealed class CpuTopology
        {
            public IReadOnlyList<ProcessorGroup> Groups { get; init; } = Array.Empty<ProcessorGroup>();
            public IReadOnlyList<CoreInfo> Cores { get; init; } = Array.Empty<CoreInfo>();

            public GroupedAffinityMask PCoreMask { get; init; } = GroupedAffinityMask.Empty;

            public GroupedAffinityMask ECoreMask { get; init; } = GroupedAffinityMask.Empty;

            public GroupedAffinityMask AllMask { get; init; } = GroupedAffinityMask.Empty;

            public bool HasCoreTypeClassification { get; init; }
        }

        internal sealed class ProcessorGroup
        {
            public ushort GroupNumber { get; init; }
            public int ActiveProcessorCount { get; init; }
            public ulong ActiveMask { get; init; }
        }

        internal sealed class CoreInfo
        {
            public ushort GroupNumber { get; init; }

            public ulong SmtSiblingMask { get; init; }

            public int LogicalCount { get; init; }

            public CoreType Type { get; init; }
        }

        internal enum CoreType
        {
            Unknown = 0,
            PCore = 1,
            ECore = 2
        }

        internal sealed class GroupedAffinityMask
        {
            public static readonly GroupedAffinityMask Empty = new GroupedAffinityMask(new Dictionary<ushort, ulong>(), flatMask: System.Numerics.BigInteger.Zero);

            public IReadOnlyDictionary<ushort, ulong> PerGroupMasks { get; }
            public System.Numerics.BigInteger FlatMask { get; }

            public GroupedAffinityMask(Dictionary<ushort, ulong> perGroupMasks, System.Numerics.BigInteger flatMask)
            {
                PerGroupMasks = perGroupMasks;
                FlatMask = flatMask;
            }

            public override string ToString()
            {
                return $"Groups={PerGroupMasks.Count}, Flat=0x{FlatMask.ToString("X")}";
            }

            public string ToFlatHexString()
            {
                if (FlatMask.IsZero) return "0x0";
                return "0x" + FlatMask.ToString("X");
            }
        }


        public static CpuTopology GetTopology()
        {
            var (cores, groups) = GetCoresAndGroups();

            var allPerGroup = new Dictionary<ushort, ulong>();
            foreach (var g in groups)
                allPerGroup[g.GroupNumber] = g.ActiveMask;

            var allFlat = BuildFlatMask(allPerGroup);
            var allMask = new GroupedAffinityMask(allPerGroup, allFlat);

            var lpEfficiency = TryGetLogicalProcessorEfficiencyClasses(groups, out var effByLp, out var maxEffClass);

            var typedCores = new List<CoreInfo>(cores.Count);
            var pPerGroup = new Dictionary<ushort, ulong>();
            var ePerGroup = new Dictionary<ushort, ulong>();
            bool hasAnyType = false;

            foreach (var c in cores)
            {
                CoreType type = CoreType.Unknown;

                if (lpEfficiency)
                {
                    bool anyP = false;
                    bool anyE = false;

                    foreach (int bit in EnumerateSetBits(c.SmtSiblingMask))
                    {
                        var lpKey = (c.GroupNumber, bit);
                        if (effByLp.TryGetValue(lpKey, out byte eff))
                        {
                            if (eff == maxEffClass) anyP = true;
                            else anyE = true;
                        }
                    }

                    if (anyP && !anyE) type = CoreType.PCore;
                    else if (!anyP && anyE) type = CoreType.ECore;
                    else if (anyP && anyE)
                    {
                        type = CoreType.Unknown;
                    }

                    if (type != CoreType.Unknown)
                        hasAnyType = true;
                }

                typedCores.Add(new CoreInfo
                {
                    GroupNumber = c.GroupNumber,
                    SmtSiblingMask = c.SmtSiblingMask,
                    LogicalCount = c.LogicalCount,
                    Type = type
                });

                if (type == CoreType.PCore)
                {
                    pPerGroup.TryGetValue(c.GroupNumber, out ulong existing);
                    pPerGroup[c.GroupNumber] = existing | c.SmtSiblingMask;
                }
                else if (type == CoreType.ECore)
                {
                    ePerGroup.TryGetValue(c.GroupNumber, out ulong existing);
                    ePerGroup[c.GroupNumber] = existing | c.SmtSiblingMask;
                }
            }

            var pMask = new GroupedAffinityMask(pPerGroup, BuildFlatMask(pPerGroup));
            var eMask = new GroupedAffinityMask(ePerGroup, BuildFlatMask(ePerGroup));

            return new CpuTopology
            {
                Groups = groups.AsReadOnly(),
                Cores = typedCores.AsReadOnly(),
                AllMask = allMask,
                PCoreMask = pMask,
                ECoreMask = eMask,
                HasCoreTypeClassification = hasAnyType
            };
        }

        public static GroupedAffinityMask ComputeHtOffMask(CpuTopology topo, CoreType restrictTo)
        {
            var perGroup = new Dictionary<ushort, ulong>();

            foreach (var c in topo.Cores)
            {
                if (restrictTo != CoreType.Unknown)
                {
                    if (!topo.HasCoreTypeClassification) continue;
                    if (c.Type != restrictTo) continue;
                }

                ulong pick = LowestSetBit(c.SmtSiblingMask);
                if (pick == 0) continue;

                perGroup.TryGetValue(c.GroupNumber, out ulong existing);
                perGroup[c.GroupNumber] = existing | pick;
            }

            if (restrictTo != CoreType.Unknown && perGroup.Count == 0)
            {
                return ComputeHtOffMask(topo, CoreType.Unknown);
            }

            return new GroupedAffinityMask(perGroup, BuildFlatMask(perGroup));
        }

        public static GroupedAffinityMask ComputeHtOnMask(CpuTopology topo, CoreType restrictTo)
        {
            var perGroup = new Dictionary<ushort, ulong>();

            foreach (var c in topo.Cores)
            {
                if (restrictTo != CoreType.Unknown)
                {
                    if (!topo.HasCoreTypeClassification) continue;
                    if (c.Type != restrictTo) continue;
                }

                perGroup.TryGetValue(c.GroupNumber, out ulong existing);
                perGroup[c.GroupNumber] = existing | c.SmtSiblingMask;
            }

            if (restrictTo != CoreType.Unknown && perGroup.Count == 0)
            {
                return ComputeHtOnMask(topo, CoreType.Unknown);
            }

            return new GroupedAffinityMask(perGroup, BuildFlatMask(perGroup));
        }


        private static (List<CoreInfo> cores, List<ProcessorGroup> groups) GetCoresAndGroups()
        {
            uint len = 0;
            bool ok = GetLogicalProcessorInformationEx(LOGICAL_PROCESSOR_RELATIONSHIP.RelationAll, IntPtr.Zero, ref len);
            int err = Marshal.GetLastWin32Error();

            if (!ok && err != ERROR_INSUFFICIENT_BUFFER)
                throw new Win32Exception(err, "GetLogicalProcessorInformationEx (size query) failed.");

            IntPtr buffer = Marshal.AllocHGlobal((int)len);
            try
            {
                ok = GetLogicalProcessorInformationEx(LOGICAL_PROCESSOR_RELATIONSHIP.RelationAll, buffer, ref len);
                if (!ok)
                    throw new Win32Exception(Marshal.GetLastWin32Error(), "GetLogicalProcessorInformationEx failed.");

                var cores = new List<CoreInfo>();
                var groups = new Dictionary<ushort, ProcessorGroup>();

                IntPtr ptr = buffer;
                IntPtr end = IntPtr.Add(buffer, (int)len);

                while (ptr.ToInt64() < end.ToInt64())
                {
                    var rel = Marshal.PtrToStructure<SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX>(ptr);

                    if (rel.Relationship == LOGICAL_PROCESSOR_RELATIONSHIP.RelationProcessorCore)
                    {
                        var core = ReadProcessorCore(ptr, rel.Size);
                        cores.Add(core);
                    }
                    else if (rel.Relationship == LOGICAL_PROCESSOR_RELATIONSHIP.RelationGroup)
                    {
                        ReadGroups(ptr, rel.Size, groups);
                    }

                    ptr = IntPtr.Add(ptr, (int)rel.Size);
                }

                if (groups.Count == 0)
                {
                    ulong mask = 0;
                    foreach (var c in cores)
                        mask |= c.SmtSiblingMask;

                    groups[0] = new ProcessorGroup
                    {
                        GroupNumber = 0,
                        ActiveProcessorCount = PopCount(mask),
                        ActiveMask = mask
                    };
                }

                return (cores, new List<ProcessorGroup>(groups.Values));
            }
            finally
            {
                Marshal.FreeHGlobal(buffer);
            }
        }

        private static CoreInfo ReadProcessorCore(IntPtr basePtr, uint size)
        {
            var header = Marshal.PtrToStructure<SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX>(basePtr);

            IntPtr unionPtr = IntPtr.Add(basePtr, Marshal.SizeOf<LOGICAL_PROCESSOR_RELATIONSHIP>() + sizeof(uint));

            byte flags = Marshal.ReadByte(unionPtr, 0);
            ushort groupCount = (ushort)Marshal.ReadInt16(unionPtr, 24);

            IntPtr gaPtr = IntPtr.Add(unionPtr, 26);

            ushort group = 0;
            ulong mask = 0;

            for (int i = 0; i < groupCount; i++)
            {
                var ga = Marshal.PtrToStructure<GROUP_AFFINITY>(IntPtr.Add(gaPtr, i * Marshal.SizeOf<GROUP_AFFINITY>()));
                group = ga.Group;
                mask |= ga.Mask;
            }

            return new CoreInfo
            {
                GroupNumber = group,
                SmtSiblingMask = mask,
                LogicalCount = PopCount(mask),
                Type = CoreType.Unknown
            };
        }

        private static void ReadGroups(IntPtr basePtr, uint size, Dictionary<ushort, ProcessorGroup> groups)
        {
            IntPtr unionPtr = IntPtr.Add(basePtr, Marshal.SizeOf<LOGICAL_PROCESSOR_RELATIONSHIP>() + sizeof(uint));
            ushort maxGroupCount = (ushort)Marshal.ReadInt16(unionPtr, 0);
            ushort activeGroupCount = (ushort)Marshal.ReadInt16(unionPtr, 2);

            IntPtr infoPtr = IntPtr.Add(unionPtr, 24);

            for (ushort i = 0; i < activeGroupCount; i++)
            {
                var info = Marshal.PtrToStructure<PROCESSOR_GROUP_INFO>(IntPtr.Add(infoPtr, i * Marshal.SizeOf<PROCESSOR_GROUP_INFO>()));
                groups[i] = new ProcessorGroup
                {
                    GroupNumber = i,
                    ActiveProcessorCount = info.ActiveProcessorCount,
                    ActiveMask = info.ActiveProcessorMask
                };
            }
        }


        private static bool TryGetLogicalProcessorEfficiencyClasses(
            List<ProcessorGroup> groups,
            out Dictionary<(ushort group, int bit), byte> effByLp,
            out byte maxEfficiencyClass)
        {
            effByLp = new Dictionary<(ushort group, int bit), byte>();
            maxEfficiencyClass = 0;

            try
            {
                uint len = 0;
                bool ok = GetLogicalProcessorInformationEx(LOGICAL_PROCESSOR_RELATIONSHIP.RelationProcessorCore, IntPtr.Zero, ref len);
                int err = Marshal.GetLastWin32Error();

                if (!ok && err != ERROR_INSUFFICIENT_BUFFER)
                    return false;

                IntPtr buffer = Marshal.AllocHGlobal((int)len);
                try
                {
                    ok = GetLogicalProcessorInformationEx(LOGICAL_PROCESSOR_RELATIONSHIP.RelationProcessorCore, buffer, ref len);
                    if (!ok)
                        return false;

                    IntPtr ptr = buffer;
                    IntPtr end = IntPtr.Add(buffer, (int)len);

                    while (ptr.ToInt64() < end.ToInt64())
                    {
                        var rel = Marshal.PtrToStructure<SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX>(ptr);
                        if (rel.Relationship != LOGICAL_PROCESSOR_RELATIONSHIP.RelationProcessorCore)
                        {
                            ptr = IntPtr.Add(ptr, (int)rel.Size);
                            continue;
                        }

                        IntPtr unionPtr = IntPtr.Add(ptr, Marshal.SizeOf<LOGICAL_PROCESSOR_RELATIONSHIP>() + sizeof(uint));

                        byte eff = Marshal.ReadByte(unionPtr, 1);
                        if (eff > maxEfficiencyClass) maxEfficiencyClass = eff;

                        ushort groupCount = (ushort)Marshal.ReadInt16(unionPtr, 24);
                        IntPtr gaPtr = IntPtr.Add(unionPtr, 26);

                        for (int i = 0; i < groupCount; i++)
                        {
                            var ga = Marshal.PtrToStructure<GROUP_AFFINITY>(IntPtr.Add(gaPtr, i * Marshal.SizeOf<GROUP_AFFINITY>()));
                            foreach (int bit in EnumerateSetBits(ga.Mask))
                            {
                                effByLp[(ga.Group, bit)] = eff;
                            }
                        }

                        ptr = IntPtr.Add(ptr, (int)rel.Size);
                    }

                    return effByLp.Count > 0 && maxEfficiencyClass > 0;
                }
                finally
                {
                    Marshal.FreeHGlobal(buffer);
                }
            }
            catch
            {
                return false;
            }
        }


        private static System.Numerics.BigInteger BuildFlatMask(Dictionary<ushort, ulong> perGroup)
        {
            var mask = System.Numerics.BigInteger.Zero;

            foreach (var kv in perGroup)
            {
                ushort group = kv.Key;
                ulong m = kv.Value;

                int offset = group * 64;
                if (m == 0) continue;

                mask |= (System.Numerics.BigInteger)m << offset;
            }

            return mask;
        }

        private static IEnumerable<int> EnumerateSetBits(ulong mask)
        {
            int bit = 0;
            while (mask != 0)
            {
                if ((mask & 1UL) != 0)
                    yield return bit;

                mask >>= 1;
                bit++;
            }
        }

        private static ulong LowestSetBit(ulong mask)
        {
            return mask & (~mask + 1UL);
        }

        private static int PopCount(ulong mask)
        {
            int count = 0;
            while (mask != 0)
            {
                mask &= (mask - 1);
                count++;
            }
            return count;
        }


        private const int ERROR_INSUFFICIENT_BUFFER = 122;

        private enum LOGICAL_PROCESSOR_RELATIONSHIP : int
        {
            RelationProcessorCore = 0,
            RelationNumaNode = 1,
            RelationCache = 2,
            RelationProcessorPackage = 3,
            RelationGroup = 4,
            RelationProcessorDie = 5,
            RelationNumaNodeEx = 6,
            RelationProcessorModule = 7,
            RelationAll = 0xFFFF
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX
        {
            public LOGICAL_PROCESSOR_RELATIONSHIP Relationship;
            public uint Size;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct GROUP_AFFINITY
        {
            public ulong Mask;
            public ushort Group;
            public ushort Reserved0;
            public ushort Reserved1;
            public ushort Reserved2;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct PROCESSOR_GROUP_INFO
        {
            public byte MaximumProcessorCount;
            public byte ActiveProcessorCount;
            public ushort Reserved;
            public uint ActiveProcessorMaskLow;
            public uint ActiveProcessorMaskHigh;
            public ulong ActiveProcessorMask;
        }

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool GetLogicalProcessorInformationEx(
            LOGICAL_PROCESSOR_RELATIONSHIP relationshipType,
            IntPtr buffer,
            ref uint returnedLength);
    }
}
