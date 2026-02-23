using System;
using System.Runtime.InteropServices;

namespace DARKSTAR.Core
{
    public static class KernelDriverInterface
    {
        // Custom Darkstar driver IOCTL codes (must match darkstar_driver.c)
        private const uint DARKSTAR_DEVICE_TYPE = 0x8000;
        private static uint DARKSTAR_CTL_CODE(uint function) =>
            ((DARKSTAR_DEVICE_TYPE << 16) | (0 << 14) | (function << 2) | 0);

        private static readonly uint IOCTL_SET_THREAD_PRIORITY       = DARKSTAR_CTL_CODE(0x800);
        private static readonly uint IOCTL_SET_THREAD_AFFINITY        = DARKSTAR_CTL_CODE(0x801);
        private static readonly uint IOCTL_SET_PROCESS_PRIORITY       = DARKSTAR_CTL_CODE(0x802);
        private static readonly uint IOCTL_SET_PROCESS_IO_PRIORITY    = DARKSTAR_CTL_CODE(0x803);
        private static readonly uint IOCTL_SET_PROCESS_PAGE_PRIORITY  = DARKSTAR_CTL_CODE(0x804);
        private static readonly uint IOCTL_SET_THREAD_IDEAL_PROCESSOR = DARKSTAR_CTL_CODE(0x805);
        private static readonly uint IOCTL_BOOST_THREAD               = DARKSTAR_CTL_CODE(0x806);
        private static readonly uint IOCTL_SET_DPC_CORE0_LOCK          = DARKSTAR_CTL_CODE(0x807);

        #region Input Structures (must match driver definitions)

        [StructLayout(LayoutKind.Sequential)]
        private struct SET_THREAD_PRIORITY_INPUT
        {
            public uint ThreadId;
            public int Priority;
            public byte Permanent;   // BOOLEAN: 1 = disable dynamic boost
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct SET_THREAD_AFFINITY_INPUT
        {
            public uint ThreadId;
            public UIntPtr AffinityMask;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct SET_PROCESS_PRIORITY_INPUT
        {
            public uint ProcessId;
            public byte PriorityClass;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct SET_PROCESS_IO_PRIORITY_INPUT
        {
            public uint ProcessId;
            public int IoPriority;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct SET_PROCESS_PAGE_PRIORITY_INPUT
        {
            public uint ProcessId;
            public int PagePriority;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct SET_IDEAL_PROCESSOR_INPUT
        {
            public uint ThreadId;
            public byte IdealProcessor;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct BOOST_THREAD_INPUT
        {
            public uint ThreadId;
            public byte BoostAmount;     // 0-15
            public uint DurationMs;      // Max 5000ms
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct SET_DPC_CORE0_LOCK_INPUT
        {
            public byte Enabled;
            public uint Reserved;
        }

        #endregion

        #region P/Invoke

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern IntPtr CreateFile(
            string lpFileName,
            uint dwDesiredAccess,
            uint dwShareMode,
            IntPtr lpSecurityAttributes,
            uint dwCreationDisposition,
            uint dwFlagsAndAttributes,
            IntPtr hTemplateFile);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool DeviceIoControl(
            IntPtr hDevice,
            uint dwIoControlCode,
            IntPtr lpInBuffer,
            uint nInBufferSize,
            IntPtr lpOutBuffer,
            uint nOutBufferSize,
            out uint lpBytesReturned,
            IntPtr lpOverlapped);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool CloseHandle(IntPtr hObject);

        private const uint GENERIC_READ = 0x80000000;
        private const uint GENERIC_WRITE = 0x40000000;
        private const uint FILE_SHARE_READ = 0x00000001;
        private const uint FILE_SHARE_WRITE = 0x00000002;
        private const uint OPEN_EXISTING = 3;
        private const uint FILE_ATTRIBUTE_NORMAL = 0x80;
        private static readonly IntPtr INVALID_HANDLE_VALUE = new IntPtr(-1);

        #endregion

        #region State

        private static IntPtr _driverHandle = IntPtr.Zero;
        private static bool _isAvailable = false;
        private static string _driverVersion = "Unknown";

        public static bool IsAvailable => _isAvailable;
        public static string DriverVersion => _driverVersion;
        public static bool IsPplBypassAvailable => _isAvailable;

        #endregion

        /// <summary>
        /// Initialize connection to the Darkstar kernel driver.
        /// </summary>
        public static bool Initialize()
        {
            Logger.WriteVerbose("=== Darkstar Kernel Driver Detection ===", ConsoleColor.Cyan);

            string devicePath = "\\\\.\\DarkstarDriver";
            Logger.WriteVerbose($"Attempting connection to Darkstar driver: {devicePath}", ConsoleColor.Cyan);

            IntPtr handle = CreateFile(
                devicePath,
                GENERIC_READ | GENERIC_WRITE,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                IntPtr.Zero,
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL,
                IntPtr.Zero);

            if (handle != INVALID_HANDLE_VALUE && handle != IntPtr.Zero)
            {
                _driverHandle = handle;
                _driverVersion = "DarkstarDriver";
                _isAvailable = true;

                Logger.WriteMinimal("Darkstar kernel driver connected", ConsoleColor.Green);
                Logger.WriteMinimal("  Thread priority and affinity modifications will use kernel mode", ConsoleColor.Cyan);
                Logger.WriteVerbose("=== End Kernel Driver Detection ===", ConsoleColor.Cyan);
                return true;
            }

            int error = Marshal.GetLastWin32Error();
            Logger.WriteVerbose($"  Darkstar driver not available: Win32 error {error}", ConsoleColor.DarkGray);
            Logger.WriteMinimal("Kernel driver not available - using user-mode (limited on protected processes)", ConsoleColor.Yellow);
            Logger.WriteVerbose("=== End Kernel Driver Detection ===", ConsoleColor.Cyan);
            return false;
        }

        public static void Shutdown()
        {
            if (_driverHandle != IntPtr.Zero && _driverHandle != INVALID_HANDLE_VALUE)
            {
                CloseHandle(_driverHandle);
                _driverHandle = IntPtr.Zero;
            }
            _isAvailable = false;
        }

        #region Thread Operations

        /// <summary>
        /// Set thread priority via kernel driver.
        /// </summary>
        public static bool SetThreadPriority(int threadId, int priority, bool permanent = false)
        {
            if (!_isAvailable || _driverHandle == IntPtr.Zero)
                return false;

            var input = new SET_THREAD_PRIORITY_INPUT
            {
                ThreadId = (uint)threadId,
                Priority = priority,
                Permanent = (byte)(permanent ? 1 : 0)
            };

            return SendIoctl(IOCTL_SET_THREAD_PRIORITY, ref input, "SetThreadPriority");
        }

        /// <summary>
        /// Set thread affinity mask via kernel driver.
        /// </summary>
        public static bool SetThreadAffinity(int threadId, IntPtr affinityMask)
        {
            if (!_isAvailable || _driverHandle == IntPtr.Zero)
                return false;

            var input = new SET_THREAD_AFFINITY_INPUT
            {
                ThreadId = (uint)threadId,
                AffinityMask = (UIntPtr)(ulong)affinityMask
            };

            return SendIoctl(IOCTL_SET_THREAD_AFFINITY, ref input, "SetThreadAffinity");
        }

        /// <summary>
        /// Set the ideal processor for a thread (scheduler hint for core placement).
        /// </summary>
        public static bool SetThreadIdealProcessor(int threadId, byte idealProcessor)
        {
            if (!_isAvailable || _driverHandle == IntPtr.Zero)
                return false;

            var input = new SET_IDEAL_PROCESSOR_INPUT
            {
                ThreadId = (uint)threadId,
                IdealProcessor = idealProcessor
            };

            return SendIoctl(IOCTL_SET_THREAD_IDEAL_PROCESSOR, ref input, "SetThreadIdealProcessor");
        }

        /// <summary>
        /// Temporarily boost a thread's priority for a specified duration.
        /// The driver automatically restores the original priority when the timer expires.
        /// </summary>
        /// <param name="threadId">Target thread ID</param>
        /// <param name="boostAmount">Priority boost amount (0-15)</param>
        /// <param name="durationMs">Duration in milliseconds (max 5000)</param>
        public static bool BoostThread(int threadId, int boostAmount, int durationMs)
        {
            if (!_isAvailable || _driverHandle == IntPtr.Zero)
                return false;

            if (boostAmount < 0 || boostAmount > 15 || durationMs <= 0 || durationMs > 5000)
            {
                Logger.WriteVerbose($"[DARKSTAR] BoostThread invalid params: amount={boostAmount}, duration={durationMs}", ConsoleColor.Yellow);
                return false;
            }

            var input = new BOOST_THREAD_INPUT
            {
                ThreadId = (uint)threadId,
                BoostAmount = (byte)boostAmount,
                DurationMs = (uint)durationMs
            };

            return SendIoctl(IOCTL_BOOST_THREAD, ref input, "BoostThread");
        }


        /// <summary>
        /// Enable or disable experimental DPC Core0 lock behavior in the kernel driver.
        /// </summary>
        public static bool SetDpcCore0Lock(bool enabled)
        {
            if (!_isAvailable || _driverHandle == IntPtr.Zero)
                return false;

            var input = new SET_DPC_CORE0_LOCK_INPUT
            {
                Enabled = enabled ? (byte)1 : (byte)0,
                Reserved = 0
            };

            return SendIoctl(IOCTL_SET_DPC_CORE0_LOCK, ref input, "SetDpcCore0Lock");
        }

        #endregion

        #region Process Operations

        /// <summary>
        /// Set process priority class via kernel driver.
        /// </summary>
        public static bool SetProcessPriority(uint processId, byte priorityClass)
        {
            if (!_isAvailable || _driverHandle == IntPtr.Zero)
                return false;

            var input = new SET_PROCESS_PRIORITY_INPUT
            {
                ProcessId = processId,
                PriorityClass = priorityClass
            };

            return SendIoctl(IOCTL_SET_PROCESS_PRIORITY, ref input, "SetProcessPriority");
        }

        /// <summary>
        /// Compatibility wrapper used by optimizer code paths that target the
        /// shared-memory Darkstar implementation.
        /// </summary>
        public static bool SetProcessPriorityDarkstar(uint processId, byte priorityClass)
        {
            return SetProcessPriority(processId, priorityClass);
        }

        /// <summary>
        /// Set process I/O priority via kernel driver.
        /// Values: 0=VeryLow, 1=Low, 2=Normal, 3=High, 4=Critical
        /// </summary>
        public static bool SetProcessIoPriority(uint processId, int ioPriority)
        {
            if (!_isAvailable || _driverHandle == IntPtr.Zero)
                return false;

            var input = new SET_PROCESS_IO_PRIORITY_INPUT
            {
                ProcessId = processId,
                IoPriority = ioPriority
            };

            return SendIoctl(IOCTL_SET_PROCESS_IO_PRIORITY, ref input, "SetProcessIoPriority");
        }

        /// <summary>
        /// Set process page priority via kernel driver.
        /// Values: 0=Lowest, 1=VeryLow, 2=Low, 3=Medium, 4=BelowNormal, 5=Normal
        /// </summary>
        public static bool SetProcessPagePriority(uint processId, int pagePriority)
        {
            if (!_isAvailable || _driverHandle == IntPtr.Zero)
                return false;

            var input = new SET_PROCESS_PAGE_PRIORITY_INPUT
            {
                ProcessId = processId,
                PagePriority = pagePriority
            };

            return SendIoctl(IOCTL_SET_PROCESS_PAGE_PRIORITY, ref input, "SetProcessPagePriority");
        }

        #endregion

        #region IOCTL Helper

        private static bool SendIoctl<T>(uint ioctlCode, ref T input, string operationName) where T : struct
        {
            int size = Marshal.SizeOf<T>();
            IntPtr inputPtr = Marshal.AllocHGlobal(size);
            try
            {
                Marshal.StructureToPtr(input, inputPtr, false);

                bool success = DeviceIoControl(
                    _driverHandle,
                    ioctlCode,
                    inputPtr,
                    (uint)size,
                    IntPtr.Zero,
                    0,
                    out uint bytesReturned,
                    IntPtr.Zero);

                if (!success)
                {
                    int error = Marshal.GetLastWin32Error();
                    Logger.WriteVerbose($"[DARKSTAR] {operationName} failed: Win32 error {error}", ConsoleColor.DarkGray);
                }

                return success;
            }
            finally
            {
                Marshal.FreeHGlobal(inputPtr);
            }
        }

        #endregion
    }
}
