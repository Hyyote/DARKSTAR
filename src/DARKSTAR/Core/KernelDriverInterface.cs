using System;
using System.Collections.Generic;
using System.Buffers.Binary;
using System.Linq;
using System.Runtime.InteropServices;
using System.ServiceProcess;

namespace DARKSTAR.Core
{
    public static class KernelDriverInterface
    {
        
        // KPH message details from System Informer (kphmsg.h / kphapi.h) - for filter-based drivers
        private const ushort KPH_MESSAGE_VERSION = 5;
        private const ushort KPH_MESSAGE_MIN_SIZE = 380;
        private const int KPH_MESSAGE_MAX_SIZE = 0x2000;
        private const uint KPH_MSG_OPEN_THREAD = 8;
        private const uint KPH_MSG_SET_INFORMATION_THREAD = 18;
        private const uint KPH_THREAD_PRIORITY = 0;
        private const uint KPH_THREAD_AFFINITY_MASK = 2;
        private const uint THREAD_SET_INFORMATION = 0x0020;
        private const uint THREAD_QUERY_INFORMATION = 0x0040;
        
        // IOCTL codes for KProcessHacker (device-based driver)
        private const uint FILE_DEVICE_KPH = 0x9999;
        private const uint METHOD_NEITHER = 3;
        private const uint FILE_READ_DATA = 1;
        private const uint FILE_WRITE_DATA = 2;
        
        // IOCTL code calculation: CTL_CODE(FILE_DEVICE_KPH, function, METHOD_NEITHER, FILE_READ_DATA | FILE_WRITE_DATA)
        private static uint CTL_CODE(uint DeviceType, uint Function, uint Method, uint Access)
        {
            return ((DeviceType << 16) | (Access << 14) | (Function << 2) | Method);
        }
        
        private static readonly uint KPH_OPENTHREAD = CTL_CODE(FILE_DEVICE_KPH, 0x20, METHOD_NEITHER, FILE_READ_DATA | FILE_WRITE_DATA);
        private static readonly uint KPH_SETINFORMATIONTHREAD = CTL_CODE(FILE_DEVICE_KPH, 0x27, METHOD_NEITHER, FILE_READ_DATA | FILE_WRITE_DATA);
        
        // Thread information classes for KProcessHacker
        private const uint ThreadPriority = 0;
        private const uint ThreadAffinityMask = 4;
        
        // Custom Darkstar driver IOCTL codes
        private const uint DARKSTAR_DEVICE_TYPE = 0x8000;
        private static uint DARKSTAR_CTL_CODE(uint function) => 
            ((DARKSTAR_DEVICE_TYPE << 16) | (0 << 14) | (function << 2) | 0);

        private static readonly uint IOCTL_DARKSTAR_SET_THREAD_PRIORITY = DARKSTAR_CTL_CODE(0x800);
        private static readonly uint IOCTL_DARKSTAR_SET_THREAD_AFFINITY = DARKSTAR_CTL_CODE(0x801);
        private static readonly uint IOCTL_DARKSTAR_SET_PROCESS_PRIORITY = DARKSTAR_CTL_CODE(0x802);

        [StructLayout(LayoutKind.Sequential)]
        private struct DARKSTAR_SET_THREAD_PRIORITY_INPUT
        {
            public uint ThreadId;
            public int Priority;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct DARKSTAR_SET_THREAD_AFFINITY_INPUT
        {
            public uint ThreadId;
            public UIntPtr AffinityMask;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct DARKSTAR_SET_PROCESS_PRIORITY_INPUT
        {
            public uint ProcessId;
            public byte PriorityClass;
        }
        
        // P/Invoke declarations
        [DllImport("psapi.dll", SetLastError = true)]
        private static extern bool EnumDeviceDrivers(
            [Out] IntPtr[] lpImageBase,
            uint cb,
            out uint lpcbNeeded);
            
        [DllImport("psapi.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern uint GetDeviceDriverBaseName(
            IntPtr ImageBase,
            [Out] char[] lpFilename,
            uint nSize);
        
        // Filter-based driver APIs (for System Informer 3.x / KSystemInformer)
        [DllImport("fltlib.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern int FilterConnectCommunicationPort(
            string lpPortName,
            uint dwOptions,
            IntPtr lpContext,
            ushort wSizeOfContext,
            IntPtr lpSecurityAttributes,
            out IntPtr hPort);
        
        [DllImport("fltlib.dll", SetLastError = true)]
        private static extern int FilterSendMessage(
            IntPtr hPort,
            byte[] lpInBuffer,
            uint dwInBufferSize,
            IntPtr lpOutBuffer,
            uint dwOutBufferSize,
            out uint lpBytesReturned);
        
        // Device-based driver APIs (for Process Hacker 2.x / KProcessHacker)
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
        
        // Constants for CreateFile
        private const uint GENERIC_READ = 0x80000000;
        private const uint GENERIC_WRITE = 0x40000000;
        private const uint FILE_SHARE_READ = 0x00000001;
        private const uint FILE_SHARE_WRITE = 0x00000002;
        private const uint OPEN_EXISTING = 3;
        private const uint FILE_ATTRIBUTE_NORMAL = 0x80;
        
        private static readonly IntPtr INVALID_HANDLE_VALUE = new IntPtr(-1);
        
        private static IntPtr _driverHandle = IntPtr.Zero;
        private static bool _isAvailable = false;
        private static string _driverVersion = "Unknown";
        private static string _portName = string.Empty;
        private static bool _isDeviceDriver = false; // true for KProcessHacker, false for KSystemInformer
        private static bool _isDarkstarDriver = false;
        
        public static bool IsAvailable => _isAvailable;
        public static string DriverVersion => _driverVersion;
        
        /// <summary>
        /// Check if PPL bypass is available (Darkstar driver connected)
        /// </summary>
        public static bool IsPplBypassAvailable => _isDarkstarDriver && _isAvailable;
        
        /// <summary>
        /// Enumerate all loaded kernel drivers and find Process Hacker drivers
        /// </summary>
        private static List<string> FindProcessHackerDrivers()
        {
            var drivers = new List<string>();
            
            try
            {
                // Get all loaded kernel drivers
                uint needed = 0;
                EnumDeviceDrivers(null, 0, out needed);
                
                if (needed == 0)
                {
                    Logger.WriteVerbose("Failed to enumerate device drivers", ConsoleColor.Yellow);
                    return drivers;
                }
                
                uint count = needed / (uint)IntPtr.Size;
                IntPtr[] imageBase = new IntPtr[count];
                
                if (!EnumDeviceDrivers(imageBase, needed, out needed))
                {
                    Logger.WriteVerbose($"EnumDeviceDrivers failed: {Marshal.GetLastWin32Error()}", ConsoleColor.Yellow);
                    return drivers;
                }
                
                // Get driver names and filter for Process Hacker
                foreach (IntPtr baseAddr in imageBase)
                {
                    char[] baseName = new char[256];
                    uint ret = GetDeviceDriverBaseName(baseAddr, baseName, (uint)baseName.Length);
                    
                    if (ret > 0)
                    {
                        string driverName = new string(baseName, 0, (int)ret);
                        
                        // Look for Process Hacker driver patterns
                        if (driverName.StartsWith("KProcessHacker", StringComparison.OrdinalIgnoreCase) ||
                            driverName.StartsWith("KSystemInformer", StringComparison.OrdinalIgnoreCase))
                        {
                            drivers.Add(driverName);
                            Logger.WriteVerbose($"Found Process Hacker kernel driver: {driverName}", ConsoleColor.Green);
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Logger.WriteVerbose($"Exception during driver enumeration: {ex.Message}", ConsoleColor.Yellow);
            }
            
            return drivers;
        }
        
        /// <summary>
        /// Find Process Hacker driver services via Service Control Manager
        /// </summary>
        private static List<string> FindProcessHackerServices()
        {
            var services = new List<string>();
            
            try
            {
                var allServices = ServiceController.GetDevices();
                
                foreach (var service in allServices)
                {
                    string name = service.ServiceName;
                    
                    if (name.StartsWith("KProcessHacker", StringComparison.OrdinalIgnoreCase) ||
                        name.StartsWith("KSystemInformer", StringComparison.OrdinalIgnoreCase))
                    {
                        if (service.Status == ServiceControllerStatus.Running)
                        {
                            services.Add(name);
                            Logger.WriteVerbose($"Found running driver service: {name}", ConsoleColor.Green);
                        }
                        else
                        {
                            Logger.WriteVerbose($"Found stopped driver service: {name} (status: {service.Status})", ConsoleColor.DarkGray);
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Logger.WriteVerbose($"Exception during service enumeration: {ex.Message}", ConsoleColor.Yellow);
            }
            
            return services;
        }
        
        /// <summary>
        /// Try to connect to the custom Darkstar kernel driver (bypasses PPL)
        /// </summary>
        private static bool TryConnectDarkstarDriver()
        {
            string devicePath = "\\\\.\\DarkstarDriver";
            Logger.WriteVerbose($"Attempting connection to custom Darkstar driver: {devicePath}", ConsoleColor.Cyan);
            
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
                _driverVersion = "DarkstarDriver (PPL Bypass)";
                _portName = devicePath;
                _isAvailable = true;
                _isDeviceDriver = true;
                _isDarkstarDriver = true;
                
                Logger.WriteMinimal($"✓ Darkstar kernel driver connected (PPL bypass enabled)", ConsoleColor.Green);
                return true;
            }
            
            int error = Marshal.GetLastWin32Error();
            Logger.WriteVerbose($"  Darkstar driver not available: Win32 error {error}", ConsoleColor.DarkGray);
            return false;
        }
        
        /// <summary>
        /// Build filter port name variations from a driver name
        /// </summary>
        private static IEnumerable<string> BuildPortNameVariations(string driverName)
        {
            // Remove .sys extension if present
            string baseName = driverName.EndsWith(".sys", StringComparison.OrdinalIgnoreCase) 
                ? driverName.Substring(0, driverName.Length - 4) 
                : driverName;
            
            // Try primary port name format
            yield return $"\\{baseName}";
            
            // Ensure we try known port names for Process Hacker/System Informer
            if (baseName.StartsWith("KProcessHacker", StringComparison.OrdinalIgnoreCase))
            {
                yield return "\\KProcessHacker";
            }
            if (baseName.StartsWith("KSystemInformer", StringComparison.OrdinalIgnoreCase))
            {
                yield return "\\KSystemInformer";
            }
        }
        
        /// <summary>
        /// Initialize connection to kernel driver
        /// </summary>
        public static bool Initialize()
        {
            Logger.WriteVerbose("=== Dynamic Kernel Driver Detection ===", ConsoleColor.Cyan);
            
            // Try custom Darkstar driver first (has PPL bypass capability)
            if (TryConnectDarkstarDriver())
            {
                Logger.WriteVerbose("=== End Kernel Driver Detection ===", ConsoleColor.Cyan);
                return true;
            }
            
            // Method 1: Enumerate loaded drivers directly
            var loadedDrivers = FindProcessHackerDrivers();
            
            // Method 2: Query running services
            var runningServices = FindProcessHackerServices();
            
            // Combine both methods
            var candidateNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            candidateNames.UnionWith(loadedDrivers);
            candidateNames.UnionWith(runningServices);
            
            if (candidateNames.Count == 0)
            {
                Logger.WriteVerbose("No kernel driver names detected; trying default names", ConsoleColor.Yellow);
                candidateNames.Add("KSystemInformer");
                candidateNames.Add("KProcessHacker3");
                candidateNames.Add("KProcessHacker");
            }
            else
            {
                Logger.WriteVerbose($"Found {candidateNames.Count} Process Hacker driver candidate(s)", ConsoleColor.Cyan);
            }

            // Try each candidate - first as device driver (KProcessHacker), then as filter driver (KSystemInformer)
            foreach (var driverName in candidateNames)
            {
                // Attempt device driver connection (Process Hacker 2.x)
                if (TryConnectDeviceDriver(driverName))
                {
                    _driverVersion = driverName;
                    _portName = $"\\\\.\\{driverName}";
                    _isAvailable = true;
                    _isDeviceDriver = true;

                    Logger.WriteMinimal($"✓ Kernel driver connected: {_driverVersion}", ConsoleColor.Green);
                    Logger.WriteMinimal($"  Device path: {_portName}", ConsoleColor.Cyan);
                    Logger.WriteMinimal($"  Driver type: Device-based (Process Hacker 2.x)", ConsoleColor.Cyan);
                    Logger.WriteVerbose("=== End Kernel Driver Detection ===", ConsoleColor.Cyan);
                    return true;
                }
                
                // Attempt filter port connection (System Informer 3.x)
                foreach (var portName in BuildPortNameVariations(driverName))
                {
                    Logger.WriteVerbose($"Attempting connection to kernel port: {portName}", ConsoleColor.Cyan);
                    _driverHandle = TryConnectFilterPort(portName);
                    if (_driverHandle != IntPtr.Zero && _driverHandle != INVALID_HANDLE_VALUE)
                    {
                        _driverVersion = driverName;
                        _portName = portName;
                        _isAvailable = true;
                        _isDeviceDriver = false;

                        Logger.WriteMinimal($"✓ Kernel driver connected: {_driverVersion}", ConsoleColor.Green);
                        Logger.WriteMinimal($"  Port name: {portName}", ConsoleColor.Cyan);
                        Logger.WriteMinimal($"  Driver type: Filter-based (System Informer 3.x)", ConsoleColor.Cyan);
                        Logger.WriteVerbose("=== End Kernel Driver Detection ===", ConsoleColor.Cyan);
                        return true;
                    }
                }
            }

            Logger.WriteColored("✗ Failed to connect to Process Hacker kernel port", ConsoleColor.Yellow);
            Logger.WriteVerbose("  Ensure the driver is loaded and kernel mode is enabled", ConsoleColor.Yellow);
            Logger.WriteVerbose("=== End Kernel Driver Detection ===", ConsoleColor.Cyan);

            return false;
        }
        
        /// <summary>
        /// Try to connect to a kernel device driver (Process Hacker 2.x style)
        /// </summary>
        private static bool TryConnectDeviceDriver(string driverName)
        {
            // Try different numbering variations for the device name
            // Common variations: 3 (most common for PH 2.39), 0 (fallback), 1-2 (older versions), 50/100 (custom builds)
            int[] variations = { 3, 0, 1, 2, 50, 100 };
            
            foreach (int num in variations)
            {
                string devicePath = $"\\\\.\\{driverName}{num}";
                Logger.WriteVerbose($"  Trying device: {devicePath}", ConsoleColor.DarkCyan);
                
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
                    Logger.WriteVerbose("    ✓ Connected successfully", ConsoleColor.Green);
                    return true;
                }
                
                int error = Marshal.GetLastWin32Error();
                Logger.WriteVerbose($"    Failed: Win32 error {error}", ConsoleColor.DarkGray);
            }
            
            return false;
        }
        
        /// <summary>
        /// Try to connect to a kernel driver filter port (System Informer 3.x style)
        /// </summary>
        private static IntPtr TryConnectFilterPort(string portName)
        {
            Logger.WriteVerbose($"  Trying port: {portName}", ConsoleColor.DarkCyan);

            int result = FilterConnectCommunicationPort(
                portName,
                0,
                IntPtr.Zero,
                0,
                IntPtr.Zero,
                out IntPtr handle);

            if (result != 0 || handle == IntPtr.Zero || handle == INVALID_HANDLE_VALUE)
            {
                int error = Marshal.GetLastWin32Error();
                Logger.WriteVerbose($"    Failed: HRESULT 0x{result:X8} (Win32 {error})", ConsoleColor.DarkGray);
                return IntPtr.Zero;
            }

            Logger.WriteVerbose("    ✓ Connected successfully", ConsoleColor.Green);
            return handle;
        }
        
        /// <summary>
        /// Set thread priority via kernel driver
        /// </summary>
        public static bool SetThreadPriority(int threadId, int priority)
        {
            if (!_isAvailable) return false;
            
            // Prefer Darkstar driver for PPL bypass
            if (_isDarkstarDriver)
            {
                return SetThreadPriorityDarkstar((uint)threadId, priority);
            }
            
            if (_isDeviceDriver)
            {
                return SetThreadInformationDevice(threadId, ThreadPriority, priority, sizeof(int));
            }
            else
            {
                return SetThreadInformation(threadId, KPH_THREAD_PRIORITY, priority, sizeof(int));
            }
        }
        
        /// <summary>
        /// Set thread affinity via kernel driver
        /// </summary>
        public static bool SetThreadAffinity(int threadId, IntPtr affinityMask)
        {
            if (!_isAvailable) return false;
            
            // Prefer Darkstar driver for PPL bypass
            if (_isDarkstarDriver)
            {
                return SetThreadAffinityDarkstar((uint)threadId, (UIntPtr)(ulong)affinityMask);
            }
            
            if (_isDeviceDriver)
            {
                return SetThreadInformationDevice(threadId, ThreadAffinityMask, affinityMask, IntPtr.Size);
            }
            else
            {
                return SetThreadInformation(threadId, KPH_THREAD_AFFINITY_MASK, affinityMask, IntPtr.Size);
            }
        }
        
        /// <summary>
        /// Open a thread handle with full access via kernel driver
        /// </summary>
        public static IntPtr OpenThread(int threadId, uint desiredAccess)
        {
            if (!_isAvailable) return IntPtr.Zero;
            
            if (_isDeviceDriver)
            {
                if (TryOpenThreadHandleDevice(threadId, desiredAccess, out IntPtr threadHandle))
                {
                    return threadHandle;
                }
            }
            else
            {
                if (TryOpenThreadHandle(threadId, desiredAccess, out IntPtr threadHandle))
                {
                    return threadHandle;
                }
            }

            return IntPtr.Zero;
        }
        
        /// <summary>
        /// Set thread priority via Darkstar driver (bypasses all PPL protection)
        /// </summary>
        public static bool SetThreadPriorityDarkstar(uint threadId, int priority)
        {
            if (!_isAvailable || !_isDarkstarDriver || _driverHandle == IntPtr.Zero) 
                return false;
            
            var input = new DARKSTAR_SET_THREAD_PRIORITY_INPUT
            {
                ThreadId = threadId,
                Priority = priority
            };
            
            IntPtr inputPtr = Marshal.AllocHGlobal(Marshal.SizeOf<DARKSTAR_SET_THREAD_PRIORITY_INPUT>());
            try
            {
                Marshal.StructureToPtr(input, inputPtr, false);
                
                bool success = DeviceIoControl(
                    _driverHandle,
                    IOCTL_DARKSTAR_SET_THREAD_PRIORITY,
                    inputPtr,
                    (uint)Marshal.SizeOf<DARKSTAR_SET_THREAD_PRIORITY_INPUT>(),
                    IntPtr.Zero,
                    0,
                    out uint bytesReturned,
                    IntPtr.Zero);
                
                if (!success)
                {
                    int error = Marshal.GetLastWin32Error();
                    Logger.WriteVerbose($"[DARKSTAR] SetThreadPriority failed: Win32 error {error}", ConsoleColor.DarkGray);
                }
                
                return success;
            }
            finally
            {
                Marshal.FreeHGlobal(inputPtr);
            }
        }

        /// <summary>
        /// Set thread affinity via Darkstar driver (bypasses all PPL protection)
        /// </summary>
        public static bool SetThreadAffinityDarkstar(uint threadId, UIntPtr affinityMask)
        {
            if (!_isAvailable || !_isDarkstarDriver || _driverHandle == IntPtr.Zero) 
                return false;
            
            var input = new DARKSTAR_SET_THREAD_AFFINITY_INPUT
            {
                ThreadId = threadId,
                AffinityMask = affinityMask
            };
            
            IntPtr inputPtr = Marshal.AllocHGlobal(Marshal.SizeOf<DARKSTAR_SET_THREAD_AFFINITY_INPUT>());
            try
            {
                Marshal.StructureToPtr(input, inputPtr, false);
                
                bool success = DeviceIoControl(
                    _driverHandle,
                    IOCTL_DARKSTAR_SET_THREAD_AFFINITY,
                    inputPtr,
                    (uint)Marshal.SizeOf<DARKSTAR_SET_THREAD_AFFINITY_INPUT>(),
                    IntPtr.Zero,
                    0,
                    out uint bytesReturned,
                    IntPtr.Zero);
                
                if (!success)
                {
                    int error = Marshal.GetLastWin32Error();
                    Logger.WriteVerbose($"[DARKSTAR] SetThreadAffinity failed: Win32 error {error}", ConsoleColor.DarkGray);
                }
                
                return success;
            }
            finally
            {
                Marshal.FreeHGlobal(inputPtr);
            }
        }

        /// <summary>
        /// Set process priority class via Darkstar driver (bypasses all PPL protection)
        /// </summary>
        public static bool SetProcessPriorityDarkstar(uint processId, byte priorityClass)
        {
            if (!_isAvailable || !_isDarkstarDriver || _driverHandle == IntPtr.Zero) 
                return false;
            
            var input = new DARKSTAR_SET_PROCESS_PRIORITY_INPUT
            {
                ProcessId = processId,
                PriorityClass = priorityClass
            };
            
            IntPtr inputPtr = Marshal.AllocHGlobal(Marshal.SizeOf<DARKSTAR_SET_PROCESS_PRIORITY_INPUT>());
            try
            {
                Marshal.StructureToPtr(input, inputPtr, false);
                
                bool success = DeviceIoControl(
                    _driverHandle,
                    IOCTL_DARKSTAR_SET_PROCESS_PRIORITY,
                    inputPtr,
                    (uint)Marshal.SizeOf<DARKSTAR_SET_PROCESS_PRIORITY_INPUT>(),
                    IntPtr.Zero,
                    0,
                    out uint bytesReturned,
                    IntPtr.Zero);
                
                if (!success)
                {
                    int error = Marshal.GetLastWin32Error();
                    Logger.WriteVerbose($"[DARKSTAR] SetProcessPriority failed: Win32 error {error}", ConsoleColor.DarkGray);
                }
                
                return success;
            }
            finally
            {
                Marshal.FreeHGlobal(inputPtr);
            }
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

        // ======== Device Driver Methods (KProcessHacker) ========
        
        // Structures for IOCTL communication with KProcessHacker
        [StructLayout(LayoutKind.Sequential)]
        private struct KPH_OPEN_THREAD_INPUT
        {
            public IntPtr ProcessHandle;
            public uint DesiredAccess;
            public IntPtr ClientId;  // Pointer to CLIENT_ID structure
        }
        
        [StructLayout(LayoutKind.Sequential)]
        private struct KPH_OPEN_THREAD_OUTPUT
        {
            public IntPtr ThreadHandle;
        }
        
        [StructLayout(LayoutKind.Sequential)]
        private struct KPH_SET_INFORMATION_THREAD_INPUT
        {
            public IntPtr ThreadHandle;
            public uint ThreadInformationClass;
            public IntPtr ThreadInformation;
            public uint ThreadInformationLength;
        }
        
        [StructLayout(LayoutKind.Sequential)]
        private struct CLIENT_ID
        {
            public IntPtr UniqueProcess;
            public IntPtr UniqueThread;
        }
        
        /// <summary>
        /// Open thread handle via device IOCTL (KProcessHacker)
        /// </summary>
        private static bool TryOpenThreadHandleDevice(int threadId, uint desiredAccess, out IntPtr threadHandle)
        {
            threadHandle = IntPtr.Zero;
            
            CLIENT_ID clientId = new CLIENT_ID
            {
                UniqueProcess = IntPtr.Zero,
                UniqueThread = new IntPtr(threadId)
            };
            
            IntPtr clientIdPtr = Marshal.AllocHGlobal(Marshal.SizeOf<CLIENT_ID>());
            IntPtr inputPtr = Marshal.AllocHGlobal(Marshal.SizeOf<KPH_OPEN_THREAD_INPUT>());
            IntPtr outputPtr = Marshal.AllocHGlobal(Marshal.SizeOf<KPH_OPEN_THREAD_OUTPUT>());
            
            try
            {
                Marshal.StructureToPtr(clientId, clientIdPtr, false);
                
                KPH_OPEN_THREAD_INPUT input = new KPH_OPEN_THREAD_INPUT
                {
                    ProcessHandle = IntPtr.Zero,
                    DesiredAccess = desiredAccess,
                    ClientId = clientIdPtr
                };
                
                Marshal.StructureToPtr(input, inputPtr, false);
                
                bool success = DeviceIoControl(
                    _driverHandle,
                    KPH_OPENTHREAD,
                    inputPtr,
                    (uint)Marshal.SizeOf<KPH_OPEN_THREAD_INPUT>(),
                    outputPtr,
                    (uint)Marshal.SizeOf<KPH_OPEN_THREAD_OUTPUT>(),
                    out uint bytesReturned,
                    IntPtr.Zero);
                
                if (!success)
                {
                    int error = Marshal.GetLastWin32Error();
                    Logger.WriteVerbose($"[KERNEL] DeviceIoControl KPH_OPENTHREAD failed: Win32 error {error}", ConsoleColor.DarkGray);
                    return false;
                }
                
                KPH_OPEN_THREAD_OUTPUT output = Marshal.PtrToStructure<KPH_OPEN_THREAD_OUTPUT>(outputPtr);
                threadHandle = output.ThreadHandle;
                return threadHandle != IntPtr.Zero;
            }
            finally
            {
                Marshal.FreeHGlobal(clientIdPtr);
                Marshal.FreeHGlobal(inputPtr);
                Marshal.FreeHGlobal(outputPtr);
            }
        }
        
        /// <summary>
        /// Set thread information via device IOCTL (KProcessHacker)
        /// </summary>
        private static bool SetThreadInformationDevice(int threadId, uint infoClass, int infoValue, int infoLength)
        {
            IntPtr infoBuffer = Marshal.AllocHGlobal(infoLength);
            try
            {
                Marshal.WriteInt32(infoBuffer, infoValue);
                return SetThreadInformationDevice(threadId, infoClass, infoBuffer, infoLength);
            }
            finally
            {
                Marshal.FreeHGlobal(infoBuffer);
            }
        }
        
        private static bool SetThreadInformationDevice(int threadId, uint infoClass, IntPtr infoBuffer, int infoLength)
        {
            IntPtr threadHandle = IntPtr.Zero;
            IntPtr inputPtr = IntPtr.Zero;
            
            try
            {
                if (!TryOpenThreadHandleDevice(threadId, THREAD_SET_INFORMATION | THREAD_QUERY_INFORMATION, out threadHandle))
                {
                    return false;
                }
                
                inputPtr = Marshal.AllocHGlobal(Marshal.SizeOf<KPH_SET_INFORMATION_THREAD_INPUT>());
                
                KPH_SET_INFORMATION_THREAD_INPUT input = new KPH_SET_INFORMATION_THREAD_INPUT
                {
                    ThreadHandle = threadHandle,
                    ThreadInformationClass = infoClass,
                    ThreadInformation = infoBuffer,
                    ThreadInformationLength = (uint)infoLength
                };
                
                Marshal.StructureToPtr(input, inputPtr, false);
                
                bool success = DeviceIoControl(
                    _driverHandle,
                    KPH_SETINFORMATIONTHREAD,
                    inputPtr,
                    (uint)Marshal.SizeOf<KPH_SET_INFORMATION_THREAD_INPUT>(),
                    IntPtr.Zero,
                    0,
                    out uint bytesReturned,
                    IntPtr.Zero);
                
                if (!success)
                {
                    int error = Marshal.GetLastWin32Error();
                    Logger.WriteVerbose($"[KERNEL] DeviceIoControl KPH_SETINFORMATIONTHREAD failed: Win32 error {error}", ConsoleColor.DarkGray);
                    return false;
                }
                
                return true;
            }
            finally
            {
                if (threadHandle != IntPtr.Zero)
                {
                    CloseHandle(threadHandle);
                }
                if (inputPtr != IntPtr.Zero)
                {
                    Marshal.FreeHGlobal(inputPtr);
                }
            }
        }

        // ======== Filter Driver Methods (KSystemInformer) ========

        private static bool SetThreadInformation(int threadId, uint infoClass, int infoValue, int infoLength)
        {
            IntPtr infoBuffer = Marshal.AllocHGlobal(infoLength);
            try
            {
                Marshal.WriteInt32(infoBuffer, infoValue);
                return SetThreadInformation(threadId, infoClass, infoBuffer, infoLength);
            }
            finally
            {
                Marshal.FreeHGlobal(infoBuffer);
            }
        }

        private static bool SetThreadInformation(int threadId, uint infoClass, IntPtr infoBuffer, int infoLength)
        {
            if (!TryOpenThreadHandle(threadId, THREAD_SET_INFORMATION | THREAD_QUERY_INFORMATION, out IntPtr threadHandle))
            {
                return false;
            }

            try
            {
                byte[] message = CreateMessageBuffer(KPH_MSG_SET_INFORMATION_THREAD);
                WritePointer(message, GetSetThreadHandleOffset(), threadHandle);
                WriteUInt32(message, GetSetThreadInfoClassOffset(), infoClass);
                WritePointer(message, GetSetThreadInfoPointerOffset(), infoBuffer);
                WriteUInt32(message, GetSetThreadInfoLengthOffset(), (uint)infoLength);

                if (!SendMessage(message))
                {
                    return false;
                }

                int status = ReadInt32(message, GetSetThreadStatusOffset());
                if (status != 0)
                {
                    Logger.WriteVerbose($"[KERNEL] SetInformationThread failed: 0x{status:X8}", ConsoleColor.DarkGray);
                    return false;
                }

                return true;
            }
            finally
            {
                CloseHandle(threadHandle);
            }
        }

        private static bool TryOpenThreadHandle(int threadId, uint desiredAccess, out IntPtr threadHandle)
        {
            threadHandle = IntPtr.Zero;

            IntPtr handleBuffer = Marshal.AllocHGlobal(IntPtr.Size);
            IntPtr clientIdBuffer = Marshal.AllocHGlobal(IntPtr.Size * 2);

            try
            {
                Marshal.WriteIntPtr(handleBuffer, IntPtr.Zero);
                Marshal.WriteIntPtr(clientIdBuffer, IntPtr.Zero);
                Marshal.WriteIntPtr(clientIdBuffer + IntPtr.Size, new IntPtr(threadId));

                byte[] message = CreateMessageBuffer(KPH_MSG_OPEN_THREAD);
                WritePointer(message, GetOpenThreadHandleOffset(), handleBuffer);
                WriteUInt32(message, GetOpenThreadDesiredAccessOffset(), desiredAccess);
                WritePointer(message, GetOpenThreadClientIdOffset(), clientIdBuffer);

                if (!SendMessage(message))
                {
                    return false;
                }

                int status = ReadInt32(message, GetOpenThreadStatusOffset());
                if (status != 0)
                {
                    Logger.WriteVerbose($"[KERNEL] OpenThread failed: 0x{status:X8}", ConsoleColor.DarkGray);
                    return false;
                }

                threadHandle = Marshal.ReadIntPtr(handleBuffer);
                return threadHandle != IntPtr.Zero;
            }
            finally
            {
                Marshal.FreeHGlobal(handleBuffer);
                Marshal.FreeHGlobal(clientIdBuffer);
            }
        }

        private static bool SendMessage(byte[] message)
        {
            uint bytesReturned;
            int result = FilterSendMessage(_driverHandle, message, KPH_MESSAGE_MIN_SIZE, IntPtr.Zero, 0, out bytesReturned);
            if (result != 0)
            {
                Logger.WriteVerbose($"[KERNEL] FilterSendMessage failed: 0x{result:X8}", ConsoleColor.DarkGray);
                return false;
            }

            return true;
        }

        private static byte[] CreateMessageBuffer(uint messageId)
        {
            byte[] buffer = new byte[KPH_MESSAGE_MAX_SIZE];
            var span = buffer.AsSpan(0, KPH_MESSAGE_MIN_SIZE);
            BinaryPrimitives.WriteUInt16LittleEndian(span.Slice(0, 2), KPH_MESSAGE_VERSION);
            BinaryPrimitives.WriteUInt16LittleEndian(span.Slice(2, 2), KPH_MESSAGE_MIN_SIZE);
            BinaryPrimitives.WriteUInt32LittleEndian(span.Slice(4, 4), messageId);
            long timestamp = DateTime.UtcNow.ToFileTimeUtc();
            BinaryPrimitives.WriteInt64LittleEndian(span.Slice(8, 8), timestamp);
            return buffer;
        }

        private static int GetOpenThreadStatusOffset() => 16;

        private static int GetOpenThreadHandleOffset() => 24;

        private static int GetOpenThreadDesiredAccessOffset() => 32;

        private static int GetOpenThreadClientIdOffset() => 40;

        private static int GetSetThreadStatusOffset() => 16;

        private static int GetSetThreadHandleOffset() => 24;

        private static int GetSetThreadInfoClassOffset() => 32;

        private static int GetSetThreadInfoPointerOffset() => 40;

        private static int GetSetThreadInfoLengthOffset() => 48;

        private static void WritePointer(byte[] buffer, int offset, IntPtr value)
        {
            if (IntPtr.Size == 8)
            {
                BinaryPrimitives.WriteInt64LittleEndian(buffer.AsSpan(offset, 8), value.ToInt64());
            }
            else
            {
                BinaryPrimitives.WriteInt32LittleEndian(buffer.AsSpan(offset, 4), value.ToInt32());
            }
        }

        private static void WriteUInt32(byte[] buffer, int offset, uint value)
        {
            BinaryPrimitives.WriteUInt32LittleEndian(buffer.AsSpan(offset, 4), value);
        }

        private static int ReadInt32(byte[] buffer, int offset)
        {
            return BinaryPrimitives.ReadInt32LittleEndian(buffer.AsSpan(offset, 4));
        }
    }
}
