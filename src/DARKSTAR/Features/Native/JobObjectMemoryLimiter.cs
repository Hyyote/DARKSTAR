using System;
using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;

namespace DARKSTAR.Features.Native
{
    public sealed class JobObjectMemoryLimiter : IDisposable
    {
        private IntPtr _jobHandle;
        private bool _disposed;

        public JobObjectMemoryLimiter(string? name = null)
        {
            _jobHandle = CreateJobObject(IntPtr.Zero, name);
            if (_jobHandle == IntPtr.Zero)
                throw new Win32Exception(Marshal.GetLastWin32Error(), "CreateJobObject failed.");
        }

        public void SetProcessMemoryLimitBytes(ulong bytes, bool killOnJobClose = true)
        {
            if (bytes == 0) throw new ArgumentOutOfRangeException(nameof(bytes), "bytes must be > 0");
            EnsureNotDisposed();

            var info = new JOBOBJECT_EXTENDED_LIMIT_INFORMATION();
            info.BasicLimitInformation.LimitFlags = JOBOBJECT_LIMIT_FLAGS.JOB_OBJECT_LIMIT_PROCESS_MEMORY;

            if (killOnJobClose)
                info.BasicLimitInformation.LimitFlags |= JOBOBJECT_LIMIT_FLAGS.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;

            info.ProcessMemoryLimit = new UIntPtr(bytes);

            SetExtendedLimitInfo(info);
        }

        public void SetJobMemoryLimitBytes(ulong bytes, bool killOnJobClose = true)
        {
            if (bytes == 0) throw new ArgumentOutOfRangeException(nameof(bytes), "bytes must be > 0");
            EnsureNotDisposed();

            var info = new JOBOBJECT_EXTENDED_LIMIT_INFORMATION();
            info.BasicLimitInformation.LimitFlags = JOBOBJECT_LIMIT_FLAGS.JOB_OBJECT_LIMIT_JOB_MEMORY;

            if (killOnJobClose)
                info.BasicLimitInformation.LimitFlags |= JOBOBJECT_LIMIT_FLAGS.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;

            info.JobMemoryLimit = new UIntPtr(bytes);

            SetExtendedLimitInfo(info);
        }

        public void Assign(Process process)
        {
            EnsureNotDisposed();
            if (process == null) throw new ArgumentNullException(nameof(process));

            bool ok = AssignProcessToJobObject(_jobHandle, process.Handle);
            if (!ok)
                throw new Win32Exception(Marshal.GetLastWin32Error(), "AssignProcessToJobObject failed.");
        }

        public Process LaunchInJob(ProcessStartInfo psi)
        {
            EnsureNotDisposed();
            if (psi == null) throw new ArgumentNullException(nameof(psi));

            psi.UseShellExecute = false;

            string fileName = psi.FileName ?? "";
            if (string.IsNullOrWhiteSpace(fileName))
                throw new ArgumentException("ProcessStartInfo.FileName is required.", nameof(psi));

            string? workingDir = psi.WorkingDirectory;
            if (string.IsNullOrWhiteSpace(workingDir))
                workingDir = null;

            string args = psi.Arguments ?? "";
            string commandLine = string.IsNullOrWhiteSpace(args)
                ? Quote(fileName)
                : Quote(fileName) + " " + args;

            STARTUPINFO si = new STARTUPINFO();
            si.cb = (uint)Marshal.SizeOf<STARTUPINFO>();

            PROCESS_INFORMATION pi = new PROCESS_INFORMATION();

            const uint CREATE_SUSPENDED = 0x00000004;
            const uint CREATE_NO_WINDOW = 0x08000000;

            uint flags = CREATE_SUSPENDED;
            if (psi.CreateNoWindow)
                flags |= CREATE_NO_WINDOW;

            bool ok = CreateProcessW(
                lpApplicationName: null,
                lpCommandLine: commandLine,
                lpProcessAttributes: IntPtr.Zero,
                lpThreadAttributes: IntPtr.Zero,
                bInheritHandles: false,
                dwCreationFlags: flags,
                lpEnvironment: IntPtr.Zero,
                lpCurrentDirectory: workingDir,
                lpStartupInfo: ref si,
                lpProcessInformation: out pi);

            if (!ok)
                throw new Win32Exception(Marshal.GetLastWin32Error(), "CreateProcessW failed.");

            try
            {
                bool assigned = AssignProcessToJobObject(_jobHandle, pi.hProcess);
                if (!assigned)
                    throw new Win32Exception(Marshal.GetLastWin32Error(), "AssignProcessToJobObject failed.");

                uint resume = ResumeThread(pi.hThread);
                if (resume == 0xFFFFFFFF)
                    throw new Win32Exception(Marshal.GetLastWin32Error(), "ResumeThread failed.");

                var p = Process.GetProcessById((int)pi.dwProcessId);
                return p;
            }
            catch
            {
                try
                {
                    TerminateProcess(pi.hProcess, 1);
                }
                catch { }

                throw;
            }
            finally
            {
                if (pi.hThread != IntPtr.Zero) CloseHandle(pi.hThread);
                if (pi.hProcess != IntPtr.Zero) CloseHandle(pi.hProcess);
            }
        }

        private static string Quote(string s)
        {
            if (string.IsNullOrEmpty(s))
                return "\"\"";
            if (s.Contains("\""))
                s = s.Replace("\"", "\\\"");
            if (s.Contains(" ") || s.Contains("\t"))
                return "\"" + s + "\"";
            return s;
        }

        private void SetExtendedLimitInfo(JOBOBJECT_EXTENDED_LIMIT_INFORMATION info)
        {
            int length = Marshal.SizeOf<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>();
            IntPtr ptr = IntPtr.Zero;

            try
            {
                ptr = Marshal.AllocHGlobal(length);
                Marshal.StructureToPtr(info, ptr, fDeleteOld: false);

                bool ok = SetInformationJobObject(
                    _jobHandle,
                    JOBOBJECTINFOCLASS.JobObjectExtendedLimitInformation,
                    ptr,
                    (uint)length);

                if (!ok)
                    throw new Win32Exception(Marshal.GetLastWin32Error(),
                        "SetInformationJobObject(JobObjectExtendedLimitInformation) failed.");
            }
            finally
            {
                if (ptr != IntPtr.Zero)
                    Marshal.FreeHGlobal(ptr);
            }
        }

        private void EnsureNotDisposed()
        {
            if (_disposed)
                throw new ObjectDisposedException(nameof(JobObjectMemoryLimiter));
        }

        public void Dispose()
        {
            if (_disposed) return;
            _disposed = true;

            if (_jobHandle != IntPtr.Zero)
            {
                CloseHandle(_jobHandle);
                _jobHandle = IntPtr.Zero;
            }
        }

        #region P/Invoke

        private enum JOBOBJECTINFOCLASS
        {
            JobObjectExtendedLimitInformation = 9,
        }

        [Flags]
        private enum JOBOBJECT_LIMIT_FLAGS : uint
        {
            JOB_OBJECT_LIMIT_WORKINGSET = 0x00000001,
            JOB_OBJECT_LIMIT_PROCESS_TIME = 0x00000002,
            JOB_OBJECT_LIMIT_JOB_TIME = 0x00000004,
            JOB_OBJECT_LIMIT_ACTIVE_PROCESS = 0x00000008,
            JOB_OBJECT_LIMIT_AFFINITY = 0x00000010,
            JOB_OBJECT_LIMIT_PRIORITY_CLASS = 0x00000020,
            JOB_OBJECT_LIMIT_PRESERVE_JOB_TIME = 0x00000040,
            JOB_OBJECT_LIMIT_SCHEDULING_CLASS = 0x00000080,
            JOB_OBJECT_LIMIT_PROCESS_MEMORY = 0x00000100,
            JOB_OBJECT_LIMIT_JOB_MEMORY = 0x00000200,
            JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION = 0x00000400,
            JOB_OBJECT_LIMIT_BREAKAWAY_OK = 0x00000800,
            JOB_OBJECT_LIMIT_SILENT_BREAKAWAY_OK = 0x00001000,
            JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x00002000,
            JOB_OBJECT_LIMIT_SUBSET_AFFINITY = 0x00004000,
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct IO_COUNTERS
        {
            public ulong ReadOperationCount;
            public ulong WriteOperationCount;
            public ulong OtherOperationCount;
            public ulong ReadTransferCount;
            public ulong WriteTransferCount;
            public ulong OtherTransferCount;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct JOBOBJECT_BASIC_LIMIT_INFORMATION
        {
            public long PerProcessUserTimeLimit;
            public long PerJobUserTimeLimit;
            public JOBOBJECT_LIMIT_FLAGS LimitFlags;
            public UIntPtr MinimumWorkingSetSize;
            public UIntPtr MaximumWorkingSetSize;
            public uint ActiveProcessLimit;
            public UIntPtr Affinity;
            public uint PriorityClass;
            public uint SchedulingClass;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct JOBOBJECT_EXTENDED_LIMIT_INFORMATION
        {
            public JOBOBJECT_BASIC_LIMIT_INFORMATION BasicLimitInformation;
            public IO_COUNTERS IoInfo;
            public UIntPtr ProcessMemoryLimit;
            public UIntPtr JobMemoryLimit;
            public UIntPtr PeakProcessMemoryUsed;
            public UIntPtr PeakJobMemoryUsed;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct STARTUPINFO
        {
            public uint cb;
            public string? lpReserved;
            public string? lpDesktop;
            public string? lpTitle;
            public uint dwX;
            public uint dwY;
            public uint dwXSize;
            public uint dwYSize;
            public uint dwXCountChars;
            public uint dwYCountChars;
            public uint dwFillAttribute;
            public uint dwFlags;
            public short wShowWindow;
            public short cbReserved2;
            public IntPtr lpReserved2;
            public IntPtr hStdInput;
            public IntPtr hStdOutput;
            public IntPtr hStdError;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct PROCESS_INFORMATION
        {
            public IntPtr hProcess;
            public IntPtr hThread;
            public uint dwProcessId;
            public uint dwThreadId;
        }

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern IntPtr CreateJobObject(IntPtr lpJobAttributes, string? lpName);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool SetInformationJobObject(
            IntPtr hJob,
            JOBOBJECTINFOCLASS jobObjectInfoClass,
            IntPtr lpJobObjectInfo,
            uint cbJobObjectInfoLength);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool AssignProcessToJobObject(IntPtr job, IntPtr process);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern bool CreateProcessW(
            string? lpApplicationName,
            string lpCommandLine,
            IntPtr lpProcessAttributes,
            IntPtr lpThreadAttributes,
            bool bInheritHandles,
            uint dwCreationFlags,
            IntPtr lpEnvironment,
            string? lpCurrentDirectory,
            ref STARTUPINFO lpStartupInfo,
            out PROCESS_INFORMATION lpProcessInformation);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern uint ResumeThread(IntPtr hThread);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool TerminateProcess(IntPtr hProcess, uint uExitCode);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool CloseHandle(IntPtr hObject);

        #endregion
    }
}
