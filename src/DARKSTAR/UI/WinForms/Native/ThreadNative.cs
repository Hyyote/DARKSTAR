using System;
using System.ComponentModel;
using System.Runtime.InteropServices;

namespace DARKSTAR.UI.WinForms.Native
{
    internal static class ThreadNative
    {

        public static bool TryGetThreadDescription(int threadId, out string? description, out string? error)
        {
            description = null;
            error = null;

            IntPtr hThread = IntPtr.Zero;
            try
            {
                hThread = OpenThread(ThreadAccess.THREAD_QUERY_LIMITED_INFORMATION, false, (uint)threadId);
                if (hThread == IntPtr.Zero)
                {
                    error = new Win32Exception(Marshal.GetLastWin32Error()).Message;
                    return false;
                }

                int hr = GetThreadDescription(hThread, out IntPtr pDesc);
                if (hr < 0)
                {
                    error = Marshal.GetExceptionForHR(hr)?.Message ?? $"HRESULT 0x{hr:X8}";
                    return false;
                }

                try
                {
                    if (pDesc == IntPtr.Zero)
                    {
                        description = null;
                        return true;
                    }

                    description = Marshal.PtrToStringUni(pDesc);
                    return true;
                }
                finally
                {
                    if (pDesc != IntPtr.Zero)
                        LocalFree(pDesc);
                }
            }
            catch (Exception ex)
            {
                error = ex.Message;
                return false;
            }
            finally
            {
                if (hThread != IntPtr.Zero)
                    CloseHandle(hThread);
            }
        }

        public static bool TryGetWin32StartAddress(int threadId, out ulong startAddress, out string? error)
        {
            startAddress = 0;
            error = null;

            IntPtr hThread = IntPtr.Zero;
            try
            {
                hThread = OpenThread(ThreadAccess.THREAD_QUERY_INFORMATION, false, (uint)threadId);
                if (hThread == IntPtr.Zero)
                {
                    hThread = OpenThread(ThreadAccess.THREAD_QUERY_LIMITED_INFORMATION, false, (uint)threadId);
                }

                if (hThread == IntPtr.Zero)
                {
                    error = new Win32Exception(Marshal.GetLastWin32Error()).Message;
                    return false;
                }

                IntPtr outPtr = IntPtr.Zero;
                uint returnLen = 0;

                int status = NtQueryInformationThread(
                    hThread,
                    THREADINFOCLASS.ThreadQuerySetWin32StartAddress,
                    ref outPtr,
                    (uint)IntPtr.Size,
                    out returnLen);

                if (status != 0)
                {
                    error = $"NtQueryInformationThread failed: 0x{unchecked((uint)status):X8}";
                    return false;
                }

                startAddress = unchecked((ulong)outPtr.ToInt64());
                return true;
            }
            catch (Exception ex)
            {
                error = ex.Message;
                return false;
            }
            finally
            {
                if (hThread != IntPtr.Zero)
                    CloseHandle(hThread);
            }
        }


        [Flags]
        private enum ThreadAccess : uint
        {
            THREAD_QUERY_INFORMATION = 0x0040,
            THREAD_QUERY_LIMITED_INFORMATION = 0x0800,
        }

        private enum THREADINFOCLASS : int
        {
            ThreadQuerySetWin32StartAddress = 9
        }

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr OpenThread(ThreadAccess dwDesiredAccess, bool bInheritHandle, uint dwThreadId);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool CloseHandle(IntPtr hObject);

        [DllImport("kernel32.dll", ExactSpelling = true)]
        private static extern int GetThreadDescription(IntPtr hThread, out IntPtr ppszThreadDescription);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr LocalFree(IntPtr hMem);

        [DllImport("ntdll.dll")]
        private static extern int NtQueryInformationThread(
            IntPtr ThreadHandle,
            THREADINFOCLASS ThreadInformationClass,
            ref IntPtr ThreadInformation,
            uint ThreadInformationLength,
            out uint ReturnLength);
    }
}
