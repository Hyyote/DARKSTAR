using System;
using System.Collections.Generic;
using System.IO;
using Microsoft.Win32;

namespace DARKSTAR.Core.Native
{
    public static class AppPathResolver
    {
        private const string AppPathsSubKey = @"Software\Microsoft\Windows\CurrentVersion\App Paths";

        public static string? ResolveExeFullPath(string exeNameOrBase)
        {
            if (string.IsNullOrWhiteSpace(exeNameOrBase))
                return null;

            string exe = NormalizeExeName(exeNameOrBase);

            foreach (var candidate in EnumerateRegistryCandidates(exe))
            {
                if (File.Exists(candidate))
                    return candidate;
            }

            return null;
        }

        public static bool TryResolveExeFullPathAndAppDirectory(string exeNameOrBase, out string exeFullPath, out string? appDirectory)
        {
            exeFullPath = "";
            appDirectory = null;

            if (string.IsNullOrWhiteSpace(exeNameOrBase))
                return false;

            string exe = NormalizeExeName(exeNameOrBase);

            foreach (var entry in EnumerateRegistryEntries(exe))
            {
                if (File.Exists(entry.exePath))
                {
                    exeFullPath = entry.exePath;

                    if (!string.IsNullOrWhiteSpace(entry.appPathDir) && Directory.Exists(entry.appPathDir))
                        appDirectory = entry.appPathDir;
                    else
                        appDirectory = Path.GetDirectoryName(entry.exePath);

                    return true;
                }
            }

            return false;
        }

        private static string NormalizeExeName(string exeNameOrBase)
        {
            string s = exeNameOrBase.Trim();

            try
            {
                if (s.Contains(Path.DirectorySeparatorChar) || s.Contains(Path.AltDirectorySeparatorChar))
                    s = Path.GetFileName(s);
            }
            catch
            {
            }

            if (!s.EndsWith(".exe", StringComparison.OrdinalIgnoreCase))
                s += ".exe";

            return s;
        }

        private static IEnumerable<string> EnumerateRegistryCandidates(string exe)
        {
            foreach (var entry in EnumerateRegistryEntries(exe))
                yield return entry.exePath;
        }

        private static IEnumerable<(string exePath, string? appPathDir)> EnumerateRegistryEntries(string exe)
        {
            foreach (var e in ReadAppPathKey(Registry.CurrentUser, exe))
                yield return e;

            foreach (var e in ReadAppPathKey(Registry.LocalMachine, exe))
                yield return e;

            foreach (var e in ReadWow6432AppPathKey(Registry.LocalMachine, exe))
                yield return e;
        }

        private static IEnumerable<(string exePath, string? appPathDir)> ReadAppPathKey(RegistryKey root, string exe)
        {
            RegistryKey? key = null;
            try
            {
                key = root.OpenSubKey(Path.Combine(AppPathsSubKey, exe), writable: false);
                if (key == null)
                    yield break;

                string? defaultValue = key.GetValue(null) as string;
                string? pathValue = key.GetValue("Path") as string;

                var exePath = NormalizeExeValue(defaultValue);
                var appDir = NormalizeDirValue(pathValue);

                if (!string.IsNullOrWhiteSpace(exePath))
                    yield return (exePath!, appDir);
            }
            finally
            {
                key?.Dispose();
            }
        }

        private static IEnumerable<(string exePath, string? appPathDir)> ReadWow6432AppPathKey(RegistryKey root, string exe)
        {
            RegistryKey? key = null;
            try
            {
                string wowSubKey = @"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\App Paths";
                key = root.OpenSubKey(Path.Combine(wowSubKey, exe), writable: false);
                if (key == null)
                    yield break;

                string? defaultValue = key.GetValue(null) as string;
                string? pathValue = key.GetValue("Path") as string;

                var exePath = NormalizeExeValue(defaultValue);
                var appDir = NormalizeDirValue(pathValue);

                if (!string.IsNullOrWhiteSpace(exePath))
                    yield return (exePath!, appDir);
            }
            finally
            {
                key?.Dispose();
            }
        }

        private static string? NormalizeExeValue(string? value)
        {
            if (string.IsNullOrWhiteSpace(value))
                return null;

            string s = value.Trim().Trim('"');

            int idx = s.IndexOf(".exe", StringComparison.OrdinalIgnoreCase);
            if (idx >= 0)
            {
                var maybe = s.Substring(0, idx + 4).Trim().Trim('"');
                return maybe;
            }

            return s;
        }

        private static string? NormalizeDirValue(string? value)
        {
            if (string.IsNullOrWhiteSpace(value))
                return null;

            return value.Trim().Trim('"');
        }
    }
}
