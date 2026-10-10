using System;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

internal static class MtkwlanProbe
{
    private const uint GenericRead = 0x80000000;
    private const uint GenericWrite = 0x40000000;
    private const uint OpenExisting = 3;
    private const uint IoctlNdisQueryGlobalStats = 0x00170002;
    private const uint OidMtkSniffer = 0xfffcf01c;

    [DllImport("kernel32.dll", CharSet = CharSet.Ansi, SetLastError = true)]
    private static extern SafeFileHandle CreateFile(
        string name, uint access, uint share, IntPtr security,
        uint creation, uint flags, IntPtr template);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool DeviceIoControl(
        SafeFileHandle device, uint controlCode,
        byte[] input, uint inputLength,
        byte[] output, uint outputLength,
        out uint returned, IntPtr overlapped);

    private static string JsonEscape(string value)
    {
        return value.Replace("\\", "\\\\").Replace("\"", "\\\"")
            .Replace("\r", "\\r").Replace("\n", "\\n");
    }

    public static int Main(string[] args)
    {
        string outputPath = null;
        for (int i = 0; i + 1 < args.Length; i++)
            if (args[i] == "--output") outputPath = args[i + 1];

        int exitCode = 0;
        int win32Error = 0;
        uint bytesReturned = 0;
        uint statusA = 0, statusB = 0, statusC = 0;
        string error = null;
        bool opened = false, queried = false;

        try
        {
            using (SafeFileHandle device = CreateFile(
                @"\\.\MTKWLAN", GenericRead | GenericWrite, 0, IntPtr.Zero,
                OpenExisting, 0, IntPtr.Zero))
            {
                if (device.IsInvalid)
                    throw new Win32Exception(Marshal.GetLastWin32Error(), "CreateFile(\\\\.\\MTKWLAN) failed");
                opened = true;

                byte[] oid = BitConverter.GetBytes(OidMtkSniffer);
                byte[] payload = new byte[0x1c];
                Buffer.BlockCopy(BitConverter.GetBytes((uint)2), 0, payload, 0, 4); // query only
                if (!DeviceIoControl(device, IoctlNdisQueryGlobalStats,
                    oid, (uint)oid.Length, payload, (uint)payload.Length,
                    out bytesReturned, IntPtr.Zero))
                {
                    throw new Win32Exception(Marshal.GetLastWin32Error(), "sniffer status query failed");
                }
                queried = true;
                statusA = BitConverter.ToUInt32(payload, 0x10);
                statusB = BitConverter.ToUInt32(payload, 0x14);
                statusC = BitConverter.ToUInt32(payload, 0x18);
            }
        }
        catch (Win32Exception ex)
        {
            exitCode = 1;
            win32Error = ex.NativeErrorCode;
            error = ex.Message;
        }
        catch (Exception ex)
        {
            exitCode = 1;
            error = ex.ToString();
        }

        string json = string.Format(
            "{{\n  \"schemaVersion\": 1,\n  \"timestampUtc\": \"{0}\",\n" +
            "  \"device\": \"\\\\\\\\.\\\\MTKWLAN\",\n  \"opened\": {1},\n" +
            "  \"operation\": \"query-sniffer-status\",\n  \"oid\": \"0xfffcf01c\",\n" +
            "  \"ioctl\": \"0x00170002\",\n  \"queried\": {2},\n" +
            "  \"bytesReturned\": {3},\n  \"status\": [{4}, {5}, {6}],\n" +
            "  \"win32Error\": {7},\n  \"error\": {8}\n}}",
            DateTime.UtcNow.ToString("o"), opened.ToString().ToLowerInvariant(),
            queried.ToString().ToLowerInvariant(), bytesReturned,
            statusA, statusB, statusC, win32Error,
            error == null ? "null" : "\"" + JsonEscape(error) + "\"");

        Console.WriteLine(json);
        if (outputPath != null)
        {
            Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(outputPath)));
            File.WriteAllText(outputPath, json);
        }
        return exitCode;
    }
}
