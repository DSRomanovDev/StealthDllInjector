using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Threading;

public static class AntiDebugging
{
    [DllImport("kernel32.dll")]
    private static extern bool IsDebuggerPresent();

    [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
    private static extern bool CheckRemoteDebuggerPresent(IntPtr hProcess, ref bool isDebuggerPresent);

    [DllImport("ntdll.dll", SetLastError = true)]
    private static extern int NtQueryInformationProcess(IntPtr processHandle, int processInformationClass, ref int processInformation, int processInformationLength, ref int returnLength);

    [DllImport("kernel32.dll")]
    private static extern void OutputDebugString(string lpOutputString);

    [DllImport("ntdll.dll")]
    private static extern int NtSetInformationThread(IntPtr threadHandle, int threadInformationClass, ref int threadInformation, int threadInformationLength);

    public static void Check()
    {
        if (IsDebugging())
        {
            Environment.FailFast("Debugger detected and application terminated.");
        }

        RandomDelay();
    }

    private static bool IsDebugging()
    {
        return Debugger.IsAttached ||
               TryLaunchDebugger() ||
               IsDebuggerPresent() ||
               IsRemoteDebuggerPresent() ||
               IsBeingDebuggedViaNtQuery() ||
               IsOutputDebugStringBeingHooked() ||
               IsThreadHidingAttemptDetected();
    }

    private static bool TryLaunchDebugger()
    {
        try
        {
            Debugger.Launch();
            return true;
        }
        catch
        {
            return false;
        }
    }

    private static bool IsRemoteDebuggerPresent()
    {
        bool isDebuggerPresent = false;
        return CheckRemoteDebuggerPresent(Process.GetCurrentProcess().Handle, ref isDebuggerPresent) && isDebuggerPresent;
    }

    private static bool IsBeingDebuggedViaNtQuery()
    {
        int isBeingDebugged = 0;
        int returnLength = 0;
        return NtQueryInformationProcess(Process.GetCurrentProcess().Handle, 7, ref isBeingDebugged, sizeof(int), ref returnLength) == 0 && isBeingDebugged == 1;
    }

    private static bool IsOutputDebugStringBeingHooked()
    {
        try
        {
            OutputDebugString("Test");
            return Marshal.GetLastWin32Error() != 0;
        }
        catch
        {
            return true;
        }
    }

    private static bool IsThreadHidingAttemptDetected()
    {
        try
        {
            int hideThreadFromDebugger = 0x11;
            int status = NtSetInformationThread(Process.GetCurrentProcess().MainModule.BaseAddress, 0x11, ref hideThreadFromDebugger, sizeof(int));
            return status != 0;
        }
        catch
        {
            return true;
        }
    }

    private static void RandomDelay()
    {
        Random rnd = new Random();
        int delay = rnd.Next(1000, 5000); // Delay between 1 and 5 seconds
        Thread.Sleep(delay);
    }
}
