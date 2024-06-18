using System.Security.Cryptography;
using System.Threading;

public static class Utility
{
    public static void RandomDelay()
    {
        Random rnd = new Random();
        int delay = rnd.Next(1000, 5000); // Delay between 1 and 5 seconds
        Thread.Sleep(delay);
    }

    public static byte[] GenerateRandomBytes(int length)
    {
        byte[] randomBytes = new byte[length];
        using (RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider())
        {
            rng.GetBytes(randomBytes);
        }
        return randomBytes;
    }

    public static bool VerifyIntegrity(string filePath, byte[] expectedHash)
    {
        using (SHA256 sha256 = SHA256.Create())
        {
            using (FileStream fileStream = File.OpenRead(filePath))
            {
                byte[] fileHash = sha256.ComputeHash(fileStream);
                return fileHash.SequenceEqual(expectedHash);
            }
        }
    }

    public static bool IsRunningInVirtualMachine()
    {
        return SystemInformation.GetSystemMetrics(0x1000) != 0; // Проверка на наличие Hypervisor
    }
}
