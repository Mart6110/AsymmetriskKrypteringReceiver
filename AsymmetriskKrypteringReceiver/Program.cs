using System;
using System.Diagnostics;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace AsymmetricEncryptionReceiver
{
    internal class Program
    {
        static void Main(string[] args)
        {
            bool continueLoop = true;

            while (continueLoop)
            {
                Console.WriteLine("Choose an option:");
                Console.WriteLine("1. Decrypt received data (existing functionality)");
                Console.WriteLine("2. Evaluate RSA operation time costs");
                Console.WriteLine("3. Exit");

                int option;
                if (!int.TryParse(Console.ReadLine(), out option))
                {
                    Console.WriteLine("Invalid option. Please try again.");
                    continue;
                }

                switch (option)
                {
                    case 1:
                        DecryptReceivedData();
                        break;
                    case 2:
                        EvaluateRSAOperations();
                        break;
                    case 3:
                        continueLoop = false;
                        break;
                    default:
                        Console.WriteLine("Invalid option. Please try again.");
                        break;
                }
            }
        }

        static void DecryptReceivedData()
        {
            using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider())
            {
                Console.WriteLine("Public key (Exponent): " + FormatColor(ConsoleColor.Green, BitConverter.ToString(rsa.ExportParameters(false).Exponent)));
                Console.WriteLine("Public key (Modulus): " + FormatColor(ConsoleColor.Green, BitConverter.ToString(rsa.ExportParameters(false).Modulus)));

                Console.WriteLine("Enter encrypted data: ");
                string encryptedData = Console.ReadLine();
                byte[] encryptedBytes = encryptedData.Split('-').Select(s => Convert.ToByte(s, 16)).ToArray();
                byte[] decryptedBytes = rsa.Decrypt(encryptedBytes, false);
                string decryptedText = Encoding.UTF8.GetString(decryptedBytes);
                Console.WriteLine("Decrypted data: " + decryptedText);
            }
        }

        static void EvaluateRSAOperations()
        {
            Console.WriteLine("Time Cost for RSA Operations:");
            Console.WriteLine("--------------------------------------------------------------------------------");
            Console.WriteLine("| Key Size | Key Generation | Encryption | Decryption | Signing | Verification |");
            Console.WriteLine("--------------------------------------------------------------------------------");

            int[] keySizes = { 1024, 2048, 3072, 4096 };

            foreach (int keySize in keySizes)
            {
                using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider(keySize))
                {
                    long totalKeyGenerationTime = 0;
                    long totalEncryptionTime = 0;
                    long totalDecryptionTime = 0;
                    long totalSigningTime = 0;
                    long totalVerificationTime = 0;

                    byte[] messageBytes = Encoding.UTF8.GetBytes("Test Message");

                    for (int i = 0; i < 5000; i++)
                    {
                        Stopwatch keyGenerationTimer = Stopwatch.StartNew();
                        RSAParameters rsaParams = rsa.ExportParameters(true);
                        keyGenerationTimer.Stop();
                        totalKeyGenerationTime += keyGenerationTimer.ElapsedMilliseconds;

                        Stopwatch encryptionTimer = Stopwatch.StartNew();
                        byte[] encryptedBytes = rsa.Encrypt(messageBytes, false);
                        encryptionTimer.Stop();
                        totalEncryptionTime += encryptionTimer.ElapsedMilliseconds;

                        Stopwatch decryptionTimer = Stopwatch.StartNew();
                        byte[] decryptedBytes = rsa.Decrypt(encryptedBytes, false);
                        decryptionTimer.Stop();
                        totalDecryptionTime += decryptionTimer.ElapsedMilliseconds;

                        Stopwatch signingTimer = Stopwatch.StartNew();
                        byte[] signature = rsa.SignData(messageBytes, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
                        signingTimer.Stop();
                        totalSigningTime += signingTimer.ElapsedMilliseconds;

                        Stopwatch verificationTimer = Stopwatch.StartNew();
                        bool verified = rsa.VerifyData(messageBytes, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
                        verificationTimer.Stop();
                        totalVerificationTime += verificationTimer.ElapsedMilliseconds;
                    }

                    Console.WriteLine($"| {keySize} bits   | {FormatColor(ConsoleColor.Cyan, totalKeyGenerationTime.ToString().PadLeft(10))} ms | {FormatColor(ConsoleColor.Cyan, totalEncryptionTime.ToString().PadLeft(10))} ms | {FormatColor(ConsoleColor.Cyan, totalDecryptionTime.ToString().PadLeft(11))} ms | {FormatColor(ConsoleColor.Cyan, totalSigningTime.ToString().PadLeft(8))} ms | {FormatColor(ConsoleColor.Cyan, totalVerificationTime.ToString().PadLeft(12))} ms |");
                }
            }

            Console.WriteLine("--------------------------------------------------------------------------------");
        }

        // Method to format text with color
        static string FormatColor(ConsoleColor color, string text)
        {
            return $"\u001b[38;5;{(int)color}m{text}ms\u001b[0m"; // ANSI escape code for text color
        }
    }
}
