using System;
using System.Security.Cryptography;
using System.Text;

// Sample for cryptobom regression testing. .NET encodes the algorithm in the type.
namespace Example
{
    class CryptoSamples
    {
        void Vulnerable()
        {
            // Quantum-vulnerable asymmetric crypto; key size from Create(n)/ctor(n).
            var rsa = RSA.Create(2048);
            var weakRsa = new RSACryptoServiceProvider(1024);
            var ecdsa = ECDsa.Create();
            var ecdh = ECDiffieHellman.Create();
        }

        void WeakAndMisused(Aes aes)
        {
            // Weak / deprecated algorithms and an ECB misuse.
            var md5 = MD5.Create();
            var sha1 = SHA1.Create();
            var des = new DESCryptoServiceProvider();
            var tdes = TripleDES.Create();
            aes.Mode = CipherMode.ECB;
        }

        void HardcodedAndPrng(Aes aes, byte[] external)
        {
            // Hardcoded key and a variable key (the latter must NOT be flagged).
            aes.Key = Encoding.UTF8.GetBytes("hardcoded-demo-key");
            aes.IV = external;

            // Key material from System.Random — flagged via sink taint.
            var r = new Random();
            var buf = new byte[16];
            r.NextBytes(buf);
            aes.Key = buf;

            // RandomNumberGenerator is correct — must NOT be flagged.
            var good = new byte[16];
            RandomNumberGenerator.Fill(good);
            aes.IV = good;
        }

        void StrongOrInventory()
        {
            // Good usage — must NOT be flagged as a problem.
            var aes = Aes.Create();
            var sha256 = SHA256.Create();
        }
    }
}
