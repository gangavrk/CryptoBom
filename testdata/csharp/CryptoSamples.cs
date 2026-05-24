using System;
using System.Linq;
using System.Net.Security;
using System.Security.Authentication;
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

        bool TimingCompare(byte[] key, byte[] msg, byte[] provided)
        {
            var mac = new HMACSHA256(key);
            var tag = mac.ComputeHash(msg);
            // Non-constant-time comparison of a MAC — flagged.
            if (tag.SequenceEqual(provided))
            {
                return true;
            }
            // Constant-time comparison — must NOT be flagged.
            if (CryptographicOperations.FixedTimeEquals(tag, provided))
            {
                return true;
            }
            // Non-crypto comparison — must NOT be flagged.
            return msg.SequenceEqual(provided);
        }

        void TlsSetup(SslStream stream, byte[] cert)
        {
            // TLS protocol enum members: deprecated flagged, modern inventoried.
            var legacy = SslProtocols.Tls11;
            var modern = SslProtocols.Tls13;
        }

        void StrongOrInventory()
        {
            // Good usage — must NOT be flagged as a problem.
            var aes = Aes.Create();
            var sha256 = SHA256.Create();
        }
    }
}
