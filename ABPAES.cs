using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Modes;
using System;
using System.Security.Cryptography;
using System.Text;

namespace ABPPack
{
    public static class ABPAES
    {
        public const int macSize = 128;
        public const int ivCount = 12;
        public const int keyCount = 32;

        public static byte[] MakeIV()
        {
            using (RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider())
            {
                byte[] iv = new byte[ivCount];
                rng.GetBytes(iv);
                return iv;
            }
        }

        public static KeyParameter MakeKey()
        {
            using (RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider())
            {
                byte[] key = new byte[keyCount];
                rng.GetBytes(key);
                return MakeKey(key);
            }
        }

        public static KeyParameter MakeKey(byte[] key)
        {
            return new KeyParameter(key);
        }

        public static byte[] Encrypt(byte[] data, KeyParameter key, byte[] iv)
        {
            try
            {
                var cipher = new GcmBlockCipher(new AesEngine());
                var parameters = new AeadParameters(key, macSize, iv);
                cipher.Init(true, parameters);

                var output = new byte[cipher.GetOutputSize(data.Length)];
                var len = cipher.ProcessBytes(data, 0, data.Length, output, 0);
                cipher.DoFinal(output, len);

                return output;
            }
            catch (Exception e)
            {
                Console.Error.WriteLine($"[ABPAES.Encrypt] {e}");
                return null;
            }
        }

        public static byte[] Decrypt(byte[] data, KeyParameter key, byte[] iv)
        {
            try
            {
                var cipher = new GcmBlockCipher(new AesEngine());
                var parameters = new AeadParameters(key, macSize, iv);
                cipher.Init(false, parameters);

                var output = new byte[cipher.GetOutputSize(data.Length)];
                var len = cipher.ProcessBytes(data, 0, data.Length, output, 0);
                cipher.DoFinal(output, len);

                return output;
            }
            catch (Exception e)
            {
                Console.Error.WriteLine($"[ABPAES.Decrypt] {e}");
                return null;
            }
        }

        public static bool SelfTest(KeyParameter key)
        {
            byte[] testIV = MakeIV();
            string testInputStr = "Testing Testing 123!!!";
            var testInput = Encoding.UTF8.GetBytes(testInputStr);

            var encrypted = Encrypt(testInput, key, testIV);
            var decrypted = Decrypt(encrypted, key, testIV);

            var decryptedStr = Encoding.UTF8.GetString(decrypted);

            if (decryptedStr != testInputStr)
            {
                Console.Error.WriteLine($"[ABPAES.SelfTest] Selftest failed: Decrypted doesn't match input!");
                return false;
            }
            else
            {
                return true;
            }
        }
    }
}
