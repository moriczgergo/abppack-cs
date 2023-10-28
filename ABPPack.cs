using System;
using System.Text;
using Org.BouncyCastle.Crypto.Parameters;

namespace ABPPack
{
    public class ABPPack
    {
        public byte version = 0;
        public byte[] data;

        public ABPPack() { }

        public ABPPack(byte[] x, KeyParameter key)
        {
            var version = x[0];
            var iv = new byte[ABPAES.ivCount];
            var enc = new byte[x.Length - 1 - iv.Length];

            Array.Copy(x, 1, iv, 0, iv.Length);
            Array.Copy(x, 1 + iv.Length, enc, 0, enc.Length);

            this.version = version;
            this.data = ABPAES.Decrypt(enc, key, iv);
        }

        public byte[] Pack(KeyParameter key)
        {
            var iv = ABPAES.MakeIV();
            var enc = ABPAES.Encrypt(this.data, key, iv);

            var x = new byte[1 + iv.Length + enc.Length];
            x[0] = this.version;
            Array.Copy(iv, 0, x, 1, iv.Length);
            Array.Copy(enc, 0, x, 1 + iv.Length, enc.Length);
            return x;
        }

        public static bool SelfTest(KeyParameter key)
        {
            string testInputStr = "Testing Testing 123!!!";
            var testInput = Encoding.UTF8.GetBytes(testInputStr);

            var pack = new ABPPack { data = testInput };
            var packBytes = pack.Pack(key);
            var decryptedPack = new ABPPack(packBytes, key);

            var decryptedStr = Encoding.UTF8.GetString(decryptedPack.data);

            if (decryptedStr != testInputStr)
            {
                Console.Error.WriteLine($"[ABPPack.SelfTest] Selftest failed: Decrypted doesn't match input!");
                return false;
            }
            else
            {
                return true;
            }
        }
    }
}
