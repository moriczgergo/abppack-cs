using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using System;
using System.Text;

namespace ABPPack
{
    public class ABPHPack
    {
        public byte version = 0;
        public byte[] data;

        public ABPHPack() { }

        public ABPHPack(byte[] x, RsaKeyParameters key)
        {
            this.version = x[0];
            var enc = new byte[x.Length - 1];

            Array.Copy(x, 1, enc, 0, enc.Length);

            this.data = ABPRSA.Decrypt(enc, key);
        }

        public byte[] Pack(RsaKeyParameters key)
        {
            var enc = ABPRSA.Encrypt(this.data, key);

            var x = new byte[1 + enc.Length];
            x[0] = this.version;
            Array.Copy(enc, 0, x, 1, enc.Length);
            return x;
        }

        public static bool SelfTest(AsymmetricCipherKeyPair keypair)
        {
            string testInputStr = "Testing Testing 123!!!";
            var testInput = Encoding.UTF8.GetBytes(testInputStr);

            var pack = new ABPHPack { data = testInput };
            var packBytes = pack.Pack((RsaKeyParameters)keypair.Public);
            var decryptedPack = new ABPHPack(packBytes, (RsaKeyParameters)keypair.Private);

            var decryptedStr = Encoding.UTF8.GetString(decryptedPack.data);

            if (decryptedStr != testInputStr)
            {
                Console.Error.WriteLine($"[ABPHPack.SelfTest] Selftest failed: Decrypted doesn't match input!");
                return false;
            }
            else
            {
                return true;
            }
        }
    }
}
