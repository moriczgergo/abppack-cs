using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Encodings;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Security;
using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace ABPPack
{
    public static class ABPRSA
    {
        public static RsaKeyParameters MakeKey(string modulusHex, string exponentHex, bool isPrivate)
        {
            var modulus = new Org.BouncyCastle.Math.BigInteger(modulusHex, 16);
            var exponent = new Org.BouncyCastle.Math.BigInteger(exponentHex, 16);

            return new RsaKeyParameters(isPrivate, modulus, exponent);
        }

        public static AsymmetricCipherKeyPair MakeKeys(string pem)
        {
            using (var reader = new StringReader(pem))
            {
                return (AsymmetricCipherKeyPair)new PemReader(reader).ReadObject();
            }
        }

        public static byte[] Sign(byte[] data, RsaKeyParameters key)
        {
            try
            {
                ISigner sig = SignerUtilities.GetSigner("SHA512withRSA");

                sig.Init(true, key);
                sig.BlockUpdate(data, 0, data.Length);

                return sig.GenerateSignature();
            }
            catch (Exception e)
            {
                Console.Error.WriteLine($"[ABPRSA.Sign] {e}");
                return null;
            }
        }

        public static bool Verify(byte[] data, byte[] signature, RsaKeyParameters key)
        {
            try
            {
                ISigner sig = SignerUtilities.GetSigner("SHA512withRSA");

                sig.Init(false, key);
                sig.BlockUpdate(data, 0, data.Length);

                return sig.VerifySignature(signature);
            }
            catch (Exception e)
            {
                Console.Error.WriteLine($"[ABPRSA.Verify] {e}");
                return false;
            }
        }

        public static byte[] Encrypt(byte[] data, RsaKeyParameters key)
        {
            try
            {
                var engine = new Pkcs1Encoding(new RsaEngine());
                engine.Init(true, key);

                var inputSize = engine.GetInputBlockSize();
                var outputSize = engine.GetOutputBlockSize();

                var inputBlockCount = (int)Math.Ceiling(data.Length / (double)inputSize);

                byte[] blocks = new byte[outputSize * inputBlockCount];

                for (var i = 0; i < inputBlockCount; i++)
                {
                    var absI = i * inputSize;
                    var block = engine.ProcessBlock(data, absI, Math.Min(data.Length - absI, inputSize));
                    Array.Copy(block, 0, blocks, i * outputSize, outputSize);
                }

                return blocks;
            }
            catch (Exception e)
            {
                Console.Error.WriteLine($"[ABPRSA.Encrypt] {e}");
                return null;
            }
        }

        public static byte[] Decrypt(byte[] data, RsaKeyParameters key)
        {
            try
            {
                var engine = new Pkcs1Encoding(new RsaEngine());
                engine.Init(false, key);

                var inputSize = engine.GetInputBlockSize();
                var outputSize = engine.GetOutputBlockSize();

                var inputBlockCount = (int)Math.Ceiling(data.Length / (double)inputSize);

                List<byte[]> blocks = new List<byte[]>();
                //byte[] blocks = new byte[outputSize * inputBlockCount];

                var totalBlockSize = 0;

                for (var i = 0; i < inputBlockCount; i++)
                {
                    var absI = i * inputSize;
                    var block = engine.ProcessBlock(data, absI, Math.Min(data.Length - absI, inputSize));
                    //Array.Copy(block, 0, blocks, i * outputSize, block.Length);
                    blocks.Add(block);
                    totalBlockSize += block.Length;
                }

                byte[] blockCat = new byte[totalBlockSize];
                var j = 0;
                for (var i = 0; i < blocks.Count; i++)
                {
                    Array.Copy(blocks[i], 0, blockCat, j, blocks[i].Length);
                    j += blocks[i].Length;
                }

                return blockCat;
            }
            catch (Exception e)
            {
                Console.Error.WriteLine($"[ABPRSA.Decrypt] {e}");
                return null;
            }
        }

        public static bool SelfTest(AsymmetricCipherKeyPair keypair)
        {
            string testInputStr = "Testing Testing 123!!!";
            var testInput = Encoding.UTF8.GetBytes(testInputStr);

            var signature = Sign(testInput, (RsaKeyParameters)keypair.Private);
            var encrypted = Encrypt(testInput, (RsaKeyParameters)keypair.Public);

            var decrypted = Decrypt(encrypted, (RsaKeyParameters)keypair.Private);
            var verified = Verify(decrypted, signature, (RsaKeyParameters)keypair.Public);

            var decryptedStr = Encoding.UTF8.GetString(decrypted);

            if (decryptedStr != testInputStr)
            {
                Console.Error.WriteLine($"[ABPRSA.SelfTest] Selftest failed: Decrypted doesn't match input!");
                return false;
            }
            else if (!verified)
            {
                Console.Error.WriteLine($"[ABPRSA.SelfTest] Selftest failed: Couldn't verify input!");
                return false;
            }
            else
            {
                return true;
            }
        }
    }
}
