using System;
using NUnit.Framework;
using MifielAPI.Crypto;
using System.Text;
using MifielAPI.Exceptions;
using MifielAPITests.crypto;
using MifielAPI.Utils;

namespace MifielAPITests
{
    [TestFixture] 
    public class AesTest : CryptoTest<ItemAes>
    {
        private static readonly string fixturePath = "crypto\\fixtureAes.json";

        public AesTest() : base(fixturePath)
        {
        }

        [Test]
        public void Aes_Encrypt_Test()
        {
            foreach (ItemAes item in ArrayTest.GetRange(0, 9))
             {
                byte[] key = Encoding.ASCII.GetBytes(item.key);
                byte[] data = Encoding.ASCII.GetBytes(item.dataToEncrypt);
                byte[] iv = Encoding.ASCII.GetBytes(item.iv);
                byte[] res = Aes.Encrypt(key, data, iv);
                Assert.AreEqual(item.encrypted, BitConverter.ToString(res).Replace("-", "").ToLower());
             }
        }

        [Test]
        public void Aes_Decrypt_Test()
        {
            foreach (ItemAes item in ArrayTest.GetRange(0, 9))
            {
                byte[] key = Encoding.ASCII.GetBytes(item.key);
                byte[] data = MifielUtils.StringToByteArray(item.encrypted);
                byte[] iv = Encoding.ASCII.GetBytes(item.iv);
                byte[] res = Aes.Decrypt(key, data, iv);
                Assert.AreEqual(item.dataToEncrypt, Encoding.Default.GetString(res));
            }
        }

        [Test]
        public void Aes_Encrypt_BadKey()
        {
            Assert.Throws<MifielException>(() => Aes.Encrypt(new byte[4], Aes.GetIV(), Aes.GetIV()));
            Assert.Throws<MifielException>(() => Aes.Encrypt(null, Aes.GetIV(), Aes.GetIV()));
            Assert.Throws<MifielException>(() => Aes.Encrypt(new byte[400], Aes.GetIV(), Aes.GetIV()));
        }

        [Test]
        public void Aes_Decrypt_BadKey()
        {
            Assert.Throws<MifielException>(() => Aes.Decrypt(new byte[4], Aes.GetIV(), Aes.GetIV()));
            Assert.Throws<MifielException>(() => Aes.Decrypt(null, Aes.GetIV(), Aes.GetIV()));
            Assert.Throws<MifielException>(() => Aes.Decrypt(new byte[400], Aes.GetIV(), Aes.GetIV()));
        }

        [Test]
        public void Aes_Encrypt_BadData()
        {
            Assert.Throws<MifielException>(() => Aes.Encrypt(Aes.GetIV(), Encoding.ASCII.GetBytes("") ,Aes.GetIV()));
            Assert.Throws<MifielException>(() => Aes.Encrypt(Aes.GetIV(), null, Aes.GetIV()));
        }

        [Test]
        public void Aes_Decrypt_BadData()
        {
            Assert.Throws<MifielException>(() => Aes.Decrypt(Aes.GetIV(), Encoding.ASCII.GetBytes(""), Aes.GetIV()));
            Assert.Throws<MifielException>(() => Aes.Decrypt(Aes.GetIV(), null, Aes.GetIV()));
        }

        [Test]
        public void Aes_Encrypt_BadIV()
        {
            Assert.Throws<MifielException>(() => Aes.Encrypt(Aes.GetIV(), Aes.GetIV(), new byte[40]));
            Assert.Throws<MifielException>(() => Aes.Encrypt(Aes.GetIV(), Aes.GetIV(), Encoding.ASCII.GetBytes("")));
            Assert.Throws<MifielException>(() => Aes.Encrypt(Aes.GetIV(), Aes.GetIV(), null));
        }

        [Test]
        public void Aes_Decrypt_BadIV()
        {
            Assert.Throws<MifielException>(() => Aes.Decrypt(Aes.GetIV(), Aes.GetIV(), new byte[40]));
            Assert.Throws<MifielException>(() => Aes.Decrypt(Aes.GetIV(), Aes.GetIV(), Encoding.ASCII.GetBytes("")));
            Assert.Throws<MifielException>(() => Aes.Decrypt(Aes.GetIV(), Aes.GetIV(), null));
        }

        [Test]
        public void Aes_IV()
        {
            int len = 16;
            byte[] iv = Aes.GetIV();
            Assert.AreEqual(len, iv.Length);
        }
    }

    public class ItemAes
    {
        public string key;
        public string dataToEncrypt;
        public string iv;
        public string encrypted;
        public string desciption;
    }
}
