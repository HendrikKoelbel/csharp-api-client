using System;
using NUnit.Framework;
using MifielAPI.Crypto;
using MifielAPITests.crypto;
using MifielAPI.Exceptions;

namespace MifielAPITests
{
    [TestFixture]
    public class Pkcs5Test : CryptoTest<ItemPkcs5>
    {
        private static readonly string fixturePath = "crypto\\fixturePKCS5.json";

        public Pkcs5Test() : base(fixturePath)
        {
        }

        [Test]
        public void PKCS5_Read()
        {
            foreach (ItemPkcs5 item in ArrayTest.GetRange(0, 3))
            {
                Pkcs5 pkcs5 = new Pkcs5();
                pkcs5.Read(StringToByteArray(item.pkcs5));
                Assert.AreEqual(item.salt, BitConverter.ToString(pkcs5.Salt).Replace("-", "").ToLower());
                Assert.AreEqual(item.iterations, pkcs5.Iterations);
                Assert.AreEqual(item.iv, BitConverter.ToString(pkcs5.Iv).Replace("-", "").ToLower());
                Assert.AreEqual(item.encrypted, BitConverter.ToString(pkcs5.Encrypted).Replace("-", "").ToLower());
                Assert.AreEqual(item.sizeKey, pkcs5.SizeKey);
            }
        }

        [Test]
        public void PKCS5_Create()
        {
            foreach (ItemPkcs5 item in ArrayTest.GetRange(0, 3))
            {
                Pkcs5 pkcs5 = new Pkcs5(StringToByteArray(item.salt), StringToByteArray(item.iv), StringToByteArray(item.encrypted), item.iterations, item.sizeKey);
                byte[] res = pkcs5.Create();
                Console.WriteLine(item.pkcs5);
                Assert.AreEqual(item.pkcs5, BitConverter.ToString(res).Replace("-", "").ToLower());
            }
        }
        [Test]
        public void PKCS5_Exception()
        {
                Pkcs5 pkcs5 = new Pkcs5();
                Assert.Throws<MifielException>(() => pkcs5.Read(StringToByteArray(ArrayTest[3].pkcs5)));
                Assert.Throws<MifielException>(() => pkcs5.Read(StringToByteArray(ArrayTest[4].pkcs5)));
                Assert.Throws<MifielException>(() => pkcs5.Read(StringToByteArray(ArrayTest[5].pkcs5)));
        }


    }

    public class ItemPkcs5
    {
        public string pkcs5;
        public string iv;
        public string salt;
        public string password;
        public int iterations;
        public int sizeKey;
        public string encrypted;
    }
}
