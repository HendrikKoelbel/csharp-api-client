using System;
using NUnit.Framework;
using MifielAPI.Crypto;
using System.Text;
using MifielAPI.Exceptions;
using MifielAPITests.crypto;

namespace MifielAPITests
{
    [TestFixture]
    public class PbeTest : CryptoTest <ItemPbe>
    {
        private static readonly string fixturePath = "crypto\\fixturePbe.json";

        public PbeTest( ) : base(fixturePath)
        {
        }

        [Test] 
        public void PBE_Valid()
        {
               foreach (ItemPbe item in ArrayTest.GetRange(0,7))
            {
                byte[] salt = Encoding.ASCII.GetBytes(item.salt);
                byte[] res = Pbe.DerivedKeySHA256(item.key, salt, item.keylen, item.iterations);
                Assert.AreEqual(item.result, BitConverter.ToString(res).Replace("-", "").ToLower());
            }
        }

        [Test]
        public void PBE_KeytooLong()
        {
            ItemPbe item = ArrayTest[7];
            byte[] salt = Encoding.ASCII.GetBytes(item.salt);
            Assert.Throws<MifielException>(()=>Pbe.DerivedKeySHA256(item.key, salt, item.keylen, item.iterations), item.description);
        }

        [Test] 
        public void PBE_EmptySalt()
        {
            ItemPbe item = ArrayTest[8];
            byte[] salt = Encoding.ASCII.GetBytes(item.salt);
            byte[] res = Pbe.DerivedKeySHA256(item.key, salt, item.keylen, item.iterations);
            Assert.AreEqual(item.result, BitConverter.ToString(res).Replace("-", "").ToLower());
        }

        [Test]
        public void PBE_Pass()
        {
            Pbe pbe = new Pbe();
            int len = 45;
            string pass = Pbe.RandomPassword(len);
            Assert.AreEqual(len, pass.Length);
        }

        [Test]
        public void PBE_Salt()
        {
            Pbe pbe = new Pbe();
            int len = 16;
            byte[] salt = Pbe.GetSalt();
            Assert.AreEqual(len, salt.Length);
        }
    }

    public class ItemPbe
    {
        public string key;
        public string salt;
        public int iterations;
        public int keylen;
        public string result;
        public string description;
    }
}
