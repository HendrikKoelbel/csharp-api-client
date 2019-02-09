using System;
using System.Text;
using MifielAPI.Crypto;
using MifielAPITests.crypto;
using NUnit.Framework;

namespace MifielAPITests
{
    [TestFixture]
    public class EciesTest : CryptoTest<ItemEcies>
    {
        private static readonly string fixturePath = "crypto\\fixtureECIES.json";


        public EciesTest() : base(fixturePath)
        {

        }
        [Test]
        public void Ecies_Decrypt_Test()
        {
            foreach (ItemEcies item in ArrayTest.GetRange(0, 4))
            {
                byte[] publicKey = StringToByteArray(item.publicKey);
                byte[] privateKey = StringToByteArray(item.privateKey);
                byte[] data = StringToByteArray(item.iv + item.ephemPublicKey + item.ciphertext + item.mac);
                string decrypted = item.decrypted;
                Ecies ecies = new Ecies();
                byte[] res = ecies.Decrypt(privateKey, data);

                Assert.AreEqual(item.decrypted, Encoding.Default.GetString(res));
            }
        }

        [Test]
        public void Ecies_Encrypt_Test()
        {
            byte[] res = null;
            byte[] encrypt = null;

            byte[] publicKey = StringToByteArray(ArrayTest[0].publicKey);
            byte[] privateKey = StringToByteArray(ArrayTest[0].privateKey);
            string test = "Texto de prueba para cifrado";
            Ecies ecies = new Ecies();
            encrypt = ecies.Encrypt(publicKey, Encoding.ASCII.GetBytes(test));
            res = ecies.Decrypt(privateKey, encrypt);
            //            Console.WriteLine(" youp " + BitConverter.ToString(encrypt).Replace("-", "").ToLower());
            //            Console.WriteLine("res" + Encoding.Default.GetString(res));

            Assert.AreEqual(test, Encoding.Default.GetString(res));
        }

    }
    public class ItemEcies
    {
        public string publicKey;
        public string privateKey;
        public string iv;
        public string ephemPublicKey;
        public string ciphertext;
        public string mac;
        public string decrypted;
    }
}
