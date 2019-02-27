using System.IO;
using System.Text;
using MifielAPI.Crypto;
using MifielAPI.Exceptions;
using MifielAPI.Utils;
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
                byte[] publicKey = MifielUtils.StringToByteArray(item.publicKey);
                byte[] privateKey = MifielUtils.StringToByteArray(item.privateKey);
                byte[] data = MifielUtils.StringToByteArray(item.iv + item.ephemPublicKey + item.ciphertext + item.mac);
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

            byte[] publicKey = MifielUtils.StringToByteArray(ArrayTest[0].publicKey);
            byte[] privateKey = MifielUtils.StringToByteArray(ArrayTest[0].privateKey);
            string test = "Texto de prueba para cifrado";
            Ecies ecies = new Ecies();
            encrypt = ecies.Encrypt(publicKey, Encoding.ASCII.GetBytes(test));
            res = ecies.Decrypt(privateKey, encrypt);

            Assert.AreEqual(test, Encoding.Default.GetString(res));
        }

        [Test]
        public void Ecies_Error_Encrypt_Test()
        {
            byte[] publicKey = MifielUtils.StringToByteArray("");
            string test = "Texto de prueba para cifrado";
            Ecies ecies = new Ecies();
            Assert.Throws<IOException>(() => ecies.Encrypt(publicKey, Encoding.ASCII.GetBytes(test)));
        }

        [Test]
        public void Ecies_Eror_IV_Dencrypt_Test()
        {
            byte[] privateKey = MifielUtils.StringToByteArray(ArrayTest[4].privateKey);
            byte[] data = MifielUtils.StringToByteArray(ArrayTest[4].iv + ArrayTest[4].ephemPublicKey + ArrayTest[4].ciphertext + ArrayTest[4].mac);
            string decrypted = ArrayTest[4].decrypted;
            Ecies ecies = new Ecies();
            Assert.Throws<MifielException>(() => ecies.Decrypt(privateKey, data));
        }
        [Test]
        public void Ecies_Error__Private_Dencrypt_Test()
        {
            byte[] publicKey = MifielUtils.StringToByteArray(ArrayTest[5].publicKey);
            byte[] privateKey = MifielUtils.StringToByteArray(ArrayTest[5].privateKey);
            byte[] data = MifielUtils.StringToByteArray(ArrayTest[5].iv + ArrayTest[5].ephemPublicKey + ArrayTest[5].ciphertext + ArrayTest[5].mac);
            string decrypted = ArrayTest[5].decrypted;
            Ecies ecies = new Ecies();
            Assert.Throws<MifielException>(() => ecies.Decrypt(privateKey, data));
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
