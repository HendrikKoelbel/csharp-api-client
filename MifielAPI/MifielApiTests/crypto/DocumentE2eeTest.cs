using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using MifielAPI.Crypto;
using MifielAPITests.crypto;
using NUnit.Framework;

namespace MifielAPITests
{
    [TestFixture]
    class DocumentE2eeTest : CryptoTest<ItemPkcs5>
    {
        private static readonly string fixturePath = "crypto\\fixturePKCS5.json";
        private string fileName = Path.Combine(_currentDirectory, "test-e2ee.pdf");
        

        private static string Decrypted = "This memo represents a republication of PKCS #5 v2.0 from RSA\n"
                + "Laboratories' Public-Key Cryptography Standards (PKCS) series, and\n"
                + "change control is retained within the PKCS process.  The body of this\n"
                + "document, except for the security considerations section, is taken\n"
                + "directly from that specification.\n" +

                "This document provides recommendations for the implementation of\n"
                + "password-based cryptography, covering key derivation functions,\n"
                + "encryption schemes, message-authentication schemes, and ASN.1 syntax\n" + "identifying the techniques.\n"
                +

                "The recommendations are intended for general application within\n"
                + "computer and communications systems, and as such include a fair\n"
                + "amount of flexibility. They are particularly intended for the\n"
                + "protection of sensitive information such as private keys, as in PKCS\n"
                + "#8 [25]. It is expected that application standards and implementation\n"
                + "profiles based on these specifications may include additional\n" + "constraints.\n" +

                "Other cryptographic techniques based on passwords, such as password-\n"
                + "based key entity authentication and key establishment protocols\n"
                + "[4][5][26] are outside the scope of this document.  Guidelines for\n"
                + "the selection of passwords are also outside the scope.	";

        public DocumentE2eeTest() : base(fixturePath)
        {
        }
        [Test]
        public void DocumentE2ee_Encrypt_Test()
        {
            byte[] data = File.ReadAllBytes(fileName);
            byte[] res;
            DocumentE2ee documentE2Ee = new DocumentE2ee();
            string pass = documentE2Ee.EncryptDocument(data);
            res = documentE2Ee.Pkcs5Bytes;
            res = documentE2Ee.DecryptDocument(pass);
            Assert.AreEqual(data, res);
        }
        [Test]
        public void DocumentE2ee_Decrypt_Test()
        {
            foreach (ItemPkcs5 item in ArrayTest.GetRange(0, 3))
            {
                DocumentE2ee documentE2Ee = new DocumentE2ee();
                documentE2Ee.Pkcs5Bytes = StringToByteArray(item.pkcs5);
                byte[] res = documentE2Ee.DecryptDocument(item.password);
                Assert.AreEqual(Decrypted, Encoding.Default.GetString(res));
            }
        }
    }
}
