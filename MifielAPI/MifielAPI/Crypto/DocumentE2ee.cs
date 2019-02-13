namespace MifielAPI.Crypto
{
    using MifielAPI.Exceptions;
    using System;


    public class DocumentE2ee
    {

        internal int AES_KEY_SIZE = 24;
        public byte[] Pkcs5Bytes { get; set; }

        public string EncryptDocument(byte[] document)
        {

            byte[] secretKey;
            string password = Pbe.RandomPassword();

            Pkcs5 pkcs5 = new Pkcs5
            {
                Salt = Pbe.GetSalt(),
                Iv = Aes.GetIV(),
                Iterations = Pbe.ITERATIONS
            };

            try
            {
                secretKey = Pbe.DerivedKeySHA256(password, pkcs5.Salt, AES_KEY_SIZE);
                pkcs5.SizeKey = secretKey.Length;
                pkcs5.Encrypted = Aes.Encrypt(secretKey, document, pkcs5.Iv);
                Pkcs5Bytes = pkcs5.Create();
            }
            catch (Exception e)
            {
                throw new MifielException("No se pudo cifrar el documento:" + e.Message);
            }
            return password;
        }


        public byte[] DecryptDocument(string password)
        {
            Pkcs5 pkcs5 = new Pkcs5();
            byte[] decrypted;
            try
            {
                pkcs5.Read(Pkcs5Bytes);
                byte[] secretKey = secretKey = Pbe.DerivedKeySHA256(password, pkcs5.Salt, pkcs5.SizeKey, pkcs5.Iterations);
                decrypted = Aes.Decrypt(secretKey, pkcs5.Encrypted, pkcs5.Iv);
            }
            catch (Exception e)
            {
                throw new MifielException("Could not DECRYPT:" + e.Message);
            }
            return decrypted;
        }
    }
}
