using System;
using System.Security.Cryptography;
using System.Text;
using MifielAPI.Exceptions;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;

namespace MifielAPI.Crypto
{
    public class Pbe
    {
        public const int PASSWORD_LENGTH = 32;
        public const int SALT_SIZE = 16;
        public const int ITERATIONS = 1000;
        public const string ALGORITHM = "PBKDF2WithHmacSHA256";
        public const string CHARACTERS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_+=#&.*";


        public static string RandomPassword(int len = PASSWORD_LENGTH)
        {
            char[] chars = CHARACTERS.ToCharArray();
            byte[] data = new byte[len];
            using (RNGCryptoServiceProvider crypto = new RNGCryptoServiceProvider())
            {
                crypto.GetBytes(data);
            }
            StringBuilder result = new StringBuilder(len);
            foreach (byte b in data)
            {
                result.Append(chars[b % (chars.Length)]);
            }
            return result.ToString();
        }

        public static byte[] GetSalt(int size = SALT_SIZE)
        {
            RNGCryptoServiceProvider provider = new RNGCryptoServiceProvider();
            var byteArray = new byte[size];
            provider.GetBytes(byteArray);
            return byteArray;
        }

        public static byte[] DerivedKeySHA256(string password, byte[] salt,  int size, int iterations = ITERATIONS)
        {
            if (size <= 0 || size >= 300)
                throw new MifielException("key length too long");

            var pdb = new Pkcs5S2ParametersGenerator(new Org.BouncyCastle.Crypto.Digests.Sha256Digest());
            pdb.Init(Org.BouncyCastle.Crypto.PbeParametersGenerator.Pkcs5PasswordToBytes(password.ToCharArray()), salt,
                         iterations);
            var key = (KeyParameter)pdb.GenerateDerivedMacParameters(size * 8);
            return key.GetKey();

        }
    }


}
