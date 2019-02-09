using MifielAPI.Exceptions;
using System;
using System.IO;
using System.Security.Cryptography;

namespace MifielAPI.Crypto
{
    public class Aes
    {
        public const int IV_SIZE = 16;

        public static byte[] Decrypt(byte[] key, byte[] dataEncrypt, byte[] iv) 
        {   
            if (key == null || !(key.Length == 16 || key.Length == 24 || key.Length == 32))
                throw new MifielException("La clave especificada no tiene un tamaño válido para este algoritmo");

            if (dataEncrypt == null || dataEncrypt.Length == 0)
                throw new MifielException("No hay datos que descifrar");

            if (iv == null || iv.Length == 0 || iv.Length > 16)
                throw new MifielException("IV incorrecto");

            byte[] decrypted;

            using (AesManaged cipher = new AesManaged())
            {
                cipher.Mode = CipherMode.CBC;
                cipher.Padding = PaddingMode.PKCS7;
                try
                {
                    using (ICryptoTransform decryptor = cipher.CreateDecryptor(key, iv))
                    {
                        decrypted = AsymmetriCryptography(decryptor, dataEncrypt);
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine(ex.StackTrace);
                    throw new MifielException("Error al descifrar " + ex.Message);
                }

                cipher.Clear();
            }
            return decrypted;
        }


        public static byte[] Encrypt(byte[] key, byte[] plainBytes, byte[] iv)
        {
            if (key == null || !(key.Length == 16 || key.Length == 24 || key.Length == 32) )
                throw new MifielException(" La clave especificada no tiene un tamaño válido para este algoritmo");

            if (plainBytes == null || plainBytes.Length == 0)
                throw new MifielException("No hay datos que cifrar");

            if (iv == null || iv.Length == 0 || iv.Length > 16)
                throw new MifielException("IV incorrecto");

            byte[] encrypted;
            using (AesManaged cipher = new AesManaged())
            {
                cipher.Mode = CipherMode.CBC;
                cipher.Padding = PaddingMode.PKCS7;
                using (ICryptoTransform encryptor = cipher.CreateEncryptor(key, iv))
                {
                    encrypted = AsymmetriCryptography(encryptor, plainBytes);
                }
                cipher.Clear();
            }
            return encrypted;
        }

        public static byte[] GetIV( )
        {
            RNGCryptoServiceProvider provider = new RNGCryptoServiceProvider();
            var byteArray = new byte[IV_SIZE];
            provider.GetBytes(byteArray);
            return byteArray;
        }

        private static byte[] AsymmetriCryptography(ICryptoTransform icryptoTransform, byte[] data)
        {
            using (var memoryStream = new MemoryStream())
            {
                using (var cryptoStream = new CryptoStream(memoryStream, icryptoTransform, CryptoStreamMode.Write))
                {
                    cryptoStream.Write(data, 0, data.Length);
                    cryptoStream.FlushFinalBlock();
                    return memoryStream.ToArray();
                }
            }
        }
    }
}
