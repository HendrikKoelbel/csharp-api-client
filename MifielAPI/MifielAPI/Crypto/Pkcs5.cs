namespace MifielAPI.Crypto
{
    using MifielAPI.Exceptions;
    using Org.BouncyCastle.Asn1;
    using Org.BouncyCastle.Asn1.Nist;
    using Org.BouncyCastle.Asn1.Pkcs;
    using Org.BouncyCastle.Asn1.X509;
    using System;

    public class Pkcs5
    {
        public byte[] Salt { get; set; }
        public int Iterations { get; set; }
        public byte[] Iv { get; set; }
        public byte[] Encrypted { get; set; }
        public int SizeKey { get; set; }

        public Pkcs5()
        {

        }

        public Pkcs5(byte[] salt, byte[]iv, byte[] encrypted, int iterations, int sizekey)
        {
            Salt = salt;
            Iv = iv;
            Encrypted = encrypted;
            Iterations = iterations;
            SizeKey = sizekey;
        }

        private KeyDerivationFunc GeneratePkbdAlgorithmIdentifier(byte[] pbkdSalt, int iterations)
        {
            return new KeyDerivationFunc(PkcsObjectIdentifiers.IdPbkdf2, new Pbkdf2Params(pbkdSalt, iterations,
                    new AlgorithmIdentifier(PkcsObjectIdentifiers.IdHmacWithSha256)));
        }

        public byte[] Create()
        {

            ValidateData();
            KeyDerivationFunc pbkdAlgId = GeneratePkbdAlgorithmIdentifier(Salt, Iterations);
            DerObjectIdentifier id = null;
            switch (SizeKey)
            {
                case 16:
                    id = NistObjectIdentifiers.IdAes128Cbc;
                    break;
                case 24:
                    id = NistObjectIdentifiers.IdAes192Cbc;
                    break;
                case 32:
                    id = NistObjectIdentifiers.IdAes256Cbc;
                    break;
                default:
                    throw new MifielException("Key length not 128/192/256 bits");
            }

            PbeS2Parameters pbeParams = new PbeS2Parameters(pbkdAlgId,
                
                    new EncryptionScheme(id, new DerOctetString(Iv)));
            EncryptedPrivateKeyInfo keyInfo = new EncryptedPrivateKeyInfo(
                    new AlgorithmIdentifier(PkcsObjectIdentifiers.IdPbeS2, pbeParams), Encrypted);
            return keyInfo.GetEncoded();
        }

        private void ValidateData()
        {
            if (Salt == null)
                throw new MifielException("SALT cannot be null");

            if (Iv == null)
                throw new MifielException("IV cannot be null");

            if (Encrypted == null)
                throw new MifielException("Data ENCRYPTED cannot be null");

        }

        public void Read(byte[] pkcs5Bytes)
        {
            EncryptedPrivateKeyInfo encPkInfo = null;
            try
            {
                encPkInfo = EncryptedPrivateKeyInfo.GetInstance(Asn1Sequence.GetInstance(pkcs5Bytes));
            }
            catch (Exception e1)
            {
                throw new MifielException("Exception decoding bytes: Bytes are not PKCS5");
            }

            Encrypted = encPkInfo.GetEncryptedData();
            PbeS2Parameters alg = PbeS2Parameters.GetInstance(encPkInfo.EncryptionAlgorithm.Parameters);
            Pbkdf2Params func = Pbkdf2Params.GetInstance(alg.KeyDerivationFunc.Parameters);
            EncryptionScheme scheme = alg.EncryptionScheme;

            if (!PkcsObjectIdentifiers.IdHmacWithSha256.Equals(func.Prf.Algorithm))
            {
                throw new MifielException("Digest algorithm not supported");
            }

            if (!(NistObjectIdentifiers.IdAes128Cbc.Equals(scheme.Algorithm)
                    || NistObjectIdentifiers.IdAes192Cbc.Equals(scheme.Algorithm)
                    || NistObjectIdentifiers.IdAes256Cbc.Equals(scheme.Algorithm)))
            {
                throw new MifielException("Encryption algorithm not supported");
            }

            SetSizeKey(scheme.Algorithm);
            Iterations = func.IterationCount.IntValue;
            Salt = func.GetSalt(); 
            Iv = Asn1OctetString.GetInstance(scheme.Parameters).GetOctets();
        }


        private void SetSizeKey(DerObjectIdentifier algorithm)
        {
            if (NistObjectIdentifiers.IdAes128Cbc.Equals(algorithm))
                SizeKey = 16;

            if (NistObjectIdentifiers.IdAes192Cbc.Equals(algorithm))
                SizeKey = 24;

            if (NistObjectIdentifiers.IdAes256Cbc.Equals(algorithm))
                SizeKey = 32;
        }
    }
}
