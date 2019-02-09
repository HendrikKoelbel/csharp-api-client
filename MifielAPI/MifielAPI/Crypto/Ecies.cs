using Org.BouncyCastle.Asn1.Sec;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Agreement;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Macs;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Paddings;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using System;
using System.IO;

namespace MifielAPI.Crypto
{
    public class Ecies
    {
        private readonly X9ECParameters curve;
        private readonly ECDomainParameters domainParameters;
        private readonly Kdf kdf;
        private readonly HMac mac;
        private readonly CbcBlockCipher cbc;
        private readonly IesParameters iesParameters;
        private readonly int IV_LENGTH = 16;
        private readonly IBasicAgreement agree;
        public Ecies()
        {
            curve = SecNamedCurves.GetByName("secp256k1");
            this.domainParameters = new ECDomainParameters(curve.Curve, curve.G, curve.N, curve.H, curve.GetSeed());
            this.kdf = new Kdf(new Sha512Digest());
            this.mac = new HMac(new Sha256Digest());
            this.cbc = new CbcBlockCipher(new AesEngine());
            this.iesParameters = new IesWithCipherParameters (new byte[] { }, new byte[] { }, 256, 256);
            this.agree = new ECDHBasicAgreement();
        }

        public byte[] Decrypt(byte[] privateKey, byte[] cipherData)
        {
            BigInteger prv = new BigInteger(1, privateKey);
            byte[] iv = new byte[IV_LENGTH];
            byte[] cipher = new byte[cipherData.Length - IV_LENGTH];
            Array.Copy(cipherData, 0, iv, 0, IV_LENGTH);
            Array.Copy(cipherData, IV_LENGTH, cipher, 0, cipherData.Length - IV_LENGTH);
            ParametersWithIV parametersWithIV = new ParametersWithIV(iesParameters, iv);
            IesEnginee engine = new IesEnginee(agree, kdf, mac, new PaddedBufferedBlockCipher(cbc));
            ECPrivateKeyParameters privParameters = new ECPrivateKeyParameters(prv, domainParameters);
            engine.InitDecryption(privParameters, parametersWithIV);

            return engine.ProcessBlock(cipher, 0, cipher.Length);
        }

        public byte[] Encrypt(byte[] pubKey, byte[] plaintext) {
            MemoryStream streamPubkey = new MemoryStream(pubKey);
            IesEnginee engine = new IesEnginee(agree, kdf, mac, new PaddedBufferedBlockCipher(cbc));
            ECPublicKeyParameters publicKey = engine.ReadKey(domainParameters, streamPubkey);
            ParametersWithIV parametersWithIV = new ParametersWithIV(iesParameters, Aes.GetIV());
            engine.InitEncryption(publicKey, parametersWithIV);
		    return engine.ProcessBlock(plaintext, 0, plaintext.Length);
	    }

    public class Kdf : IDerivationFunction
        {
            private IDigest digest;
            private byte[] shared;

            public Kdf(IDigest digest)
            {
                this.digest = digest;
            }
            public IDigest Digest
            {
                get { return digest; }
            }

            public int GenerateBytes(byte[] output, int outOff, int length)
            {
                digest.BlockUpdate(shared, 0, shared.Length);
                digest.DoFinal(output, 0);
                return output.Length;
            }

            public void Init(IDerivationParameters parameters)
            {
                if (parameters is KdfParameters p) {
                    shared = p.GetSharedSecret();
                    
                } else {
                    throw new ArgumentException("KDF parameters required for generator");
                }
            }
        }
    }
}
