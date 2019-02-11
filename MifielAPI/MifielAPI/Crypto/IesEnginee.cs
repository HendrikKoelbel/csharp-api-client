namespace MifielAPI.Crypto
{
    using MifielAPI.Exceptions;
    using Org.BouncyCastle.Crypto;
    using Org.BouncyCastle.Crypto.Generators;
    using Org.BouncyCastle.Crypto.Parameters;
    using Org.BouncyCastle.Math;
    using Org.BouncyCastle.Security;
    using System;
    using System.IO;

    public class IesEnginee
    {

        private readonly IBasicAgreement agree;
        private readonly BufferedBlockCipher cipher;
        private readonly IDerivationFunction kdf;
        private readonly IMac mac;
        private readonly byte[] macBuf;
        private bool forEncryption;
        private byte[] IV;
        private byte[] ephemeralKey;
        private IesParameters param;
        private ECPrivateKeyParameters privParam;
        private ECPublicKeyParameters pubParam;
       
        public IesEnginee(
            IBasicAgreement agree,
            IDerivationFunction kdf,
            IMac mac,
            BufferedBlockCipher cipher)
        {
            this.agree = agree;
            this.kdf = kdf;
            this.mac = mac;
            this.macBuf = new byte[mac.GetMacSize()];
            this.cipher = cipher;
        }

         public void InitEncryption(
             ECPublicKeyParameters pubParameters,
             ParametersWithIV parameters)
         {
            this.forEncryption = true;
            this.pubParam = pubParameters;
            ExtractParams(parameters);
         }

        public void InitDecryption(
            ECPrivateKeyParameters privParameters,
            ParametersWithIV parameters)
        {
            this.forEncryption = false;
            this.privParam = privParameters;
            ExtractParams(parameters);
        }

         private void ExtractParams(ParametersWithIV parameters)
        {
            this.IV = parameters.GetIV();
            this.param = (IesParameters)parameters.Parameters;
        }

        public byte[] ProcessBlock( byte[] input, int inOff, int inLen)
        {
            if (forEncryption)
            {
                AsymmetricCipherKeyPair pair = GenerateEphemeralKey(pubParam.Parameters);
                this.privParam = (ECPrivateKeyParameters)pair.Private;
                this.ephemeralKey = ((ECPublicKeyParameters) pair.Public).Q.GetEncoded(false);
            }
            else
            {
                MemoryStream stream = new MemoryStream(input, inOff, inLen);
                this.pubParam = ReadKey(privParam.Parameters, stream);
                ephemeralKey = new byte[ inLen - (stream.Length - stream.Position)];
                Array.Copy(input, 0, ephemeralKey, inOff, inOff + ephemeralKey.Length);
            }

            agree.Init(privParam);
            BigInteger z = agree.CalculateAgreement(pubParam);

            byte[] zBytes = z.ToByteArrayUnsigned();

            return forEncryption
                ? EncryptBlock(input, inOff, inLen, zBytes)
                : DecryptBlock(input, inOff, inLen, zBytes);
        }


        private byte[] DecryptBlock( byte[] in_enc, int inOff, int inLen, byte[] z)
        {
            byte[] M = null;

            if (inLen < ephemeralKey.Length + mac.GetMacSize())
                throw new MifielException("Length of input must be greater than the MAC and V combined");

            KeyParameter macKey = null;
            KdfParameters kParam = new KdfParameters(z, param.GetDerivationV());
            int macKeySize = param.MacKeySize;

            if (cipher == null)
                throw new MifielException("Se espera el cipher block");


            int cipherKeySize = ((IesWithCipherParameters)param).CipherKeySize;
            byte[] Buffer = GenerateKdfBytes(kParam, (cipherKeySize / 8) + (macKeySize / 8));

            ICipherParameters cp = new KeyParameter(Buffer, 0, (cipherKeySize / 8));

            if (IV != null)
                cp = new ParametersWithIV(cp, IV);

            cipher.Init(false,cp);

            macKey = new KeyParameter(Buffer, (cipherKeySize / 8), (macKeySize / 8));

            mac.Init(macKey);

            if (IV != null)
                mac.BlockUpdate(IV, 0, IV.Length);

            if (ephemeralKey.Length != 0)
                mac.BlockUpdate(ephemeralKey, 0, ephemeralKey.Length);

            mac.BlockUpdate(in_enc, inOff + ephemeralKey.Length, inLen - ephemeralKey.Length - macBuf.Length);
            mac.DoFinal(macBuf, 0);

            for (int t = 0; t < macBuf.Length; t++)
            {
                if (macBuf[t] != in_enc[inOff + inLen - macKeySize/8 + t])
                {
                    throw (new MifielException("IMac codes failed to equal."));
                }
            }

            M = cipher.DoFinal(in_enc, inOff + ephemeralKey.Length, inLen - ephemeralKey.Length - mac.GetMacSize());
            return M;
        }

        
        private byte[] EncryptBlock(byte[] input,  int inOff, int inLen, byte[] z)
        {
            byte[] Output = null;
            KeyParameter macKey = null;
            KdfParameters kParam = new KdfParameters(z, param.GetDerivationV());
            int c_text_length = 0;
            int macKeySize = param.MacKeySize;

            if (cipher == null)     // stream mode
                throw new MifielException("Se espera el cipher block");

            int cipherKeySize = ((IesWithCipherParameters)param).CipherKeySize;
            byte[] Buffer = GenerateKdfBytes(kParam, (cipherKeySize / 8) + (macKeySize / 8));

            KeyParameter keyParameter = new KeyParameter(Buffer, 0, (cipherKeySize / 8));

            if (IV != null)
                cipher.Init(true, new ParametersWithIV(keyParameter, IV));
            else
                cipher.Init(true, keyParameter);

            c_text_length = cipher.GetOutputSize(inLen);

            byte[] encrypt = new byte[c_text_length];
            int len = cipher.ProcessBytes(input, inOff, inLen, encrypt, 0);
            len += cipher.DoFinal(encrypt, len);

            byte[] computedMAC = new byte[mac.GetMacSize()];
            macKey = new KeyParameter(Buffer, (cipherKeySize / 8), (macKeySize / 8));
            mac.Init(macKey);

            if (IV != null)
                mac.BlockUpdate(IV, 0, IV.Length);
            
            if (ephemeralKey.Length != 0)
                mac.BlockUpdate(ephemeralKey, 0, ephemeralKey.Length);
            
            mac.BlockUpdate(encrypt, 0, encrypt.Length);
            mac.DoFinal(computedMAC, 0);

            Output = new byte[IV.Length + ephemeralKey.Length + len + computedMAC.Length];
            
            Array.Copy(IV, 0, Output, 0, IV.Length);
            Array.Copy(ephemeralKey, 0, Output, IV.Length, ephemeralKey.Length);
            Array.Copy(encrypt, 0, Output, IV.Length + ephemeralKey.Length, len);
            Array.Copy(computedMAC, 0, Output, IV.Length + ephemeralKey.Length + len, computedMAC.Length);

            return Output;
        }

        private byte[] GenerateKdfBytes(KdfParameters kParam, int length)
        {
            byte[] buf = new byte[length];
            kdf.Init(kParam);
            kdf.GenerateBytes(buf, 0, buf.Length);
            return buf;
        }


        public AsymmetricCipherKeyPair GenerateEphemeralKey(ECDomainParameters ecParams)
        {
            ECKeyPairGenerator keyPairGenerator = new ECKeyPairGenerator();
            SecureRandom random = new SecureRandom();
            keyPairGenerator.Init(new ECKeyGenerationParameters(ecParams, random));
            return keyPairGenerator.GenerateKeyPair();
        }


        public ECPublicKeyParameters ReadKey(ECDomainParameters ecParams, MemoryStream stream)
        {
            byte[] V;
            int first = stream.ReadByte();

            // Decode the public ephemeral key
            switch (first)
            {
                case 0x00: // infinity
                    throw new IOException("Sender's public key invalid.");

                case 0x02: // compressed
                case 0x03: // Byte length calculated as in ECPoint.getEncoded();
                    V = new byte[1 + (ecParams.Curve.FieldSize + 7) / 8];
                    break;

                case 0x04: // uncompressed or
                case 0x06: // hybrid
                case 0x07: // Byte length calculated as in ECPoint.getEncoded();
                    V = new byte[1 + 2 * ((ecParams.Curve.FieldSize + 7) / 8)];
                    break;

                default:
                    throw new IOException("Sender's public key has invalid point encoding 0x" + first.ToString());
            }

            V[0] = (byte)first;
            stream.ReadAsync(V, 1, V.Length - 1);
            
            return new ECPublicKeyParameters(ecParams.Curve.DecodePoint(V), ecParams);
        }
    }
}
