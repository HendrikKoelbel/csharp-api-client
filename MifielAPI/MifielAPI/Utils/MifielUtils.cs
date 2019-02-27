using MifielAPI.Exceptions;
using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Net.Http;
using Newtonsoft.Json;
using System.Collections.Generic;
using MifielAPI.Objects;
using System.Net.Http.Headers;

namespace MifielAPI.Utils
{
    public static class MifielUtils
    {
        private static Regex _rgx = new Regex("/+$");
        private static SHA256 _sha256 = SHA256.Create();
        private static UTF8Encoding _utfEncoding = new UTF8Encoding();

        internal static bool IsValidUrl(string url)
        {
            Uri uriResult;
            return Uri.TryCreate(url, UriKind.Absolute, out uriResult)
                    && (uriResult.Scheme == Uri.UriSchemeHttp ||
                        uriResult.Scheme == Uri.UriSchemeHttps);
        }

        internal static string RemoveLastSlashFromUrl(string url)
        {
            return _rgx.Replace(url, "");
        }

        public static string GetDocumentHash(string path)
        {
            try
            {
                using (FileStream stream = File.OpenRead(path))
                {
                    byte[] hashValue = _sha256.ComputeHash(stream);
                    return BitConverter.ToString(hashValue).Replace("-", string.Empty);
                }
            }
            catch (Exception ex)
            {
                throw new MifielException("Error generating document Hash", ex);
            }
        }

        public static string CalculateMD5(string content)
        {
            try
            {
                byte[] contentBytes = _utfEncoding.GetBytes(content);
                byte[] conetntHash = ((HashAlgorithm)CryptoConfig.CreateFromName("MD5")).ComputeHash(contentBytes);
                return BitConverter.ToString(conetntHash).Replace("-", string.Empty);
            }
            catch (Exception ex)
            {
                throw new MifielException("Error calculating MD5", ex);
            }
        }

        internal static void SaveHttpResponseToFile(HttpContent httpResponse, string localPath)
        {
            try
            {
                byte[] byteContent = httpResponse.ReadAsByteArrayAsync().Result;
                File.WriteAllBytes(localPath, byteContent);
            }
            catch (Exception ex)
            {
                throw new MifielException("Error saving file", ex);
            }
        }

        public static string CalculateHMAC(string appSecret, string canonicalString)
        {
            try
            {
                HMACSHA1 hmacSha1 = new HMACSHA1(Encoding.UTF8.GetBytes(appSecret));
                byte[] byteArray = Encoding.ASCII.GetBytes(canonicalString);
                MemoryStream stream = new MemoryStream(byteArray);
                return Convert.ToBase64String(hmacSha1.ComputeHash(stream));
            }
            catch (Exception ex)
            {
                throw new MifielException("Error calculating HMAC SHA1", ex);
            }
        }

        internal static void AppendTextParamToContent(Dictionary<string, string> parameters, string name, string value)
        {
            if (!string.IsNullOrEmpty(value))
            {
                parameters.Add(name, value);
            }
        }

        public static T ConvertJsonToObject<T>(string json)
        {
            try
            {
                using (var stringReader = new StringReader(json))
                {
                    using (var jsonReader = new JsonTextReader(stringReader))
                    {
                        var jsonSerializer = new JsonSerializer();
                        return jsonSerializer.Deserialize<T>(jsonReader);
                    }
                }
            }
            catch (Exception e)
            {
                throw new MifielException("Error converting JSON to Object", e);
            }
        }

        public static string ConvertObjectToJson<T>(T objectToConvert)
        {
            try
            {
                return JsonConvert.SerializeObject(objectToConvert);
            }
            catch (Exception e)
            {
                throw new MifielException("Error converting Object to JSON", e);
            }
        }


        public static byte[] StringToByteArray(String hex)
        {
            int NumberChars = hex.Length;
            byte[] bytes = new byte[NumberChars / 2];
            for (int i = 0; i < NumberChars; i += 2)
                bytes[i / 2] = Convert.ToByte(hex.Substring(i, 2), 16);
            return bytes;
        }


        public static HttpContent BuildHttpBody(Document document, byte[] pkcs5 = null)
        {
            List<Signature> signatures = document.Signatures;
            string filePath = document.File;
            string fileName = document.FileName;
            string originalHash = document.OriginalHash;

            if (!string.IsNullOrEmpty(filePath))
            {
                MultipartFormDataContent multipartContent = new MultipartFormDataContent();

                var parameters = new List<KeyValuePair<string, string>>();

                if (document.Encrypted)
                {
                    ByteArrayContent pdfContent = new ByteArrayContent(pkcs5);
                    pdfContent.Headers.ContentType = MediaTypeHeaderValue.Parse("application/pdf");
                    multipartContent.Add(pdfContent, "file", Path.GetFileName(filePath) + ".enc");
                    document.OriginalHash = MifielAPI.Utils.MifielUtils.GetDocumentHash(filePath);
                    parameters.Add(new KeyValuePair<string, string>("original_hash", document.OriginalHash));
                } else
                {
                    ByteArrayContent pdfContent = new ByteArrayContent(File.ReadAllBytes(filePath));
                    pdfContent.Headers.ContentType = MediaTypeHeaderValue.Parse("application/pdf");
                    multipartContent.Add(pdfContent, "file", Path.GetFileName(filePath));
                }

                

                if (!String.IsNullOrEmpty(document.CallbackUrl))
                {
                    parameters.Add(new KeyValuePair<string, string>("callback_url", document.CallbackUrl));
                }


                parameters.Add(new KeyValuePair<string, string>("manual_close", document.ManualClose.ToString().ToLower()));
                parameters.Add(new KeyValuePair<string, string>("encrypted", document.Encrypted.ToString().ToLower()));

                if (signatures != null)
                {
                    for (int i = 0; i < signatures.Count; i++)
                    {
                        parameters.Add(new KeyValuePair<string, string>("signatories[" + i + "][name]", signatures[i].SignerName));
                        parameters.Add(new KeyValuePair<string, string>("signatories[" + i + "][email]", signatures[i].Email));
                        parameters.Add(new KeyValuePair<string, string>("signatories[" + i + "][tax_id]", signatures[i].TaxId));
                    }
                }


                foreach (var keyValuePair in parameters)
                {
                    multipartContent.Add(new StringContent(keyValuePair.Value),
                        String.Format("\"{0}\"", keyValuePair.Key));
                }

                return multipartContent;
            }
            if (!string.IsNullOrEmpty(originalHash)
                && !string.IsNullOrEmpty(fileName))
            {
                Dictionary<string, string> parameters = new Dictionary<string, string>();
                parameters.Add("encripted", false.ToString());
                parameters.Add("original_hash", originalHash);
                parameters.Add("name", fileName);
                parameters.Add("manual_close", document.ManualClose.ToString().ToLower());

                MifielUtils.AppendTextParamToContent(parameters, "callback_url", document.CallbackUrl);

                if (signatures != null)
                {
                    for (int i = 0; i < signatures.Count; i++)
                    {
                        MifielUtils.AppendTextParamToContent(parameters,
                            "signatories[" + i + "][name]", signatures[i].SignerName);
                        MifielUtils.AppendTextParamToContent(parameters,
                            "signatories[" + i + "][email]", signatures[i].Email);
                        MifielUtils.AppendTextParamToContent(parameters,
                            "signatories[" + i + "][tax_id]", signatures[i].TaxId);
                    }
                }

                return new FormUrlEncodedContent(parameters);
            }
            throw new MifielException("You must provide file or original hash and file name");
        }

    }
}
