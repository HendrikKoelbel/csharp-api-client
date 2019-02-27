using MifielAPI.Exceptions;
using MifielAPI.Objects;
using MifielAPI.Utils;
using NBitcoin;
using NBitcoin.DataEncoders;
using Org.BouncyCastle.Security;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;
using System.Web.Script.Serialization;

namespace MifielAPI.Crypto
{
    public class E2ee
    {
        private string _documentsPath;
        private ApiClient apiClient;

        public E2ee(string _documentsPath, ApiClient apiClient)
        {
            this._documentsPath = _documentsPath;
            this.apiClient = apiClient;
        }


        public  Document Create( Document document) 
        {
                if (!string.IsNullOrEmpty(document.File))
                {
                    byte[] fileContent = File.ReadAllBytes(document.File);
                    DocumentE2ee docCrypto = new DocumentE2ee();
                    string pass = docCrypto.EncryptDocument(fileContent);
                    Document docPub = PostDocument(document, docCrypto.Pkcs5Bytes);
                    return SendEncryptedPass(docPub, pass);
                }
                else
                {
                    throw new MifielException("You must provide file ");
                }
        }

        private  Document PostDocument( Document document, byte[] pkcs5) 
        {
            HttpContent httpContent = MifielUtils.BuildHttpBody(document, pkcs5);
            HttpContent httpResponse = apiClient.Post(_documentsPath, httpContent); 
            string response = httpResponse.ReadAsStringAsync().Result;
            return  MifielUtils.ConvertJsonToObject<Document>(response);
        }

        private Document SendEncryptedPass(Document document, string pass)
        {
            Ecies ecies = new Ecies();
            Dictionary<string, object> signerDictionary = new Dictionary<string, object>();
            
            foreach (Signer singer in document.Signers) {
                Dictionary<string, object> group = new Dictionary<string, object>();
                string index = singer.E2e.Index;
                
                if (null != singer.E2e.Group.Client)
                {
                    ExtKey derive = GetPublicDerivedKey(index);
                    byte[] e_pass = ecies.Encrypt(derive.PrivateKey.PubKey.ToBytes(), Encoding.ASCII.GetBytes(pass));
                    singer.E2e.Group.Client.Epass = BitConverter.ToString(e_pass).Replace("-", "").ToLower();
                    group.Add("e_client", new Dictionary<string, object>() {
                        {"e_pass", singer.E2e.Group.Client.Epass}
                    });

                }
                if( null != singer.E2e.Group.User)
                {
                    byte[] pubKey = MifielUtils.StringToByteArray(singer.E2e.Group.User.Pub);
                    byte[] e_pass = ecies.Encrypt(pubKey, Encoding.ASCII.GetBytes(pass));
                    singer.E2e.Group.User.Epass = BitConverter.ToString(e_pass).Replace("-", "").ToLower();
                    group.Add("e_user", new Dictionary<string, object>() {
                        {"e_pass", singer.E2e.Group.User.Epass}
                    });
                }
                signerDictionary.Add(singer.Id, group);
            }

            Dictionary<string, object> signatories = new Dictionary<string, object>(){
                {"signatories", signerDictionary}
            };

            string json = (new JavaScriptSerializer()).Serialize((object)signatories);
            HttpContent httpContent = new StringContent(json, Encoding.UTF8, "application/json");
            HttpContent httpResponse = apiClient.Put(_documentsPath + "/" + document.Id, httpContent);
            string response = httpResponse.ReadAsStringAsync().Result;
            return MifielUtils.ConvertJsonToObject<Document>(response);
        }

        private ExtKey GetPublicDerivedKey(string index)
        {
            KeyPath keyPath = KeyPath.Parse(index);
            return apiClient.MasterKey.Derive(keyPath);
        }
    }
}
