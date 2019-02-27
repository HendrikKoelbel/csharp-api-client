using System;
using MifielAPI.Exceptions;
using MifielAPI.Objects;
using MifielAPI.Utils;
using System.Collections.Generic;
using System.IO;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;
using MifielAPI.Crypto;

namespace MifielAPI.Dao
{
    public class Documents : BaseObjectDAO<Document>
    {
        private string _documentsPath = "documents";

        public Documents(ApiClient apiClient) : base(apiClient) { }

        public override void Delete(string id)
        {
            ApiClient.Delete(_documentsPath + "/" + id);
        }

        public override Document Find(string id)
        {
            HttpContent httpResponse = ApiClient.Get(_documentsPath + "/" + id);
            string response = httpResponse.ReadAsStringAsync().Result;
            return MifielUtils.ConvertJsonToObject<Document>(response);
        }

        public  CloseDocument Close(string id)
        {
            var stringBuilder=new StringBuilder(_documentsPath);
            stringBuilder.Append("/");
            stringBuilder.Append(id);
            stringBuilder.Append("/close");

            HttpContent httpResponse = ApiClient.Post(stringBuilder.ToString());
            string response = httpResponse.ReadAsStringAsync().Result;
            return MifielUtils.ConvertJsonToObject<CloseDocument>(response);
        }

        public override List<Document> FindAll()
        {
            HttpContent httpResponse = ApiClient.Get(_documentsPath);
            string response = httpResponse.ReadAsStringAsync().Result;
            return MifielUtils.ConvertJsonToObject<List<Document>>(response);
        }

        public void SaveFile(string id, string localPath)
        {
            HttpContent httpResponse = ApiClient.Get(_documentsPath + "/" + id + "/file");
            MifielUtils.SaveHttpResponseToFile(httpResponse, localPath);
        }


        public void SaveXml(string id, string localPath)
        {
            HttpContent httpResponse = ApiClient.Get(_documentsPath + "/" + id + "/xml");
            MifielUtils.SaveHttpResponseToFile(httpResponse, localPath);
        }

        public SignatureResponse RequestSignature(string id, string email, string cc)
        {
            Dictionary<string, string> parameters = new Dictionary<string, string>();
            parameters.Add("email", email);
            parameters.Add("cc", cc);

            FormUrlEncodedContent httpContent = new FormUrlEncodedContent(parameters);
            HttpContent httpResponse = ApiClient.Post(_documentsPath + "/" + id + "/request_signature", httpContent);
            string response = httpResponse.ReadAsStringAsync().Result;
            return MifielUtils.ConvertJsonToObject<SignatureResponse>(response);
        }

        public override Document Save(Document document)
        {
            if (string.IsNullOrEmpty(document.Id))
            {
                if (document.Encrypted)
                {
                    E2ee e2ee = new E2ee(_documentsPath, ApiClient);
                    return e2ee.Create(document);
                }
                else
                { 
                    HttpContent httpContent = MifielUtils.BuildHttpBody(document);
                    HttpContent httpResponse = ApiClient.Post(_documentsPath, httpContent);
                    string response = httpResponse.ReadAsStringAsync().Result;
                    return MifielUtils.ConvertJsonToObject<Document>(response);
                }
            }
            else
            {
                string json = MifielUtils.ConvertObjectToJson(document);
                HttpContent httpContent = new StringContent(json, Encoding.UTF8, "application/json");
                HttpContent httpResponse = ApiClient.Put(_documentsPath, httpContent);
                string response = httpResponse.ReadAsStringAsync().Result;
                return MifielUtils.ConvertJsonToObject<Document>(response);
            }
        }

    }
}
