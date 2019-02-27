using System.IO;
using System.Collections.Generic;
using NUnit.Framework;
using MifielAPI;
using MifielAPI.Objects;
using MifielAPI.Dao;
using MifielAPI.Crypto;
using System.Web.Script.Serialization;
using MifielAPI.Utils;

namespace MifielApiTests
{
    [TestFixture]
    public class DocumentsE2eeTests
    {
        private static ApiClient _apiClient;
        private static Documents _docs;
        private static string _pdfFilePath;

        private readonly string _currentDirectory = Path.GetFullPath(TestContext.CurrentContext.TestDirectory);

        [SetUp]
        public void SetUp()
        {
            string appId = "9eb50147761dc169444c346c0e281fb8f327aecb";
            string appSecret = "doSudYTvdpnFpkppHMU/Xjg6mF6Z3UUgurUhbHhzfQevPv2DXeJxGA6U9zXzDADWMbGnRH3PNKaTlAdSoMEvIw==";

            _pdfFilePath = Path.Combine(_currentDirectory, "test-pdf.pdf");
            _apiClient = new ApiClient(appId, appSecret);
            _docs = new Documents(_apiClient);
        }

        [Test]
        public void Documents__FindAllDocuments__ShouldReturnAList()
        {
            SetSandboxUrl();
            var allDocuments = _docs.FindAll();
            Assert.IsNotNull(allDocuments);
        }

        [Test]
        public void Documents__SaveWithFilePath__ShouldReturnADocument()
        {
            SetSandboxUrl();
            _apiClient.SetMasterFromSeed("000102030405060708090a0b0c0d0e0f");
            var document = new Document()
            {
                File = Path.Combine(_currentDirectory, _pdfFilePath),
                ManualClose = false,
                CallbackUrl = "https://requestb.in/1cuddmz1",
                Encrypted = true 
            };

            var signatures = new List<Signature>(){
                new Signature(){
                    Email = "ja.zavala.aguilar@gmail.com",
                    TaxId = "ZAAJ8301061E0",
                    SignerName = "Juan Antonio Zavala Aguilar"
                },
                   new Signature(){
                    Email = "genmadrid@gmail.com",
                    TaxId = "MARG840730UP8",
                    SignerName = "GENARO MADRID RAMIREZ"
                }
            };
           
            document.Signatures = signatures;
            document = _docs.Save(document);
            Assert.IsNotNull(document);
        }

        [Test]
        public void Documents__Find__ShouldReturnADocument()
        {
            SetSandboxUrl();
            _docs.SaveFile("75e9ee45-d8ae-4345-93b0-3f12206bf096", Path.Combine(_currentDirectory, "pdf_save_test.pdf.enc"));
        }

        private void SetSandboxUrl()
        {
            _apiClient.Url = "http://192.168.1.70:3000";
            //_apiClient.Url = "https://sandbox.mifiel.com";
        }
    }
}
