using Newtonsoft.Json;
using NUnit.Framework;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace MifielAPITests.crypto
{
    public class CryptoTest<T>
    {
        protected List<T> ArrayTest { get; }
        private readonly string _currentDirectory = Path.GetFullPath(TestContext.CurrentContext.WorkDirectory);

        public CryptoTest(string fixturePath)
        {
            ArrayTest = LoadJson(fixturePath);
        }

        private List<T> LoadJson( string fixturePath)
        {
            string filePath = Path.Combine(_currentDirectory, fixturePath);
            StreamReader r = new StreamReader(filePath);
            string json = r.ReadToEnd();
            List<T> items = JsonConvert.DeserializeObject<List<T>>(json);
            return items;
        }

        protected byte[] StringToByteArray(String hex)
        {
            int NumberChars = hex.Length;
            byte[] bytes = new byte[NumberChars / 2];
            for (int i = 0; i < NumberChars; i += 2)
                bytes[i / 2] = Convert.ToByte(hex.Substring(i, 2), 16);
            return bytes;
        }
    }
}
