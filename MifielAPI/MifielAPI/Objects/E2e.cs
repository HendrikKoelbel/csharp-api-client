using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace MifielAPI.Objects
{
    public class E2e
    {
        [JsonProperty("e_index")]
        public string Index { get; set; }
        [JsonProperty("group")]
        public Group Group { get; set; } 
    }
}
