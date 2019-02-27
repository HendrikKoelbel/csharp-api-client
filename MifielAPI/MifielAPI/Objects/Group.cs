using Newtonsoft.Json;

namespace MifielAPI.Objects
{
    public class Group
    {
        [JsonProperty("e_client")]
        public EpassClient Client { get; set; }
        [JsonProperty("e_user")]
        public EpassUser User { get; set; }
    }

    public class EpassClient
    {
        [JsonProperty("e_pass")]
        public string Epass { get; set; }
    }

    public class EpassUser
    {
        [JsonProperty("pub")]
        public string Pub { get; set; }
        [JsonProperty("e_pass")]
        public string Epass { get; set; }
    }
}
