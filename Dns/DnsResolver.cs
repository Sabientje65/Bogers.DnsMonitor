using System.Net;
using System.Net.Sockets;
using Microsoft.Data.Sqlite;

namespace Bogers.DnsMonitor.Dns;

public class DnsResolver
{
    public static async Task QueryResourceRecords(string hostName)
    {
        await SqliteCache.Initialize();
        
        // 1.1.1.1, cloudflare dns, 00000001_00000001_00000001_00000001
        long myRouterIp = ((long)192 << 0 | ((long)168 << 8) | ((long)1 << 16) | ((long)1 << 24));
        long cloudflareIp = ((byte)1 << 0) | ((byte)1 << 8) | ((byte)1 << 16) | ((byte)1 << 24);
        
        var ns = new IPEndPoint(new IPAddress(RootNameServer.A), 53);
        
        using var udp = new UdpClient(AddressFamily.InterNetwork);
        // udp.Connect(ns);

        // var msg = Message.Request(new Question("bogers.online", RecordType.A));
        var myIPV4 = await QueryARecord(udp, "chapoco.bogers.online", ns);
        Console.WriteLine($"IPV4 for bogers.online is {myIPV4}");
    }

    private static async Task<string> QueryARecord(
        UdpClient udp,
        string name,
        IPEndPoint to
    )
    {
        var answer = await SqliteCache.Find(name, RecordType.A);
        if (answer != null) return answer.Data;
        
        var request = Message.Request(new Question(name, RecordType.A));
        await udp.SendAsync(MessageSerializer.Serialize(request), to);
        var responseBuffer = await udp.ReceiveAsync();
        var response = MessageSerializer.Deserialize(responseBuffer.Buffer);

        answer = response.Answer.FirstOrDefault(x => x.Type == RecordType.A) ?? 
                     response.Additional.FirstOrDefault(x => x.Type == RecordType.A && x.Data.Equals(name));

        if (answer != null) return answer.Data;

        foreach (var rr in response.Answer.Where(x => x.Type == RecordType.A)) await SqliteCache.Add(rr);
        foreach (var rr in response.Additional.Where(x => x.Type == RecordType.A)) await SqliteCache.Add(rr);

        foreach (var ns in response.Authority)
        {
            if (ns.Type != RecordType.NS) continue;

            // take A records for ease, can also take AAAA as fallback?
            var glue = response.Additional.FirstOrDefault(x => x.Type == RecordType.A && x.Name.Equals(ns.Data));
            var glueData = glue?.Data;
            if (glueData == null)
            {
                glueData = await QueryARecord(udp, ns.Data, new IPEndPoint(RootNameServer.A, 53));
                if (glueData == null) continue;
            }

            var glueEp = IPEndPoint.Parse(glueData);
            glueEp.Port = 53;

            var glueResponse = await QueryARecord(udp, name, glueEp);
            if (!String.IsNullOrEmpty(glueResponse)) return glueResponse;
        }

        return null;
    }

    /// <summary>
    /// SQLite based cache implementation
    /// </summary>
    private class SqliteCache
    {
        private static string ConnectionString = """Data Source=.\dnscache.db; Pooling=True""";

        /// <summary>
        /// Initialize the SQLite cache, ensuring the necessary tables etc. are created
        /// </summary>
        public static async Task Initialize()
        {
            await using var con = CreateConnection();
            await con.OpenAsync();
            await using var cmd = con.CreateCommand();

            cmd.CommandText = """
                CREATE TABLE IF NOT EXISTS resource_records ( 
                    name TEXT collate nocase NOT NULL
                    , type NUMERIC NOT NULL
                    , class NUMERIC NOT NULL
                    , ttl NUMERIC NOT NULL 
                    , data TEXT NOT NULL
                    , created INTEGER DEFAULT CURRENT_TIMESTAMP
                );
                
                CREATE INDEX IF NOT EXISTS resource_records_name_type_ttl_created ON resource_records (name, type, ttl, created) 
            """;

            await cmd.ExecuteNonQueryAsync();
        }
        
        /// <summary>
        /// Add a resource record to the cache
        /// </summary>
        /// <param name="record">Record to cache</param>
        public static async Task Add(ResourceRecord record)
        {
            await using var con = CreateConnection();
            await con.OpenAsync();
            await using var cmd = con.CreateCommand();

            cmd.CommandText = """
                INSERT INTO resource_records (name, type, class, ttl, data)
                values (@name, @type, @class, @tll, @data)
            """;

            cmd.Parameters.Add("@name", SqliteType.Text).Value = record.Name;
            cmd.Parameters.Add("@type", SqliteType.Text).Value = record.Type;
            cmd.Parameters.Add("@class", SqliteType.Text).Value = record.Class;
            cmd.Parameters.Add("@tll", SqliteType.Text).Value = record.TimeToLive;
            cmd.Parameters.Add("@data", SqliteType.Text).Value = record.Data;

            await cmd.ExecuteNonQueryAsync();
        }

        /// <summary>
        /// Attempt to lookup a non-expired resource record for the given domain name of the given type
        /// </summary>
        /// <param name="name">Domain name</param>
        /// <param name="type">Record type <see cref="RecordType"/></param>
        /// <returns>Resource record when found</returns>
        public static async Task<ResourceRecord?> Find(string name, ushort type)
        {
            await using var con = CreateConnection();
            await con.OpenAsync();
            await using var cmd = con.CreateCommand();

            cmd.CommandText = """
                SELECT name, type, class, ttl, data
                FROM resource_records
                WHERE name = @name
                    AND type = @type
                    AND ttl < CURRENT_TIMESTAMP
                LIMIT 1
            """;

            cmd.Parameters.Add("@name", SqliteType.Text).Value = name;
            cmd.Parameters.Add("@type", SqliteType.Integer).Value = type;

            await using var reader = await cmd.ExecuteReaderAsync();
            if (!reader.Read()) return null;

            return new ResourceRecord
            {
                Name = reader.GetString(0),
                Type = (ushort)reader.GetInt16(1),
                Class = (ushort)reader.GetInt16(2),
                TimeToLive = reader.GetInt32(3),
                Data = reader.GetString(4),
            };
        }

        /// <summary>
        /// Cleanup expired records from the DB
        /// </summary>
        public Task Vacuum()
        {
            return Task.CompletedTask;
        }

        private static SqliteConnection CreateConnection() => new SqliteConnection(ConnectionString);

        class Config
        {
            public string ConnectionString { get; set; } 
        }
    }


    // todo: Move cache to SQLite DB
    private static class Cache
    {
        private static readonly IDictionary<string, ResourceRecord> _lookup = new Dictionary<string, ResourceRecord>();

        public static Task Flush()
        {
            _lookup.Clear();
            return Task.CompletedTask;
        }

        // todo: account for ttl
        public static void Push(ResourceRecord record) => _lookup[$"{record.Name}_{record.Type}"] = record;
        
        public static ResourceRecord? Lookup(string name, ushort type) => _lookup.TryGetValue($"{name}_{type}", out var record) ? record : null;
        
    }
    
    /// <summary>
    /// Collection of all official root name server IP addresses
    /// </summary>
    static class RootNameServer
    {
        public static readonly long A = ((long)198 << 0) | ((long)41 << 8)  | ((long)0 << 16)   | ((long)4 << 24);
        public static readonly long B = ((long)170 << 0) | ((long)247 << 8) | ((long)170 << 16) | ((long)2 << 24);
        public static readonly long C = ((long)192 << 0) | ((long)33 << 8)  | ((long)4 << 16)   | ((long)12 << 24);
        public static readonly long D = ((long)199 << 0) | ((long)7 << 8)   | ((long)91 << 16)  | ((long)13 << 24);
        public static readonly long E = ((long)192 << 0) | ((long)203 << 8) | ((long)230 << 16) | ((long)10 << 24);
        public static readonly long F = ((long)192 << 0) | ((long)5 << 8)   | ((long)5 << 16)   | ((long)241 << 24);
        public static readonly long G = ((long)192 << 0) | ((long)112 << 8) | ((long)36 << 16)  | ((long)4 << 24);
        public static readonly long H = ((long)198 << 0) | ((long)97 << 8)  | ((long)190 << 16) | ((long)53 << 24);
        public static readonly long I = ((long)192 << 0) | ((long)36 << 8)  | ((long)148 << 16) | ((long)17 << 24);
        public static readonly long J = ((long)192 << 0) | ((long)58 << 8)  | ((long)128 << 16) | ((long)30 << 24);
        public static readonly long K = ((long)193 << 0) | ((long)0 << 8)   | ((long)14 << 16)  | ((long)129 << 24);
        public static readonly long L = ((long)199 << 0) | ((long)7 << 8)   | ((long)83 << 16)  | ((long)42 << 24);
        public static readonly long M = ((long)202 << 0) | ((long)12 << 8)  | ((long)27 << 16)  | ((long)33 << 24);
    }
    
}
