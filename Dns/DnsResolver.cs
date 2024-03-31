using System.Net;
using System.Net.Sockets;

namespace Bogers.DnsMonitor.Dns;

public class DnsResolver
{
    public static async Task QueryResourceRecords(string hostName)
    {
        await SqliteResolverCache.Initialize();
        await SqliteResolverCache.Clean();
        
        // start of by normalizing our hostname
        if (!hostName.EndsWith('.')) hostName += '.';
        
        // 1.1.1.1, cloudflare dns, 00000001_00000001_00000001_00000001
        long myRouterIp = ((long)192 << 0 | ((long)168 << 8) | ((long)1 << 16) | ((long)1 << 24));
        long cloudflareIp = ((byte)1 << 0) | ((byte)1 << 8) | ((byte)1 << 16) | ((byte)1 << 24);
        
        var ns = new IPEndPoint(new IPAddress(RootNameServer.A), 53);
        
        using var udp = new UdpClient(AddressFamily.InterNetwork);
        // udp.Connect(ns);

        // var msg = Message.Request(new Question("bogers.online", RecordType.A));
        var myIPV4 = await QueryARecord(udp, "chapoco.bogers.online.", ns);
        Console.WriteLine($"IPV4 for bogers.online is {myIPV4}");
    }

    private static async Task<string> QueryARecord(
        UdpClient udp,
        string name,
        IPEndPoint to
    )
    {
        var answer = await SqliteResolverCache.FindFirst(name, RecordType.A);
        if (answer != null) return answer.Data;
        
        var request = Message.Request(new Question(name, RecordType.A));
        await udp.SendAsync(MessageSerializer.Serialize(request), to);
        var responseBuffer = await udp.ReceiveAsync();
        var response = MessageSerializer.Deserialize(responseBuffer.Buffer);
        
        // first, cache everything in our response for quicker future lookups
        foreach (var rr in response.Answer) await SqliteResolverCache.Add(rr); 
        foreach (var rr in response.Authority) await SqliteResolverCache.Add(rr); 
        foreach (var rr in response.Additional) await SqliteResolverCache.Add(rr); 
        
        answer = response.Answer.FirstOrDefault(x => x.Type == RecordType.A);
        if (answer != null) return answer.Data;

        foreach (var ns in response.Authority)
        {
            // assumed to always be true
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