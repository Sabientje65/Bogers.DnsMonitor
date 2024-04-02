using System.Net;
using System.Net.Sockets;

namespace Bogers.DnsMonitor.Dns;

class DnsResolver : IDisposable
{
    private readonly UdpClient _udp = new UdpClient(AddressFamily.InterNetwork);
    private readonly SqliteResolverCache _resolverCache;

    public DnsResolver(SqliteResolverCache resolverCache) => _resolverCache = resolverCache;
    
    /// <summary>
    /// Resolve the IPV4 address associated with the given domain name
    /// </summary>
    /// <param name="name">Domain name</param>
    /// <returns>IPV4 for the given domain or null when resolution failed</returns>
    public async Task<string?> ResolveIPV4(string name)
    {
        // start of by normalizing our hostname
        if (!name.EndsWith('.')) name += '.';
        
        // follow cname to actual name
        var cname = await _resolverCache.FindFirst(name, RecordType.CNAME);
        if (cname != null) name = cname.Data;
        
        var answer = await _resolverCache.FindFirst(name, RecordType.A);
        if (answer != null) return answer.Data;

        var ns = await ResolveNS(name);
        var result = await ResolveIPV4(name, ns);
        
        // assuming we got our ns from cache... try one last time starting from a root server
        if (String.IsNullOrEmpty(result)) result = await ResolveIPV4(name, new IPAddress(RootNameServer.A));

        return result;
    }
    
    /// <summary>
    /// Resolve the IPV4 address associated with the given domain name using the given nameserver as starting point
    /// </summary>
    /// <param name="name">Domain name</param>
    /// <param name="ns">Nameserver to use as starting point</param>
    /// <returns>When found, IPV4 address associated with the given domain</returns>
    private async Task<string?> ResolveIPV4(string name, IPAddress ns)
    {
        var response = await QueryRemote(ns, new Question(name, RecordType.A)); 
        var answer = response.Answer.FirstOrDefault(x => x.Type == RecordType.A);
        if (answer != null) return answer.Data;
            
        foreach (var nsRecord in response.Authority)
        {
            // assumed to always be true
            if (nsRecord.Type != RecordType.NS) continue;

            // take A records for ease, can also take AAAA as fallback?
            var glue = response.Additional.FirstOrDefault(x => x.Type == RecordType.A && x.Name.Equals(nsRecord.Data));
            var glueData = glue?.Data;
            if (glueData == null)
            {
                var glueNS = await ResolveNS(nsRecord.Data);
                glueData = await ResolveIPV4(nsRecord.Data, glueNS);
                if (glueData == null) continue;
            }

            var glueResponse = await ResolveIPV4(name, IPAddress.Parse(glueData));
            if (!String.IsNullOrEmpty(glueResponse)) return glueResponse;
        }

        return null;
    }
    
    /// <summary>
    /// Resolve the IP address of the NameServer server for the given <paramref name="name"/>
    /// </summary>
    /// <param name="name">Domain name</param>
    /// <returns>NameServer IP address</returns>
    private async Task<IPAddress> ResolveNS(string name)
    {
        // first try searching for our specific domain
        var segments = name.Split('.');
        var domains = new string[segments.Length - 1];
        for (var i = 0; i < domains.Length; i++) domains[i] = String.Join('.', segments[i..]);

        foreach (var domain in domains)
        {
            var nsRecord = await _resolverCache.FindFirst(domain, RecordType.NS);
            if (nsRecord == null) continue;
                
            // we do know our ns, just not its ip, take slow path -> full lookup
            var nsIP = await ResolveIPV4(nsRecord.Data);
            if (!String.IsNullOrEmpty(nsIP)) return IPAddress.Parse(nsIP);
        }

        // worst case scenario, default to one of the root servers
        return new IPAddress(RootNameServer.A);
    }
    
    
    /// <summary>
    /// Collection of pending query responses
    /// </summary>
    private readonly IDictionary<ushort, TaskCompletionSource<Message>> _pending = new Dictionary<ushort, TaskCompletionSource<Message>>();
    
    /// <summary>
    /// Query the  <paramref name="remote"/> for the given <paramref name="question"/> 
    /// </summary>
    /// <param name="remote">Remote address</param>
    /// <param name="question">DNS question</param>
    /// <returns>Answer message</returns>
    private async Task<Message> QueryRemote(IPAddress remote, Question question)
    {
        var ep = new IPEndPoint(remote, 53);
        var req = Message.Request(question);
        // byte[] responseBuffer;

        Task<Message> myResponse;
        lock (_pending) myResponse = (_pending[req.Header.Id] = new TaskCompletionSource<Message>()).Task;
            
        await _udp.SendAsync(MessageSerializer.Serialize(req), ep);
        
        // response is not guaranteed to be for our query, could also be for another query fired earlier on
        var responseMessage = MessageSerializer.Deserialize(
            (await _udp.ReceiveAsync()).Buffer
        );
        
        lock (_pending)
        {
            if (_pending.TryGetValue(responseMessage.Header.Id, out var pending))
            {
                pending.SetResult(responseMessage);
                _pending.Remove(responseMessage.Header.Id);
            }
        }
        
        var msg = await myResponse;

        // first, cache everything in our response for quicker future lookups
        foreach (var rr in msg.Answer) await _resolverCache.Add(rr); 
        foreach (var rr in msg.Authority) await _resolverCache.Add(rr); 
        foreach (var rr in msg.Additional) await _resolverCache.Add(rr); 

        return msg;
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

    public void Dispose()
    {
        _udp.Dispose();
        
        // should our resolver own its cache? -> create cache from factory?
        // _resolverCache.Dispose();
    }
}
