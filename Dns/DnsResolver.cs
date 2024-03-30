using System.Net;
using System.Net.Sockets;
using System.Numerics;
using System.Text;

namespace Bogers.DnsMonitor.Dns;

public class DnsResolver
{
    private static class RootNameServer
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
    
    public static async Task QueryResourceRecords(string host)
    {
        // 1.1.1.1, cloudflare dns, 00000001_00000001_00000001_00000001
        long myRouterIp = ((long)192 << 0 | ((long)168 << 8) | ((long)1 << 16) | ((long)1 << 24));
        long cloudflareIp = ((byte)1 << 0) | ((byte)1 << 8) | ((byte)1 << 16) | ((byte)1 << 24);
        
        var id = new byte[2];
        Random.Shared.NextBytes(id);

        // BitMask.ReadNybble(0b1111_0001, 3);
        // BitMask.ReadNybble(0b1000_1111, 7);
        // BitMask.ReadNybble(0b1100_0111, 6);

        // using var sock = new Socket(SocketType.Dgram, ProtocolType.Udp);
        // var cloudflare = new IPEndPoint(new IPAddress(cloudflareIp), 53);
        // var myRouter = new IPEndPoint(new IPAddress(myRouterIp), 53);
        var root = new IPEndPoint(new IPAddress(RootNameServer.A), 53);
        
        using var udp = new UdpClient(AddressFamily.InterNetwork);
        udp.Connect(root);

        var msg = Message.Request(new Question("online", RecordType.A));
        
        // var bytes = new List<byte>(new Header {
        //     Id = (ushort)((id[0] << 8) | id[1]),
        //     QuestionCount = 1,
        //     OpCode = OpCode.Standard
        // }.Serialize());
        //
        // bytes.AddRange(new Question
        // {
        //     Name = "online",
        //     QuestionClass = 1, // A
        //     QuestionType = 1 // IN
        // }.Serialize());

        var serialized = MessageSerializer.Serialize(msg);
        await udp.SendAsync(serialized);
        var result = await udp.ReceiveAsync();

        var original = result.Buffer;
        var message = MessageSerializer.Deserialize(result.Buffer);
        var reSerialized = MessageSerializer.Serialize(message);
        var diff = original
            .Select((b, i) => new { b, i })
            .Where((v) => reSerialized[v.i] != v.b)
            .Select((v) => new { i = v.i, o = v.b, n = reSerialized[v.i] })
            .ToArray();
        
        var message2 = MessageSerializer.Deserialize(reSerialized);
    }
    
}

static class MessageSerializer
{
    /// <summary>
    /// Deserialize and decompress a message based on the RFC-1035 message format https://datatracker.ietf.org/doc/html/rfc1035#section-4
    /// </summary>
    /// <param name="src">Message to deserialize</param>
    /// <returns>Deserialized message</returns>
    public static Message Deserialize(byte[] src)
    {
        var idx = 0;
        
        var header = DeserializeHeader(src, ref idx);
        var questions = new Question[header.QuestionCount];
        var answers = new ResourceRecord[header.AnswerCount];
        var authorities = new ResourceRecord[header.NameServerCount];
        var additionalRecords = new ResourceRecord[header.AdditionalRecordCount];
        for (var rrIdx = 0; rrIdx < questions.Length; rrIdx++) questions[rrIdx] = DeserializeQuestion(src, ref idx);
        for (var rrIdx = 0; rrIdx < answers.Length; rrIdx++) answers[rrIdx] = DeserializeResourceRecord(src, ref idx);
        for (var rrIdx = 0; rrIdx < authorities.Length; rrIdx++) authorities[rrIdx] = DeserializeResourceRecord(src, ref idx);
        for (var rrIdx = 0; rrIdx < additionalRecords.Length; rrIdx++) additionalRecords[rrIdx] = DeserializeResourceRecord(src, ref idx);

        return new Message
        {
            Header = header,
            Question = questions,
            Answer = answers,
            Authority = authorities,
            Additional = additionalRecords
        };
    }

    /// <summary>
    /// Serialize and compress a message based on the RFC-1035 message format https://datatracker.ietf.org/doc/html/rfc1035#section-4
    /// </summary>
    /// <param name="message">Message to serialize</param>
    /// <returns>Serialized message</returns>
    public static byte[] Serialize(Message message)
    {
        // length is based on contained data, currently we calculate everything on the fly
        // if deemed necessary, length can also be calculated beforehand on field modification
        // all kinda depends on how often length is used
        var buffer = new byte[512]; // max size
        var idx = 0;
        var seen = new Dictionary<string, byte>();

        SerializeHeader(message.Header, buffer, ref idx);
        foreach (var question in message.Question) SerializeQuestion(question, buffer, seen, ref idx);
        foreach (var answer in message.Answer) SerializeResourceRecord(answer, buffer, seen, ref idx);
        foreach (var authority in message.Authority) SerializeResourceRecord(authority, buffer, seen, ref idx);
        foreach (var additional in message.Additional) SerializeResourceRecord(additional, buffer, seen, ref idx);

        return buffer;
    }
    
    /// <summary>
    /// Deserialize a header according to https://datatracker.ietf.org/doc/html/rfc1035#section-4.1.1
    /// </summary>
    /// <param name="src">Source byte array to deserialize header from</param>
    /// <param name="idx">Current index in deserialization process</param>
    /// <returns>DNS message header</returns>
    private static Header DeserializeHeader(byte[] src, ref int idx)
    {
        // header is always 12 bytes long
        idx += 12;
        
        return new Header
        {
            Id = (byte)(src[0] << 8 | src[1]),

            IsResponse = BitMask.IsSet(src[2], 7),
            OpCode = BitMask.ReadNybble(src[2], 6),
            IsAuthoritativeAnswer = BitMask.IsSet(src[2], 2),
            IsTruncated = BitMask.IsSet(src[2], 1),
            RecursionDesired = BitMask.IsSet(src[2], 0),

            RecursionAvailable = BitMask.IsSet(src[3], 7),
            ResponseCode = BitMask.ReadNybble(src[3], 3),

            QuestionCount = (byte)(src[4] << 8 | src[5]),
            AnswerCount = (byte)(src[6] << 8 | src[7]),
            NameServerCount = (byte)(src[8] << 8 | src[9]),
            AdditionalRecordCount = (byte)(src[10] << 8 | src[11]),
        };
    }

    /// <summary>
    /// Deserialize a question according to https://datatracker.ietf.org/doc/html/rfc1035#section-4.1.2
    /// </summary>
    /// <param name="src">Source byte array to deserialize header from</param>
    /// <param name="idx">Current index in deserialization process</param>
    /// <returns>DNS message question</returns>
    private static Question DeserializeQuestion(byte[] src, ref int idx)
    {
        return new Question
        {
            Name = NameUtils.ReadName(src, ref idx),
            QuestionType = (ushort)(src[idx++] << 8 | src[idx++]),
            QuestionClass = (ushort)(src[idx++] << 8 | src[idx++]),
        };
    }

    /// <summary>
    /// Deserialize a resource record according to https://datatracker.ietf.org/doc/html/rfc1035#section-4.1.3
    /// </summary>
    /// <param name="src">Source byte array to deserialize header from</param>
    /// <param name="idx">Current index in deserialization process</param>
    /// <returns>DNS message resource record</returns>
    private static ResourceRecord DeserializeResourceRecord(byte[] src, ref int idx)
    {
        var name = NameUtils.ReadName(src, ref idx);
        var type = (short)((src[idx++] << 8) | src[idx++]);
        var cls = (short)((src[idx++] << 8) | src[idx++]);
        var ttl = ((src[idx++] << 24) | (src[idx++] << 16) | (src[idx++] << 8) | (src[idx++]));
        var data = type switch
        {
            RecordType.A => DeserializeHostAddress(src, ref idx),
            RecordType.AAAA => DeserializeHostAddress(src, ref idx),
            RecordType.NS => DeserializeNS(src, ref idx),
            _ => DeserializeUnknownData(src, ref idx)
        };

        return new ResourceRecord
        {
            Name = name,
            Type = type,
            Class = cls,
            TimeToLive = ttl,
            Data = data
        };
    }
    
    /// <summary>
    /// Skip the given data section by moving the index past it
    /// </summary>
    private static string DeserializeUnknownData(byte[] src, ref int idx)
    {
        var length = (short)((short)src[idx++] << 8) | ((short)src[idx++]);
        idx += length;
        return String.Empty;
    }

    /// <summary>
    /// Deserialize a host address, can be ipv4 or ipv6
    /// </summary>
    private static string DeserializeHostAddress(byte[] src, ref int idx)
    {
        var length = (short)((short)src[idx++] << 8) | ((short)src[idx++]);
        var ip = new IPAddress(src[idx..(idx + length)]);
        idx += length;
        return ip.ToString();
    }
    
    /// <summary>
    /// Deserialize a name server name
    /// </summary>
    private static string DeserializeNS(byte[] src, ref int idx)
    {
        var length = (short)((short)src[idx++] << 8) | ((short)src[idx++]);
        var label = NameUtils.ReadName(src, idx);
        idx += length;
        return label;
    }
    
    /// <summary>
    /// Serialize a header according to https://datatracker.ietf.org/doc/html/rfc1035#section-4.1.1
    /// </summary>
    /// <param name="header">Header to serialize</param>
    /// <param name="buffer">Buffer to write serialized header to</param>
    /// <param name="idx">Current index in serialization process</param>
    private static void SerializeHeader(Header header, byte[] buffer, ref int idx)
    {
        idx += 12;
        
        buffer[0] = BitMask.ReadOctet(header.Id, 1);
        buffer[1] = BitMask.ReadOctet(header.Id, 0);
        if (header.IsResponse) buffer[2] |= 0b_1_0000000;
        buffer[2] |= (byte)(BitMask.ReadNybble(header.OpCode, 3) << 3);
        if (header.IsAuthoritativeAnswer) buffer[2] |= 00000_1_00;
        if (header.IsTruncated) buffer[2] |= 000000_1_0;
        if (header.RecursionDesired) buffer[2] |= 000000_1;

        if (header.RecursionAvailable) buffer[3] |= 0b_1_0000000;
        buffer[3] |= (BitMask.ReadNybble(header.ResponseCode, 3));
        
        buffer[4] = BitMask.ReadOctet(header.QuestionCount, 1);
        buffer[5] = BitMask.ReadOctet(header.QuestionCount, 0);
            
        buffer[6] = BitMask.ReadOctet(header.AnswerCount, 1);
        buffer[7] = BitMask.ReadOctet(header.AnswerCount, 0);
        
        buffer[8] = BitMask.ReadOctet(header.NameServerCount, 1);
        buffer[9] = BitMask.ReadOctet(header.NameServerCount, 0);
        
        buffer[10] = BitMask.ReadOctet(header.AdditionalRecordCount, 1);
        buffer[11] = BitMask.ReadOctet(header.AdditionalRecordCount, 0);
    }
    
    /// <summary>
    /// Serialize a question according to https://datatracker.ietf.org/doc/html/rfc1035#section-4.1.2
    /// </summary>
    /// <param name="question">Question to serialize</param>
    /// <param name="buffer">Buffer to write serialized header to</param>
    /// <param name="idx">Current index in serialization process</param>
    private static void SerializeQuestion(Question question, byte[] buffer, Dictionary<string, byte> seen, ref int idx) 
    {
        NameUtils.SerializeName(question.Name, buffer, seen, ref idx);
        buffer[idx++] = BitMask.ReadOctet(question.QuestionType, 1);
        buffer[idx++] = BitMask.ReadOctet(question.QuestionType, 0);
        buffer[idx++] = BitMask.ReadOctet(question.QuestionClass, 1);
        buffer[idx++] = BitMask.ReadOctet(question.QuestionClass, 0);
    }

    /// <summary>
    /// Serialize a resource record according to https://datatracker.ietf.org/doc/html/rfc1035#section-4.1.3
    /// </summary>
    /// <param name="resourceRecord">Resource record to serialize</param>
    /// <param name="buffer">Buffer to write serialized header to</param>
    /// <param name="idx">Current index in serialization process</param>
    private static void SerializeResourceRecord(ResourceRecord resourceRecord, byte[] buffer, Dictionary<string, byte> seen, ref int idx)
    {
        NameUtils.SerializeName(resourceRecord.Name, buffer, seen, ref idx);
        buffer[idx++] = BitMask.ReadOctet(resourceRecord.Type, 1);
        buffer[idx++] = BitMask.ReadOctet(resourceRecord.Type, 0);
        buffer[idx++] = BitMask.ReadOctet(resourceRecord.Class, 1);
        buffer[idx++] = BitMask.ReadOctet(resourceRecord.Class, 0);
        buffer[idx++] = BitMask.ReadOctet(resourceRecord.TimeToLive, 3);
        buffer[idx++] = BitMask.ReadOctet(resourceRecord.TimeToLive, 2);
        buffer[idx++] = BitMask.ReadOctet(resourceRecord.TimeToLive, 1);
        buffer[idx++] = BitMask.ReadOctet(resourceRecord.TimeToLive, 0);
        
        // fixme: include rdatalength, should be based on data (type)
        var length = resourceRecord.Type switch
        {
            RecordType.A => 4,
            RecordType.NS => NameUtils.CalculateNameLength(resourceRecord.Data, seen),
            RecordType.AAAA => 16,
            _ => 0
        };
        
        buffer[idx++] = BitMask.ReadOctet(length, 1);
        buffer[idx++] = BitMask.ReadOctet(length, 0);
        
        switch (resourceRecord.Type)
        {
            case RecordType.NS:
                NameUtils.SerializeName(resourceRecord.Data, buffer, seen, ref idx);
                break;
            case RecordType.A:
            case RecordType.AAAA:
                SerializeIp(resourceRecord.Data, buffer, ref idx);
                break;
        }
    }

    private static void SerializeIp(string ip, byte[] buffer, ref int idx)
    {
        var bytes = IPAddress.Parse(ip).GetAddressBytes();
        bytes.CopyTo(buffer, idx);
        idx += bytes.Length;
    }
    
}

/// <summary>
/// Message format according to https://datatracker.ietf.org/doc/html/rfc1035#section-4
/// </summary>
struct Message
{
    public Message()
    {
        Header = new Header();
        Question = Array.Empty<Question>();
        Answer = Array.Empty<ResourceRecord>();
        Authority = Array.Empty<ResourceRecord>();
        Additional = Array.Empty<ResourceRecord>();
    }

    /// <summary>
    /// Simple constructor building a valid question request message
    /// </summary>
    /// <param name="question">Single question</param>
    /// <returns>Message</returns>
    public static Message Request(Question question) => Request([question]);

    /// <summary>
    /// Simple constructor building a valid question request message
    /// </summary>
    /// <param name="questions">Collection of questions to include in message</param>
    /// <returns>Message</returns>
    public static Message Request(Question[] questions) => new Message
    {
        Header = new Header
        {
            Id = (ushort)Random.Shared.Next(),
            QuestionCount = (byte)questions.Length
        },
        Question = questions
    };

    public Header Header;

    public Question[] Question;

    public ResourceRecord[] Answer;

    public ResourceRecord[] Authority;

    public ResourceRecord[] Additional;
}


struct Question
{
    public Question(string name, ushort questionType)
    {
        // normalize
        if (!name.EndsWith('.')) name += '.';
        
        Name = name;
        QuestionType = questionType;
        QuestionClass = RecordClass.IN;
    }
    
    public string Name;

    public ushort QuestionType;

    public ushort QuestionClass;
}

/// <summary>
/// Collection of utilities for reading/writing domain names from and to DNS messages
/// </summary>
public static class NameUtils
{

    /// <summary>
    /// Read the domain name at the given index, index will be advanced to the end of the name 
    /// </summary>
    /// <param name="src">Source to read domain name from</param>
    /// <param name="idx">Starting index</param>
    /// <returns>Domain name</returns>
    public static string ReadName(byte[] src, ref int idx)
    {
        int length;
        
        // pointer -> static length of 2
        if (IsPointer(src, idx)) length = 2;
        else
        {
            // sequence length + sequence content
            length = src[idx] + 1;
            
            // sequences end with either a pointer (2 bytes) or a terminator (1 byte)
            length += IsPointer(src, src[idx + length]) ? 2 : 1;
        }
        
        var sb = new StringBuilder();
        AppendLabelSequence(sb, src, idx);
        idx += length;
        return sb.ToString();
    }
    
    /// <summary>
    /// Read the domain name at the given index 
    /// </summary>
    /// <param name="src">Source to read domain name from</param>
    /// <param name="idx">Starting index</param>
    /// <returns>Domain name</returns>
    public static string ReadName(byte[] src, int idx)
    {
        var sb = new StringBuilder();
        AppendLabelSequence(sb, src, idx);
        return sb.ToString();
    }

    /// <summary>
    /// Append the sequence of labels starting at the given index, see https://datatracker.ietf.org/doc/html/rfc1035#section-4.1.4
    /// </summary>
    /// <param name="sb">StringBuilder to append labels to</param>
    /// <param name="src">Source to read labels from</param>
    /// <param name="idx">Starting index</param>
    private static void AppendLabelSequence(StringBuilder sb, byte[] src, int idx)
    {
        // starts with pointer -> follow pointer to label
        if (IsPointer(src, idx))
        {
            AppendLabelSequence(sb, src, PointerOffset(src, idx));
            return;
        }

        // read until we're either terminated, or find a pointer to follow
        while (
            !IsTerminator(src, idx) &&
            !IsPointer(src, idx)
        )
        {
            var length = src[idx];
            sb.Append(Encoding.ASCII.GetString(src, idx + 1, length));
            sb.Append('.');
            idx += src[idx] + 1;
        }
        
        // ends with a pointer -> follow pointer
        if (IsPointer(src, idx)) AppendLabelSequence(sb, src, PointerOffset(src, idx));
    }
    
    /// <summary>
    /// Calculate the length the given name would have if it were to be written to a message
    /// </summary>
    /// <param name="name">Sequence of labels separated by `.`</param>
    /// <param name="seen">Dictionary containing positions of already seen names</param>
    /// <returns>Length the label would occupy in bytes if written to a message</returns>
    public static int CalculateNameLength(string name, Dictionary<string, byte> seen)
    {
        // pointer
        if (seen.ContainsKey(name)) return 2;
        
        // local copy, we only care about a value becoming a pointer, use a simple hashset for that
        var seenLite = new HashSet<string>(seen.Keys);

        var length = 0;
        while (true)
        {
            // close sequence with a pointer
            if (!seenLite.Add(name)) return length + 2;
            
            // are we done?
            var segmentEnd = name.IndexOf('.');
            if (segmentEnd == -1) break;

            var segment = name[..segmentEnd];
            
            // assume 1 byte/char + length marker
            length += segment.Length + 1;
            
            // prepare for next segment, ignore segment separator ('.')
            name = name[(segmentEnd + 1)..];
        }

        // account for termiantor
        return length + 1;
    }
    
    /// <summary>
    /// Write the given name to the given buffer starting at the given index, index will be advanced to the end of the name
    /// </summary>
    /// <param name="name">Sequence of labels separated by `.`</param>
    /// <param name="buffer">Buffer to write name two</param>
    /// <param name="seen">Dictionary containing positions of already seen names</param>
    /// <param name="idx">Pointer to current position in the buffer</param>
    public static void SerializeName(string name, byte[] buffer, Dictionary<string, byte> seen, ref int idx)
    {
        // b.nic.online
        // entire label sequence can be a pointer
        if (seen.TryGetValue(name, out var pointerOffset))
        {
            buffer[idx++] = 0b1100_0000;
            buffer[idx++] = pointerOffset;
            return;
        }

        while (true)
        {
            // close sequence with a pointer
            if (seen.TryGetValue(name, out pointerOffset))
            {
                buffer[idx++] = 0b1100_0000;
                buffer[idx++] = pointerOffset;
                return;
            }
            
            // are we done?
            var segmentEnd = name.IndexOf('.');
            if (segmentEnd == -1) break;
            
            seen[name] = (byte)idx;
            var segment = name[..segmentEnd];
            
            buffer[idx++] = (byte)segment.Length;
            Encoding.ASCII.GetBytes(segment).CopyTo(buffer, idx);
            idx += segment.Length;
            
            // prepare for next segment, ignore segment separator ('.')
            name = name[(segmentEnd + 1)..];
        }

        // 0 byte, terminator
        buffer[idx++] = 0x00;
    }

    private static int PointerOffset(byte[] src, int idx) => ((src[idx] << 8) & 0b0011_1111) | src[idx + 1];
    private static bool IsPointer(byte[] src, int idx) => (src[idx] & 0b1100_0000) == 0b1100_0000;
    private static bool IsTerminator(byte[] src, int idx) => src[idx] == 0b0000_0000;

}

/// <summary>
/// Object representation of a DNS message header https://datatracker.ietf.org/doc/html/rfc1035#section-4.1.1
/// </summary>
struct Header
{
    /// <summary>
    /// Identifier for an individual request
    /// </summary>
    public ushort Id;

    /// <summary>
    /// Whether the message is a response
    /// </summary>
    public bool IsResponse;

    /// <summary>
    /// Query kind, length of 4 bits <see cref="Bogers.DnsMonitor.Dns.OpCode"/>
    /// </summary>
    public byte OpCode;

    /// <summary>
    /// When true, indicates the name server is an authority for the domain name in the message's question section
    /// </summary>
    public bool IsAuthoritativeAnswer;

    /// <summary>
    /// When true, indicates the response has been truncated, full request should be processed over TCP instead of UDP
    /// </summary>
    public bool IsTruncated;

    /// <summary>
    /// Optional, when true, directs the name server to pursue the query recursively
    /// </summary>
    public bool RecursionDesired; // <-- todo, research what 'pursuing a query recursively' implies in the context of a name server
    
    /// <summary>
    /// Indicates recursive query support being available in the name server
    /// </summary>
    public bool RecursionAvailable;

    /// <summary>
    /// Query response code, length of 4 bits <see cref="Bogers.DnsMonitor.Dns.ResponseCode"/>
    /// </summary>
    public byte ResponseCode;

    /// <summary>
    /// Number of entries in message question section
    /// </summary>
    public ushort QuestionCount;

    /// <summary>
    /// Number of entries in message answer section 
    /// </summary>
    public ushort AnswerCount;

    /// <summary>
    /// Number of entries in message name server section
    /// </summary>
    public ushort NameServerCount;

    /// <summary>
    /// Number of entries in message additional record count
    /// </summary>
    public ushort AdditionalRecordCount;

    /// <summary>
    /// Serialize to resource record header format
    /// </summary>
    /// <returns>Headers serialized as byte array</returns>
    // public byte[] Serialize()
    // {
    //     var serialized = new byte[12];
    //     serialized[0] = BitMask.ReadOctet(Id, 1);
    //     serialized[1] = BitMask.ReadOctet(Id, 0);
    //     if (IsResponse) serialized[2] |= 0b_1_0000000;
    //     serialized[2] |= (byte)(BitMask.ReadNybble(OpCode, 3) << 3);
    //     if (IsAuthoritativeAnswer) serialized[2] |= 00000_1_00;
    //     if (IsTruncated) serialized[2] |= 000000_1_0;
    //     if (RecursionDesired) serialized[2] |= 000000_1;
    //
    //     if (RecursionAvailable) serialized[3] |= 0b_1_0000000;
    //     serialized[3] |= (BitMask.ReadNybble(ResponseCode, 3));
    //     
    //     // QDCOUNT
    //     serialized[4] = BitMask.ReadOctet(QuestionCount, 1);
    //     serialized[5] = BitMask.ReadOctet(QuestionCount, 0);
    //
    //     // ANCOUNT
    //     serialized[6] = BitMask.ReadOctet(AnswerCount, 1);
    //     serialized[7] = BitMask.ReadOctet(AnswerCount, 0);
    //     
    //     // NSCOUNT
    //     serialized[8] = BitMask.ReadOctet(NameServerCount, 1);
    //     serialized[9] = BitMask.ReadOctet(NameServerCount, 0);
    //     
    //     // ARCOUNT
    //     serialized[10] = BitMask.ReadOctet(AdditionalRecordCount, 1);
    //     serialized[11] = BitMask.ReadOctet(AdditionalRecordCount, 0);
    //
    //     return serialized;
    // }
    //
    // public static Header Deserialize(byte[] data) => new Header
    // {
    //     Id = (byte)(data[0] << 8 | data[1]),
    //     
    //     IsResponse = BitMask.IsSet(data[2], 7),
    //     OpCode = BitMask.ReadNybble(data[2], 6),
    //     IsAuthoritativeAnswer = BitMask.IsSet(data[2], 2),
    //     IsTruncated = BitMask.IsSet(data[2], 1),
    //     RecursionDesired = BitMask.IsSet(data[2], 0),
    //     
    //     RecursionAvailable = BitMask.IsSet(data[3], 7),
    //     ResponseCode = BitMask.ReadNybble(data[3], 3),
    //     
    //     QuestionCount = (byte)(data[4] << 8 | data[5]),
    //     AnswerCount = (byte)(data[6] << 8 | data[7]),
    //     NameServerCount = (byte)(data[8] << 8 | data[9]),
    //     AdditionalRecordCount = (byte)(data[10] << 8 | data[11]),
    // };
}

struct ResourceRecord
{
    public string Name;
    public short Type;
    public short Class;
    public int TimeToLive;
    public string Data;
}

/// <summary>
/// https://datatracker.ietf.org/doc/html/rfc1035#section-4.1.1
/// </summary>
class OpCode
{
    // private OpCode(byte value) => _value = value;
    //
    // private readonly byte _value;

    /// <summary>
    /// Standard query (QUERY)
    /// </summary>
    public const byte Standard = 0;
    
    /// <summary>
    /// Inverse query (IQUERY)
    /// </summary>
    public const byte Inverse = 1;

    /// <summary>
    /// Server status (STATUS)
    /// </summary>
    public const byte Status = 2;

    // public static explicit operator byte(OpCode c) => c._value;
    // public static implicit operator byte(OpCode c) => c._value;
    //
    // public static implicit operator OpCode(byte b) => b switch
    // {
    //     0 => Standard,
    //     1 => Inverse,
    //     2 => Status,
    //
    //     // reserved for future use
    //     _ => new OpCode(b)
    // };
}

/// <summary>
/// https://datatracker.ietf.org/doc/html/rfc1035#section-4.1.1
/// </summary>
class ResponseCode
{
    /// <summary>
    /// Success
    /// </summary>
    public const byte Ok = 0;

    /// <summary>
    /// Query format not interpretable by server
    /// </summary>
    public const byte FormatError = 1;

    /// <summary>
    /// Name server failed to process the query
    /// </summary>
    public const byte ServerFailure = 2;

    /// <summary>
    /// When returned from an authoritative server, name does not exist
    /// </summary>
    public const byte NameError = 3;

    /// <summary>
    /// Query kind not supported
    /// </summary>
    public const byte NotImplemented = 4;

    /// <summary>
    /// Name server actively refuses to perform the given operation
    /// </summary>
    public const byte Refused = 5;
}

/// <summary>
/// https://datatracker.ietf.org/doc/html/rfc1035#section-3.2.2
/// </summary>
class RecordType
{
    /// <summary>
    /// IPV4 Host address
    /// </summary>
    public const byte A = 1;
    
    /// <summary>
    /// Authoritative name server
    /// </summary>
    public const byte NS = 2;
    
    /// <summary>
    /// Canonical name, alias
    /// </summary>
    public const byte CNAME = 5;
    
    /// <summary>
    /// Start of a zone of authority
    /// </summary>
    public const byte SOA = 5;
    
    /// <summary>
    /// Simple text value
    /// </summary>
    public const byte TXT = 16;
    
    /// <summary>
    /// IPV6 Host address
    /// </summary>
    public const byte AAAA = 28;
}

/// <summary>
/// https://datatracker.ietf.org/doc/html/rfc1035#section-3.2.4
/// </summary>
class RecordClass
{
    /// <summary>
    /// Internet, default
    /// </summary>
    public const byte IN = 1;
}

static class BitMask
{
    /// <summary>
    /// Check if a '1' bit is present at the given position
    /// </summary>
    /// <param name="value">Value</param>
    /// <param name="position">Position to check</param>
    /// <typeparam name="TValue">Numeric type</typeparam>
    /// <returns>True when '1' bit is detected</returns>
    public static bool IsSet<TValue>(TValue value, int position)
        where TValue : IBitwiseOperators<TValue, TValue, TValue>,  // can perform bitwise ops with self
        IComparisonOperators<TValue, TValue, bool>, // can compare with self
        IShiftOperators<TValue, int, TValue>,       // can shift self with int resulting in self
        INumber<TValue>                             // contains 'one' and 'zero' statics
        => (value & (TValue.One << position)) != TValue.Zero;
    
    /// <summary>
    /// Check if a '0' bit is present at the given position
    /// </summary>
    /// <param name="value">Value</param>
    /// <param name="position">Position to check</param>
    /// <typeparam name="TValue">Numeric type</typeparam>
    /// <returns>True when '0' bit is detected</returns>
    public static bool IsUnset<TValue>(TValue value, int position)
        where TValue : IBitwiseOperators<TValue, TValue, TValue>, 
        IComparisonOperators<TValue, TValue, bool>,
        IShiftOperators<TValue, int, TValue>,
        INumber<TValue>
        => (value & (TValue.One << position)) == TValue.Zero;

    /// <summary>
    /// Sets a '1' bit at the given position
    /// </summary>
    /// <param name="value">Base value</param>
    /// <param name="position">Position to set bit at</param>
    /// <typeparam name="TValue">Input/output type</typeparam>
    /// <returns>Copy of <see cref="value"/> with bit at position <see cref="position"/> set to '1'</returns>
    public static TValue Set<TValue>(TValue value, int position)
        where TValue : IBitwiseOperators<TValue, TValue, TValue>,
        IShiftOperators<TValue, int, TValue>,
        INumber<TValue>
        => value | (TValue.One << position);
    
    /// <summary>
    /// Sets a '0' bit at the given position
    /// </summary>
    /// <param name="value">Base value</param>
    /// <param name="position">Position to set bit at</param>
    /// <typeparam name="TValue">Input/output type</typeparam>
    /// <returns>Copy of <see cref="value"/> with bit at position <see cref="position"/> set to '0'</returns>
    public static TValue Unset<TValue>(TValue value, int position)
        where TValue : IBitwiseOperators<TValue, TValue, TValue>,
        IShiftOperators<TValue, int, TValue>,
        INumber<TValue>
        => value & ~(TValue.One << position);

    /// <summary>
    /// Read the byte octet at the given position
    /// </summary>
    /// <param name="value">64 bit integer</param>
    /// <param name="octet">Octet position</param>
    /// <returns>Octet at given position</returns>
    public static byte ReadOctet(long value, int octet) => (byte)(value >> (octet * 8));
    
    /// <summary>
    /// Read the byte octet at the given position
    /// </summary>
    /// <param name="value">32 bit integer</param>
    /// <param name="octet">Octet position</param>
    /// <returns>Octet at given position</returns>
    public static byte ReadOctet(int value, int octet) => (byte)(value >> (octet * 8));
    
    /// <summary>
    /// Read the byte octet from at the given position
    /// </summary>
    /// <param name="value">16 bit integer</param>
    /// <param name="octet">Octet position</param>
    /// <returns>Octet at given position</returns>
    public static byte ReadOctet(short value, int octet) => (byte)(value >> (octet * 8));
    
    /// <summary>
    /// Read the nybble at the given position
    /// </summary>
    /// <param name="value">8 bit integer</param>
    /// <param name="startAt">Starting bit index</param>
    /// <returns>Nybble at given position</returns>
    public static byte ReadNybble(byte value, int startAt)
    {
        // value: 1111_0001 -> startAt(3) -> 0001 => 0000_0001
        // value: 1000_1111 -> startAt(7) -> 1000 1000_0000 -> 0000_1000
        // value: 1100_1111 -> startAt(6) -> 1000 1100_0000 -> 0000_0100
        
        byte r = 0;
        if (IsSet(value, startAt)) r |= 0b1000;
        if (IsSet(value, startAt - 1)) r |= 0b0100;
        if (IsSet(value, startAt - 2)) r |= 0b0010;
        if (IsSet(value, startAt - 3)) r |= 0b0001;
        return r;
    }

    /// <summary>
    /// Calculate the size in bytes of the given value
    /// </summary>
    /// <param name="value">unsigned 64 bit integer</param>
    /// <returns>Size in bytes</returns>
    public static byte SizeOf(ulong value)
    {
        if (value > (1L << 56)) return 8;
        if (value > (1L << 48)) return 7;
        if (value > (1L << 40)) return 6;
        if (value > (1L << 32)) return 5;
        if (value > (1L << 24)) return 4;
        if (value > (1L << 16)) return 3;
        if (value > (1L << 8)) return 2;
        return 1;
    }
    
    /// <summary>
    /// Calculate the size in bytes of the given value
    /// </summary>
    /// <param name="value">64 bit integer</param>
    /// <returns>Size in bytes</returns>
    public static byte SizeOf(long value)
    {
        if (value > (1L << 56)) return 8;
        if (value > (1L << 48)) return 7;
        if (value > (1L << 40)) return 6;
        if (value > (1L << 32)) return 5;
        if (value > (1L << 24)) return 4;
        if (value > (1L << 16)) return 3;
        if (value > (1L << 8)) return 2;
        return 1;
    }
    
    /// <summary>
    /// Calculate the size in bytes of the given value
    /// </summary>
    /// <param name="value">32 bit integer</param>
    /// <returns>Size in bytes</returns>
    public static byte SizeOf(int value)
    {
        if (value > (1 << 24)) return 4;
        if (value > (1 << 16)) return 3;
        if (value > (1 << 8)) return 2;
        return 1;
    }

    /// <summary>
    /// Calculate the size in bytes of the given value
    /// </summary>
    /// <param name="value">unsigned 32 bit integer</param>
    /// <returns>Size in bytes</returns>
    public static byte SizeOf(uint value)
    {
        if (value > (1 << 24)) return 4;
        if (value > (1 << 16)) return 3;
        if (value > (1 << 8)) return 2;
        return 1;
    }
}
