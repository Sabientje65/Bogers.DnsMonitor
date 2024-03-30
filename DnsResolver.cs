using System.Collections;
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Numerics;
using System.Runtime.InteropServices;
using System.Text;

namespace Bogers.DnsMonitor;

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
 
        var bytes = new List<byte>(new Header {
            Id = (ushort)((id[0] << 8) | id[1]),
            QuestionCount = 1,
            OpCode = 0
        }.Serialize());
        
        bytes.AddRange(new Question
        {
            Name = "online",
            QuestionClass = 1, // A
            QuestionType = 1 // IN
        }.Serialize());
        
        await udp.SendAsync(bytes.ToArray());
        var result = await udp.ReceiveAsync();

        var original = result.Buffer;
        var message = Message.Deserialize(result.Buffer);
        var reSerialized = message.Serialize();
        var diff = original
            .Select((b, i) => new { b, i })
            .Where((v) => reSerialized[v.i] != v.b)
            .Select((v) => new { i = v.i, o = v.b, n = reSerialized[v.i] })
            .ToArray();
        
        var message2 = Message.Deserialize(reSerialized);

        // todo: make span/memory<byte>
        // var resultBuffer = result.Buffer;

        // var response = Header.Deserialize(resultBuffer);
        // var question = Question.Deserialize(resultBuffer, 12);
        // var idx = 12 + question.Serialize().Length;
        // var resourceRecords = new ResourceRecord[response.ResourceRecordCount];
        // var nameServerRecords = new ResourceRecord[response.NameServerResourceRecordCount];
        // var additionalRecords = new ResourceRecord[response.AdditionalRecordCount];
        // for (var rrIdx = 0; rrIdx < resourceRecords.Length; rrIdx++) resourceRecords[rrIdx] = ResourceRecord.Deserialize(resultBuffer, ref idx);
        // for (var rrIdx = 0; rrIdx < nameServerRecords.Length; rrIdx++) nameServerRecords[rrIdx] = ResourceRecord.Deserialize(resultBuffer, ref idx);
        // for (var rrIdx = 0; rrIdx < additionalRecords.Length; rrIdx++) additionalRecords[rrIdx] = ResourceRecord.Deserialize(resultBuffer, ref idx);

        // var res = 0;
    }
    
}

/// <summary>
/// Message format according to https://datatracker.ietf.org/doc/html/rfc1035#section-4
/// </summary>
struct Message
{

    public Header Header;

    public Question[] Question;

    public ResourceRecord[] Answer;

    public ResourceRecord[] Authority;

    public ResourceRecord[] Additional;

    public static Message Deserialize(byte[] src)
    {
        var idx = 0;
        
        var header = DeserializeHeader(src, ref idx);
        var questions = new Question[header.QuestionCount];
        var answers = new ResourceRecord[header.ResourceRecordCount];
        var authorities = new ResourceRecord[header.NameServerResourceRecordCount];
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

    public byte[] Serialize()
    {
        // length is based on contained data, currently we calculate everything on the fly
        // if deemed necessary, length can also be calculated beforehand on field modification
        // all kinda depends on how often length is used
        var buffer = new byte[512]; // max size
        var idx = 0;
        var seen = new Dictionary<string, byte>();

        SerializeHeader(buffer, ref idx);
        SerializeQuestions(buffer, seen, ref idx);
        foreach (var answer in Answer) SerializeResourceRecord(answer, buffer, seen, ref idx);
        foreach (var authority in Authority) SerializeResourceRecord(authority, buffer, seen, ref idx);
        foreach (var additional in Additional) SerializeResourceRecord(additional, buffer, seen, ref idx);

        return buffer;
    }

    private void SerializeHeader(byte[] buffer, ref int idx)
    {
        idx += 12;
        
        buffer[0] = BitMask.ReadOctet(Header.Id, 1);
        buffer[1] = BitMask.ReadOctet(Header.Id, 0);
        if (Header.IsResponse) buffer[2] |= 0b_1_0000000;
        buffer[2] |= (byte)(BitMask.ReadNybble(Header.OpCode, 3) << 3);
        if (Header.IsAuthoritativeAnswer) buffer[2] |= 00000_1_00;
        if (Header.IsTruncated) buffer[2] |= 000000_1_0;
        if (Header.RecursionDesired) buffer[2] |= 000000_1;

        if (Header.RecursionAvailable) buffer[3] |= 0b_1_0000000;
        buffer[3] |= (BitMask.ReadNybble(Header.ResponseCode, 3));
        
        // QDCOUNT
        buffer[4] = BitMask.ReadOctet(Header.QuestionCount, 1);
        buffer[5] = BitMask.ReadOctet(Header.QuestionCount, 0);

        // ANCOUNT
        buffer[6] = BitMask.ReadOctet(Header.ResourceRecordCount, 1);
        buffer[7] = BitMask.ReadOctet(Header.ResourceRecordCount, 0);
        
        // NSCOUNT
        buffer[8] = BitMask.ReadOctet(Header.NameServerResourceRecordCount, 1);
        buffer[9] = BitMask.ReadOctet(Header.NameServerResourceRecordCount, 0);
        
        // ARCOUNT
        buffer[10] = BitMask.ReadOctet(Header.AdditionalRecordCount, 1);
        buffer[11] = BitMask.ReadOctet(Header.AdditionalRecordCount, 0);
    }
    
    private void SerializeQuestions(byte[] buffer, Dictionary<string, byte> seen, ref int idx) 
    {
        foreach (var question in Question)
        {
            SerializeLabel(question.Name, buffer, seen, ref idx);
            buffer[idx++] = BitMask.ReadOctet(question.QuestionType, 1);
            buffer[idx++] = BitMask.ReadOctet(question.QuestionType, 0);
            buffer[idx++] = BitMask.ReadOctet(question.QuestionClass, 1);
            buffer[idx++] = BitMask.ReadOctet(question.QuestionClass, 0);
        }
    }

    private void SerializeAnswer(byte[] buffer, Dictionary<string, byte> seen, ref int idx)
    {
        foreach (var answer in Answer) SerializeResourceRecord(answer, buffer, seen, ref idx);
    }

    private void SerializeResourceRecord(ResourceRecord resourceRecord, byte[] buffer, Dictionary<string, byte> seen, ref int idx)
    {
        SerializeLabel(resourceRecord.Name, buffer, seen, ref idx);
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
            1 => 4, // ipv 4
            2 => CalculateLabelLength(resourceRecord.Data, seen),
            28 => 16, // ipv 6
            _ => 0
        };
        
        buffer[idx++] = BitMask.ReadOctet(length, 1);
        buffer[idx++] = BitMask.ReadOctet(length, 0);
        
        switch (resourceRecord.Type)
        {
            case 2:
                SerializeLabel(resourceRecord.Data, buffer, seen, ref idx);
                break;
            case 1:
            case 28:
                SerializeIp(resourceRecord.Data, buffer, ref idx);
                break;
        }
    }

    private int CalculateLabelLength(string label, Dictionary<string, byte> seen)
    {
        // pointer
        if (seen.ContainsKey(label)) return 2;
        
        // local copy, we only care about a value becoming a pointer, use a simple hashset for that
        var seenLite = new HashSet<string>(seen.Keys);

        var length = 0;
        while (true)
        {
            // close sequence with a pointer
            if (!seenLite.Add(label)) return length + 2;
            
            // are we done?
            var segmentEnd = label.IndexOf('.');
            if (segmentEnd == -1) break;

            var segment = label[..segmentEnd];
            
            // assume 1 byte/char + length marker
            length += segment.Length + 1;
            
            // prepare for next segment, ignore segment separator ('.')
            label = label[(segmentEnd + 1)..];
        }

        // account for termiantor
        return length + 1;
    }

    private void SerializeIp(string ip, byte[] buffer, ref int idx)
    {
        var bytes = IPAddress.Parse(ip).GetAddressBytes();
        bytes.CopyTo(buffer, idx);
        idx += bytes.Length;
    }
    
    private void SerializeLabel(string label, byte[] buffer, Dictionary<string, byte> seen, ref int idx)
    {
        // b.nic.online
        // entire label sequence can be a pointer
        if (seen.TryGetValue(label, out var pointerOffset))
        {
            buffer[idx++] = 0b1100_0000;
            buffer[idx++] = pointerOffset;
            return;
        }

        // var segmentStart = 0;
        while (true)
        {
            // close sequence with a pointer
            if (seen.TryGetValue(label, out pointerOffset))
            {
                buffer[idx++] = 0b1100_0000;
                buffer[idx++] = pointerOffset;
                return;
            }
            
            // are we done?
            var segmentEnd = label.IndexOf('.');
            if (segmentEnd == -1) break;
            
            seen[label] = (byte)idx;
            var segment = label[..segmentEnd];
            
            buffer[idx++] = (byte)segment.Length;
            Encoding.ASCII.GetBytes(segment).CopyTo(buffer, idx);
            idx += segment.Length;
            
            // prepare for next segment, ignore segment separator ('.')
            label = label[(segmentEnd + 1)..];
        }

        // 0 byte, terminator
        buffer[idx++] = 0x00;
    }

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
            ResourceRecordCount = (byte)(src[6] << 8 | src[7]),
            NameServerResourceRecordCount = (byte)(src[8] << 8 | src[9]),
            AdditionalRecordCount = (byte)(src[10] << 8 | src[11]),
        };
    }

    private static Question DeserializeQuestion(byte[] src, ref int idx)
    {
        return new Question
        {
            Name = LabelUtils.ReadLabel(src, ref idx),
            QuestionType = (short)(src[idx++] << 8 | src[idx++]),
            QuestionClass = (short)(src[idx++] << 8 | src[idx++]),
        };
    }
    
    // public static Question Deserialize(byte[] src, int idx)
    // {
    //     var nameLength = src[idx++];
    //     
    //     return new Question
    //     {
    //         Name = Encoding.ASCII.GetString(src, idx, nameLength),
    //         QuestionType = (short)(src[idx + 1 + nameLength] << 8 | src[idx + 2 + nameLength]),
    //         QuestionClass = (short)(src[idx + 3 + nameLength] << 8 | src[idx + 4 + nameLength]),
    //     };
    // }

    private static ResourceRecord DeserializeResourceRecord(byte[] src, ref int idx)
    {
        var name = LabelUtils.ReadLabel(src, ref idx);
        var type = (short)((src[idx++] << 8) | src[idx++]);
        var @class = (short)((src[idx++] << 8) | src[idx++]);
        var ttl = ((src[idx++] << 24) | (src[idx++] << 16) | (src[idx++] << 8) | (src[idx++]));
        var data = type switch
        {
            // A record
            1 => ReadHostAddress(src, ref idx),
            
            // AAAA record
            28 => ReadHostAddress(src, ref idx),
            
            // NS record
            2 => ReadNSName(src, ref idx),
            _ => SkipUnknownData(src, ref idx)
        };

        return new ResourceRecord
        {
            Name = name,
            Type = type,
            Class = @class,
            TimeToLive = ttl,
            Data = data
        };
    }

    private static string SkipUnknownData(byte[] src, ref int idx)
    {
        var length = (short)((short)src[idx++] << 8) | ((short)src[idx++]);
        idx += length;
        return String.Empty;
    }

    private static string ReadHostAddress(byte[] src, ref int idx)
    {
        var length = (short)((short)src[idx++] << 8) | ((short)src[idx++]);
        var ip = new IPAddress(src[idx..(idx + length)]);
        idx += length;
        return ip.ToString();
    }
    
    private static string ReadNSName(byte[] src, ref int idx)
    {
        var length = (short)((short)src[idx++] << 8) | ((short)src[idx++]);
        var label = LabelUtils.ReadLabel(src, idx);
        idx += length;
        return label;
    }
    
}


struct Question
{
    public string Name;

    public short QuestionType;

    public short QuestionClass;

    public byte[] Serialize()
    {
        var response = new byte[
            // Name length
            1 + 
            // Name itself
            Name.Length +
            // Terminator byte
            1 +
            // Question type
            2 + 
            // Question class
            2
        ];

        var idx = 0;
        response[idx++] = (byte)Name.Length;
        for (var nIdx = 0; nIdx < Name.Length; nIdx++) response[idx++] = (byte)Name[nIdx];
        response[idx++] = 0x00;
        response[idx++] = BitMask.ReadOctet(QuestionType, 1);
        response[idx++] = BitMask.ReadOctet(QuestionType, 0);
        response[idx++] = BitMask.ReadOctet(QuestionClass, 1);
        response[idx] = BitMask.ReadOctet(QuestionClass, 0);
        
        return response;
    }

    // public static Question Deserialize(byte[] src, int idx)
    // {
    //     var nameLength = src[idx++];
    //     
    //     return new Question
    //     {
    //         Name = Encoding.ASCII.GetString(src, idx, nameLength),
    //         QuestionType = (short)(src[idx + 1 + nameLength] << 8 | src[idx + 2 + nameLength]),
    //         QuestionClass = (short)(src[idx + 3 + nameLength] << 8 | src[idx + 4 + nameLength]),
    //     };
    // }
}

struct ResourceRecord
{
    public string Name;
    public short Type;
    public short Class;
    public int TimeToLive;
    public string Data;

    // public static ResourceRecord Deserialize(byte[] src, ref int idx)
    // {
    //     var name = LabelUtils.ReadLabel(src, ref idx);
    //     var type = (short)((src[idx++] << 8) | src[idx++]);
    //     var @class = (short)((src[idx++] << 8) | src[idx++]);
    //     var ttl = ((src[idx++] << 24) | (src[idx++] << 16) | (src[idx++] << 8) | (src[idx++]));
    //     var data = type switch
    //     {
    //         // A record
    //         1 => ReadHostAddress(src, ref idx),
    //         
    //         // AAAA record
    //         28 => ReadHostAddress(src, ref idx),
    //         
    //         // NS record
    //         2 => ReadNSName(src, ref idx),
    //         _ => SkipUnknownData(src, ref idx)
    //     };
    //
    //     return new ResourceRecord
    //     {
    //         Name = name,
    //         Type = type,
    //         Class = @class,
    //         TimeToLive = ttl,
    //         Data = data
    //     };
    // }
    //
    // private static string SkipUnknownData(byte[] src, ref int idx)
    // {
    //     var length = (short)((short)src[idx++] << 8) | ((short)src[idx++]);
    //     idx += length;
    //     return String.Empty;
    // }
    //
    // private static string ReadHostAddress(byte[] src, ref int idx)
    // {
    //     var length = (short)((short)src[idx++] << 8) | ((short)src[idx++]);
    //     var ip = new IPAddress(src[idx..(idx + length)]);
    //     idx += length;
    //     return ip.ToString();
    // }
    //
    // private static string ReadNSName(byte[] src, ref int idx)
    // {
    //     var length = (short)((short)src[idx++] << 8) | ((short)src[idx++]);
    //     var (label, _) = LabelUtils.ReadLabel(src, idx);
    //     idx += length;
    //     return label;
    // }
}

// ILabel -> ConcreteLabel, OffsetLabel, LabelCollection, etc.
// should make labels their own types after we're done prototyping
public static class LabelUtils
{

    public static string ReadLabel(byte[] src, ref int idx)
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
        AppendLabels(sb, src, idx);
        idx += length;
        return sb.ToString();
    }
    
    public static string ReadLabel(byte[] src, int idx)
    {
        var sb = new StringBuilder();
        AppendLabels(sb, src, idx);
        return sb.ToString();
    }

    private static void AppendLabels(StringBuilder sb, byte[] src, int idx)
    {
        // starts with pointer -> follow pointer to label
        if (IsPointer(src, idx))
        {
            AppendLabels(sb, src, src[idx + 1]);
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
        if (IsPointer(src, idx)) AppendLabels(sb, src, src[idx + 1]);
    }
    
    private static bool IsPointer(byte[] src, int idx) => (src[idx] & 0b1100_0000) == 0b1100_0000;
    private static bool IsTerminator(byte[] src, int idx) => src[idx] == 0b0000_0000;

}

// [StructLayout(LayoutKind.Sequential)]
struct Header
{
    public ushort Id;

    public bool IsResponse;

    public byte OpCode;

    public bool IsAuthoritativeAnswer;

    public bool IsTruncated;

    public bool RecursionDesired;
    
    public bool RecursionAvailable;

    public byte ResponseCode;

    public ushort QuestionCount;

    public ushort ResourceRecordCount;

    public ushort NameServerResourceRecordCount;

    public ushort AdditionalRecordCount;

    /// <summary>
    /// Serialize to resource record header format
    /// </summary>
    /// <returns>Headers serialized as byte array</returns>
    public byte[] Serialize()
    {
        var serialized = new byte[12];
        serialized[0] = BitMask.ReadOctet(Id, 1);
        serialized[1] = BitMask.ReadOctet(Id, 0);
        if (IsResponse) serialized[2] |= 0b_1_0000000;
        serialized[2] |= (byte)(BitMask.ReadNybble(OpCode, 3) << 3);
        if (IsAuthoritativeAnswer) serialized[2] |= 00000_1_00;
        if (IsTruncated) serialized[2] |= 000000_1_0;
        if (RecursionDesired) serialized[2] |= 000000_1;

        if (RecursionAvailable) serialized[3] |= 0b_1_0000000;
        serialized[3] |= (BitMask.ReadNybble(ResponseCode, 3));
        
        // QDCOUNT
        serialized[4] = BitMask.ReadOctet(QuestionCount, 1);
        serialized[5] = BitMask.ReadOctet(QuestionCount, 0);

        // ANCOUNT
        serialized[6] = BitMask.ReadOctet(ResourceRecordCount, 1);
        serialized[7] = BitMask.ReadOctet(ResourceRecordCount, 0);
        
        // NSCOUNT
        serialized[8] = BitMask.ReadOctet(NameServerResourceRecordCount, 1);
        serialized[9] = BitMask.ReadOctet(NameServerResourceRecordCount, 0);
        
        // ARCOUNT
        serialized[10] = BitMask.ReadOctet(AdditionalRecordCount, 1);
        serialized[11] = BitMask.ReadOctet(AdditionalRecordCount, 0);

        return serialized;
    }

    public static Header Deserialize(byte[] data) => new Header
    {
        Id = (byte)(data[0] << 8 | data[1]),
        
        IsResponse = BitMask.IsSet(data[2], 7),
        OpCode = BitMask.ReadNybble(data[2], 6),
        IsAuthoritativeAnswer = BitMask.IsSet(data[2], 2),
        IsTruncated = BitMask.IsSet(data[2], 1),
        RecursionDesired = BitMask.IsSet(data[2], 0),
        
        RecursionAvailable = BitMask.IsSet(data[3], 7),
        ResponseCode = BitMask.ReadNybble(data[3], 3),
        
        QuestionCount = (byte)(data[4] << 8 | data[5]),
        ResourceRecordCount = (byte)(data[6] << 8 | data[7]),
        NameServerResourceRecordCount = (byte)(data[8] << 8 | data[9]),
        AdditionalRecordCount = (byte)(data[10] << 8 | data[11]),
    };
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
