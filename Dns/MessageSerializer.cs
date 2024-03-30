using System.Net;
using System.Text;

namespace Bogers.DnsMonitor.Dns;

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

        return buffer[..idx];
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
            Name = NameSerializer.ReadName(src, ref idx),
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
        var name = NameSerializer.ReadName(src, ref idx);
        var type = (ushort)((src[idx++] << 8) | src[idx++]);
        var cls = (ushort)((src[idx++] << 8) | src[idx++]);
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
        var label = NameSerializer.ReadName(src, idx);
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
        NameSerializer.SerializeName(question.Name, buffer, seen, ref idx);
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
        NameSerializer.SerializeName(resourceRecord.Name, buffer, seen, ref idx);
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
            RecordType.NS => NameSerializer.CalculateNameLength(resourceRecord.Data, seen),
            RecordType.AAAA => 16,
            _ => 0
        };
        
        buffer[idx++] = BitMask.ReadOctet(length, 1);
        buffer[idx++] = BitMask.ReadOctet(length, 0);
        
        switch (resourceRecord.Type)
        {
            case RecordType.NS:
                NameSerializer.SerializeName(resourceRecord.Data, buffer, seen, ref idx);
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
/// Collection of utilities for reading/writing domain names from and to DNS messages
/// </summary>
static class NameSerializer
{
    
    // worth considering: having instances of our serializer -> tracking seen internally when serializing

    /// <summary>
    /// Read the domain name at the given index, index will be advanced to the end of the name 
    /// </summary>
    /// <param name="src">Source to read domain name from</param>
    /// <param name="idx">Starting index</param>
    /// <returns>Domain name</returns>
    public static string ReadName(byte[] src, ref int idx)
    {
        // first read our label, then retroactively move our index to accomodate the actual amount of bytes read
        var sb = new StringBuilder();
        AppendLabelSequence(sb, src, idx);
        
        // pointer -> static length of 2
        if (IsPointer(src, idx)) idx += 2;
        else
        {
            // Keep shifting index to end of sequence length indicator + sequence itself
            // until we encounter one of two possible sequence terminators
            while (!IsPointer(src, idx) && !IsTerminator(src, idx)) idx += src[idx] + 1;

            // Shift past pointer/terminator
            idx += IsPointer(src, idx) ? 2 : 1;
        }
        
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