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

        BitMask.ReadNybble(0b1111_0001, 3);
        BitMask.ReadNybble(0b1000_1111, 7);
        BitMask.ReadNybble(0b1100_0111, 6);

        // using var sock = new Socket(SocketType.Dgram, ProtocolType.Udp);
        var cloudflare = new IPEndPoint(new IPAddress(cloudflareIp), 53);
        var myRouter = new IPEndPoint(new IPAddress(myRouterIp), 53);
        var root = new IPEndPoint(new IPAddress(RootNameServer.A), 53);
        
        using var udp = new UdpClient(AddressFamily.InterNetwork);
        udp.Connect(root);
 
        var bytes = new List<byte>(new Headers {
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
        

        var bytesSend = await udp.SendAsync(bytes.ToArray());
        
        var result = await udp.ReceiveAsync();

        // todo: make span
        var resultBuffer = result.Buffer;

        var response = Headers.Deserialize(resultBuffer);
        var question = Question.Deserialize(resultBuffer, 12);
        var idx = 12 + question.Serialize().Length;
        var resourceRecords = new ResourceRecord[response.NameServerResourceRecordCount];
        var additionalRecords = new ResourceRecord[response.AdditionalRecordCount];
        for (var rrIdx = 0; rrIdx < resourceRecords.Length; rrIdx++) resourceRecords[rrIdx] = ResourceRecord.Deserialize(resultBuffer, ref idx);
        for (var rrIdx = 0; rrIdx < additionalRecords.Length; rrIdx++) additionalRecords[rrIdx] = ResourceRecord.Deserialize(resultBuffer, ref idx);

        var hexResult = BitConverter.ToString(result.Buffer).Replace("-", "");
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

    public static Question Deserialize(byte[] src, int idx)
    {
        var nameLength = src[idx++];
        
        return new Question
        {
            Name = Encoding.ASCII.GetString(src, idx, nameLength),
            QuestionType = (short)(src[idx + 1 + nameLength] << 8 | src[idx + 2 + nameLength]),
            QuestionClass = (short)(src[idx + 3 + nameLength] << 8 | src[idx + 4 + nameLength]),
        };
    }
}

struct ResourceRecord
{
    public string Name;
    public short Type;
    public short Class;
    public int TimeToLive;
    public string Data;

    public static ResourceRecord Deserialize(byte[] src, ref int idx)
    {
        var name = ReadName(src, ref idx);
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
            _ => null
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

    private static string ReadName(byte[] src, ref int idx)
    {
        var (label, length) = LabelUtils.ReadLabel(src, idx);
        idx += length;
        return label;
    }

    private readonly string ReadUnknownData(byte[] src, ref int idx)
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
        // when type = 2
        
        var length = (short)((short)src[idx++] << 8) | ((short)src[idx++]);
        var label = LabelUtils.ReadLabel(src, idx, length);
        idx += length;
        return label;
    }
}

// ILabel -> ConcreteLabel, OffsetLabel, LabelCollection, etc.
// should make labels their own types after we're done prototyping
public static class LabelUtils
{

    public static (string label, int length) ReadLabel(byte[] src, int idx)
    {
        var length = IsPointer(src[idx]) ? 2 : src[idx];
        return (ReadLabel(src, idx, length), length);
    }

    public static string ReadLabel(byte[] src, int idx, int length)
    {
        var sb = new StringBuilder();
        AppendLabel(sb, src, idx, length);
        return sb.ToString();
    }

    private static void AppendLabel(StringBuilder sb, byte[] src, int idx, int length)
    {
        // just a pointer is a valid label
        if (IsPointer(src[idx]))
        {
            AppendPointer(sb, src, idx);
            return;
        }

        var sequenceLength =  length;
        var sequenceEnd = idx + sequenceLength;
        var wasPointer = false;
        
        // a sequence of labels of predefined length
        while (idx < sequenceEnd)
        {
            wasPointer = false;
            if (IsPointer(src[idx]))
            {
                wasPointer = true;
                idx += AppendPointer(sb, src, idx);
                continue;
            }
        
            var labelLength = src[idx];
            var labelStartIdx = idx + 1;
            
            sb.Append(Encoding.ASCII.GetString(src, labelStartIdx, labelLength));
            sb.Append('.');
            
            idx += labelLength + 1;
        }
        
        // sequences may end with a terminator or a pointer
        if (!wasPointer && IsPointer(src[idx])) AppendPointer(sb, src, idx);
    }

    private static int AppendPointer(StringBuilder sb, byte[] src, int idx)
    {
        var offset = ReadPointerOffset(src, idx);
        AppendLabel(sb, src, offset, src[offset]);

        // pointers always have a length of 2 octets
        return 2;
    }
    
    private static bool IsPointer(byte b) => (b & 0b1100_0000) == 0b1100_0000;

    private static short ReadPointerOffset(byte[] src, int idx) => (short)(((short)(src[idx] & 0b0011_1111) << 8) | (short)src[idx + 1]);
    
    private static bool IsTerminator(byte b) => b == 0b0000_0000;

}

// [StructLayout(LayoutKind.Sequential)]
struct Headers
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

    public static Headers Deserialize(byte[] data) => new Headers
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
    /// Read the byte octet at the given position
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

/// <summary>
/// Implementation of: https://datatracker.ietf.org/doc/html/rfc1035#autoid-40
/// </summary>
// public struct Header
// {
//     /// <summary>
//     /// Unique request identifier, will be included in answers
//     /// </summary>
//     public ushort Id;
//
//     /// <summary>
//     /// 0 for query, 1 for response
//     /// </summary>
//     public bool IsAnswer;
//
//     /// <summary>
//     /// DNS opcode, can be one of the following values:
//     /// 0    - Standard query (QUERY)
//     /// 1    - Inverse query (IQUERY)
//     /// 2    - Server status request (STATUS)
//     /// 3-15 - Reserved for future use
//     /// </summary>
//     public Nybble Opcode;
//
//     public bool AuthoritativeAnswer;
//     
//     
// }

[StructLayout(LayoutKind.Sequential)]
public struct Nybble
{
    public static implicit operator byte(Nybble n)
    {
        byte b = 0;
        if (n.Bit1) b |= 0b_0001;
        if (n.Bit2) b |= 0b_0010;
        if (n.Bit3) b |= 0b_0100;
        if (n.Bit4) b |= 0b_1000;
        return b;
    }

    public static implicit operator Nybble(byte b) => new Nybble
    {
        Bit1 = (b & 0b_0001) == 1,
        Bit2 = (b & 0b_0010) == 1,
        Bit3 = (b & 0b_0100) == 1,
        Bit4 = (b & 0b_1000) == 1,
    };

    public bool Bit1;
    public bool Bit2;
    public bool Bit3;
    public bool Bit4;
}