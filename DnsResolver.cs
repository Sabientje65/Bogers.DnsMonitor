using System.Net;
using System.Net.Sockets;
using System.Numerics;
using System.Runtime.InteropServices;
using System.Text;

namespace Bogers.DnsMonitor;

public class DnsResolver
{
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
        
        using var udp = new UdpClient(AddressFamily.InterNetwork);
        udp.Connect(myRouter);
        
        // Dns.GetHostEntry()
        

        var msg = new byte[]
        {
            // begin header (12 bytes)

            // id
            id[0],
            id[1],

            // should move this into a struct, lol
            (
                0000_0000

                // query (1 bit)
                | 0b_0_0000000

                // opcode (4 bits)
                | 0_0000_000

                // Authoritative Answer (1 bit)
                | 00000_0_00

                // TrunCation (1 bit), should use TCP when set to 1
                | 000000_0_0

                // Recursion Desired (1 bit), tell NS to query recursively
                | 000000_0
            ),
            (
                0000_0000

                // Recursion Available (1 bit), set by response, determines if recursion is available or not
                | 0b_0_0000000

                // Z (3 bits), reserved for future use, MUST be empty
                | 0_000_0000

                // Response code (4 bits)
                | 0_000_0000
            ),

            // Question count (16 bits), amount of questions in question section
            0000_0000,
            0000_0001,

            // Answer count (16 bits), amount of answers in answer section, not relevant for querying
            0000_0000,
            0000_0000,

            // NSCount (16 bits), amount of ns server records, not relevant for querying
            0000_0000,
            0000_0000,

            // ARCount (16 bits), additional records count, not relevant for querying
            0000_0000,
            0000_0000,

            // end header

            // begin question (dynamic length)

            // (tld -> online = 6 bytes)
            // multiple levels are supported: eg. bogers.online -> bogers = 6 bytes, online = 6 bytes
            // length (1 byte)
            0x06,
            (byte)'o',
            (byte)'n',
            (byte)'l',
            (byte)'i',
            (byte)'n',
            (byte)'e',
            
            // terminate with 0 byte
            0x00,
            // (byte)'.',

            // type (2 bytes), 1 -> A
            0000_0000,
            0000_0001,

            // class (2 bytes), 1 -> Internet
            0000_0000,
            0000_0001,
            
            // end question
        };

        var bytes = new List<byte>(new Headers {
            Id = (ushort)((id[0] << 8) | id[1]),
            QuestionCount = 1,
            OpCode = 0
        }.Serialize());
        
        bytes.AddRange(new byte[]
        {
            // (tld -> online = 6 bytes)
            // multiple levels are supported: eg. bogers.online -> bogers = 6 bytes, online = 6 bytes
            // length (1 byte)
            0x06,
            (byte)'o',
            (byte)'n',
            (byte)'l',
            (byte)'i',
            (byte)'n',
            (byte)'e',
            
            // terminate with 0 byte
            0x00,
            // (byte)'.',

            // type (2 bytes), 1 -> A
            0000_0000,
            0000_0001,

            // class (2 bytes), 1 -> Internet
            0000_0000,
            0000_0001,
        });
        

        var bytesSend = await udp.SendAsync(bytes.ToArray());
        
        var result = await udp.ReceiveAsync();
        var response = Headers.Deserialize(result.Buffer);


        // todo: make span
        var answer = result.Buffer
            .Skip(12)
            .ToArray();

        var answ = Question.Deserialize(answer, 0);
        
        // var b1 = result.Buffer[2];
        // var b2 = result.Buffer[3];
        
        
        // var response = new
        // {
        //     IsResponse = BitMask.IsSet(b1, 7),
        //     OpCode = BitMask.ReadNybble(b1, 6),
        //     AuthoritiveAnswer = BitMask.IsSet(b1, 2),
        //     IsTruncated = BitMask.IsSet(b1, 1),
        //     RecursionDesired = BitMask.IsSet(b1, 0),
        //     
        //     RecursionAvailable = BitMask.IsSet(b2, 7),
        //     ResultCode = BitMask.ReadNybble(b2, 3),
        // };
        
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
            // Question type
            2 + 
            // Question class
            2
        ];

        var idx = 0;
        response[idx++] = (byte)Name.Length;
        for (var nIdx = 0; nIdx < Name.Length; nIdx++) response[idx++] = (byte)Name[nIdx++];
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
            QuestionType = (byte)(src[idx + 1 + nameLength] << 8 | src[idx + 1 + nameLength + 1]),
            QuestionClass = (byte)(src[idx + 1 + nameLength] << 8 | src[idx + 1 + nameLength + 1]),
        };
    }
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