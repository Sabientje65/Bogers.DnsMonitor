using System.Diagnostics;
using System.Text;

namespace Bogers.DnsMonitor.Dns;

/// <summary>
/// DNS Message https://datatracker.ietf.org/doc/html/rfc1035#section-4
/// </summary>
class Message
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

    /// <summary>
    /// <see cref="Bogers.DnsMonitor.Dns.Header"/>
    /// </summary>
    public Header Header;

    /// <summary>
    /// Collection of <see cref="Bogers.DnsMonitor.Dns.Question"/>
    /// </summary>
    public Question[] Question;

    /// <summary>
    /// Collection of <see cref="Bogers.DnsMonitor.Dns.ResourceRecord"/> answering the the question
    /// </summary>
    public ResourceRecord[] Answer;

    /// <summary>
    /// Collection of <see cref="Bogers.DnsMonitor.Dns.ResourceRecord"/> pointing towards authorities
    /// </summary>
    public ResourceRecord[] Authority;

    /// <summary>
    /// Collection of <see cref="Bogers.DnsMonitor.Dns.ResourceRecord"/> holding additional information
    /// </summary>
    public ResourceRecord[] Additional;
}

/// <summary>
/// Object representation of a DNS message header https://datatracker.ietf.org/doc/html/rfc1035#section-4.1.1
/// </summary>
[DebuggerDisplay("{DebuggerDisplay()}")]
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

    private string DebuggerDisplay()
    {
        var sb = new StringBuilder();
        sb.Append($"Id: 0x{Id:X}, ");
        sb.Append($"QR: {IsResponse}, ");
        sb.Append($"OPCODE: 0x{OpCode:X}, ");
        sb.Append($"AA: {IsAuthoritativeAnswer}, ");
        sb.Append($"TC: {IsTruncated}, ");
        sb.Append($"RD: {RecursionDesired}, ");
        sb.Append($"RA: {RecursionAvailable}, ");
        sb.Append($"RCODE: {ResponseCode}, ");
        sb.Append($"QDCOUNT: 0x{QuestionCount:X}, ");
        sb.Append($"ANCOUNT: 0x{AnswerCount:X}, ");
        sb.Append($"NSCOUNT: 0x{NameServerCount:X}, ");
        sb.Append($"ARCOUNT: 0x{AdditionalRecordCount:X}");
        return sb.ToString();
    }
}

/// <summary>
/// DNS Question https://datatracker.ietf.org/doc/html/rfc1035#section-4.1.2
/// </summary>
[DebuggerDisplay("Name: {Name}, Type: {QuestionType}")] // <-- QuestionType name?
class Question
{
    public Question(string name, ushort questionType)
    {
        // normalize
        if (!name.EndsWith('.')) name += '.';
        
        Name = name;
        QuestionType = questionType;
        QuestionClass = RecordClass.IN;
    }
    
    public Question(string name, ushort questionType, ushort questionClass)
    {
        // normalize
        if (!name.EndsWith('.')) name += '.';
        
        Name = name;
        QuestionType = questionType;
        QuestionClass = questionClass;
    }
    
    /// <summary>
    /// Domain name
    /// </summary>
    public string Name;

    /// <summary>
    /// Type of record being requested, <see cref="RecordType"/>
    /// </summary>
    public ushort QuestionType;

    /// <summary>
    /// Question class, will always be <see cref="RecordClass.IN"/>
    /// </summary>
    public ushort QuestionClass;
}

/// <summary>
/// DNS Resource Record https://datatracker.ietf.org/doc/html/rfc1035#section-4.1.2
/// </summary>
[DebuggerDisplay("Name: {Name}, Type: {Type}, TTL: {TimeToLive}, Data: {Data}")] // <-- QuestionType name?
class ResourceRecord
{
    /// <summary>
    /// Domain name resource record is for
    /// </summary>
    public string Name;
    
    /// <summary>
    /// Record type, see <see cref="RecordType"/>
    /// </summary>
    public ushort Type;
    
    /// <summary>
    /// Record class, will always be <see cref="RecordClass.IN"/>
    /// </summary>
    public ushort Class;
    
    /// <summary>
    /// Duration the record may be cached in seconds
    /// </summary>
    public int TimeToLive;
    
    /// <summary>
    /// Record data, contents differ based on <see cref="Type"/>
    /// </summary>
    public string Data;
}

/// <summary>
/// https://datatracker.ietf.org/doc/html/rfc1035#section-4.1.1
/// </summary>
class OpCode
{
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
