using Microsoft.Data.Sqlite;

namespace Bogers.DnsMonitor.Dns;

// todo: cache in memory -> flush to sqlite cache

/// <summary>
/// SQLite based cache implementation
/// </summary>
class SqliteResolverCache
{
    private static string ConnectionString = """Data Source=D:\Data\dnscache.db; Pooling=True""";

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
                                  , type INTEGER NOT NULL
                                  , class INTEGER NOT NULL
                                  , expires INTEGER NOT NULL
                                  , ttl INTEGER NOT NULL
                                  , data TEXT NOT NULL
                                  , created INTEGER DEFAULT CURRENT_TIMESTAMP
                              );
                              
                              CREATE INDEX IF NOT EXISTS resource_records_expires ON resource_records (expires);
                              CREATE INDEX IF NOT EXISTS resource_records_name_type_expires_created ON resource_records (name, type, expires, created);
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

        // only add if previous record was expired
        cmd.CommandText = """
                              INSERT INTO resource_records (name, type, class, ttl, expires, data)
                              select @name, @type, @class, @tll, @expires, @data
                              WHERE NOT EXISTS (SELECT 1 from resource_records WHERE name = @name AND type = @type AND expires < CURRENT_TIMESTAMP)
                          """;

        cmd.Parameters.Add("@name", SqliteType.Text).Value = record.Name;
        cmd.Parameters.Add("@type", SqliteType.Integer).Value = record.Type;
        cmd.Parameters.Add("@class", SqliteType.Integer).Value = record.Class;
        cmd.Parameters.Add("@tll", SqliteType.Integer).Value = record.TimeToLive;
        cmd.Parameters.Add("@expires", SqliteType.Integer).Value = DateTime.UtcNow.AddSeconds(record.TimeToLive);
        cmd.Parameters.Add("@data", SqliteType.Text).Value = record.Data;

        await cmd.ExecuteNonQueryAsync();
    }

    /// <summary>
    /// Attempt to lookup the first non-expired resource record for the given domain name of the given type
    /// </summary>
    /// <param name="name">Domain name</param>
    /// <param name="type">Record type <see cref="RecordType"/></param>
    /// <returns>Resource record when found</returns>
    public static async Task<ResourceRecord?> FindFirst(string name, ushort type)
    {
        var records = await FindAll(name, type);
        return records.FirstOrDefault();
    }

    /// <summary>
    /// Attempt to lookup all non-expired resource records for the given domain name of the given type
    /// </summary>
    /// <param name="name">Domain name</param>
    /// <param name="type">Record type <see cref="RecordType"/></param>
    /// <returns>All matching resource records</returns>
    public static async Task<ResourceRecord[]> FindAll(string name, ushort type)
    {
        await using var con = CreateConnection();
        await con.OpenAsync();
        await using var cmd = con.CreateCommand();

        // depending on type, one or more entries may be present for any given given name + type combination
        cmd.CommandText = """
                              SELECT name, type, class, ttl, data
                              FROM resource_records
                              WHERE name = @name
                                  AND type = @type
                                  AND CURRENT_TIMESTAMP < expires
                              ORDER BY CREATED DESC
                          """;

        cmd.Parameters.Add("@name", SqliteType.Text).Value = name;
        cmd.Parameters.Add("@type", SqliteType.Integer).Value = type;

        await using var reader = await cmd.ExecuteReaderAsync();
        var result = new List<ResourceRecord>();
        while (await reader.ReadAsync())
        {
            result.Add(new ResourceRecord
            {
                Name = reader.GetString(0),
                Type = (ushort)reader.GetInt16(1),
                Class = (ushort)reader.GetInt16(2),
                TimeToLive = reader.GetInt32(3),
                Data = reader.GetString(4),
            });
        }
        return result.ToArray();
    }

    /// <summary>
    /// Expunge expired records from the DB
    /// </summary>
    public static async Task Clean()
    {
        await using var con = CreateConnection();
        await con.OpenAsync();
        await using var cmd = con.CreateCommand();

        cmd.CommandText = """DELETE FROM resource_records WHERE CURRENT_TIMESTAMP > expires;""";

        await cmd.ExecuteNonQueryAsync();
    }

    private static SqliteConnection CreateConnection() => new SqliteConnection(ConnectionString);
}