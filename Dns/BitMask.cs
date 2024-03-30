using System.Numerics;

namespace Bogers.DnsMonitor.Dns;

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
}