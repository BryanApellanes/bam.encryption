using System.Text;

namespace Bam.Encryption.Cose;

/// <summary>
/// A strict decoder for the CBOR subset (RFC 8949) that WebAuthn attestation objects and COSE
/// keys use.  Definite lengths only; indefinite-length items, duplicate map keys, map keys that
/// are not integers or text, integers outside <see cref="long"/>, invalid UTF-8, truncated input
/// and nesting deeper than <see cref="MaxDepth"/> are refused with a
/// <see cref="CborFormatException"/>.  Tags (major type 6) are skipped transparently and the
/// tagged item is returned in their place.
/// </summary>
public static class CborReader
{
    /// <summary>
    /// The maximum nesting depth of arrays and maps the reader accepts.
    /// </summary>
    public const int MaxDepth = 32;

    private static readonly UTF8Encoding StrictUtf8 = new UTF8Encoding(encoderShouldEmitUTF8Identifier: false, throwOnInvalidBytes: true);

    /// <summary>
    /// Decodes exactly one data item that spans the whole input.
    /// </summary>
    /// <param name="input">The encoded item.</param>
    /// <returns>The decoded item.</returns>
    /// <exception cref="CborFormatException">The input is malformed or has trailing bytes.</exception>
    public static CborValue Read(ReadOnlySpan<byte> input)
    {
        CborValue value = Read(input, out int consumed);
        if (consumed != input.Length)
        {
            throw new CborFormatException($"Trailing bytes after the data item: {input.Length - consumed}.", consumed);
        }
        return value;
    }

    /// <summary>
    /// Decodes one data item from the start of the input and reports how many bytes it occupied.
    /// </summary>
    /// <param name="input">The encoded item, possibly followed by other data.</param>
    /// <param name="consumed">The number of bytes the item occupied.</param>
    /// <returns>The decoded item.</returns>
    /// <exception cref="CborFormatException">The input is malformed.</exception>
    public static CborValue Read(ReadOnlySpan<byte> input, out int consumed)
    {
        Cursor cursor = new Cursor(input.ToArray());
        CborValue value = ReadItem(cursor, 0);
        consumed = cursor.Position;
        return value;
    }

    private static CborValue ReadItem(Cursor cursor, int depth)
    {
        if (depth > MaxDepth)
        {
            throw new CborFormatException($"Nesting deeper than {MaxDepth}.", cursor.Position);
        }

        int start = cursor.Position;
        byte initial = cursor.ReadByte();
        int majorType = initial >> 5;
        int additional = initial & 0x1f;

        switch (majorType)
        {
            case 0:
                return new CborInteger(ToInt64(ReadArgument(cursor, additional, start), start));
            case 1:
            {
                ulong argument = ReadArgument(cursor, additional, start);
                if (argument > long.MaxValue)
                {
                    throw new CborFormatException("Negative integer below the supported range.", start);
                }
                return new CborInteger(-1L - (long)argument);
            }
            case 2:
                return new CborBytes(cursor.ReadBytes(ToLength(ReadArgument(cursor, additional, start), cursor, start)));
            case 3:
            {
                byte[] encoded = cursor.ReadBytes(ToLength(ReadArgument(cursor, additional, start), cursor, start));
                try
                {
                    return new CborText(StrictUtf8.GetString(encoded));
                }
                catch (DecoderFallbackException e)
                {
                    throw new CborFormatException("Text string is not valid UTF-8: " + e.Message, start);
                }
            }
            case 4:
            {
                int count = ToLength(ReadArgument(cursor, additional, start), cursor, start);
                List<CborValue> items = new List<CborValue>(count);
                for (int i = 0; i < count; i++)
                {
                    items.Add(ReadItem(cursor, depth + 1));
                }
                return new CborArray(items);
            }
            case 5:
            {
                int count = ToLength(ReadArgument(cursor, additional, start), cursor, start);
                List<KeyValuePair<CborValue, CborValue>> entries = new List<KeyValuePair<CborValue, CborValue>>(count);
                HashSet<CborValue> seenKeys = new HashSet<CborValue>();
                for (int i = 0; i < count; i++)
                {
                    int keyStart = cursor.Position;
                    CborValue key = ReadItem(cursor, depth + 1);
                    if (key is not CborInteger && key is not CborText)
                    {
                        throw new CborFormatException("Map keys must be integers or text.", keyStart);
                    }
                    if (!seenKeys.Add(key))
                    {
                        throw new CborFormatException("Duplicate map key.", keyStart);
                    }
                    CborValue value = ReadItem(cursor, depth + 1);
                    entries.Add(new KeyValuePair<CborValue, CborValue>(key, value));
                }
                return new CborMap(entries);
            }
            case 6:
                ReadArgument(cursor, additional, start);
                return ReadItem(cursor, depth + 1);
            default:
                return ReadSimple(cursor, additional, start);
        }
    }

    private static CborValue ReadSimple(Cursor cursor, int additional, int start)
    {
        switch (additional)
        {
            case 20:
                return CborSimple.False;
            case 21:
                return CborSimple.True;
            case 22:
                return CborSimple.Null;
            case 23:
                return CborSimple.Undefined;
            case 24:
            {
                byte number = cursor.ReadByte();
                if (number < 32)
                {
                    throw new CborFormatException("Simple value below 32 must use the one-byte form.", start);
                }
                return new CborSimple(CborSimpleKind.Other, number);
            }
            case 25:
                return new CborSimple(CborSimpleKind.Float, (double)BitConverter.UInt16BitsToHalf((ushort)ReadFixed(cursor, 2)));
            case 26:
                return new CborSimple(CborSimpleKind.Float, BitConverter.UInt32BitsToSingle((uint)ReadFixed(cursor, 4)));
            case 27:
                return new CborSimple(CborSimpleKind.Float, BitConverter.UInt64BitsToDouble(ReadFixed(cursor, 8)));
            case 31:
                throw new CborFormatException("Unexpected break code.", start);
            default:
                if (additional < 20)
                {
                    return new CborSimple(CborSimpleKind.Other, additional);
                }
                throw new CborFormatException("Reserved simple value encoding.", start);
        }
    }

    private static ulong ReadArgument(Cursor cursor, int additional, int start)
    {
        if (additional < 24)
        {
            return (ulong)additional;
        }
        switch (additional)
        {
            case 24:
                return ReadFixed(cursor, 1);
            case 25:
                return ReadFixed(cursor, 2);
            case 26:
                return ReadFixed(cursor, 4);
            case 27:
                return ReadFixed(cursor, 8);
            case 31:
                throw new CborFormatException("Indefinite-length items are not supported.", start);
            default:
                throw new CborFormatException("Reserved additional information value.", start);
        }
    }

    private static ulong ReadFixed(Cursor cursor, int byteCount)
    {
        ulong result = 0;
        for (int i = 0; i < byteCount; i++)
        {
            result = (result << 8) | cursor.ReadByte();
        }
        return result;
    }

    private static long ToInt64(ulong argument, int start)
    {
        if (argument > long.MaxValue)
        {
            throw new CborFormatException("Unsigned integer above the supported range.", start);
        }
        return (long)argument;
    }

    private static int ToLength(ulong argument, Cursor cursor, int start)
    {
        if (argument > (ulong)cursor.Remaining)
        {
            throw new CborFormatException("Length exceeds the remaining input.", start);
        }
        return (int)argument;
    }

    private sealed class Cursor
    {
        private readonly byte[] _data;

        public Cursor(byte[] data)
        {
            _data = data;
        }

        public int Position { get; private set; }

        public int Remaining => _data.Length - Position;

        public byte ReadByte()
        {
            if (Position >= _data.Length)
            {
                throw new CborFormatException("Unexpected end of input.", Position);
            }
            return _data[Position++];
        }

        public byte[] ReadBytes(int count)
        {
            if (count > Remaining)
            {
                throw new CborFormatException("Unexpected end of input.", Position);
            }
            byte[] slice = new byte[count];
            Array.Copy(_data, Position, slice, 0, count);
            Position += count;
            return slice;
        }
    }
}
