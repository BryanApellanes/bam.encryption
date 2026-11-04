using System.Text;

namespace Bam.Encryption.Cose;

/// <summary>
/// Encodes a <see cref="CborValue"/> tree as definite-length CBOR (RFC 8949), the inverse of
/// <see cref="CborReader"/>.  Integer arguments (values, lengths, tags) use the shortest encoding;
/// floating-point <see cref="CborSimple"/> values are always written as 64-bit doubles, so a half
/// or single read in re-encodes wider and float round trips are by value, not by bytes.  Used to
/// build COSE keys and attestation objects in tests and by hosts that emit COSE structures.
/// </summary>
public static class CborWriter
{
    /// <summary>
    /// Encodes the value.
    /// </summary>
    /// <param name="value">The value to encode.</param>
    /// <returns>The encoded bytes.</returns>
    public static byte[] Encode(CborValue value)
    {
        ArgumentNullException.ThrowIfNull(value);
        List<byte> output = new List<byte>();
        Write(output, value);
        return output.ToArray();
    }

    /// <summary>
    /// Builds a map from integer-keyed entries, a convenience for COSE structures.
    /// </summary>
    /// <param name="entries">The entries in encoded order.</param>
    /// <returns>The map value.</returns>
    public static CborMap Map(params KeyValuePair<CborValue, CborValue>[] entries)
    {
        return new CborMap(entries);
    }

    /// <summary>
    /// Builds an integer-keyed map entry.
    /// </summary>
    public static KeyValuePair<CborValue, CborValue> Entry(long key, CborValue value)
    {
        return new KeyValuePair<CborValue, CborValue>(new CborInteger(key), value);
    }

    /// <summary>
    /// Builds a text-keyed map entry.
    /// </summary>
    public static KeyValuePair<CborValue, CborValue> Entry(string key, CborValue value)
    {
        return new KeyValuePair<CborValue, CborValue>(new CborText(key), value);
    }

    private static void Write(List<byte> output, CborValue value)
    {
        switch (value)
        {
            case CborInteger integer:
                if (integer.Value >= 0)
                {
                    WriteHead(output, 0, (ulong)integer.Value);
                }
                else
                {
                    WriteHead(output, 1, (ulong)(-1L - integer.Value));
                }
                break;
            case CborBytes bytes:
                WriteHead(output, 2, (ulong)bytes.Value.Length);
                output.AddRange(bytes.Value);
                break;
            case CborText text:
            {
                byte[] encoded = Encoding.UTF8.GetBytes(text.Value);
                WriteHead(output, 3, (ulong)encoded.Length);
                output.AddRange(encoded);
                break;
            }
            case CborArray array:
                WriteHead(output, 4, (ulong)array.Items.Count);
                foreach (CborValue item in array.Items)
                {
                    Write(output, item);
                }
                break;
            case CborMap map:
                WriteHead(output, 5, (ulong)map.Entries.Count);
                foreach (KeyValuePair<CborValue, CborValue> entry in map.Entries)
                {
                    Write(output, entry.Key);
                    Write(output, entry.Value);
                }
                break;
            case CborSimple simple:
                WriteSimple(output, simple);
                break;
            default:
                throw new CborFormatException($"Cannot encode {value.GetType().Name}.");
        }
    }

    private static void WriteSimple(List<byte> output, CborSimple simple)
    {
        switch (simple.Kind)
        {
            case CborSimpleKind.False:
                output.Add(0xf4);
                break;
            case CborSimpleKind.True:
                output.Add(0xf5);
                break;
            case CborSimpleKind.Null:
                output.Add(0xf6);
                break;
            case CborSimpleKind.Undefined:
                output.Add(0xf7);
                break;
            case CborSimpleKind.Float:
            {
                double number = simple.Number ?? 0d;
                output.Add(0xfb);
                ulong bits = BitConverter.DoubleToUInt64Bits(number);
                for (int shift = 56; shift >= 0; shift -= 8)
                {
                    output.Add((byte)(bits >> shift));
                }
                break;
            }
            default:
            {
                int number = (int)(simple.Number ?? 0d);
                if (number < 24)
                {
                    output.Add((byte)(0xe0 | number));
                }
                else
                {
                    output.Add(0xf8);
                    output.Add((byte)number);
                }
                break;
            }
        }
    }

    private static void WriteHead(List<byte> output, int majorType, ulong argument)
    {
        byte major = (byte)(majorType << 5);
        if (argument < 24)
        {
            output.Add((byte)(major | (byte)argument));
        }
        else if (argument <= byte.MaxValue)
        {
            output.Add((byte)(major | 24));
            output.Add((byte)argument);
        }
        else if (argument <= ushort.MaxValue)
        {
            output.Add((byte)(major | 25));
            output.Add((byte)(argument >> 8));
            output.Add((byte)argument);
        }
        else if (argument <= uint.MaxValue)
        {
            output.Add((byte)(major | 26));
            for (int shift = 24; shift >= 0; shift -= 8)
            {
                output.Add((byte)(argument >> shift));
            }
        }
        else
        {
            output.Add((byte)(major | 27));
            for (int shift = 56; shift >= 0; shift -= 8)
            {
                output.Add((byte)(argument >> shift));
            }
        }
    }
}
