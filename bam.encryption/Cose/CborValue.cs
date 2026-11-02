namespace Bam.Encryption.Cose;

/// <summary>
/// A decoded CBOR data item (RFC 8949).  <see cref="CborReader"/> produces these and
/// <see cref="CborWriter"/> consumes them.  The model covers the subset WebAuthn and COSE use:
/// integers that fit in a <see cref="long"/>, byte strings, text strings, definite-length arrays
/// and maps, and the simple values (booleans, null, undefined, floating point).
/// </summary>
public abstract record CborValue
{
    /// <summary>
    /// Looks up a map entry by integer key.  Returns null when this value is not a map or the key
    /// is absent, so callers can probe optional COSE labels without a type test.
    /// </summary>
    /// <param name="key">The integer key.</param>
    public virtual CborValue? this[long key] => null;

    /// <summary>
    /// Looks up a map entry by text key.  Returns null when this value is not a map or the key
    /// is absent.
    /// </summary>
    /// <param name="key">The text key.</param>
    public virtual CborValue? this[string key] => null;

    /// <summary>
    /// Returns this value as an integer.
    /// </summary>
    /// <exception cref="CborFormatException">This value is not an integer.</exception>
    public long AsInt64()
    {
        if (this is CborInteger integer)
        {
            return integer.Value;
        }
        throw new CborFormatException($"Expected an integer but found {Describe()}.");
    }

    /// <summary>
    /// Returns this value as a byte string.
    /// </summary>
    /// <exception cref="CborFormatException">This value is not a byte string.</exception>
    public byte[] AsBytes()
    {
        if (this is CborBytes bytes)
        {
            return bytes.Value;
        }
        throw new CborFormatException($"Expected a byte string but found {Describe()}.");
    }

    /// <summary>
    /// Returns this value as a text string.
    /// </summary>
    /// <exception cref="CborFormatException">This value is not a text string.</exception>
    public string AsText()
    {
        if (this is CborText text)
        {
            return text.Value;
        }
        throw new CborFormatException($"Expected a text string but found {Describe()}.");
    }

    /// <summary>
    /// Returns this value as a map.
    /// </summary>
    /// <exception cref="CborFormatException">This value is not a map.</exception>
    public CborMap AsMap()
    {
        if (this is CborMap map)
        {
            return map;
        }
        throw new CborFormatException($"Expected a map but found {Describe()}.");
    }

    /// <summary>
    /// A short description of the value's kind, for messages.
    /// </summary>
    protected virtual string Describe()
    {
        return GetType().Name;
    }
}

/// <summary>
/// A CBOR integer (major types 0 and 1) that fits in a <see cref="long"/>.
/// </summary>
/// <param name="Value">The integer value.</param>
public sealed record CborInteger(long Value) : CborValue;

/// <summary>
/// A CBOR byte string (major type 2).
/// </summary>
/// <param name="Value">The bytes.</param>
public sealed record CborBytes(byte[] Value) : CborValue
{
    /// <inheritdoc />
    public bool Equals(CborBytes? other)
    {
        return other is not null && Value.AsSpan().SequenceEqual(other.Value);
    }

    /// <inheritdoc />
    public override int GetHashCode()
    {
        HashCode hash = new HashCode();
        hash.AddBytes(Value);
        return hash.ToHashCode();
    }
}

/// <summary>
/// A CBOR text string (major type 3), always valid UTF-8.
/// </summary>
/// <param name="Value">The text.</param>
public sealed record CborText(string Value) : CborValue;

/// <summary>
/// A definite-length CBOR array (major type 4).
/// </summary>
/// <param name="Items">The items, in order.</param>
public sealed record CborArray(IReadOnlyList<CborValue> Items) : CborValue
{
    /// <inheritdoc />
    public bool Equals(CborArray? other)
    {
        return other is not null && Items.SequenceEqual(other.Items);
    }

    /// <inheritdoc />
    public override int GetHashCode()
    {
        HashCode hash = new HashCode();
        foreach (CborValue item in Items)
        {
            hash.Add(item);
        }
        return hash.ToHashCode();
    }
}

/// <summary>
/// A definite-length CBOR map (major type 5) whose keys are integers or text, in encoded order.
/// </summary>
/// <param name="Entries">The entries, in order.</param>
public sealed record CborMap(IReadOnlyList<KeyValuePair<CborValue, CborValue>> Entries) : CborValue
{
    /// <inheritdoc />
    public override CborValue? this[long key]
    {
        get
        {
            foreach (KeyValuePair<CborValue, CborValue> entry in Entries)
            {
                if (entry.Key is CborInteger integer && integer.Value == key)
                {
                    return entry.Value;
                }
            }
            return null;
        }
    }

    /// <inheritdoc />
    public override CborValue? this[string key]
    {
        get
        {
            foreach (KeyValuePair<CborValue, CborValue> entry in Entries)
            {
                if (entry.Key is CborText text && string.Equals(text.Value, key, StringComparison.Ordinal))
                {
                    return entry.Value;
                }
            }
            return null;
        }
    }

    /// <summary>
    /// Gets the number of entries.
    /// </summary>
    public int Count => Entries.Count;

    /// <inheritdoc />
    public bool Equals(CborMap? other)
    {
        if (other is null || other.Entries.Count != Entries.Count)
        {
            return false;
        }
        for (int i = 0; i < Entries.Count; i++)
        {
            if (!Entries[i].Key.Equals(other.Entries[i].Key) || !Entries[i].Value.Equals(other.Entries[i].Value))
            {
                return false;
            }
        }
        return true;
    }

    /// <inheritdoc />
    public override int GetHashCode()
    {
        HashCode hash = new HashCode();
        foreach (KeyValuePair<CborValue, CborValue> entry in Entries)
        {
            hash.Add(entry.Key);
            hash.Add(entry.Value);
        }
        return hash.ToHashCode();
    }
}

/// <summary>
/// The kinds of CBOR simple value (major type 7) the model distinguishes.
/// </summary>
public enum CborSimpleKind
{
    /// <summary>The boolean false.</summary>
    False,
    /// <summary>The boolean true.</summary>
    True,
    /// <summary>The null value.</summary>
    Null,
    /// <summary>The undefined value.</summary>
    Undefined,
    /// <summary>A half, single or double precision floating point number, widened to double.</summary>
    Float,
    /// <summary>An unassigned simple value, carried by its number.</summary>
    Other
}

/// <summary>
/// A CBOR simple value or floating point number (major type 7).
/// </summary>
/// <param name="Kind">Which simple value this is.</param>
/// <param name="Number">The floating point value for <see cref="CborSimpleKind.Float"/>, the simple-value number for <see cref="CborSimpleKind.Other"/>, otherwise null.</param>
public sealed record CborSimple(CborSimpleKind Kind, double? Number) : CborValue
{
    /// <summary>The boolean false.</summary>
    public static readonly CborSimple False = new CborSimple(CborSimpleKind.False, null);
    /// <summary>The boolean true.</summary>
    public static readonly CborSimple True = new CborSimple(CborSimpleKind.True, null);
    /// <summary>The null value.</summary>
    public static readonly CborSimple Null = new CborSimple(CborSimpleKind.Null, null);
    /// <summary>The undefined value.</summary>
    public static readonly CborSimple Undefined = new CborSimple(CborSimpleKind.Undefined, null);
}
