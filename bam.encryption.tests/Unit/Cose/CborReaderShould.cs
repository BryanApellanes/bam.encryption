using Bam.Encryption.Cose;
using Bam.Encryption.Tests.TestClasses;
using Bam.Test;

namespace Bam.Encryption.Tests.Unit.Cose;

[UnitTestMenu("CborReaderShould", Selector = "cbor")]
public class CborReaderShould : UnitTestMenuContainer
{
    [UnitTest]
    public void DecodeRfc8949AppendixAIntegers()
    {
        After.Setup(reg =>
        {
            reg.Set(new CborVectors());
        })
        .When<CborVectors>("decodes the integer vectors from RFC 8949 appendix A", (vectors, reg) =>
        {
            return new IntegerOutcome(
                CborReader.Read(vectors.Hex("00")).AsInt64(),
                CborReader.Read(vectors.Hex("17")).AsInt64(),
                CborReader.Read(vectors.Hex("1864")).AsInt64(),
                CborReader.Read(vectors.Hex("1903e8")).AsInt64(),
                CborReader.Read(vectors.Hex("1a000f4240")).AsInt64(),
                CborReader.Read(vectors.Hex("1b000000e8d4a51000")).AsInt64(),
                CborReader.Read(vectors.Hex("20")).AsInt64(),
                CborReader.Read(vectors.Hex("3863")).AsInt64(),
                CborReader.Read(vectors.Hex("3903e7")).AsInt64(),
                CborReader.Read(vectors.Hex("1b7fffffffffffffff")).AsInt64(),
                CborReader.Read(vectors.Hex("3b7fffffffffffffff")).AsInt64());
        })
        .TheTest
        .ShouldPass<IntegerOutcome>((because, outcome) =>
        {
            because.ItsTrue("0x00 is 0", outcome.Zero == 0);
            because.ItsTrue("0x17 is 23", outcome.TwentyThree == 23);
            because.ItsTrue("0x1864 is 100", outcome.Hundred == 100);
            because.ItsTrue("0x1903e8 is 1000", outcome.Thousand == 1000);
            because.ItsTrue("0x1a000f4240 is 1000000", outcome.Million == 1000000);
            because.ItsTrue("0x1b000000e8d4a51000 is 1000000000000", outcome.Trillion == 1000000000000L);
            because.ItsTrue("0x20 is -1", outcome.MinusOne == -1);
            because.ItsTrue("0x3863 is -100", outcome.MinusHundred == -100);
            because.ItsTrue("0x3903e7 is -1000", outcome.MinusThousand == -1000);
            because.ItsTrue("largest supported positive is long.MaxValue", outcome.Max == long.MaxValue);
            because.ItsTrue("smallest supported negative is long.MinValue", outcome.Min == long.MinValue);
        })
        .SoBeHappy()
        .UnlessItFailed();
    }

    [UnitTest]
    public void DecodeStringsArraysMapsAndSimpleValues()
    {
        After.Setup(reg =>
        {
            reg.Set(new CborVectors());
        })
        .When<CborVectors>("decodes byte strings, text, arrays, maps, tags and simple values", (vectors, reg) =>
        {
            CborValue bytes = CborReader.Read(vectors.Hex("4401020304"));
            CborValue text = CborReader.Read(vectors.Hex("63e6b0b4"));
            CborValue array = CborReader.Read(vectors.Hex("83010203"));
            CborValue map = CborReader.Read(vectors.Hex("a26161016162820203"));
            CborValue tagged = CborReader.Read(vectors.Hex("c11a514b67b0"));
            CborValue half = CborReader.Read(vectors.Hex("f93e00"));
            CborValue single = CborReader.Read(vectors.Hex("fa47c35000"));
            CborValue dbl = CborReader.Read(vectors.Hex("fb3ff199999999999a"));
            CborValue negativeKeyMap = CborReader.Read(vectors.Hex("a3010220032201"));
            return new StructureOutcome(bytes, text, array, map, tagged, half, single, dbl, negativeKeyMap,
                CborReader.Read(vectors.Hex("f4")), CborReader.Read(vectors.Hex("f5")), CborReader.Read(vectors.Hex("f6")), CborReader.Read(vectors.Hex("f7")),
                CborReader.Read(vectors.Hex("f0")), CborReader.Read(vectors.Hex("f8ff")));
        })
        .TheTest
        .ShouldPass<StructureOutcome>((because, outcome) =>
        {
            because.ItsTrue("byte string decodes", outcome.Bytes.AsBytes().AsSpan().SequenceEqual(new byte[] { 1, 2, 3, 4 }));
            because.ItsTrue("text string decodes as UTF-8", outcome.Text.AsText() == "水");
            CborArray array = (CborArray)outcome.Array;
            because.ItsTrue("array has three items", array.Items.Count == 3 && array.Items[2].AsInt64() == 3);
            CborMap map = outcome.Map.AsMap();
            because.ItsTrue("text-keyed map resolves 'a'", map["a"]!.AsInt64() == 1);
            because.ItsTrue("text-keyed map resolves 'b' to an array", map["b"] is CborArray inner && inner.Items.Count == 2);
            because.ItsTrue("missing text key is null", map["c"] is null);
            because.ItsTrue("missing integer key on a text map is null", map[1] is null);
            because.ItsTrue("tag is skipped and the tagged integer returned", outcome.Tagged.AsInt64() == 1363896240);
            because.ItsTrue("half float widens", outcome.Half is CborSimple h && h.Kind == CborSimpleKind.Float && h.Number == 1.5);
            because.ItsTrue("single float widens", outcome.Single is CborSimple s && s.Kind == CborSimpleKind.Float && s.Number == 100000.0);
            because.ItsTrue("double float decodes", outcome.Double is CborSimple d && d.Kind == CborSimpleKind.Float && d.Number == 1.1);
            CborMap negative = outcome.NegativeKeyMap.AsMap();
            because.ItsTrue("integer key 1 resolves", negative[1]!.AsInt64() == 2);
            because.ItsTrue("integer key -1 resolves", negative[-1]!.AsInt64() == 3);
            because.ItsTrue("integer key -3 resolves", negative[-3]!.AsInt64() == 1);
            because.ItsTrue("missing text key on an integer map is null", negative["x"] is null);
            because.ItsTrue("false decodes", outcome.False == CborSimple.False);
            because.ItsTrue("true decodes", outcome.True == CborSimple.True);
            because.ItsTrue("null decodes", outcome.Null == CborSimple.Null);
            because.ItsTrue("undefined decodes", outcome.Undefined == CborSimple.Undefined);
            because.ItsTrue("simple 16 decodes as other", outcome.Simple16 is CborSimple s16 && s16.Kind == CborSimpleKind.Other && s16.Number == 16);
            because.ItsTrue("simple 255 decodes as other", outcome.Simple255 is CborSimple s255 && s255.Kind == CborSimpleKind.Other && s255.Number == 255);
        })
        .SoBeHappy()
        .UnlessItFailed();
    }

    [UnitTest]
    public void RejectMalformedInput()
    {
        After.Setup(reg =>
        {
            reg.Set(new CborVectors());
        })
        .When<CborVectors>("decodes each malformed vector", (vectors, reg) =>
        {
            byte[] tooDeep = new byte[41];
            Array.Fill(tooDeep, (byte)0x81, 0, 40);
            tooDeep[40] = 0x00;
            byte[] justDeepEnough = new byte[33];
            Array.Fill(justDeepEnough, (byte)0x81, 0, 32);
            justDeepEnough[32] = 0x00;
            return new RejectionOutcome(
                Rejects(vectors.Hex("5f4101ff")),
                Rejects(vectors.Hex("9f01ff")),
                Rejects(vectors.Hex("ff")),
                Rejects(vectors.Hex("440102")),
                Rejects(vectors.Hex("a201020103")),
                Rejects(vectors.Hex("a1410001")),
                Rejects(vectors.Hex("0000")),
                Rejects(vectors.Hex("5affffffff")),
                Rejects(tooDeep),
                Rejects(vectors.Hex("61ff")),
                Rejects(vectors.Hex("1bffffffffffffffff")),
                Rejects(vectors.Hex("3bffffffffffffffff")),
                Rejects(vectors.Hex("f800")),
                Rejects(vectors.Hex("1c")),
                Rejects(Array.Empty<byte>()),
                Rejects(justDeepEnough));
        })
        .TheTest
        .ShouldPass<RejectionOutcome>((because, outcome) =>
        {
            because.ItsTrue("indefinite byte string is refused", outcome.IndefiniteBytes);
            because.ItsTrue("indefinite array is refused", outcome.IndefiniteArray);
            because.ItsTrue("stray break code is refused", outcome.Break);
            because.ItsTrue("truncated byte string is refused", outcome.Truncated);
            because.ItsTrue("duplicate map key is refused", outcome.DuplicateKey);
            because.ItsTrue("byte-string map key is refused", outcome.BytesKey);
            because.ItsTrue("trailing bytes are refused", outcome.Trailing);
            because.ItsTrue("length past the input is refused", outcome.HugeLength);
            because.ItsTrue("nesting deeper than the limit is refused", outcome.TooDeep);
            because.ItsTrue("invalid UTF-8 is refused", outcome.BadUtf8);
            because.ItsTrue("unsigned integer above long.MaxValue is refused", outcome.TooLarge);
            because.ItsTrue("negative integer below long.MinValue is refused", outcome.TooSmall);
            because.ItsTrue("two-byte simple value below 32 is refused", outcome.BadSimple);
            because.ItsTrue("reserved additional information is refused", outcome.Reserved);
            because.ItsTrue("empty input is refused", outcome.Empty);
            because.ItsTrue("nesting at exactly the limit is accepted", !outcome.AtLimit);
        })
        .SoBeHappy()
        .UnlessItFailed();
    }

    [UnitTest]
    public void ReportConsumedBytesAndRoundTripThroughWriter()
    {
        After.Setup(reg =>
        {
            reg.Set(new CborVectors());
        })
        .When<CborVectors>("decodes a prefix and re-encodes a structure", (vectors, reg) =>
        {
            byte[] prefixed = vectors.Hex("a26161016162820203deadbeef");
            CborValue prefix = CborReader.Read(prefixed, out int consumed);
            CborMap original = CborWriter.Map(
                CborWriter.Entry(1, new CborInteger(2)),
                CborWriter.Entry(3, new CborInteger(-7)),
                CborWriter.Entry(-1, new CborInteger(1)),
                CborWriter.Entry(-2, new CborBytes(new byte[] { 0xaa, 0xbb })),
                CborWriter.Entry("fmt", new CborText("none")),
                CborWriter.Entry("list", new CborArray(new CborValue[] { CborSimple.True, new CborInteger(300), new CborInteger(70000), new CborInteger(5000000000L) })),
                CborWriter.Entry("f", new CborSimple(CborSimpleKind.Float, 2.5)));
            byte[] encoded = CborWriter.Encode(original);
            CborValue decoded = CborReader.Read(encoded);
            return new RoundTripOutcome(prefix, consumed, prefixed.Length, original, decoded, encoded);
        })
        .TheTest
        .ShouldPass<RoundTripOutcome>((because, outcome) =>
        {
            because.ItsTrue("prefix decodes as the map", outcome.Prefix is CborMap m && m.Count == 2);
            because.ItsTrue("consumed stops before the trailing bytes", outcome.Consumed == outcome.TotalLength - 4);
            because.ItsTrue("writer output decodes to an equal value", outcome.Decoded.Equals(outcome.Original));
            because.ItsTrue("writer uses shortest integer encodings", outcome.Encoded.AsSpan().IndexOf(new byte[] { 0x19, 0x01, 0x2c }) >= 0
                && outcome.Encoded.AsSpan().IndexOf(new byte[] { 0x1a, 0x00, 0x01, 0x11, 0x70 }) >= 0
                && outcome.Encoded.AsSpan().IndexOf(new byte[] { 0x1b, 0x00, 0x00, 0x00, 0x01, 0x2a, 0x05, 0xf2, 0x00 }) >= 0);
        })
        .SoBeHappy()
        .UnlessItFailed();
    }

    private static bool Rejects(byte[] input)
    {
        try
        {
            CborReader.Read(input);
            return false;
        }
        catch (CborFormatException)
        {
            return true;
        }
    }

    private sealed record IntegerOutcome(long Zero, long TwentyThree, long Hundred, long Thousand, long Million, long Trillion,
        long MinusOne, long MinusHundred, long MinusThousand, long Max, long Min);

    private sealed record StructureOutcome(CborValue Bytes, CborValue Text, CborValue Array, CborValue Map, CborValue Tagged,
        CborValue Half, CborValue Single, CborValue Double, CborValue NegativeKeyMap,
        CborValue False, CborValue True, CborValue Null, CborValue Undefined, CborValue Simple16, CborValue Simple255);

    private sealed record RejectionOutcome(bool IndefiniteBytes, bool IndefiniteArray, bool Break, bool Truncated, bool DuplicateKey,
        bool BytesKey, bool Trailing, bool HugeLength, bool TooDeep, bool BadUtf8, bool TooLarge, bool TooSmall, bool BadSimple,
        bool Reserved, bool Empty, bool AtLimit);

    private sealed record RoundTripOutcome(CborValue Prefix, int Consumed, int TotalLength, CborMap Original, CborValue Decoded, byte[] Encoded);
}
