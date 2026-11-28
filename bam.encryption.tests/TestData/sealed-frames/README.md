# Sealed-frame vectors

`sealed-session.json` and `sealed-frames.json` are copied unchanged from bam.protocol's `spec/vectors/` at
59dfe335 (bam.protocol#118, the sealed-frames specification). bam.protocol's Python generator is their
source of truth. When it changes them, copy them here again, so the C# primitives, the Python reference and
the JavaScript client are held to the same bytes.

`SessionPrimitivesShould` reads them.
