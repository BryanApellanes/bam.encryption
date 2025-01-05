using Bam.ServiceProxy;
//using Bam.ServiceProxy.Data;
using Bam.ServiceProxy.Encryption;
using Bam.Services;
using Org.BouncyCastle.Crypto;
using System;
using System.Collections.Generic;
using System.Text;

namespace Bam.Encryption
{
    public class RsaByteReverseTransformer : IValueReverseTransformer<byte[], byte[]>, IRequiresHttpContext, ICloneable, IContextCloneable
    {
        public RsaByteReverseTransformer(Func<RsaPublicPrivateKeyPair> keyProvider)
        {
            this.KeyProvider = keyProvider;
        }

        public RsaByteReverseTransformer(RsaByteTransformer rsaByteReverseTransformer, Func<RsaPublicPrivateKeyPair> keyProvider)
        {
            this.RsaByteTransformer = rsaByteReverseTransformer;
            this.KeyProvider = keyProvider;
        }

        public Func<RsaPublicPrivateKeyPair> KeyProvider { get; set; }

        public RsaByteTransformer RsaByteTransformer { get; set; }

        public IHttpContext HttpContext { get; set; }

        public object Clone()
        {
            object clone = new RsaByteReverseTransformer(RsaByteTransformer, KeyProvider);
            clone.CopyProperties(this);
            clone.CopyEventHandlers(this);
            return clone;
        }

        public object Clone(IHttpContext context)
        {
            RsaByteReverseTransformer clone = new RsaByteReverseTransformer(RsaByteTransformer, KeyProvider);
            clone.CopyProperties(this);
            clone.CopyEventHandlers(this);
            clone.HttpContext = context;
            return clone;
        }

        public object CloneInContext()
        {
            return Clone(HttpContext);
        }

        public byte[] ReverseTransform(byte[] cipherBytes)
        {
            RsaPublicPrivateKeyPair rsaKey = KeyProvider();

            return rsaKey.DecryptBytes(cipherBytes);
        }

        public IValueTransformer<byte[], byte[]> GetTransformer()
        {
            Args.ThrowIfNull(this.RsaByteTransformer);

            return this.RsaByteTransformer;
        }
    }
}
