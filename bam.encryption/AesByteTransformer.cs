//using Bam.ServiceProxy.Data.Dao.Repository;

namespace Bam.Encryption
{
    [PipelineFactoryTransformerName("aes")]
    public class AesByteTransformer : ValueTransformer<byte[], byte[]>
    {
        public AesByteTransformer(Func<AesKey> keyProvider)
        {
            this.AesByteReverseTransformer = new AesByteReverseTransformer(this);
            this.KeyProvider = keyProvider;
        }

        [PipelineFactoryConstructor]
        public AesByteTransformer(IAesKeySource aesKeySource) : this(aesKeySource.GetAesKey)
        { 
        }

        public AesByteTransformer(AesKey aesKey) : this(() => aesKey)
        { 
        }

        AesByteReverseTransformer _aesByteUntransformer;
        protected AesByteReverseTransformer AesByteReverseTransformer 
        {
            get
            {
                if (this._aesByteUntransformer == null)
                {
                    this._aesByteUntransformer = new AesByteReverseTransformer(this);
                }

                return this._aesByteUntransformer;
            }

            set
            {
                this._aesByteUntransformer = value;
            }
        }

        public Func<AesKey> KeyProvider { get; set; }

        public override byte[] ReverseTransform(byte[] cipherBytes)
        {
            return GetReverseTransformer().ReverseTransform(cipherBytes);
        }

        public override byte[] Transform(byte[] plainData)
        {
            Args.ThrowIfNull(KeyProvider, nameof(KeyProvider));
            AesKey aesKey = KeyProvider();

            return aesKey.EncryptBytes(plainData);
        }

        public override IValueReverseTransformer<byte[], byte[]> GetReverseTransformer()
        {
            return this.AesByteReverseTransformer;
        }
    }
}
