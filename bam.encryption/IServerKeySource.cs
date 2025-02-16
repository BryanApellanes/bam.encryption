using Bam.Encryption;

namespace Bam.shared.Encryption
{
    public interface IServerKeySource : IAesKeySource, IRsaKeySource
    {
    }
}
