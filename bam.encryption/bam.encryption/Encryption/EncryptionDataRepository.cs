using Bam.Net.Data;
using Bam.Net.Encryption.Data;

namespace Bam.Net.Encryption
{
    public class EncryptionDataRepository
    {
        public Database Database { get; internal set; }

        internal IClientKeySet GetClientKeySet(string identifier)
        {
            throw new NotImplementedException();
        }

        internal IServerKeySet GetServerKeySet(string identifier)
        {
            throw new NotImplementedException();
        }

        internal Task<IClientKeySet> SaveAsync(IClientKeySet copy)
        {
            throw new NotImplementedException();
        }

        internal Task<IServerKeySet> SaveAsync(IServerKeySet copy) 
        {
            throw new NotImplementedException();
        }
    }
}