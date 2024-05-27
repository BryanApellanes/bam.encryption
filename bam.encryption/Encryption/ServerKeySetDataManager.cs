using Bam.Data;
using Bam.Encryption.Data;
//using Bam.Encryption.Data.Dao.Repository;
using Bam.Services;
using Org.BouncyCastle.Crypto;
using System;
using System.Collections.Generic;
using System.Text;
using System.Threading.Tasks;

namespace Bam.Encryption
{
    public class ServerKeySetDataManager : IServerKeySetDataManager
    {
        public ServerKeySetDataManager()
        {
            this.EncryptionDataRepository = new EncryptionDataRepository();
            this.ApplicationNameProvider = ProcessApplicationNameProvider.Current;
        }

        public ServerKeySetDataManager(Database database)
        {
            this.EncryptionDataRepository = new EncryptionDataRepository() { Database = database };
            this.ApplicationNameProvider = ProcessApplicationNameProvider.Current;
        }

        /// <inheritdoc />
        [Inject]
        public EncryptionDataRepository EncryptionDataRepository { get; set; }

        /// <inheritdoc />
        [Inject]
        public IApplicationNameProvider ApplicationNameProvider { get; set; }

        /// <inheritdoc />
        public async Task<IServerKeySet> CreateServerKeySetAsync(string clientHostName)
        {
            ServerKeySet serverKeySet = new ServerKeySet()
            {
                ApplicationName = ApplicationNameProvider.GetApplicationName(),
                ClientHostName = clientHostName
            };

            return await EncryptionDataRepository.SaveAsync(serverKeySet);
        }

        /// <inheritdoc />
        public Task<IClientKeySet> CreateClientKeySetForServerKeySetAsync(IServerKeySet serverKeySet)
        {
            return Task.FromResult((IClientKeySet)new ClientKeySet(false)
            {
                ServerHostName = serverKeySet.ServerHostName,
                ClientHostName = serverKeySet.ClientHostName,
                PublicKey = serverKeySet.GetAsymmetricKeys().PublicKeyToPem()
            });
        }

        public async Task<IServerKeySet> SetServerAesKeyAsync(IAesKeyExchange keyExchange)
        {
            IServerKeySet serverKeySet = EncryptionDataRepository.GetServerKeySet(keyExchange.Identifier);

            AsymmetricCipherKeyPair rsaKeyPair = serverKeySet.GetAsymmetricKeys();
            serverKeySet.AesKey = keyExchange.AesKeyCipher.DecryptWithPrivateKey(rsaKeyPair);
            serverKeySet.AesIV = keyExchange.AesIVCipher.DecryptWithPrivateKey(rsaKeyPair);
            return await EncryptionDataRepository.SaveAsync(serverKeySet);
        }

        public Task<IServerKeySet> RetrieveServerKeySetAsync(string identifier)
        {
            IServerKeySet serverKeySet = EncryptionDataRepository.GetServerKeySet(identifier);
            return Task.FromResult((IServerKeySet)serverKeySet);
        }

        public Task<IServerKeySet> RetrieveServerKeySetForPublicKeyAsync(string publicKey)
        {
            string identifier = KeySet.GetIdentifier(publicKey);
            return RetrieveServerKeySetAsync(identifier);
        }

        public Task<ISecretExchange> GetSecretExchangeAsync(IServerKeySet serverKeys)
        {
            return Task.FromResult(serverKeys.GetSecretExchange());
        }
    }
}
