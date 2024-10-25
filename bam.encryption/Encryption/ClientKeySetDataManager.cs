﻿using Bam.Data;
using Bam.Encryption.Data;
//using Bam.Encryption.Data.Dao.Repository;
using Bam.Services;
using System;
using System.Collections.Generic;
using System.Text;
using System.Threading.Tasks;

namespace Bam.Encryption
{
    public class ClientKeySetDataManager : IClientKeySetDataManager
    {
        public ClientKeySetDataManager()
        {
            this.EncryptionDataRepository = new EncryptionDataRepository();
            this.ApplicationNameProvider = ProcessApplicationNameProvider.Current;
        }

        public ClientKeySetDataManager(Database database)
        {
            this.EncryptionDataRepository = new EncryptionDataRepository() { Database = database };
            this.ApplicationNameProvider = ProcessApplicationNameProvider.Current;
        }

        [Inject]
        public EncryptionDataRepository EncryptionDataRepository { get; set; }

        [Inject]
        public IApplicationNameProvider ApplicationNameProvider { get; set; }

        public async Task<IAesKeyExchange> CreateAesKeyExchangeAsync(IClientKeySet clientKeySet)
        {
            if (!clientKeySet.GetIsInitialized())
            {
                clientKeySet.Initialize();
            }

            clientKeySet = await SaveClientKeySetAsync(clientKeySet);

            return clientKeySet.GetKeyExchange();
        }

        public Task<IClientKeySet> RetrieveClientKeySetAsync(string identifier)
        {
            return Task.FromResult((IClientKeySet)EncryptionDataRepository.GetClientKeySet(identifier));
        }

        public Task<IClientKeySet> RetrieveClientKeySetForPublicKeyAsync(string publicKey)
        {
            string identifier = KeySet.GetIdentifier(publicKey);
            return RetrieveClientKeySetAsync(identifier);
        }

        public async Task<IClientKeySet> SaveClientKeySetAsync(IClientKeySet clientKeySet)
        {
            if (!(await RetrieveClientKeySetAsync(clientKeySet.Identifier) is ClientKeySet existingClientKeySet))
            {
                ClientKeySet copy = clientKeySet.CopyAsNew<ClientKeySet>();

                clientKeySet = await EncryptionDataRepository.SaveAsync(copy);
            }
            else
            {
                existingClientKeySet.PublicKey = clientKeySet.PublicKey;
                existingClientKeySet.AesKey = clientKeySet.AesKey;
                existingClientKeySet.AesIV = clientKeySet.AesIV;
                clientKeySet = await EncryptionDataRepository.SaveAsync(existingClientKeySet);
            }

            return clientKeySet;
        }

        public async Task<IClientKeySet> SetSecret(ISecretExchange secretExchange)
        {
            IClientKeySet clientKeySet = EncryptionDataRepository.GetClientKeySet(secretExchange.Identifier);
            clientKeySet.Secret = clientKeySet.Decrypt(secretExchange.SecretCipher);
            return await EncryptionDataRepository.SaveAsync(clientKeySet);
        }
    }
}
