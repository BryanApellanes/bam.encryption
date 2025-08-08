/*
	Copyright © Bryan Apellanes 2015  
*/

using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Crypto;

namespace Bam.Encryption
{
    public static class Pem
    {
        public static string ObjectToPem(this object obj)
        {
            StringWriter stringWriter = new StringWriter();
            PemWriter pemWriter = new PemWriter(stringWriter);
            pemWriter.WriteObject(obj);
            return stringWriter.ToString();          
        }
        
        public static string ToPem(this AsymmetricKeyParameter key)
        {
            StringWriter stringWriter = new StringWriter();
            PemWriter pemWriter = new PemWriter(stringWriter);
            pemWriter.WriteObject(key);
            return stringWriter.ToString();
        }

        /// <summary>
        /// Returns the public portion of the specified keyPair in 
        /// pem format (compatible with openssl)
        /// </summary>
        /// <param name="keyPair"></param>
        /// <returns></returns>
        public static string PublicKeyToPem(this AsymmetricCipherKeyPair keyPair)
        {
            return FromPublicKey(keyPair);
        }

        /// <summary>
        /// Returns the public portion of the specified keyPair in 
        /// pem format (compatible with openssl)
        /// </summary>
        /// <param name="keyPair"></param>
        /// <returns></returns>
        public static string FromPublicKey(AsymmetricCipherKeyPair keyPair)
        {
            StringWriter stringWriter = new StringWriter();
            PemWriter pemWriter = new PemWriter(stringWriter);
            pemWriter.WriteObject(keyPair.Public);
            return stringWriter.ToString();
        }

        /// <summary>
        /// Returns the specified keyPair in
        /// pem format (compatible with openssl)
        /// </summary>
        /// <param name="keyPair"></param>
        /// <returns></returns>
        public static string ToPem(this AsymmetricCipherKeyPair keyPair)
        {
            return FromPrivateKey(keyPair);
        }

        /// <summary>
        /// Returns the specified keyPair in
        /// pem format.
        /// </summary>
        /// <param name="keyPair"></param>
        /// <returns></returns>
        public static string FromPrivateKey(AsymmetricCipherKeyPair keyPair)
        {
            StringWriter stringWriter = new StringWriter();
            PemWriter pemWriter = new PemWriter(stringWriter);
            pemWriter.WriteObject(keyPair.Private);
            return stringWriter.ToString();
        }

        public static AsymmetricKeyParameter PemToKey(this string pemString)
        {
            TextReader reader = new StringReader(pemString);
            PemReader pemReader = new PemReader(reader);
            object pemObject = pemReader.ReadObject();
            return (AsymmetricKeyParameter)pemObject;
        }

        public static AsymmetricCipherKeyPair PemToKeyPair(this string pemString)
        {
            TextReader reader = new StringReader(pemString);
            PemReader pemReader = new PemReader(reader);
            object pemObject = pemReader.ReadObject();
            return (AsymmetricCipherKeyPair)pemObject;
        }
    }
}
