/*
	Copyright © Bryan Apellanes 2015  
*/

using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Crypto;
using System.Text;

namespace Bam.Encryption
{
    public static class Pem
    {
        public static string ObjectToPem(this object obj)
        {
            using (StringWriter stringWriter = new StringWriter())
            {
                using (PemWriter pemWriter = new PemWriter(stringWriter))
                {
                    pemWriter.WriteObject(obj);
                    return stringWriter.ToString();
                }   
            }          
        }

        public static byte[] ToPem(this AsymmetricKeyParameter key, Encoding? encoding = null)
        {
            using (StringWriter stringWriter = new StringWriter())
            {
                using (PemWriter pemWriter = new PemWriter(stringWriter))
                {
                    pemWriter.WriteObject(key);
                    return (encoding ?? Encoding.UTF8).GetBytes(stringWriter.ToString());
                }   
            }
        }

        /// <summary>
        /// Converts the specified asymmetric key to its PEM-encoded string representation.
        /// </summary>
        /// <remarks>The returned string includes the standard PEM header and footer lines. This method is
        /// typically used to export keys for storage or transmission in a widely supported text format.</remarks>
        /// <param name="key">The asymmetric key to encode as a PEM-formatted string. Cannot be null.</param>
        /// <returns>A string containing the PEM-encoded representation of the specified key.</returns>
        public static string ToPem(this AsymmetricKeyParameter key)
        {
            using (StringWriter stringWriter = new StringWriter())
            {
                using (PemWriter pemWriter = new PemWriter(stringWriter))
                {
                    pemWriter.WriteObject(key);
                    return stringWriter.ToString();
                }   
            }   
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
            using (StringWriter stringWriter = new StringWriter())
            {
                using (PemWriter pemWriter = new PemWriter(stringWriter))
                {
                    pemWriter.WriteObject(keyPair.Public);
                    return stringWriter.ToString();
                }   
            }  
        }

        /// <summary>
        /// Returns the specified keyPair in
        /// pem format (compatible with openssl)
        /// </summary>
        /// <param name="keyPair"></param>
        /// <returns></returns>
        [Obsolete("Use overload that returns a byte array instead")]
        public static string ToPem(this AsymmetricCipherKeyPair keyPair)
        {
            return FromPrivateKey(keyPair);
        }

        /// <summary>
        /// Converts the specified asymmetric key pair to a PEM-encoded byte array.
        /// </summary>
        /// <param name="keyPair">The asymmetric key pair to convert. Cannot be null.</param>
        /// <param name="encoding">The character encoding to use when converting the PEM string to bytes. If null, UTF-8 encoding is used.</param>
        /// <returns>A byte array containing the PEM-encoded representation of the key pair.</returns>
        public static byte[] ToPem(this AsymmetricCipherKeyPair keyPair, Encoding? encoding = null)
        {
            return FromPrivateKey(keyPair, encoding);
        }

        /// <summary>
        /// Exports the private key from the specified asymmetric key pair in PEM format as a byte array.
        /// </summary>
        /// <param name="keyPair">The asymmetric key pair containing the private key to export. Cannot be null.</param>
        /// <param name="encoding">The character encoding to use when converting the PEM string to bytes. If null, UTF-8 encoding is used.</param>
        /// <returns>A byte array containing the PEM-encoded private key.</returns>
        public static byte[] FromPrivateKey(AsymmetricCipherKeyPair keyPair, Encoding? encoding = null)
        {
            using (StringWriter stringWriter = new StringWriter())
            {
                using (PemWriter pemWriter = new PemWriter(stringWriter))
                {
                    pemWriter.WriteObject(keyPair.Private);
                    return (encoding ?? Encoding.UTF8).GetBytes(stringWriter.ToString());
                }                    
            }
        }

        /// <summary>
        /// Returns the specified keyPair in
        /// pem format.
        /// </summary>
        /// <param name="keyPair"></param>
        /// <returns></returns>
        [Obsolete("Use overload that returns a byte array instead")]
        public static string FromPrivateKey(AsymmetricCipherKeyPair keyPair)
        {
            using (StringWriter stringWriter = new StringWriter())
            {
                using (PemWriter pemWriter = new PemWriter(stringWriter))
                {
                    pemWriter.WriteObject(keyPair.Private);
                    return stringWriter.ToString();
                }                    
            }
        }

        public static AsymmetricKeyParameter PemToKey(this string pemString)
        {
            using (TextReader reader = new StringReader(pemString))
            {
                using (PemReader pemReader = new PemReader(reader))
                {
                    object pemObject = pemReader.ReadObject();
                    return (AsymmetricKeyParameter)pemObject;
                }
            }   
        }

        public static AsymmetricKeyParameter PemToKey(this byte[] pemBytes, Encoding? encoding = null)
        {
            using (MemoryStream ms = new MemoryStream(pemBytes))
            {
                using (StreamReader sr = new StreamReader(ms, encoding ?? Encoding.UTF8))
                {
                    PemReader pemReader = new PemReader(sr);
                    object pemObject = pemReader.ReadObject();
                    return (AsymmetricKeyParameter)pemObject;
                }
            }
        }

        public static AsymmetricCipherKeyPair PemToKeyPair(this byte[] pemBytes, Encoding? encoding = null)
        {
            using (MemoryStream ms = new MemoryStream(pemBytes))
            {
                using (StreamReader sr = new StreamReader(ms, encoding ?? Encoding.UTF8))
                {
                    PemReader pemReader = new PemReader(sr);
                    object pemObject = pemReader.ReadObject();
                    return (AsymmetricCipherKeyPair)pemObject;
                }
            }
        }

        [Obsolete("Use PemToKeyPair(byte[] pemBytes, Encoding? encoding = null) instead")]
        public static AsymmetricCipherKeyPair PemToKeyPair(this string pemString)
        {
            using (TextReader reader = new StringReader(pemString))
            {
                using (PemReader pemReader = new PemReader(reader))
                {
                    object pemObject = pemReader.ReadObject();
                    return (AsymmetricCipherKeyPair)pemObject;
                }   
            }                
        }
    }
}
