/*
	Copyright © Bryan Apellanes 2015  
*/

using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Crypto;
using System.Text;

namespace Bam.Encryption
{
    /// <summary>
    /// Provides extension methods for converting cryptographic keys and objects to and from PEM format.
    /// </summary>
    public static class Pem
    {
        /// <summary>
        /// Converts the specified object to its PEM-encoded string representation.
        /// </summary>
        /// <param name="obj">The object to encode as PEM.</param>
        /// <returns>The PEM-encoded string.</returns>
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

        /// <summary>
        /// Converts the specified asymmetric key to a PEM-encoded byte array using the given encoding.
        /// </summary>
        /// <param name="key">The asymmetric key to encode.</param>
        /// <param name="encoding">The character encoding to use; defaults to UTF-8 if null.</param>
        /// <returns>A byte array containing the PEM-encoded key.</returns>
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
        /// Returns the public portion of the specified key pair in PEM format (compatible with OpenSSL).
        /// </summary>
        /// <param name="keyPair">The asymmetric key pair to extract the public key from.</param>
        /// <returns>The PEM-encoded public key string.</returns>
        public static string PublicKeyToPem(this AsymmetricCipherKeyPair keyPair)
        {
            return FromPublicKey(keyPair);
        }

        /// <summary>
        /// Returns the public portion of the specified key pair in PEM format (compatible with OpenSSL).
        /// </summary>
        /// <param name="keyPair">The asymmetric key pair to extract the public key from.</param>
        /// <returns>The PEM-encoded public key string.</returns>
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
        /// Converts the specified key pair to its PEM-encoded string representation (compatible with OpenSSL).
        /// </summary>
        /// <param name="keyPair">The asymmetric key pair to convert.</param>
        /// <returns>The PEM-encoded private key string.</returns>
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
        /// Exports the private key from the specified key pair in PEM format as a string.
        /// </summary>
        /// <param name="keyPair">The asymmetric key pair containing the private key to export.</param>
        /// <returns>The PEM-encoded private key string.</returns>
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

        /// <summary>
        /// Parses a PEM-encoded string and returns the asymmetric key parameter it contains.
        /// </summary>
        /// <param name="pemString">The PEM-encoded string to parse.</param>
        /// <returns>The parsed asymmetric key parameter.</returns>
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

        /// <summary>
        /// Parses PEM-encoded bytes and returns the asymmetric key parameter they contain.
        /// </summary>
        /// <param name="pemBytes">The PEM-encoded byte array to parse.</param>
        /// <param name="encoding">The character encoding to use; defaults to UTF-8 if null.</param>
        /// <returns>The parsed asymmetric key parameter.</returns>
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

        /// <summary>
        /// Parses PEM-encoded bytes and returns the asymmetric cipher key pair they contain.
        /// </summary>
        /// <param name="pemBytes">The PEM-encoded byte array to parse.</param>
        /// <param name="encoding">The character encoding to use; defaults to UTF-8 if null.</param>
        /// <returns>The parsed asymmetric cipher key pair.</returns>
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

        /// <summary>
        /// Parses a PEM-encoded string and returns the asymmetric cipher key pair it contains.
        /// </summary>
        /// <param name="pemString">The PEM-encoded string to parse.</param>
        /// <returns>The parsed asymmetric cipher key pair.</returns>
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
