/*
	Copyright © Bryan Apellanes 2015  
*/

namespace Bam.Encryption
{
    /// <summary>
    /// Specifies the RSA key length in bits.
    /// </summary>
    public enum RsaKeyLength
    {
        /// <summary>
        /// Unknown or unspecified key length.
        /// </summary>
        Unkown = -1,

        /// <summary>
        /// 1024-bit RSA key.
        /// </summary>
        _1024 = 1024,

        /// <summary>
        /// 2048-bit RSA key.
        /// </summary>
        _2048 = 2048,

        /// <summary>
        /// 4096-bit RSA key.
        /// </summary>
        _4096 = 4096
    }
}
