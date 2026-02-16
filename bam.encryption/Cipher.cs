namespace Bam.Encryption
{
    /// <summary>
    /// Represents a typed encryption cipher that wraps encrypted byte data with implicit conversions to and from byte arrays and Base64 strings.
    /// </summary>
    /// <typeparam name="TData">The type of data that was encrypted to produce this cipher.</typeparam>
    public class Cipher<TData> : Cipher
    {
        public static implicit operator byte[](Cipher<TData> cipher)
        {
            return cipher.Data;
        }

        public static implicit operator Cipher<TData>(byte[] data)
        {
            return new Cipher<TData>() { Data = data };
        }

        public static implicit operator string(Cipher<TData> cipher)
        {
            return cipher.Data.ToBase64();
        }

        public static implicit operator Cipher<TData>(string data)
        {
            return new Cipher<TData>() { Data = data.FromBase64() };
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="Cipher{TData}"/> class.
        /// </summary>
        public Cipher() { }

        /// <summary>
        /// Initializes a new instance of the <see cref="Cipher{TData}"/> class from a Base64-encoded cipher string.
        /// </summary>
        /// <param name="base64Data">The Base64-encoded cipher data.</param>
        public Cipher(string base64Data)
        {
            this.Data = base64Data.FromBase64();
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="Cipher{TData}"/> class from raw cipher bytes.
        /// </summary>
        /// <param name="data">The raw encrypted byte data.</param>
        public Cipher(byte[] data)
        {
            this.Data = data;
        }
    }

    /// <summary>
    /// Represents an encryption cipher that wraps encrypted byte data with implicit conversions to and from byte arrays and Base64 strings.
    /// </summary>
    public class Cipher
    {
        public static implicit operator byte[](Cipher cipher)
        {
            return cipher.Data;
        }

        public static implicit operator Cipher(byte[] data)
        {
            return new Cipher { Data = data };
        }

        public static implicit operator string(Cipher cipher)
        {
            return cipher.Data.ToBase64();
        }

        public static implicit operator Cipher(string data)
        {
            return new Cipher { Data = data.FromBase64() };
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="Cipher"/> class.
        /// </summary>
        public Cipher() { }

        /// <summary>
        /// Initializes a new instance of the <see cref="Cipher"/> class from raw cipher bytes.
        /// </summary>
        /// <param name="data">The raw encrypted byte data.</param>
        public Cipher(byte[] data)
        {
            this.Data = data;
        }

        /// <summary>
        /// Gets or sets the raw encrypted byte data.
        /// </summary>
        public byte[] Data { get; set; }

        /// <summary>
        /// Returns the cipher data as a Base64-encoded string.
        /// </summary>
        /// <returns>A Base64-encoded representation of the cipher data.</returns>
        public override string ToString()
        {
            return Data.ToBase64();
        }
    }
}
