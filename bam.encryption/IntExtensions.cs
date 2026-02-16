using Org.BouncyCastle.Security;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Bam.Encryption
{
    /// <summary>
    /// Provides cryptographically secure random string generation extension methods for integers.
    /// </summary>
    public static class IntExtensions
    {
        /// <summary>
        /// Generates a cryptographically secure random alphanumeric string of the specified length.
        /// </summary>
        /// <param name="length">The number of characters in the generated string.</param>
        /// <returns>A random alphanumeric string of the specified length.</returns>
        public static string SecureAlphaNumericCharacters(this int length)
        {
            SecureRandom rng = new SecureRandom();
            return string.Join("", rng.GetItems<string>(AlphaNumericCharacters, length));
        }

        private static ReadOnlySpan<string> AlphaNumericCharacters
        {
            get
            {
                return new ReadOnlySpan<string>(new[]
                {
                    "A","B","C","D","E","F","G","H","I","J","K","L","M","N","O","P","Q","R","S","T","U","V","W","X","Y","Z","a","b","c","d","e","f","g","h","i","j","k","l","m","n","o","p","q","r","s","t","u","v","w","x","y","z","0","1","2","3","4","5","6","7","8","9"
                });
            }
        }
    }
}
