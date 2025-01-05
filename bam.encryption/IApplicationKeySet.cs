using System;
using System.Collections.Generic;
using System.Text;

namespace Bam.Encryption
{
    public interface IApplicationKeySet
    {
        /// <summary>
        /// Gets or sets the application name.
        /// </summary>
        string ApplicationName { get; set; }
    }
}
