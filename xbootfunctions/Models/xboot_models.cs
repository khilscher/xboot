using System;
using System.Collections.Generic;
using System.Text;

namespace xbootfunctions.Models
{
    public sealed class Certificate_Request
    {
        public string Mac { get; set; }

        // Byte array as Base64 string
        public string Csr { get; set; }
    }

    public sealed class Certificate_Response
    {
        // Byte array as Base64 string
        public string Certificate { get; set; }
    }
}
