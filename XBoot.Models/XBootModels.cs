using System;

namespace XBoot.Models
{
    public sealed class Certificate_Request
    {
        public string RegistrationId { get; set; }

        // Byte array as Base64 string
        public string Csr { get; set; }
    }

    public sealed class Certificate_Response
    {
        // Byte array as Base64 string
        public string Certificate { get; set; }
    }

}
