using System;
using Newtonsoft.Json;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using XBoot.Models;


namespace XBoot.Client
{
    public class XBootClient
    {

        private RSA _rsa;
        private string _xBootUri;

        /// <summary>
        /// Initializes an XBootClient
        /// </summary>
        /// <param name="xBootServerUri">URI of XBoot.Server REST endpoint</param>
        public XBootClient(string xBootServerUri)
        {
            _xBootUri = xBootServerUri;
            _rsa = RSA.Create(2048);
        }

        /// <summary>
        /// Generates and sends a CSR to Xboot.Server REST endpoint.
        /// </summary>
        /// <param name="registrationId"></param>
        /// <param name="name"></param>
        /// <returns>Pfx in DER-encoded byte array</returns>
        public byte[] GetDeviceCertificate(string registrationId, X500DistinguishedName name)
        {
            byte[] pfx = null;

            var req = new CertificateRequest(name, _rsa, HashAlgorithmName.SHA512,
                RSASignaturePadding.Pss);

            // Returns a DER-encoded PKCS#10 CSR
            var csr = req.CreateSigningRequest();

            Certificate_Request request = new Certificate_Request
            {
                RegistrationId = registrationId,
                Csr = Convert.ToBase64String(csr)
            };

            var json = JsonConvert.SerializeObject(request);

            var client = new HttpClient();
            client.DefaultRequestHeaders.Accept.Clear();
            client.DefaultRequestHeaders.Accept.Add(
                new MediaTypeWithQualityHeaderValue("application/json"));

            var buffer = System.Text.Encoding.UTF8.GetBytes(json);
            var byteContent = new ByteArrayContent(buffer);

            try
            {

                var response = client.PostAsync(_xBootUri, byteContent).Result;

                if (response.IsSuccessStatusCode)
                {

                    // Get the response
                    var jsonString = response.Content.ReadAsStringAsync().Result;
                    var certString = JsonConvert.DeserializeObject<Certificate_Response>(jsonString);

                    byte[] certBytes = Convert.FromBase64String(certString.Certificate);

                    // Read in signed device certificate in DER format
                    X509Certificate2 cert = new X509Certificate2(certBytes);

                    // Add private key to cert
                    cert = cert.CopyWithPrivateKey(_rsa);

                    if (cert.HasPrivateKey)
                    {

                        // Combine certificate and private key into single pfx
                        // The IoT Device SDK needs both the certificate and the private key information. 
                        // It expects to load a single PFX-formatted file containing all necessarily information.
                        pfx = cert.Export(X509ContentType.Pfx);

                    }

                }
                else
                {

                    throw new Exception(response.StatusCode.ToString());

                }

            }
            catch (Exception ex)
            {

                throw new Exception(ex.Message);

            }

            // Return certificate in DER-encoded byte array
            return pfx;

        }
    }
}
