using System;
using System.IO;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Azure.WebJobs;
using Microsoft.Azure.WebJobs.Extensions.Http;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Newtonsoft.Json;
using XBoot.Models;
using Microsoft.AspNetCore.Builder;
using Org.BouncyCastle.Asn1.Pkcs;
//using System.Security.Cryptography.X509Certificates;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities.IO.Pem;
using Org.BouncyCastle.X509;
using Org.BouncyCastle.X509.Extension;

namespace XBoot.Server
{
    public static class certificate
    {

        [FunctionName("certificate")]
        public static async Task<IActionResult> Run(
            [HttpTrigger(AuthorizationLevel.Function, "post", Route = null)] HttpRequest req,
            ILogger log)
        {
            log.LogInformation("Certificate trigger function processed a request.");

            // Intermediate certificate
            // Path to intermediate certificate
            string iaCertFile = "c:\\openssl_stuff\\ia.cer";

            // The stuff between the -----BEGIN RSA PRIVATE KEY---- and ----END RSA PRIVATE KEY----
            // is the base64 encoding of a PKCS#8 PrivateKeyInfo
            string iaPrivKeyFile = "c:\\openssl_stuff\\ia.key";

            string requestBody = await new StreamReader(req.Body).ReadToEndAsync();
            Certificate_Request request = JsonConvert.DeserializeObject<Certificate_Request>(requestBody);

            // Validate payload
            if (string.IsNullOrEmpty(request.RegistrationId) || string.IsNullOrEmpty(request.Csr))
            {

                return new BadRequestResult();

            }

            // TODO Validate the RegistrationId with some external source
            // Registration ID must only contain alphanumeric and hyphen to maintain compatibility with DPS.
            // e.g. bool isAuthorized = CheckAuthorizedDevicesDB(request.RegistrationId);
            bool isAuthorized = true;

            if (isAuthorized)
            {

                Pkcs10CertificationRequest decodedCsr = null;
                RsaKeyParameters publicKey = null;
                CertificationRequestInfo info = null;

                // Get the signing certificate
                X509Certificate serverCertificate =
                    DotNetUtilities.FromX509Certificate(
                        System.Security.Cryptography.X509Certificates.X509Certificate.CreateFromCertFile(iaCertFile));

                AsymmetricKeyParameter serverPrivateKey = readPrivateKey(iaPrivKeyFile);

                byte[] csr = Convert.FromBase64String(request.Csr);

                // Decode DER
                decodedCsr = new Pkcs10CertificationRequest(csr);
                info = decodedCsr.GetCertificationRequestInfo();
                SubjectPublicKeyInfo publicKeyInfo = info.SubjectPublicKeyInfo;

                RsaPublicKeyStructure publicKeyStructure = RsaPublicKeyStructure.GetInstance(publicKeyInfo.ParsePublicKey());

                publicKey = new RsaKeyParameters(false, publicKeyStructure.Modulus, publicKeyStructure.PublicExponent);

                bool certIsOK = decodedCsr.Verify(publicKey);

                // Generate the device certificate
                X509V3CertificateGenerator generator = new X509V3CertificateGenerator();

                generator.SetSerialNumber(BigInteger.ProbablePrime(120, new Random()));
                generator.SetIssuerDN(serverCertificate.SubjectDN);
                generator.SetNotBefore(DateTime.Now);
                generator.SetNotAfter(DateTime.Now.AddYears(5));
                generator.SetSubjectDN(info.Subject);
                generator.SetPublicKey(publicKey);
                generator.SetSignatureAlgorithm("SHA512withRSA");
                generator.AddExtension(X509Extensions.AuthorityKeyIdentifier, false, new AuthorityKeyIdentifierStructure(serverCertificate));
                generator.AddExtension(X509Extensions.SubjectKeyIdentifier, false, new SubjectKeyIdentifierStructure(publicKey));

                var deviceCert = generator.Generate(serverPrivateKey);

                // Write out DER certificate
                byte[] encoded = deviceCert.GetEncoded();

                // Convert byte array to Base64 string
                string encodedString = Convert.ToBase64String(encoded);

                Certificate_Response responseMessage = new Certificate_Response
                {
                    Certificate = encodedString
                };

                log.LogInformation($"Certificate issued for: {info.Subject.ToString()}");

                return new OkObjectResult(responseMessage);

            }
            else
            {

                return new BadRequestResult();

            }
        }

        static AsymmetricKeyParameter readPrivateKey(string privateKeyFileName)
        {
            AsymmetricCipherKeyPair keyPair;

            using (var reader = File.OpenText(privateKeyFileName))
                keyPair = (AsymmetricCipherKeyPair)new Org.BouncyCastle.OpenSsl.PemReader(reader).ReadObject();

            return keyPair.Private;
        }
    }
}
