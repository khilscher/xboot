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
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;
using Org.BouncyCastle.X509.Extension;
using Azure.Storage.Blobs;
using Azure.Storage.Blobs.Models;
using Microsoft.Extensions.Configuration;
using Azure.Security.KeyVault.Certificates;
using Azure.Identity;
using Azure.Security.KeyVault.Secrets;

namespace XBoot.Server
{
    public static class certificate
    {
        // Azure Blob client
        private static BlobClient blobClient;

        // Supported locations for retrieving your cert and private key
        private enum Location { KeyVault, File, Blob, Local };

        private static string blobConnectionString;
        private static string blobContainerName;
        private static string keyVaultName;
        private static string key;
        private static string cert;
        private static Location location;
        private static KeyVaultCertificateWithPolicy keyVaultCertificate;

        // Certificate life span in years
        private static int certificateLifespanInYears = 5;


        [FunctionName("certificate")]
        public static async Task<IActionResult> Run(
            [HttpTrigger(AuthorizationLevel.Function, "post", Route = null)] HttpRequest req,
            ILogger log,
            ExecutionContext context)
        {
            log.LogInformation("Certificate trigger function processed a request.");

            try
            {
                await ReadAppSettings(context, log);

                string requestBody = await new StreamReader(req.Body).ReadToEndAsync();
                Certificate_Request request = JsonConvert.DeserializeObject<Certificate_Request>(requestBody);

                // Validate payload
                if (string.IsNullOrEmpty(request.RegistrationId) || string.IsNullOrEmpty(request.Csr))
                {
                    return new BadRequestResult();
                }

                // Check if the device is authorized to request a certificate
                bool isAuthorized = CheckIfAuthorized(request.RegistrationId);

                if (isAuthorized)
                {

                    log.LogInformation($"{request.RegistrationId} is authorized.");

                    Pkcs10CertificationRequest decodedCsr = null;
                    RsaKeyParameters publicKey = null;
                    CertificationRequestInfo info = null;

                    // Get the signing certificate from a location
                    X509Certificate serverCertificate = ReadCertificate(cert, location, log);

                    if(serverCertificate == null)
                    {
                        throw new System.Exception("ReadCertificate() was unable to retrieve the signing certificate.");
                    }

                    // Get signing cert private key from a location. 
                    AsymmetricKeyParameter serverPrivateKey = ReadPrivateKey(key, location, log);

                    if (serverPrivateKey == null)
                    {
                        throw new System.Exception("ReadPrivateKey() was unable to retrieve the private key.");
                    }

                    byte[] csr = Convert.FromBase64String(request.Csr);

                    // Decode DER
                    decodedCsr = new Pkcs10CertificationRequest(csr);
                    info = decodedCsr.GetCertificationRequestInfo();
                    SubjectPublicKeyInfo publicKeyInfo = info.SubjectPublicKeyInfo;

                    RsaPublicKeyStructure publicKeyStructure = RsaPublicKeyStructure.GetInstance(publicKeyInfo.ParsePublicKey());

                    publicKey = new RsaKeyParameters(false, publicKeyStructure.Modulus, publicKeyStructure.PublicExponent);

                    bool certIsOK = decodedCsr.Verify(publicKey);

                    // Create the device certificate
                    X509V3CertificateGenerator generator = new X509V3CertificateGenerator();

                    generator.SetSerialNumber(BigInteger.ProbablePrime(120, new Random()));
                    generator.SetIssuerDN(serverCertificate.SubjectDN);
                    generator.SetNotBefore(DateTime.Now);
                    generator.SetNotAfter(DateTime.Now.AddYears(certificateLifespanInYears));
                    generator.SetSubjectDN(info.Subject);
                    generator.SetPublicKey(publicKey);
                    generator.SetSignatureAlgorithm("SHA512withRSA");
                    generator.AddExtension(X509Extensions.AuthorityKeyIdentifier, false, new AuthorityKeyIdentifierStructure(serverCertificate));
                    generator.AddExtension(X509Extensions.SubjectKeyIdentifier, false, new SubjectKeyIdentifierStructure(publicKey));

                    // Generate the device certificate
                    var deviceCert = generator.Generate(serverPrivateKey);

                    // Convert to DER
                    byte[] encoded = deviceCert.GetEncoded();

                    // Convert byte array to Base64 string
                    string encodedString = Convert.ToBase64String(encoded);

                    Certificate_Response responseMessage = new Certificate_Response
                    {
                        Certificate = encodedString
                    };

                    log.LogInformation($"Certificate issued for: {info.Subject}");

                    return new OkObjectResult(responseMessage);

                }
                else
                {
                    log.LogError($"{request.RegistrationId} is NOT authorized.");

                    return new UnauthorizedResult();
                }

            }
            catch(Exception ex)
            {
                log.LogInformation(ex.Message);
            }

            return new BadRequestResult();

        }

        /// <summary>
        /// Checks if the device's Registration ID is authorized in some external source.
        /// </summary>
        /// <param name="registrationId"></param>
        /// <returns>True if device is authorized</returns>
        private static bool CheckIfAuthorized(string registrationId)
        {

            bool isAuthorized = true;

            // TODO You should validate the RegistrationId with some external source e.g. a database
            // e.g. isAuthorized = CheckRegistratonInCosmosDB(registrationId);

            return isAuthorized;
        }

        /// <summary>
        /// Read application settings from local.settings.json or from Application Settings
        /// </summary>
        /// <param name="context"></param>
        /// <returns>Completed Task</returns>
        private static Task ReadAppSettings(ExecutionContext context, ILogger log)
        {

            log.LogInformation($"Reading app settings...");

            try
            {
                var config = new ConfigurationBuilder()
                    .SetBasePath(context.FunctionAppDirectory)
                    .AddEnvironmentVariables()
                    .AddJsonFile("local.settings.json", optional: true, reloadOnChange: true)
                    .Build();

                location = config.GetValue<Location>("Location");

                if (location == Location.Blob)
                {
                    blobConnectionString = config["BlobConnectionString"];
                    blobContainerName = config["BlobContainerName"];
                    key = config["PrivateKeyFile"];
                    cert = config["CertificateFile"];
                }

                if (location == Location.File)
                {
                    key = config["PrivateKeyFile"];
                    cert = config["CertificateFile"];
                }

                if (location == Location.Local)
                {
                    key = config["PrivateKeyFile"];
                    cert = config["CertificateFile"];
                }

                if (location == Location.KeyVault)
                {
                    keyVaultName = config["KeyVaultName"];
                    cert = config["CertificateFile"];
                    key = ""; // Private key is read from the certificate
                }

            }
            catch
            {
                throw new System.Exception("Missing app settings");
            }

            log.LogInformation($"Finished reading app settings. Using {location}.");

            return Task.CompletedTask;

        }

        /// <summary>
        /// Extracts the signing private key (pem/pkcs8 format) from a location.
        /// Supported locations: Blob storage, File, Local, KeyVault.
        /// </summary>
        /// <param name="privateKey"></param>
        /// <param name="location"></param>
        /// <param name="log"></param>
        /// <returns>Signing cert private key</returns>
        private static AsymmetricKeyParameter ReadPrivateKey(string privateKey, Location location, ILogger log)
        {

            log.LogInformation($"Reading private key from {location}...");

            AsymmetricCipherKeyPair keyPair = null;

            try
            {

                if (location == Location.File)
                {
                    using (var reader = File.OpenText(privateKey))
                    {
                        keyPair = (AsymmetricCipherKeyPair)new Org.BouncyCastle.OpenSsl.PemReader(reader).ReadObject();
                    };
                }

                if (location == Location.Local)
                {
                    using (TextReader reader = new StringReader(privateKey))
                    {
                        Org.BouncyCastle.OpenSsl.PemReader pemReader = new Org.BouncyCastle.OpenSsl.PemReader(reader);
                        keyPair = (AsymmetricCipherKeyPair)pemReader.ReadObject();
                    };
                }

                if (location == Location.Blob)
                {
                    blobClient = new BlobClient(blobConnectionString, blobContainerName, privateKey);
                    BlobDownloadInfo download = blobClient.Download();
                    using (TextReader reader = new StreamReader(download.Content))
                    {
                        Org.BouncyCastle.OpenSsl.PemReader pemReader = new Org.BouncyCastle.OpenSsl.PemReader(reader);
                        keyPair = (AsymmetricCipherKeyPair)pemReader.ReadObject();
                    };
                }

                if (location == Location.KeyVault)
                {
                    // Get the managed secret which contains the public and private key (if exportable).
                    string secretName = ParseSecretName(keyVaultCertificate.SecretId);

                    SecretClient secretClient = new SecretClient(new Uri($"https://{keyVaultName}.vault.azure.net"), new DefaultAzureCredential());

                    KeyVaultSecret certificateSecret = secretClient.GetSecret(secretName);  // Returns PKCS12

                    byte[] certificateBytes = System.Convert.FromBase64String(certificateSecret.Value);

                    var x509 = new System.Security.Cryptography.X509Certificates.X509Certificate2(certificateBytes, "", System.Security.Cryptography.X509Certificates.X509KeyStorageFlags.Exportable | System.Security.Cryptography.X509Certificates.X509KeyStorageFlags.MachineKeySet);

                    keyPair = DotNetUtilities.GetKeyPair(x509.PrivateKey);
                }
            }
            catch (Exception ex)
            {
                log.LogError(ex.Message);
            }

            log.LogInformation($"Finished reading private key from {location}.");

            return keyPair.Private;
        }

        /// <summary>
        /// Parses the secret name.
        /// </summary>
        /// <param name="secretId"></param>
        /// <returns></returns>
        private static string ParseSecretName(Uri secretId)
        {
            if (secretId.Segments.Length < 3)
            {
                throw new InvalidOperationException($@"The secret ""{secretId}"" does not contain a valid name.");
            }

            return secretId.Segments[2].TrimEnd('/');
        }

        /// <summary>
        /// Reads the signing certificate from a location.
        /// Supported locations: Blob storage, File, Local, KeyVault.
        /// </summary>
        /// <param name="certificate"></param>
        /// <param name="location"></param>
        /// <param name="log"></param>
        /// <returns>x509 certificate without private key</returns>
        private static X509Certificate ReadCertificate(string certificate, Location location, ILogger log)
        {

            log.LogInformation($"Reading certificate from {location}...");

            X509Certificate x509 = null;

            try
            {

                if (location == Location.File)
                {
                    x509 = DotNetUtilities.FromX509Certificate(
                            System.Security.Cryptography.X509Certificates.X509Certificate.CreateFromCertFile(certificate));
                }

                if (location == Location.Local)
                {
                    using (TextReader reader = new StringReader(certificate))
                    {
                        Org.BouncyCastle.OpenSsl.PemReader pemReader = new Org.BouncyCastle.OpenSsl.PemReader(reader);
                        x509 = (X509Certificate)pemReader.ReadObject();
                    };
                }

                if (location == Location.Blob)
                {
                    blobClient = new BlobClient(blobConnectionString, blobContainerName, certificate);
                    BlobDownloadInfo download = blobClient.Download();
                    using (TextReader reader = new StreamReader(download.Content))
                    {
                        Org.BouncyCastle.OpenSsl.PemReader pemReader = new Org.BouncyCastle.OpenSsl.PemReader(reader);
                        x509 = (X509Certificate)pemReader.ReadObject();
                    };
                }

                if (location == Location.KeyVault)
                {
                    var client = new CertificateClient(new Uri($"https://{keyVaultName}.vault.azure.net"), new DefaultAzureCredential());
                    keyVaultCertificate = client.GetCertificate(certificate);
                    x509 = new Org.BouncyCastle.X509.X509CertificateParser().ReadCertificate(keyVaultCertificate.Cer);
                }
            }
            catch(Exception ex)
            {
                log.LogError(ex.Message);
            }

            log.LogInformation($"Finished reading certificate {x509.SubjectDN} from {location}.");

            return x509;
        }
    }
}
