using System;
using System.IO;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Azure.WebJobs;
using Microsoft.Azure.WebJobs.Extensions.Http;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Newtonsoft.Json;
using xbootfunctions.Models;
using Microsoft.AspNetCore.Builder;
using System.Security.Cryptography.X509Certificates;

namespace xbootfunctions
{
    public static class certificate
    {
        [FunctionName("certificate")]
        public static async Task<IActionResult> Run(
            [HttpTrigger(AuthorizationLevel.Function, "post", Route = null)] HttpRequest req,
            ILogger log)
        {
            log.LogInformation("Certificate trigger function processed a request.");

            string requestBody = await new StreamReader(req.Body).ReadToEndAsync();
            Certificate_Request request = JsonConvert.DeserializeObject<Certificate_Request>(requestBody);

            // Validate payload
            if (string.IsNullOrEmpty(request.Mac) || string.IsNullOrEmpty(request.Csr))
            {

                return new BadRequestResult();

            }

            // TODO Validate the MAC address with some external source
            // e.g. bool isAuthorized = CheckAuthorizedDevicesDB(request.Mac);
            bool isAuthorized = true;

            if (isAuthorized)
            {

                // Generate certificate

                Certificate_Response responseMessage = new Certificate_Response
                {
                    Certificate = "MIIasdlkhsldfiuoweknlknlsxcicx"
                };

                return new OkObjectResult(responseMessage);

            }
            else
            {

                return new BadRequestResult();

            }
        }
    }
}
