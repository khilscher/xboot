using System;
using System.IO;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;
using Microsoft.Azure.Devices.Client;
using Microsoft.Azure.Devices.Provisioning.Client.Transport;
using Microsoft.Azure.Devices.Shared;
using Microsoft.Azure.Devices.Provisioning.Client;
using XBoot.Client;


namespace XBoot.SampleClient
{
    class Program
    {

		private static string dpsEndpoint = "global.azure-devices-provisioning.net";
		private static string idScope = "0ne000524BE";
		private static string xbootUri = "http://localhost:7071/api/certificate";
		private static int MESSAGE_COUNT = 10;
		private static int DELAY_BETWEEN_SENDS = 2000;
		private static string pfxFile;
		private static X509Certificate2 certificate;

		static void Main(string[] args)
        {

			// This information could be read from a config file on the device
			string C = "CA";
			string ST = "AB";
			string L = "Calgary";
			string O = "Hilscher";
			string OU = "IT";
			string CN = GetRegistrationId();
			string dir = "c:\\XBoot";

			pfxFile = $"{dir}\\{CN}.pfx";

			var name = new X500DistinguishedName($"C={C}, ST={ST}, L={L}, O={O}, OU={OU}, CN={CN}");

			// Create XBoot client
			XBootClient xb = new XBootClient(xbootUri);

			// Generate key pair, CSR and submit CSR to XBoot.Server.
			// Returns as DER-encoded byte array
			Console.WriteLine("Sending CSR to XBoot server...");
			byte[] pfx = xb.GetDeviceCertificate(CN, name);

			certificate = new X509Certificate2(pfx);

			if(certificate != null)
			{
				Console.WriteLine("Received pfx from server.");

				// Save pfx to disk. Contains cert and private key.
				File.WriteAllBytes(pfxFile, pfx);
				Console.WriteLine($"Saved pfx file to: {pfxFile}");

			}

			// Provision device with DPS using pfx
			RunSampleAsync().Wait();

		}

		public static async Task RunSampleAsync()
		{
			try
			{

				using var security = new SecurityProviderX509Certificate(certificate);

				Console.WriteLine($"Initializing the device provisioning client...");

				// Use HTTP, AMQP or MQTT to communicate with DPS
				//var transportHandler = new ProvisioningTransportHandlerHttp();
				var transportHandler = new ProvisioningTransportHandlerMqtt();

				ProvisioningDeviceClient provClient = ProvisioningDeviceClient.Create(
					dpsEndpoint,
					idScope,
					security,
					transportHandler);

				Console.WriteLine($"Initialized for registration Id {security.GetRegistrationID()}.");

				Console.WriteLine("Registering with the device provisioning service... ");
				DeviceRegistrationResult result = await provClient.RegisterAsync();

				Console.WriteLine($"Registration status: {result.Status}.");
				if (result.Status != ProvisioningRegistrationStatusType.Assigned)
				{
					Console.WriteLine($"Registration status did not assign a hub, so exiting this sample.");
					return;
				}

				Console.WriteLine($"Device {result.DeviceId} registered to {result.AssignedHub}.");

				Console.WriteLine("Creating X509 authentication for IoT Hub...");
				IAuthenticationMethod auth = new DeviceAuthenticationWithX509Certificate(
					result.DeviceId,
					certificate);

				Console.WriteLine($"Connecting to IoT Hub...");
				using DeviceClient iotClient = DeviceClient.Create(result.AssignedHub, auth, TransportType.Mqtt);

				Console.WriteLine("Sending telemetry messages...");
				using var message = new Message(Encoding.UTF8.GetBytes("TestMessage"));

				for (int count = 0; count < MESSAGE_COUNT; count++)
				{
					await iotClient.SendEventAsync(message);

					Console.WriteLine($"Sent message {count}");

					await Task.Delay(DELAY_BETWEEN_SENDS);
				}

				Console.WriteLine("Finished.");
			}
			catch(Exception ex)
            {

				Console.WriteLine(ex.Message);

            }
		}

		public static string GetRegistrationId()
		{

			// Registration ID must only contain alphanumeric and hyphen to maintain compatibility with DPS.
			// Registration Id could be the device's MAC address, etc.
			return Guid.NewGuid().ToString();

		}
	}
}
