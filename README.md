# XBoot
The [Azure Device Provisioning Service](https://docs.microsoft.com/en-us/azure/iot-dps/about-iot-dps) (DPS) provisioning process assumes an x.509 certificate is already installed on the device. This is where **X.509 Bootstrap** (aka **XBoot**) comes in.

When the IoT device first boots, the IoT device generates an x.509 certificate signing request (CSR) using the (optional) **XBoot.Client** SDK, sends the CSR to the **XBoot.Server** REST endpoint, and receives a signed x.509 certificate back. This certificate can then be used by the device to attest to [Azure Device Provisioning Service](https://docs.microsoft.com/en-us/azure/iot-dps/about-iot-dps) (DPS) and to authenticate with [Azure IoT Hub](https://docs.microsoft.com/en-us/azure/iot-hub/about-iot-hub).

XBoot allows IoT device builders to have a generic firmware loaded onto their devices at time of manufacturing and avoid the cost of installing individual x.509 certificates onto each device, during or post-manufacturing.

## Components

XBoot consists of the following components:

- **XBoot.Client** is a .NET Core 3.1 SDK (packaged as a nuget) that allows IoT devices to generate and send a x.509 CSR to the XBoot.Server and receive back a pfx containing a signed certificate and private key.
  - **Note:** The private key never leaves the IoT device!
- **XBoot.Server** is a .NET Core 3.1 Azure Function which acts as a PKI server. It exposes a REST endpoint that accepts Certificate Signing Requests from IoT Devices running the XBoot.Client SDK, signs them using your ceritificate, and sends back the signed x.509 certificate to the XBoot.Client. Optionally, you can modify the XBoot.Server code to:
  - Call into your own, or your partner, PKI APIs rather than acting as a PKI server.
  - Validate the device RegistrationID with a backend database or API.
- **XBoot.SampleClient** is a .NET Core 3.1 console application that shows an E2E example of an IoT device sending a CSR, receiving a certificate back, and using that certificate to register with DPS and finally to authenticate with IoT Hub.
  - The sample client sends a GUID as its RegistrationID. In reality a client should send something unique to the device which can be verified against a backend database or API. For example, a MAC address, IMEI, etc.
  - The sample client does not integrate with a HSM. If your device has an HSM, this would be highly recommended!

The following shows the output from the XBoot.SampleClient:

![SampleClient Output](./sampleclient.JPG)

## Sequence Diagram

[Link](https://sequencediagram.org/index.html#initialData=C4S2BsFMAIA0CED2jgChUAcCGAnUBjEbAO2AHMdEBXDaAYnBDIAtydJJjoAqbgSUQAVaABFIANxD5IvTLgJEspaAHkMkHFlDEy0AMoBPAM7BIAWzl4pi5QEEMGRvi0hEXAMKIAJpEsKSwHBIKAB07oycgXoiANJ+1gGiAAp6+rHxhIkCwgASVABG0OEgkWlxnF7ofKQaZpBeIFowAB4hAKwADACcRRrAALQAfCIpAFxF7E3QnJTg4HXKFNQYADpcAGTQIMQmWHPQ0nio1aY4dQ1TrZ097n1DCMjAIXoa4hrQAGJUxPigbuPVXb7IxMYjbXSHUAAMykTVQ9kcsL+Hm8kCGag0Lh0+mMpjMowASpAsF5oOBEM5wNA1vg3DDdDCoKgMZptLpDCZzP0hginC43EVUYTIMAcCU3tAjCK2UZ4Q4+cjBT57sEnsVStEYqMAOIisSSaS3PAACiJZBAJlZrmIfC8ABpRAA5ACUqAeoXVyk1KseYQiXtiOs4mNM0AJels1OIAGtIAZsCAcG7VX6SgGYj6Pf6ooHdcQQzB3HoCVsuGsRABRAn9Ti0nykpIxIt0ACMHWTvs9OYzg3dTxeODeOE+31+1tGOUEghS0CSKj0gnGAFlbO5oABqIrF6DGosl7aiKs1n6ohtNvStjquvvPV7vL4-ZE8qjAZiIMUAL3qogkUkgRlEeBxgANQ0EAoQMMNIHNS1+RtUkLWgLAXzfT96nhFD3xAL9SX1P8AJEeBuV7FMByHEdH3HDtQjI+9RyfEjfVo4cHzHf4oJJSVQXBA4+nApEYDWJRSQwMVxCmWMDGo-s7xY+jrUzGTBzoyj2LzAtoB8A1IDWXirBhZxTFQRh81waBpNvZS5NU4hiJvLsynGSdp1SIkjAwNwpXGI1oQE0tD2rWtT1nc9WwAJmM7ZiWHRAoShCyHO9RiszTbtRk8Mx8iivTAmE6BRJAcTQzWSTS2ARB8qhZoEuzMpiN5JFrSVSBxiJYAqBwLgMCq-zK0Ck962gfIDFMABtABdOVEUMprPGVQYGpmgU5pa-QsAlLAAO65poHKskKT2TSLWjSLTKTRa4OaoYRlSTVxiSShJBBNxwTww1sxCM0LVOWwjAMH5jVdG66uGMZzJuoZsmgPJ8la6DvveLS-1tY4hGhgpiJu8ZfpBMh81JKGYdQCHrpnO7wbJ2J6vlRrlqFaAcdBb9CYKKaFVm1FIbRmGilq8m3sgLswkmUxjWaa5XRZwpEqpwYpfGK5ugZlC2dplF5ql3nUscn9tKFl5iC8Cs3lIX7-vwQHUdyAotY1WX5f0CpoDqIwjCwMh-1O6LoFiqEgA) to sequence diagram.

![Sequence Diagram](./XBoot.png)

## Setup

1. Generate your root and intermediate certificate by following the **Generating Certificates for XBoot.Server** instructions below. The intermediate certificate will be the **signing** certificate.
1. Update your local.setting.json following the  **App Settings** instructions below.
1. Save your intermediate certificate and private key in the location you specified in the previous step.
1. Deploy the **XBoot.Server** Azure Function, either to Azure or you can run it locally to test. When deploying to Azure, ensure the settings you configured in the ```local.settings.json``` are in your Function App **Application Settings**.
1. Once the **XBoot.Server** Azure Function is deployed, copy the Azure Function **REST endpoint URL** and paste it into the ```xbootUri``` in the **XBoot.SampleClient** ```Program.cs``` file.
1. Create an **Azure IoT Hub**.
1. Create an **Azure DPS** instance. Copy the **ID Scope** into ```idScope``` in the **XBoot.SampleClient** ```Program.cs``` file.
1. Link the DPS instance to your IoT Hub.
1. Upload and verify your intermediate certificate to DPS.
1. In DPS, create an **Enrollment Group**.
   - Set the **Attestation Type** to **Certificate**.
   - Set the **Certificate Type** to **CA Certificate** or **Intermediate Certificate**.
   - Configure the remaining Enrollment Group settings as needed.
1. Edit the CSR details on lines 30-36 of the **XBoot.SampleClient** ```Program.cs``` file.
1. Build and run the **XBoot.SampleClient**.

## App Settings

Add the following to your ```local.settings.json``` when running the **XBoot.Server** Azure Function locally on your development computer. When running the **XBoot.Server** Azure Function in Azure, ensure the settings below are in your **Application Settings**.

**Note:** Azure Key Vault support is not yet implemented.

### When the signing certificate and private key are stored in files

```
{
  ...,
  "Location": 1,
  "PrivateKeyFile": "c:\\openssl_stuff\\ia.key",
  "CertificateFile": "c:\\openssl_stuff\\ia.cer"
}
```

### When the signing certificate and private key are stored in Azure Blob Storage

```
{
  ...,
  "Location": 2,
  "BlobConnectionString": "DefaultEndpointsProtocol=https;AccountName=<blobaccountname>;AccountKey=...",
  "BlobContainerName": "xboot",
  "PrivateKeyFile": "ia.key",
  "CertificateFile": "ia.cer"
}
```

### When the signing certificate and private key are stored directly in the App Settings

```
{
  ...,
  "Location": 3,
  "PrivateKeyFile": "-----BEGIN RSA PRIVATE KEY-----blahblahblah-----END RSA PRIVATE KEY-----",
  "CertificateFile": "-----BEGIN CERTIFICATE-----blahblahblah-----END CERTIFICATE-----"
}
```

## Generating Certificates for XBoot.Server

The following steps can be used to generate a root certificate and an intermediate certificate. The intermediate certificate can be used by the XBoot.Server as the signing certificate. The root certificate can be stored offline.

### Generate root CA
Generate private and public key pair for root CA; output is a pem file (pkcs8 format).
```
openssl genrsa -out ca.key 2048
```

Generate self signed root certificate. When prompted, fill in certificate details.
```
openssl req -new -x509 -days 1826 -key ca.key -out ca.cer
```

### Generate intermediate CA
Generate private and public key pair for intermediate CA; output is a pem file (pkcs8 format).
```
openssl genrsa -out ia.key 2048
```

Generate CSR for intermediate. When prompted, fill in certificate details.
```
openssl req -new -key ia.key -out ia.csr
```

Generate intermediate cert signed using the root certificate.
```
openssl x509 -req -days 730 -in ia.csr -CA ca.cer -CAkey ca.key -set_serial 01 -out ia.cer -extfile intextensions.txt -extensions v3_intermediate_ca
```

intextensions.txt contents:
```
[ v3_intermediate_ca ]
# Extensions for a typical intermediate CA.
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer
basicConstraints = critical, CA:true
keyUsage = critical, digitalSignature, cRLSign, keyCertSign
```

Package in PKCS 12
```
openssl pkcs12 -export -out ia.p12 -inkey ia.key -in ia.cer -chain -CAfile ca.cer
```


## Backlog

See **XBoot Backlog** under **Projects**.