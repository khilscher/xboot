# XBoot
X.509 Bootstrap (aka XBoot) allows IoT device builders to have a generic firmware loaded onto their devices at time of manufacturing and avoid the cost of installing individual x.509 certificates onto each device.

When the IoT device first boots, the device generates an x.509 certificate signing request (CSR), sends the CSR to the XBoot server REST endpoint, and gets a signed certificate back, which can be used to authenticate with [Azure Device Provisioning Service](https://docs.microsoft.com/en-us/azure/iot-dps/about-iot-dps) (DPS) and [Azure IoT Hub](https://docs.microsoft.com/en-us/azure/iot-hub/about-iot-hub).

XBoot consists of the following components:

- **XBoot.Client** is a .NET Core SDK (packaged as a nuget) that allows IoT devices to generate and send a x.509 CSR to the XBoot.Server and receive back a pfx containing a signed certificate and private key.
  - Note, the private key never leaves the IoT device.
- **XBoot.Server** is a .NET Core Azure Function which acts as a PKI server. It exposes a REST endpoint that accepts Certificate Signing Requests from IoT Devices running the XBoot.Client SDK, signs them using your ceritificate, and sends back the signed x.509 certificate to the XBoot.Client. Optionally, you can modify the XBoot.Server code to:
  - Call into your own, or your partner, PKI APIs rather than acting as a PKI server.
  - Validate the device RegistrationID with a backend database or API.
- **XBoot.SampleClient** is a .NET Core console application that shows an E2E example of an IoT device sending a CSR, receiving a certificate back, and using that certificate to register with DPS and finally to authenticate with IoT Hub.

## Sequence Diagram

[Link](https://sequencediagram.org/index.html#initialData=C4S2BsFMAIA0CED2jgChUAcCGAnUBjEbAO2AHMdEBXDaAYnBDIAtydJJjoAqbgSUQAVaABFIANxD5IvTLgJEspaAHkMkHFlDEy0AMoBPAM7BIAWzl4pi5QEEMGRvi0hEXAMKIAJpEsKSwHBIKAB07oycgXoiANJ+1gGiAAp6+rHxhIkCwgASVABG0OEgkWlxnF7ofKQaZpBeIFowAB4hAKwADACcRRrAALQAfCIpAFxF7E3QnJTg4HXKFNQYADpcAGTQIMQmWHPQ0nio1aY4dQ1TrZ097n1DCMjAIXoa4hrQAGJUxPigbuPVXb7IxMYjbXSHUAAMykTVQ9kcsL+Hm8kCGag0Lh0+mMpjMowASpAsF5oOBEM5wNA1vg3DDdDCoKgMZptLpDCZzP0hginC43EVUYTIMAcCU3tAjCK2UZ4Q4+cjBT57sEnsVStEYqMAOIisSSaS3PAACiJZBAJlZrmIfC8ABpRAA5ACUqAeoXVyk1KseYQiXtiOs4mNM0AJels1OIAGtIAZsCAcG7VX6SgGYj6Pf6ooHdcQQzB3HoCVsuGsRABRAn9Ti0nykpIxIt0ACMHWTvs9OYzg3dTxeODeOE+31+1tGOUEghS0CSKj0gnGAFlbO5oABqIrF6DGosl7aiKs1n6ohtNvStjquvvPV7vL4-ZE8qjAZiIMUAL3qogkUkgRlEeBxgANQ0EAoQMMNIHNS1+RtUkLWgLAXzfT96nhFD3xAL9SX1P8AJEeBuV7FMByHEdH3HDtQjI+9RyfEjfVo4cHzHf4oJJSVQXBA4+nApEYDWJRSQwMVxCmWMDGo-s7xY+jrUzGTBzoyj2LzAtoB8A1IDWXirBhZxTFQRh81waBpNvZS5NU4hiJvLsynGSdp1SIkjAwNwpXGI1oQE0tD2rWtT1nc9WwAJmM7ZiWHRAoShCyHO9RiszTbtRk8Mx8iivTAmE6BRJAcTQzWSTS2ARB8qhZoEuzMpiN5JFrSVSBxiJYAqBwLgMCq-zK0Ck962gfIDFMABtABdOVEUMprPGVQYGpmgU5pa-QsAlLAAO65poHKskKT2TSLWjSLTKTRa4OaoYRlSTVxiSShJBBNxwTww1sxCM0LVOWwjAMH5jVdG66uGMZzJuoZsmgPJ8la6DvveLS-1tY4hGhgpiJu8ZfpBMh81JKGYdQCHrpnO7wbJ2J6vlRrlqFaAcdBb9CYKKaFVm1FIbRmGilq8m3sgLswkmUxjWaa5XRZwpEqpwYpfGK5ugZlC2dplF5ql3nUscn9tKFl5iC8Cs3lIX7-vwQHUdyAotY1WX5f0CpoDqIwjCwMh-1O6LoFiqEgA) to sequence diagram.

![Sequence Diagram](./XBoot.png)

## Generating Certificates for XBoot.Server

The following steps can be used to generate a root certificate and an intermediate certificate. The intermediate certificate can be used by the XBoot.Server.

### Generate root CA
Generate private and public key pair for root CA; output is a pem file (pkcs8 format).
```
openssl genrsa -out ca.key 2048
```

Generate self signed root certificate (no need for a CSR...no one to sign it). When prompted, fill in certificate details.
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