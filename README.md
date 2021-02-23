# XBoot
X.509 Bootstrap (aka XBoot) allows IoT device builders to have a generic firmware loaded onto their devices at time of manufacturing and avoid the cost of installing individual x.509 certificates onto each device.

When the IoT device first boots, the device generates an x.509 certificate signing request (CSR), sends the CSR to the XBoot server REST endpoint, and gets a signed certificate back, which can be used to authenticate with [Azure Device Provisioning Service](https://docs.microsoft.com/en-us/azure/iot-dps/about-iot-dps) (DPS) and [Azure IoT Hub](https://docs.microsoft.com/en-us/azure/iot-hub/about-iot-hub).

XBoot consists of the following components:

- **XBoot.Client** is a .NET Core SDK (packaged as a nuget package) that allows IoT devices to generate and send a x.509 CSR to the XBoot.Server and receive back a pfx containing a signed certificate and private key.
  - Note, the private key never leaves the IoT device.
- **XBoot.Server** is a .NET Core Azure Function which acts as a side-car application to [Azure Device Provisioning Service](https://docs.microsoft.com/en-us/azure/iot-dps/about-iot-dps) (DPS). It exposes a REST endpoint that accepts Certificate Signing Requests from IoT Devices running the XBoot.Client SDK.
- **XBoot.SampleClient** is a .NET Core console application that shows an E2E example of an IoT device sending a CSR, receiving a certificate back, and using that certificate to register with DPS and finally to authenticate with IoT Hub.

## Sequence Diagram

[Link](https://sequencediagram.org/index.html#initialData=C4S2BsFMAIA0CED2jgChUAcCGAnUBjEbAO2AHMdEBXDaAYnBDIAtydJJjoAqbgSUQAVaABFIANxD5IvTLgJEspaAHkMkHFlDEy0AMoBPAM7BIAWzl4pi5QEEMGRvi0hEXAMKIAJpEsKSwHBIKAB07oycgXoiANJ+1gGiAAp6+rHxhIkCwgASVABG0OEgkWlxnF7ofKQaZpBeIFowAB4hAKwADACcRRrAALQAfCIpAFxF7E3QnJTg4HXKFNQYADpcAGTQIMQmWHPQ0nio1aY4dQ1TrZ097n1DCMjAIXoa4hrQAGJUxPigbuPVXb7IxMYjbXSHUAAMykTVQ9kcsL+Hm8kCGag0Lh0+mMpjMowASpAsF5oOBEM5wNA1vg3DDdDCoKgMZptLpDCZzP0hginC43EVUYTIMAcCU3tAjCK2UZ4Q4+cjBT57sEnsVStEYqMAOIisSSaS3PAACiJZBAJlZrmIfC8ABpRAA5ACUqAeoXVyk1KseYQiXtiOs4mNM0AJels1OIAGtIAZsCAcG7VX6SgGYj6Pf6ooHdcQQzB3HoCVsuGsRABRAn9Ti0nykpIxIt0ACMHWTvs9OYzg3dTxeODeOE+31+1tGOUEghS0CSKj0gnGAFlbO5oABqIrF6DGosl7aiKs1n6ohtNvStjquvvPV7vL4-ZE8qjAZiIMUAL3qogkUkgRlEeBxgANQ0EAoQMMNIHNS1+RtUkLWgLAXzfT96nhFD3xAL9SX1P8AJEeBuV7FMByHEdH3HDtQjI+9RyfEjfVo4cHzHf4oJJSVQXBA4+nApEYDWJRSQwMVxCmWMDGo-s7xY+jrUzGTBzoyj2LzAtoB8A1IDWXirBhZxTFQRh81waBpNvZS5NU4hiJvLsynGSdp1SIkjAwNwpXGI1oQE0tD2rWtT1nc9WwAJmM7ZiWHRAoShCyHO9RiszTbtRk8Mx8iivTAmE6BRJAcTQzWSTS2ARB8qhZoEuzMpiN5JFrSVSBxiJYAqBwLgMCq-zK0Ck962gfIDFMABtABdOVEUMprPGVQYGpmgU5pa-QsAlLAAO65poHKskKT2TSLWjSLTKTRa4OaoYRlSTVxiSShJBBNxwTww1sxCM0LVOWwjAMH5jVdG66uGMZzJuoZsmgPJ8la6DvveLS-1tY4hGhgpiJu8ZfpBMh81JKGYdQCHrpnO7wbJ2J6vlRrlqFaAcdBb9CYKKaFVm1FIbRmGilq8m3sgLswkmUxjWaa5XRZwpEqpwYpfGK5ugZlC2dplF5ql3nUscn9tKFl5iC8Cs3lIX7-vwQHUdyAotY1WX5f0CpoDqIwjCwMh-1O6LoFiqEgA) to sequence diagram.

![Sequence Diagram](./XBoot.png)