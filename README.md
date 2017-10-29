# aws_teensy
Example app that uses WolfSSL (optionally with an ECC508a) to talk to AWS IoT




Install new chip, etc.

1:
Initalize ECC508a and set slot key

mqtt> setup_ecc508
config_chip start
config_chip OK
ECC508a config check OK
 
Done
mqtt>

2:
Setup Wifi parameters and AWS server

mqtt> setup
SSID: my_wifi_net
WiFi Passwd: WPA_Password
AWS Server: XYZ.iot.us-west-2.amazonaws.com
mqtt> 

3:
Connect to Wifi network.
Read parameters from encrypted memory and set time using NTP.

mqtt> wifi_connect
Attempting to connect to SSID: my_wifi_net
Connected to wifi
Set time = 1509227749
mqtt> 


4:
Generate CSR using key stored on the ECC508a
(slot must be 0)

csr 0 2017 10 1 5

mqtt> csr 0 2017 10 1 5 
Serial number: 0123000000000000EE
country: US
state: CA
locality: San Jose
sur: ()
org: ()
unit: IoT Services
commonName: Teensy Device 001
email: ()
wc_MakeCert 257
atca_tls_sign_certificate_cb OKwc_SignCert 350
-----BEGIN CERTIFICATE REQUEST-----
<...>
-----END CERTIFICATE REQUEST-----

gen_csr : Success!


5:
Sign CSR using your AWS certificate

openssl x509 -req -sha256 -in device.csr -CA signer-aws.pem -CAkey signer-aws.key -CAserial signer-aws.srl -out device.pem -days 1460

Upload and activate new device certificate and attach a policy.



6:
Write certificate chain to EEPROM

save_certs
Device Certificate:
-----BEGIN CERTIFICATE-----
<...>
-----END CERTIFICATE-----


Signer Certificate:
-----BEGIN CERTIFICATE-----
<...>
-----END CERTIFICATE-----

mqtt> 


7:
Connect to AWS

mqtt_connect 12345

8:
use sub and pub commands to interact with AWS.



