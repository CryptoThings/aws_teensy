# aws_teensy
Example app that uses WolfSSL (optionally with an ECC508a) to talk to AWS IoT




Install new chip, etc.

1:
Initalize ECC508a and set slot key<br>
<br>
mqtt> setup_ecc508<br>
config_chip start<br>
config_chip OK<br>
ECC508a config check OK<br>
 <br>
Done<br>
mqtt><br>
<br>
2:
Setup Wifi parameters and AWS server<br>
<br>
mqtt> setup<br>
SSID: my_wifi_net<br>
WiFi Passwd: WPA_Password<br>
AWS Server: XYZ.iot.us-west-2.amazonaws.com<br>
mqtt> <br>
<br>
3:
Connect to Wifi network.<br>
Read parameters from encrypted memory and set time using NTP.<br>
<br>
mqtt> wifi_connect<br>
Attempting to connect to SSID: my_wifi_net<br>
Connected to wifi<br>
Set time = 1509227749<br>
mqtt> <br>
<br>
<br>
4:
Generate CSR using key stored on the ECC508a<br>
(slot must be 0)<br>
<br>
csr 0 2017 10 1 5<br>
<br>
mqtt> csr 0 2017 10 1 5 <br>
Serial number: 0123000000000000EE<br>
country: US<br>
state: CA<br>
locality: San Jose<br>
sur: ()<br>
org: ()<br>
unit: IoT Services<br>
commonName: Teensy Device 001<br>
email: ()<br>
wc_MakeCert 257<br>
atca_tls_sign_certificate_cb OKwc_SignCert 350<br>
-----BEGIN CERTIFICATE REQUEST-----<br>
<...><br>
-----END CERTIFICATE REQUEST-----<br>
<br>
gen_csr : Success!<br>
<br>
<br>
5:
Sign CSR using your AWS certificate<br>
<br>
openssl x509 -req -sha256 -in device.csr -CA signer-aws.pem -CAkey signer-aws.key -CAserial signer-aws.srl -out device.pem -days 1460<br>
<br>
Upload and activate new device certificate and attach a policy.<br>
<br>
<br>

6:
Write certificate chain to EEPROM<br>
<br>
save_certs<br>
Device Certificate:<br>
-----BEGIN CERTIFICATE-----<br>
<...><br>
-----END CERTIFICATE-----<br>
<br>
<br>
Signer Certificate:<br>
-----BEGIN CERTIFICATE-----<br>
<...><br>
-----END CERTIFICATE-----<br>
<br>
mqtt> <br>
<br>
<br>
7:
Connect to AWS<br>
<br>
mqtt_connect 12345<br>
<br>
8:
use sub and pub commands to interact with AWS.<br>
<br>


