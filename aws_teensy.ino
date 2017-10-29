/*
 * Copyright (C) 2016-2017 Robert Totte
 *
 * This is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#include "WolfCryptoAuth.h"

#include <sys/types.h>
#include <sys/time.h>

#include "certs.h"

#ifdef CORE_TEENSY
#include "Entropy.h"
#endif
#include <TimeLib.h>
#include <EEPROM.h>

#include "Readline.h"

#include <WolfMQTTClient.h>

#include <WiFi101.h>
#include <WiFiUdp.h>

#ifdef CORE_TEENSY
  #define WINC_IRQ  15
  #define WINC_CS   17
  #define WINC_EN   16
  #define WINC_RST  14
#else
  #define WINC_CS   8
  #define WINC_IRQ  7
  #define WINC_RST  4
  #define WINC_EN   2
#endif

#define TEENSY_USE_ECC508

/** Certs are stored on internal Teensy EEPROM.
 ** All certs must be loaded and written at once.
 ** WiFi info can be written at any time.
 *
 * on teensy EEPROM without ECC508a:
 * 160 bytes wifi config (ssid, wpa key, aws server, port)
 * 2-bytes Cert 1 len (MSB first)
 * 2-bytes Cert 2 len
 * 2-bytes Private Key len
 * N-bytes Cert 1
 * N-bytes Cert 2
 * N-bytes Private Key
 * 
 * on teensy EEPROM with ECC508a:
 * 32-byte slot key
 * 2-bytes Cert 1 len (MSB first)
 *  = (EEPROM[32] << 8) | EEPROM[33]
 * 2-bytes Cert 2 len
 *  = (EEPROM[34] << 8) | EEPROM[35]
 * N-bytes Cert 1
 * N-bytes Cert 2
 */
class TeensyCertLoader : public WolfSSLCertLoader {
    int cert_id;
    uint8_t *cert_data;
    size_t   cert_data_size;

  public:
    TeensyCertLoader(int id) :
      cert_id(id), cert_data(NULL), cert_data_size(0) {}
    virtual ~TeensyCertLoader() {}
    virtual bool have_cert();
    virtual const uint8_t *data() { return cert_data; }
    virtual size_t size() { return cert_data_size; }
    virtual int type() { return SSL_FILETYPE_PEM; }
    // cert loaded, free resources allocated in data() or have_cert()
    virtual void done();
};


WiFiClient client;

WolfMQTTClient mqtt;

#ifdef TEENSY_USE_ECC508
//WolfCertEEPROM wssl_certs(2,1);
WolfCertTeensyEEPROM wssl_certs;
WolfCryptoAuth wssl(wssl_certs);
//WolfCryptoAuth wssl();
#else // TEENSY_USE_ECC508
TeensyCertLoader cert_chain(1);
TeensyCertLoader priv_key(2);

WolfSSLClient wssl;

#endif // TEENSY_USE_ECC508

extern "C"
void Logging_cb(const int logLevel, const char *const logMessage)
{
  Serial.print("WL ");
  Serial.print(logLevel);
  Serial.print(": ");
  Serial.println(logMessage);
  Serial.flush();
}

//extern "C"

void hexdump(const void *buffer, uint32_t len, uint8_t cols)
{
   uint8_t i;

   for(i = 0; i < len + ((len % cols) ? (cols - len % cols) : 0); i++)
   {
      /* print hex data */
      if(i < len) {
        int x = ((uint8_t*)buffer)[i] & 0xFF;
        if (x < 16) Serial.print('0');
        Serial.print(x, HEX);
      }

      if(i % cols == (cols - 1)) {
         Serial.println("");
      }
   }
}

class mqtt_callbacks : public WolfMQTTCallback {
public:
  void message(char *topic, uint8_t *payload, size_t payload_len) {
    Serial.print("Message arrived [");
    Serial.print(topic);
    Serial.print("] ");
    for (unsigned int i=0;i<payload_len;i++) {
      Serial.print((char)payload[i]);
    }
    Serial.println();
  }
};
mqtt_callbacks mqtt_callback;

void printWifiStatus() {
  // print the SSID of the network you're attached to:
  Serial.print("SSID: ");
  Serial.println(WiFi.SSID());

  // print your WiFi shield's IP address:
  IPAddress ip = WiFi.localIP();
  Serial.print("IP Address: ");
  Serial.println(ip);

  // print the received signal strength:
  long rssi = WiFi.RSSI();
  Serial.print("signal strength (RSSI):");
  Serial.print(rssi);
  Serial.println(" dBm");
  Serial.flush();
}

char g_printf_buf[80];

uint32_t pub_time;
bool connected;

WolfSSLCertConst verify_buffer(AWS_ROOT_CA_DER, sizeof(AWS_ROOT_CA_DER),
                               SSL_FILETYPE_ASN1);
WolfSSLCertConst private_key(priv_key_der, sizeof(priv_key_der),
                               SSL_FILETYPE_ASN1);

void read_eeprom_key(uint8_t *data)
{
  // read first 32 bytes from EEPROM
  int i;
  for (i = 0; i < 32; i++) {
    data[i] = EEPROM.read(i);
  }
}

void setup()
{
  pinMode(WINC_EN, OUTPUT);
  digitalWrite(WINC_EN, HIGH);
  WiFi.setPins(WINC_CS, WINC_IRQ, WINC_RST);

#ifdef CORE_TEENSY
  Entropy.Initialize();
#endif

  Serial.begin(9600);

  while (!Serial) { delay(100); }

  // check for the presence of the shield:
  if (WiFi.status() == WL_NO_SHIELD) {
    Serial.println("WiFi shield not present");
    // don't continue:
    while (true);
  }
}

bool did_crypto_init = 0;
bool did_wssl_init = 0;

bool do_crypto_init()
{
  if (did_crypto_init)
    return true;

  wssl.setClient(client);
  if (!wssl.init()) {
    Serial.println("Crypto init failed");
    return false;
  }

#ifdef TEENSY_USE_ECC508
{
  uint8_t slot_key[32];
  read_eeprom_key(slot_key);
  if (!wssl.crypt_init(slot_key)) {
    Serial.println("Crypt init failed");
    return false;
  }
}
#endif

  did_crypto_init = 1;
  return true;
}

bool do_wssl_init()
{
  if (did_wssl_init)
    return true;

  if (!do_crypto_init())
    return false;

  pub_time = millis();

  wolfSSL_SetLoggingCb(Logging_cb);

  mqtt.setCallback(mqtt_callback);

  mqtt.setClient(wssl);

  wssl.set_root_cert(verify_buffer);

#ifdef TEENSY_USE_ECC508
{
//  uint8_t slot_key[32];
//  read_eeprom_key(slot_key);
//  wssl.crypt_init(slot_key);
  wssl.set_private_key(private_key);
  wssl.setup_callbacks();
}
#else // TEENSY_USE_ECC508
  wssl.set_private_key(priv_key);
  wssl.set_cert_chain(cert_chain);
#endif // TEENSY_USE_ECC508

  Serial.println("Finished setup");
  Serial.flush();

  did_wssl_init = true;

  return true;
}

void mqtt_connect(uint32_t *args, uint32_t num_args)
{
  char cli_id[15];
  char server_name[64];
  uint16_t server_port;

  if (WiFi.status() != WL_CONNECTED) {
    Serial.println("ERROR: Connect to WiFi first.");
    return;
  }

  if (!do_wssl_init()) {
    Serial.println("ERROR: Init Falied");
    return;
  }

  if (num_args < 1) {
    snprintf(cli_id, 14, "A1234");
  } else {
    snprintf(cli_id, 14, "A%x", (int)args[0]);
  }

#ifdef TEENSY_USE_ECC508
{
  ATCA_STATUS ret;
  ret = wssl.read_slot(AtCryptoAuthLib::ENC_STORE, (uint8_t*)server_name, 96, 64);
  if (ret != ATCA_SUCCESS) {
    Serial.println("Server Name read ERROR");
    return;
  }
  server_port = (server_name[62] << 8) | server_name[63];
}
#else // TEENSY_USE_ECC508
{
  size_t i;
  for (i = 0; i < 62; i++) {
    server_name[i] = EEPROM.read(i+32+64);
  }
  server_port = (EEPROM.read(62+32+64) << 8) | EEPROM.read(63+32+64);
}
#endif // TEENSY_USE_ECC508
 
  Serial.println("Connect to server:");
  Serial.println(server_name);

  mqtt.setServer(server_name, server_port);

  if (connected) {
    Serial.println("MQTT already connected");
    return;
  }

  if (!mqtt.connect(cli_id)) {
    Serial.println("ERROR: mqtt.connect");
    Serial.flush();
    return;
  }

  connected = true;
}

void ntp_set_time(uint32_t *args, uint32_t num_args);

void wifi_connect(uint32_t *args, uint32_t num_args)
{
  char ssid[32]; // network SSID
  char pass[64]; // WPA Password

#ifdef TEENSY_USE_ECC508
  ATCA_STATUS ret;

  if (!do_crypto_init())
    return;

  ret = wssl.read_slot(AtCryptoAuthLib::ENC_STORE, (uint8_t*)ssid, 0, 32);
  if (ret != ATCA_SUCCESS) {
    Serial.println("SSID read ERROR");
    return;
  }

  ret = wssl.read_slot(AtCryptoAuthLib::ENC_STORE, (uint8_t*)pass, 32, 64);
  if (ret != ATCA_SUCCESS) {
    Serial.println("WiFi passwd read ERROR");
    return;
  }
#else // TEENSY_USE_ECC508
  size_t i;
  for (i = 0; i < 32; i++) {
    ssid[i] = EEPROM.read(i);
  }
  for (i = 0; i < 64; i++) {
    pass[i] = EEPROM.read(i+32);
  }
#endif // TEENSY_USE_ECC508

  while (WiFi.status() != WL_CONNECTED) {
    Serial.print("Attempting to connect to SSID: ");
    Serial.println(ssid);

    WiFi.begin(ssid, pass);

    // wait 60 seconds for connection:
    uint8_t timeout = 60;
    while (timeout && (WiFi.status() != WL_CONNECTED)) {
      timeout--;
      delay(1000);
    }

    if (WiFi.status() == WL_CONNECTED) {
      Serial.println("Connected to wifi");
    } else {
      // start over
    }
  }

  ntp_set_time(args, num_args);
}

void wifi_stat(uint32_t *args, uint32_t num_args)
{
  printWifiStatus();
}

void sub_iot(uint32_t *args, uint32_t num_args)
{
  if (connected) {
    mqtt.subscribe("iotbutton/G030JF0532269VVQ");
  }
}

void mqtt_sub(uint32_t *args, uint32_t num_args)
{
  char buf[80];
  char *topic;
  size_t tmp_len;

  if (!connected) {
    Serial.println("Connect to MQTT first");
    return;
  }

  tmp_len = 0;
  Serial.print("Subscription topic: ");
  Readline_read_str_data(&topic, buf, 79, &tmp_len);

  mqtt.subscribe(topic);
}

void mqtt_pub(uint32_t *args, uint32_t num_args)
{
  char *buf;
  char *topic;
  char *payload;
  size_t tmp_len;

  if (!connected) {
    Serial.println("Connect to MQTT first");
    return;
  }
  buf = (char*)malloc(256);

  tmp_len = 0;
  Serial.print("Publish topic: ");
  Readline_read_str_data(&topic, buf, 255, &tmp_len);
  buf[tmp_len] = '\0';

  Serial.println("Payload: ");
  payload = &(buf[tmp_len+1]);
  tmp_len = Readline_read_buf((uint8_t*)payload, 254-tmp_len, false);

  mqtt.publish(topic, (uint8_t*)payload, tmp_len);

  free(buf);
}

// NTP time stamp is in the first 48 bytes of the message
const int NTP_PACKET_SIZE = 48;

// send an NTP request to the time server at the given address
static void sendNTPpacket(WiFiUDP &Udp, IPAddress& address, byte *packetBuffer)
{
  // set all bytes in the buffer to 0
  memset(packetBuffer, 0, NTP_PACKET_SIZE);
  // Initialize values needed to form NTP request
  // (see URL above for details on the packets)
  packetBuffer[0] = 0b11100011;   // LI, Version, Mode
  packetBuffer[1] = 0;     // Stratum, or type of clock
  packetBuffer[2] = 6;     // Polling Interval
  packetBuffer[3] = 0xEC;  // Peer Clock Precision
  // 8 bytes of zero for Root Delay & Root Dispersion
  packetBuffer[12]  = 49;
  packetBuffer[13]  = 0x4E;
  packetBuffer[14]  = 49;
  packetBuffer[15]  = 52;

  // all NTP fields have been given values, now
  // you can send a packet requesting a timestamp:
  Udp.beginPacket(address, 123); //NTP requests are to port 123
  Udp.write(packetBuffer, NTP_PACKET_SIZE);
  Udp.endPacket();
}

void ntp_set_time(uint32_t *args, uint32_t num_args)
{
  WiFiUDP Udp;
  byte packetBuffer[ NTP_PACKET_SIZE];
  unsigned int localPort = 2390;      // local port to listen for UDP packets
  IPAddress timeServer(129, 6, 15, 28); // time.nist.gov NTP server
  uint32_t t;
  int tx_count;

  Udp.begin(localPort);

  for (tx_count = 0; !Udp.available() && (tx_count < 5); tx_count++) {
    // send an NTP packet to a time server
    sendNTPpacket(Udp, timeServer, packetBuffer);
    // wait to see if a reply is available
    t = millis();
    while (!Udp.available() && ((millis() - t) < 1000)) {
      delay(50);
      Udp.parsePacket();
    }
  }
  if ( Udp.parsePacket() ) {
    // We've received a packet, read the data from it
    Udp.read(packetBuffer, NTP_PACKET_SIZE); // read the packet into the buffer

    //the timestamp starts at byte 40 of the received packet and is four bytes,
    // or two words, long. First, esxtract the two words:

    unsigned long highWord = word(packetBuffer[40], packetBuffer[41]);
    unsigned long lowWord = word(packetBuffer[42], packetBuffer[43]);
    // combine the four bytes (two words) into a long integer
    // this is NTP time (seconds since Jan 1 1900):
    unsigned long secsSince1900 = highWord << 16 | lowWord;

    // now convert NTP time into everyday time:
    Serial.print("Set time = ");
    // Unix time starts on Jan 1 1970. In seconds, that's 2208988800:
    const unsigned long seventyYears = 2208988800UL;
    // subtract seventy years:
    unsigned long epoch = secsSince1900 - seventyYears;
    // print Unix time:
    Serial.println(epoch);

    setTime(epoch);
  }

  Udp.stop();
}

#ifdef TEENSY_USE_ECC508
void wifi_setup(uint32_t *args, uint32_t num_args)
{
  // SSID[32], passwd[64], aws server[64]
  char ssid[33];
  size_t ssid_len;
  char passwd[65];
  size_t passwd_len;
  char server[65];
  size_t server_len;
  ATCA_STATUS ret;

  if (!do_crypto_init())
    return;

  memset(ssid, 0, 33);
  memset(passwd, 0, 65);
  memset(server, 0, 65);

  Serial.print("SSID: ");
  ssid_len = Readline_read_str_data(ssid, 33);
  Serial.print("WiFi Passwd: ");
  passwd_len = Readline_read_str_data(passwd, 65);
  Serial.print("AWS Server: ");
  server_len = Readline_read_str_data(server, 65);

  if (ssid_len > 1) {
    ret = wssl.write_slot(AtCryptoAuthLib::ENC_STORE, (uint8_t*)ssid, 0, 32);
    if (ret != ATCA_SUCCESS) {
      return;
    }
  }

  if (passwd_len > 1) {
    ret = wssl.write_slot(AtCryptoAuthLib::ENC_STORE, (uint8_t*)passwd, 32, 64);
    if (ret != ATCA_SUCCESS) {
      return;
    }
  }

  if (server_len > 1) {
    ret = wssl.write_slot(AtCryptoAuthLib::ENC_STORE, (uint8_t*)server, 96, 64);
    if (ret != ATCA_SUCCESS) {
      return;
    }
  }
}

void config_ecc508a(uint32_t *args, uint32_t num_args)
{
  uint8_t rand_out[32];
  uint8_t data[32];
  bool lockstate = false;
  bool match = false;
  int i;
  ATCA_STATUS ret;

  if (!wssl.crypt_init()) {
    Serial.print("ERROR Crypt Init ");
    return;
  }

  // Initalize a new chip if necessary
  ret = wssl.config_locked(lockstate);
  if (ret != ATCA_SUCCESS) {
    Serial.println("ERROR: config_locked");
    Serial.flush();
    return;
  }

  if (!lockstate) {
    Serial.println("config_chip start");
    Serial.flush();
    ret = wssl.config_chip();
    if (ret != ATCA_SUCCESS) {
      Serial.println("ERROR: config_chip");
      return;
    }
    Serial.println("config_chip OK");

    ret = wssl.config_locked(lockstate);
    if (ret != ATCA_SUCCESS) {
      Serial.println("ERROR: config_locked 2");
      return;
    }
    if (!lockstate) {
      Serial.println("ERROR: not locked after config");
      return;
    }
  }

  ret = wssl.check_config(match);
  if (ret != ATCA_SUCCESS) {
    Serial.println("ERROR: init");
    return;
  }
  if (!match) {
    uint8_t configdata[ATCA_CONFIG_SIZE] = { 0 };
    Serial.println("config check MISMATCH");
    atcab_read_ecc_config_zone((uint8_t*)configdata);
    hexdump(configdata, ATCA_CONFIG_SIZE, 16);
    return;
  } else {
    Serial.println("ECC508a config check OK");
    Serial.println(" ");
  }

  // Generate a new slot key
  ret = wssl.random(rand_out);
  if (ret != ATCA_SUCCESS) {
    Serial.print("ERROR Random ");
    Serial.println(ret, HEX);
    return;
  }
  for (i = 0; i < 32;) {
    if (Entropy.available()) {
      data[i] = Entropy.random(255) ^ rand_out[i];
      i++;
    } else {
      delay(100);
    }
  }
  for (i = 0; i < 32; i++) {
    EEPROM.write(i, data[i]);
  }
  ret = wssl.write_slot(AtCryptoAuthLib::ENC_PARENT, data, 0, 32);
  if (ret != ATCA_SUCCESS) {
    Serial.print("ERROR write ENC_PARENT ");
    Serial.println(ret, HEX);
    return;
  }

  wssl.set_enc_key(data);
  Serial.println("Done");
}

void gen_csr(uint32_t *args, uint32_t num_args)
{
  WolfCryptoAuth::cert_info ci;
  int slot;
  uint8_t pem[1024];
  uint8_t sn[9];
  char cert_data[8*64];
  size_t tmp_len;
  int pemSz;
  int ret;

  if (num_args != 5)
    return;

  slot = args[0];
  ci.year = args[1];
  ci.mon = args[2];
  ci.day = args[3];
  ci.valid_years = args[4];

  wssl.serial_number(sn);
  Serial.print("Serial number: ");
  for (int i = 0; i < 9; i++) {
    if (sn[i] < 16)
      Serial.print('0');
    Serial.print(sn[i], HEX);
  }
  Serial.println("");

  tmp_len = 0;
  Serial.print("country: ");
  Readline_read_str_data(&ci.country,    cert_data, 8*64, &tmp_len);
  if (ci.country == NULL) Serial.println("()");
  Serial.print("state: ");
  Readline_read_str_data(&ci.state,      cert_data, 8*64, &tmp_len);
  if (ci.state == NULL) Serial.println("()");
  Serial.print("locality: ");
  Readline_read_str_data(&ci.locality,   cert_data, 8*64, &tmp_len);
  if (ci.locality == NULL) Serial.println("()");
  Serial.print("sur: ");
  Readline_read_str_data(&ci.sur,        cert_data, 8*64, &tmp_len);
  if (ci.sur == NULL) Serial.println("()");
  Serial.print("org: ");
  Readline_read_str_data(&ci.org,        cert_data, 8*64, &tmp_len);
  if (ci.org == NULL) Serial.println("()");
  Serial.print("unit: ");
  Readline_read_str_data(&ci.unit,       cert_data, 8*64, &tmp_len);
  if (ci.unit == NULL) Serial.println("()");
  Serial.print("commonName: ");
  Readline_read_str_data(&ci.commonName, cert_data, 8*64, &tmp_len);
  if (ci.commonName == NULL) Serial.println("()");
  Serial.print("email: ");
  Readline_read_str_data(&ci.email,      cert_data, 8*64, &tmp_len);
  if (ci.email == NULL) Serial.println("()");

  pemSz = 1024;
  ret = wssl.make_csr((AtCryptoAuthLib::SlotCfg)slot, ci, pem, &pemSz);
  if (ret != 0) {
    Serial.print("make_csr: ");
    Serial.println(ret);
  }
  pem[pemSz] = '\0';
  Serial.println((char*)pem);

  Serial.println("gen_csr : Success!");
}
#else // TEENSY_USE_ECC508

void wifi_setup(uint32_t *args, uint32_t num_args)
{
  // SSID[32], passwd[64], aws server[64]
  char ssid[33];
  size_t ssid_len;
  char passwd[65];
  size_t passwd_len;
  char server[65];
  size_t server_len;
  size_t i;

  memset(ssid, 0, 33);
  memset(passwd, 0, 65);
  memset(server, 0, 65);

  Serial.print("SSID: ");
  ssid_len = Readline_read_str_data(ssid, 33);
  Serial.print("WiFi Passwd: ");
  passwd_len = Readline_read_str_data(passwd, 65);
  Serial.print("AWS Server: ");
  server_len = Readline_read_str_data(server, 65);

  if (ssid_len > 1) {
    for (i = 0; i < 32; i++)
      EEPROM.write(i, ssid[i]);
  }

  if (passwd_len > 1) {
    for (i = 0; i < 64; i++)
      EEPROM.write(i+32, passwd[i]);
  }

  if (server_len > 1) {
    for (i = 0; i < 64; i++)
      EEPROM.write(i+32+64, server[i]);
  }
}

#endif // TEENSY_USE_ECC508

#ifdef TEENSY_USE_ECC508
void save_certs(uint32_t *args, uint32_t num_args)
{
  size_t sz1, sz2, i, a, s;
  uint8_t cert_data[2048];
  uint8_t cert_len[4];

  Serial.println("Device Certificate:");
  sz1 = Readline_read_buf(cert_data, 2048, false);
  cert_data[sz1] = '\0';
  Serial.println("");

  Serial.println("Signer Certificate:");
  sz2 = Readline_read_buf(&(cert_data[sz1]), 2048-sz1, false);
  cert_data[sz1+sz2] = '\0';

//  Serial.print((char*)cert_data);

  a = 0;
  for (i = 0; i < sz1; i++) {
    EEPROM.write(i+a+36, cert_data[i]);
    if (cert_data[i] == '\r') {
      a++;
      EEPROM.write(i+a+36, '\n');
    }
  }
  s = sz1;
  sz1 += a;

  a = 0;
  for (i = 0; i < sz2; i++) {
    EEPROM.write(i+a+36+sz1, cert_data[i+s]);
    if (cert_data[i+s] == '\r') {
      a++;
      EEPROM.write(i+a+36+sz1, '\n');
    }
  }
  sz2 += a;

  cert_len[0] = (sz1 >> 8) & 0xFF;
  cert_len[1] = sz1 & 0xFF;
  cert_len[2] = (sz2 >> 8) & 0xFF;
  cert_len[3] = sz2 & 0xFF;

  for (i = 0; i < 4; i++)
    EEPROM.write(i+32, cert_len[i]);
}

void read_certs(uint32_t *args, uint32_t num_args)
{
  WolfCertTeensyEEPROM ee;
  uint8_t *cert_data;


  if (ee.have_cert()) {
    cert_data = (uint8_t*)malloc(ee.size()+1);
    if (cert_data == NULL)
      return;

    memset(cert_data, 0, ee.size()+1);
    memcpy(cert_data, ee.data(), ee.size());
    ee.done();

    Serial.print((char*)cert_data);
    free(cert_data);
  }
}

#else // TEENSY_USE_ECC508

void save_certs(uint32_t *args, uint32_t num_args)
{
  const size_t data_sz = 3*1024;
  size_t sz1, sz2, sz3, i, a, s;
  uint8_t cert_data[data_sz];
  uint8_t cert_len[6];

  Serial.println("Device Certificate:");
  sz1 = Readline_read_buf(cert_data, data_sz, false);
  cert_data[sz1] = '\0';
  Serial.println("");

  Serial.println("Signer Certificate:");
  sz2 = Readline_read_buf(&(cert_data[sz1]), data_sz-sz1, false);
  cert_data[sz1+sz2] = '\0';
  Serial.println("");

  Serial.println("Private Key:");
  sz3 = Readline_read_buf(&(cert_data[sz1+sz2]), data_sz-sz1-sz2, false);
  cert_data[sz1+sz2+sz3] = '\0';
  Serial.println("");

//  Serial.print((char*)cert_data);

  a = 0;
  for (i = 0; i < sz1; i++) {
    EEPROM.write(i+a+166, cert_data[i]);
    if (cert_data[i] == '\r') {
      a++;
      EEPROM.write(i+a+166, '\n');
    }
  }
  s = sz1;
  sz1 += a;

  a = 0;
  for (i = 0; i < sz2; i++) {
    EEPROM.write(i+a+166+sz1, cert_data[i+s]);
    if (cert_data[i+s] == '\r') {
      a++;
      EEPROM.write(i+a+166+sz1, '\n');
    }
  }
  s += sz2;
  sz2 += a;

  a = 0;
  for (i = 0; i < sz3; i++) {
    EEPROM.write(i+a+166+sz1+sz2, cert_data[i+s]);
    if (cert_data[i+s] == '\r') {
      a++;
      EEPROM.write(i+a+166+sz1+sz2, '\n');
    }
  }
  sz3 += a;

  cert_len[0] = (sz1 >> 8) & 0xFF;
  cert_len[1] = sz1 & 0xFF;
  cert_len[2] = (sz2 >> 8) & 0xFF;
  cert_len[3] = sz2 & 0xFF;
  cert_len[4] = (sz3 >> 8) & 0xFF;
  cert_len[5] = sz3 & 0xFF;

  for (i = 0; i < 6; i++)
    EEPROM.write(i+160, cert_len[i]);
}

void read_certs(uint32_t *args, uint32_t num_args)
{
  TeensyCertLoader tl1(1), tl2(2);
  uint8_t cert_data[2048];

  memset(cert_data, 0, 2048);

  Serial.println("Cert chain:");
  if (tl1.have_cert()) {
    memcpy(cert_data, tl1.data(), tl1.size());
    tl1.done();

    Serial.print((char*)cert_data);
  }

  memset(cert_data, 0, 2048);

  Serial.println("Private key:");
  if (tl2.have_cert()) {
    memcpy(cert_data, tl2.data(), tl2.size());
    tl2.done();

    Serial.print((char*)cert_data);
  }
  Serial.println("");
  Serial.println("");
}

#endif // TEENSY_USE_ECC508

void set_debug(uint32_t *args, uint32_t num_args)
{
  if (num_args != 1)
    return;

  if (args[0] == 0) {
    wolfSSL_Debugging_OFF();
  } else {
    wolfSSL_Debugging_ON();
  }
}

void printDigits(int digits)
{
  Serial.print(":");
  if(digits < 10)
  Serial.print('0');
  Serial.print(digits);
}

void print_date(uint32_t *args, uint32_t num_args)
{
  time_t t = now();
  Serial.print(hour(t));
  printDigits(minute(t));
  printDigits(second(t));
  Serial.print(" ");
  Serial.print(day(t));
  Serial.print(" ");
  Serial.print(month(t));
  Serial.print(" ");
  Serial.print(year(t)); 
  Serial.println("");
}

void print_help(uint32_t *args, uint32_t num_args)
{
  Readline_print_command_list(command_list);
}

Readline_cmd_list command_list[] = {
  { "help             ", "Print this help", print_help },
  { "debug level      ", "Set debug level", set_debug },
  { "wifi_connect     ", "Connect to WiFi", wifi_connect },
  { "wifi_stat        ", "Print WiFi stats", wifi_stat },
  { "set_time         ", "Use NTP to set time", ntp_set_time },
  { "date             ", "Get current system date and time", print_date },
  { "mqtt_connect ID  ", "Connect to MQTT server", mqtt_connect },
  { "sub_iot          ", "Subscribe to Amazon Button", sub_iot },
  { "sub              ", "MQTT Subscribe", mqtt_sub },
  { "pub              ", "MQTT Publish", mqtt_pub },
  { "setup            ", "Setup WiFi and AWS", wifi_setup },
  { "save_certs       ", "Write signed certificates", save_certs },
  { "read_certs       ", "Read  certificates", read_certs },
#ifdef TEENSY_USE_ECC508
  { "setup_ecc508     ", "Configure ECC508a", config_ecc508a },
  { "csr         slot year mon day valid_years -> country state locality sur org unit commonName email",
      "Generate CSR", gen_csr},
#endif
  { NULL, NULL, NULL }
};

/* Provision
   Load to either EEPROM or ECC508a
*/
/* TODO
   Support disconnect/reconnect
   WiFi stop / reconnect
   Better pub / sub commands - allow strings
*/

void mqtt_loop()
{
  if (connected)
    connected = mqtt.loop(10);
}

void loop() {
  String cmd;
  Readline_idle = mqtt_loop;

  cmd = Readline("mqtt> ");

  if (cmd.length() > 0)
    Readline_parse_command(cmd, command_list);

}

bool TeensyCertLoader::have_cert()
{
  size_t sz1, sz2, sz3, st, cert_sz;
  size_t i;

  st = 160;
  sz1 = ((EEPROM.read(st+0) << 8) & 0xFF00) | (EEPROM.read(st+1) & 0x00FF);
  sz2 = ((EEPROM.read(st+2) << 8) & 0xFF00) | (EEPROM.read(st+3) & 0x00FF);
  sz3 = ((EEPROM.read(st+4) << 8) & 0xFF00) | (EEPROM.read(st+5) & 0x00FF);

  if ((sz1 == 0) || (sz2 == 0) || (sz3 == 0) || (sz1+sz2+sz3 > 4096)) {
    return false;
  }

  switch (cert_id) {
    case 1:
      st = 166;
      cert_sz = sz1+sz2;
      break;
    case 2:
      st = 166 + sz1 + sz2;
      cert_sz = sz3;
      break;
    default:
      return false;
  }

  cert_data = (uint8_t*)malloc(cert_sz+1);
  if (cert_data == NULL)
    return false;

  for (i = 0; i < cert_sz; i++) {
    cert_data[i] = EEPROM.read(st+i);
  }
  cert_data[cert_sz] = '\0';
  cert_data_size = cert_sz;

  return true;
}

void TeensyCertLoader::done()
{
  cert_data_size = 0;
  if (cert_data != NULL)
    free(cert_data);
}

