TEENSY = 36
INO_FILES = aws_teensy.ino

ifdef FEATHER
FEATHER_LIBS += Wire SPI Time
else
TEENSY_LIBS += Entropy SPI Wire Time EEPROM
endif

LIB_DIRS += /Volumes/Devel/crypto/WolfSSLClient
LIB_DIRS += /Volumes/Devel/crypto/WolfMQTTClient
LIB_DIRS += /Volumes/Devel/crypto/AtCryptoAuthLib
LIB_DIRS += /Volumes/Devel/crypto/WolfCryptoAuth
LIB_DIRS += /Volumes/Devel/Projects/Readline

LIB_DIRS += /Volumes/Devel/Arduino/WiFi101/src

##EXTRA_DEFINES = ATCAPRINTF ATCA_HAL_I2C USE_ECCX08
#EXTRA_DEFINES += WOLFMQTT_DEBUG_SOCKET
#EXTRA_DEFINES += WOLFMQTT_DEBUG_CLIENT

LIB_INCLUDE += . 

SERIAL_PORT = cu.usbmodem141131

ifdef FEATHER
include /Volumes/Devel/samd/feather.mk
else
EXTRA_DEFINES += CORE_TEENSY
include /Volumes/Devel/teensy/teensy.mk
endif

