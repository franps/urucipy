import hashlib
import sys
import time
import smartcard
from smartcard.CardType import ATRCardType, AnyCardType
from smartcard.CardRequest import CardRequest
from smartcard.CardConnection import CardConnection
from smartcard.util import toHexString, toBytes

action = userpin = stringhash = False

########### COMANDOS PRECARGADOS ####################
#               | CLA | INS | P1 | P2  |  LC |      DATA  ...
IAS = [0x00, 0xA4, 0x04, 0x00, 0x0C, 0xA0, 0x00, 0x00,
       0x00, 0x18, 0x40, 0x00, 0x00, 0x01, 0x63, 0x42, 0x00]
verifyPIN = [0x00, 0x20, 0x00, 0x11, 0x0C]

MSE_SET_DST = [0x00, 0x22, 0x41, 0xB6, 0x06]
PSO_HASH = [0x00, 0x2A, 0x90, 0xA0, 0x20]
PSO_CDS = [0x00, 0x2A, 0x9E, 0x9A, 0x00, 0xFF, 0x00]

selectFile = [0x00, 0xA4, 0x00, 0x00, 0x02, 0x70, 0x01]

####################################################
cardtype = ATRCardType(toBytes(
    "3B 7F 94 00 00 80 31 80 65 B0 85 03 00 EF 12 0F FF 82 90 00"))  # Solo eCI de UY
####################################################


def encrypt_string(hash_string):
    sha_signature = hashlib.sha256(hash_string.encode()).hexdigest()
    return sha_signature


def enviarAPDU(cmd):
    data, sw1, sw2 = cardservice.connection.transmit(cmd)
    return [data, sw1, sw2]


def toHex(str):
    m = len(str)
    lst = []
    for i in range(0, m, 2):
        lst.append(int('0x' + str[i] + str[i + 1], 16))
    return lst


def toPinHex(pin):
    m = len(pin)
    lst = []
    for i in range(0, 12, 1):
        if(i >= m):
            lst.append(int('0x00', 16))
        else:
            lst.append(int('0x3' + pin[i], 16))
    return lst


def selectIAS():
    ########### COMANDO selectIAS ################
    data, sw1, sw2 = enviarAPDU(IAS)
    if (hex(sw1) == hex(0x90) and hex(sw2) == hex(0x00)):
        print(hex(sw1), hex(sw2))
    else:
        print("ERROR AL LEER DOCUMENTO " + hex(sw1) + " " + hex(sw2))


def sign(toSign):
    ########### COMANDO verifyPIN ################
    data, sw1, sw2 = enviarAPDU(verifyPIN + toPinHex(userpin))
    if (sw1 == 0x90 and sw2 == 0x0):

        ########### COMANDO MSE_SET_DST ################
        data, sw1, sw2 = enviarAPDU(
            MSE_SET_DST + [0x84, 0x01, 0x01, 0x80, 0x01, 0x02])

        ########### COMANDO PSO_HASH ################
        data, sw1, sw2 = enviarAPDU(PSO_HASH + [0x90, 0x19] + toSign)

        ########### COMANDO PSO_Compute Digital Signature: ################
        data, sw1, sw2 = enviarAPDU(PSO_CDS)

        print(encrypt_string(toHexString(data).replace(" ", "")))

    else:
        print("PIN INVALIDO")


###############################################################################
### Hay tres acciones definidas:                                            ###
###     - readerData ( void ) : imprime la marca y modelo del Lector        ###
###     - firmar (pin, string): hace un hash y encripta con la clave        ###
###                             privada un string pasado por parametro      ###
###     - datos ( void ):       devuelve datos de la cedula conectada       ###
###############################################################################

global cardservice
cardrequest = CardRequest(timeout=20, cardType=cardtype)
cardservice = cardrequest.waitforcard()
cardservice.connection.connect(CardConnection.T0_protocol)

if(len(sys.argv) == 1):
    print("Faltan argumentos")
else:
    action = sys.argv[1]
    userpin = sys.argv[2] if len(sys.argv) > 3 else False
    stringhash = sys.argv[3] if len(sys.argv) > 3 else False


while (1):
    if (len(cardrequest.getReaders()) == 0):
        print("Lector no conectado")
    else:
        if (action == 'readerData'):
            print("--- Reader Data ---")
            print("reader" + str(cardrequest.getReaders()[0]))

        elif (action == 'firmar'):
            print("--- Sign Hash ---")
            MIHASH = toHex(encrypt_string(stringhash))
            selectIAS()
            sign(MIHASH)

        elif (action == 'datos'):
            print("--- Get data ---")
            selectIAS()
            data, sw1, sw2 = enviarAPDU(selectFile)
            print(data, hex(sw1), hex(sw2))
        else:
            print("ACCION NO DEFINIDA")
    time.sleep(1)
