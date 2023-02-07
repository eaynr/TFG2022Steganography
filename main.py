from scapy.all import *
from Cryptodome.Cipher import Salsa20
import base64

#           ESTRUCTURA MISSATGE IP
#  0     4     8            16   19                   32
#  |  v  | IHL |    TOS 	|       Total length      |
#  |     Identification     |Flags|  Fragment offset  |
#  |    TTL    |  Protocol	|     Header Checksum     |
#  |                 Source  address                  |
#  |              Destination  address                |
#  | ...

# Aqui aprofitarem les capçaleras Flags i Fragment offset per
# enviar informació codificada i guanyar mes ample de banda.
# Aqui guanyem 2 bytes

# Aixo provoca modificar: Enviament i recepcio. Veure bits com va
# IP(flags=0bXXX, frag=0bXXXXXXXXXXXXX)
# int(paquetResposta[IP].flags)
# paquetResposta[IP].frag


#           ESTRUCTURA MISSATGE ICMP                            #                ESTRUCTURA MISSATGE IP
#  0            8            16                       32        #  0           8            16                        32
#  |    Type    |    Code	|        Checksum         |         #  |  V | SIZE |    TOS 	|        T. length        |
#  |       Identifier	    |     Sequence Number     |         #  |       Identifier	    | FLAGS |  Frag Offset    |
#  |    TTL    |  Protocol  |        Checksum         |
#           ESTRUCTURA MISSATGE SECRET DESSITJAT                #  |                       ...                        |
#  0            8            16                       32        #           ESTRUCTURA MISSATGE SECRET DESSITJAT
#  |    Type    |    Code	 |        Checksum        |         #  0           8            16                        32
#  | 1byte info | 1byte info |       2byte ctr        |         #  |  V | SIZE |    TOS 	|        T. length        |
#                                                               #  |      2 byte info	    |       2 byte info       |
#  Enviament    0           3            6       7     8        #  |    TTL    |  Protocol  |        Checksum         |
#  byte ctr --> | 3bits SEQ | 3bits #ACK | Start | End |        #  |                       ...                        |
#  Recepcio     0           3            6       7     8
#  byte ctr --> | 3bits ACK | 3bits #SEQ | Start | End |        # potser toca reformular la capçalera.
# seria una opció bits inici i final que fos una cadena de caràcters en el missatge.
# mirar que tal es podria fer i com.
# NOVA MODIFICACIÓ
#  Enviament    0                     6       7     8           #  Enviament    0                     14     15    16
#  byte ctr --> |     6 bits SEQ      | Start | End |           #  byte ctr --> |     14 bits SEQ     | Start | End |
#  Recepcio     0                     6       7     8           #  Recepcio     0                     14     15    16
#  byte ctr --> |     6 bits ACK      | Start | End |           #  byte ctr --> |     14 bits ACK     | Start | End |

# Això provoca modificar: -Capçalera okey(), -sumar EXP(veure que es fa), -treball en bits(), .veure capcalera prev com va

# IP --> flags offset fraq

# mascaras:     -sumar 1 SEQ/ACK    --> ADD 00000100 - sumar 4
#               -sumar 1 #ACK/#SEQ  --> ADD 00000100 - sumar 4
#               -start a 1          --> ADD 00000010 - sumar 2
#               -end a 1            --> ADD 00000001 - sumar 1

def treballenbits(iteracio):

    base = 0b0
    suma = 1

    if iteracio > 32767: #2^16 màxim nombre d'elements de SEQ
        iteracio = iteracio % 16
        base = base + suma * iteracio
    else:
        base = base + suma * iteracio

    return base

def capcaleraOkey(cap, capEsp): #Comprovem si la SEQ rebuda es la SEQ esperada
    okey = False

    if(cap == capEsp):
        okey = True

    return okey

def establirFi(aux):
    end = 32768
    return aux + end

def bytesToFlags(nombre):

    base = 0b000

    if nombre > 8191:
        mascara = 57344 #0b1110000000000000
        resposta = bin(nombre & mascara)
        resposta = resposta[:-13]
    else:
        resposta = base

    return resposta

def bytesToFrag(nombre):

    base = 0b0000000000000
    mascara = 8191 #0b0001111111111111

    resposta = nombre & mascara

    return bin(resposta)

def flagsandfragToBytes(numA, numB):

    unificacio = numA << 13
    unificacio = unificacio | numB

    return unificacio

def menu():
    os.system("cls")
    print(" |         ESTEGANOGRAFIA        | ")
    print("  -------------------------------  ")
    print(" |   1. Enviar TXT               | ")
    print(" |   2. Enviar IMATGE            | ")
    print(" |   3. Rebre TXT                | ")
    print(" |   4. Rebre IMATGE             | ")
    print(" |   4. Recepció OFFLINE         | ")
    print(" |   5. Assignar clau privada    | ")
    print(" |   6. Sortir                   | ")
    print("")
    aux = input('Que vols fer ? ')
    return int(aux)

def encriptar(missatgeSecret):

    nonlocal clauPrivada
    contrasenya = clauPrivada

    bytesPerDatagrama = 4

    print("-----------------ENCRIPTACIO-----------------------")

    multiple = (len(missatgeSecret)+8) % bytesPerDatagrama
    if not(multiple == 0):
        missatgeSecret = missatgeSecret + " "*(bytesPerDatagrama-multiple)

    missatgeSecretBytes = bytes(missatgeSecret, 'utf-8')

    xifrador = Salsa20.new(key=contrasenya)
    missatgeEnviar = xifrador.nonce + xifrador.encrypt(missatgeSecretBytes)
    print("Contingut a enviar: " + str(missatgeEnviar) + " i ocupa: " + str(len(missatgeEnviar)) + " bytes.")

    return missatgeEnviar

def encriptarFoto(missatgeSecret):

    nonlocal clauPrivada
    contrasenya = clauPrivada

    bytesPerDatagrama = 4
    print(len(missatgeSecret))
    print(missatgeSecret)
    print("-----------------ENCRIPTACIO-----------------------")

    multiple = (len(missatgeSecret)+8) % bytesPerDatagrama
    if not(multiple == 0):
        missatgeSecret = missatgeSecret + bytes(" "*(bytesPerDatagrama-multiple), 'utf-8')
    print(len(missatgeSecret))
    print(missatgeSecret)
    missatgeSecretBytes = missatgeSecret

    xifrador = Salsa20.new(key=contrasenya)
    missatgeEnviar = xifrador.nonce + xifrador.encrypt(missatgeSecretBytes)
    print("Contingut a enviar: " + str(missatgeEnviar) + " i ocupa: " + str(len(missatgeEnviar)) + " bytes.")

    return missatgeEnviar

def desencriptar(missatgeRebut):

    nonlocal clauPrivada
    contrasenya = clauPrivada

    print("----------------DESENCRIPTACIO----------------------")
    soroll = missatgeRebut[:8]
    missatgeXifrat = missatgeRebut[8:]
    desxifrador = Salsa20.new(key=contrasenya, nonce=soroll)
    missatgeDesxifrat = desxifrador.decrypt(missatgeXifrat)
    missatgeDesxifratText = str(missatgeDesxifrat, 'utf-8')

    espai = True
    index = -1
    while espai:
        if(missatgeDesxifratText[index]) == " ":
            aux = list(missatgeDesxifratText)
            del(aux[index])
            missatgeDesxifratText = "".join(aux)
        else:
            espai = False

    return missatgeDesxifratText

def desencriptarFoto(missatgeRebut):

    nonlocal clauPrivada
    contrasenya = clauPrivada

    print("----------------DESENCRIPTACIO----------------------")
    soroll = missatgeRebut[:8]
    missatgeXifrat = missatgeRebut[8:]
    desxifrador = Salsa20.new(key=contrasenya, nonce=soroll)
    missatgeDesxifrat = desxifrador.decrypt(missatgeXifrat)

    espai = True
    index = -1
    while espai:
        if missatgeDesxifrat[index] == 32:
            missatgeDesxifrat = missatgeDesxifrat[:-1]
        else:
            espai = False

    return missatgeDesxifrat

def enviarMissatgeControlFinestra(missatgeSecret):

    def analitzar(paquet):
        nonlocal offset
        nonlocal finestra
        nonlocal finestraMax
        nonlocal n_iteracions
        nonlocal fi
        nonlocal volta
        nonlocal ipFont
        okey = False

        if paquet[IP].dst == ipFont:
            part1 = paquet[IP].id
            if(offset > 30000 and part1 < 1500):
                volta = volta + 1
            offset = part1 + volta * 32768
            if(offset + finestraMax >= n_iteracions):
                finestra = n_iteracions - offset
            else:
                finestra = finestraMax

            if part1 >= 32768:
                fi = True

            okey = True

        return okey

    nonlocal ipTransmissor
    nonlocal ipReceptor

    ipDest = ipReceptor
    ipFont = ipTransmissor

    bytesPerDatagrama = 4
    n = len(missatgeSecret) % bytesPerDatagrama

    finestraMax = 10
    finestra = finestraMax
    resposta = False
    volta = 0

    if n == 0: #fa falta ?
        n_iteracions = len(missatgeSecret) / bytesPerDatagrama  # +4 per afegir el nonce
    else:
        n_iteracions = ((bytesPerDatagrama-n)+len(missatgeSecret)) / bytesPerDatagrama   # +4 per afegir el nonce

    fi = False
    offset = 0
    ultima_it = False
    while (fi != True):

        i = 0
        packetsToSend = []
        while finestra > 0 & ultima_it != True:
            part1 = treballenbits(i+offset)

            if i + offset == n_iteracions - 1:  # ultima iteració
                part1 = establirFi(part1)
                ultima_it = True

            # part1
            part2 = int.from_bytes(missatgeSecret[(i+offset) * bytesPerDatagrama:(i+offset) * bytesPerDatagrama + 2], byteorder='big')
            part3 = int.from_bytes(missatgeSecret[(i+offset) * bytesPerDatagrama + 2:(i+offset) * bytesPerDatagrama + 4], byteorder='big')

            paquet = IP(dst=ipDest, id=part1) / ICMP(id=part2, seq=part3)
            #send(paquet)
            packetsToSend.append(paquet)

            #send(paquet)
            finestra = finestra - 1
            i = i + 1

        send(packetsToSend)
        #print("Paquets enviats")

        while (finestra == 0 and fi != True): #& timeout
            resposta = sniff(filter="icmp[0]=0 and src {0}".format(ipDest), count=1, prn=analitzar, timeout=10) #timeout

            if(type(resposta) != bool):
                finestra = finestraMax

            if(resposta == False):
                finestra = finestraMax

def rebreMissatgeControlFinestra():

    def analitzar(paquet):
        nonlocal missatgeSecret
        nonlocal paquetsDesordenats
        nonlocal final
        nonlocal capcaleraEsp
        nonlocal finestra
        nonlocal maxFinestra
        nonlocal ultimPaquet

        nonlocal ipFont
        nonlocal ipDest

        if paquet[IP].src == ipFont and paquet[IP].dst == ipDest:
            #print("Rebem 6 bytes")
            capcalera = paquet[IP].id
            part2 = paquet[ICMP].id.to_bytes(length=2, byteorder='big')
            part3 = paquet[ICMP].seq.to_bytes(length=2, byteorder='big')

            if capcalera >= 32768:
                final = True
                capcalera = capcalera - 32768
                print("Rebem el final")

            if capcaleraOkey(capcalera, capcaleraEsp):
                missatgeSecret += part2 + part3
                capcaleraEsp = capcaleraEsp + 1
                finestra = finestra - 1
            else:
                paquetsDesordenats.append(paquet)

            if (finestra == 0 or final):
                ultimPaquet = paquet

    def checkDesordenats():
        nonlocal missatgeSecret
        nonlocal paquetsDesordenats
        nonlocal final
        nonlocal capcaleraEsp
        nonlocal finestra
        nonlocal ultimPaquet

        for paquet in paquetsDesordenats:
            capcalera = paquet[IP].id

            if capcalera >= 32768:
                final = True
                capcalera = capcalera - 32768
                print("Rebem el final")

            if capcaleraOkey(capcalera, capcaleraEsp):
                #part2 = int(paquet[IP].flags)
                #part3 = paquet[IP].frag
                #part23 = (flagsandfragToBytes(part2, part3)).to_bytes(length=2, byteorder='big')
                part2 = paquet[ICMP].id.to_bytes(length=2, byteorder='big')
                part3 = paquet[ICMP].seq.to_bytes(length=2, byteorder='big')

                #missatgeSecret += part23 + part4 + part5
                missatgeSecret += part2 + part3
                capcaleraEsp = capcaleraEsp + 1
                finestra = finestra - 1

                if (finestra == 0 or final):
                    ultimPaquet = paquet

                paquetsDesordenats.remove(paquet)

    nonlocal ipTransmissor
    nonlocal ipReceptor

    ipDest = ipReceptor
    ipFont = ipTransmissor

    missatgeSecret = b""
    final = False
    capcaleraEsp = 0

    maxFinestra = 2
    finestra = maxFinestra
    paquetsDesordenats = []

    ultimPaquet = ""

    while not final:
        sniff(filter="icmp[0]=8 and dst {0}".format(ipDest), count=maxFinestra, prn=analitzar, timeout=2)
        if len(paquetsDesordenats) > 0:
            checkDesordenats()
        if (finestra == 0 or final):
            if final:
                capcaleraEsp = capcaleraEsp + 32768
            paquetResposta = IP(dst=ipFont, id=capcaleraEsp) / ICMP(type=0, id=ultimPaquet[ICMP].id, seq=ultimPaquet[ICMP].seq)
            send(paquetResposta)
            finestra = maxFinestra

    print("El missatge rebut codificat es: " + str(missatgeSecret))
    return missatgeSecret

def rebreMissatgeOffline():

    def analitzar(paquet):
        nonlocal missatgeSecret

        if paquet[Ether].type == 2048: #type = ETHERNET
            if paquet[IP].src == ipTransmissor and paquet[IP].dst == ipReceptor and paquet[IP].proto == 1:
                part2 = paquet[ICMP].id.to_bytes(length=2, byteorder='big')
                part3 = paquet[ICMP].seq.to_bytes(length=2, byteorder='big')
                missatgeSecret += part2 + part3

    nonlocal ipTransmissor
    nonlocal ipReceptor
    missatgeSecret = b""
    sniff(offline='Analitzar.pcap', prn=analitzar)

    print("El missatge rebut codificat es: " + str(missatgeSecret))
    return missatgeSecret

if __name__ == '__main__':

    execucio = True
    ipTransmissor = "192.168.1.43"
    ipReceptor = "192.168.1.49"
    clauPrivada = b'123uabtfg2022123'
    midaFinestra = 1

    while execucio:
        function = menu()
        if function == 1:
            print("Enviar dades")

            msgSecret = input('Quin missatge vols enviar ? ')
            missatgeCodificat = encriptar(msgSecret)
            enviarMissatgeControlFinestra(missatgeCodificat)

            execucio = False

        elif function == 2:
            print("Enviar foto")

            fotoURL = input('Escriu la ruta complerta de la foto a enviar:')
            image = open(fotoURL, 'rb')
            image_read = image.read()
            image_64_encode = base64.encodebytes(image_read)
            missatgeCodificat = encriptarFoto(image_64_encode)
            enviarMissatgeControlFinestra(missatgeCodificat)

            execucio = False

        elif function == 3:
            print("Rebre dades")

            missatgeRebutCodificat = rebreMissatgeControlFinestra()
            missatgeRebutDesodificat = desencriptar(missatgeRebutCodificat)
            print("El missatge rebut descodificat es: " + missatgeRebutDesodificat + " i ocupa " + str(
                len(missatgeRebutDesodificat)) + " bytes")

            execucio = False

        elif function == 4:
            print("Rebre foto")

            missatgeRebutCodificat = rebreMissatgeControlFinestra()
            missatgeRebutDesodificat = desencriptarFoto(missatgeRebutCodificat)
            image_64_decode = base64.decodebytes(missatgeRebutDesodificat)
            image_result = open('res.png', 'wb')
            image_result.write(image_64_decode)

            execucio = False

        elif function == 5:
            print("Canviar parametres")
            print("Introdueix la clau privada sistema de xifratge")
            clauPrivada = bytes(input(), 'utf-8')
            print("Introdueix la IP del Transmissor")
            IPTransmissor = input()
            print("Introdueix la IP del Receptoror")
            IPReceptor = input()
            print("Introdueix numèricament la mida")
            midaFinestra = int(input())

        elif function == 6:
            execucio = False

    exit()
