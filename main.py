from scapy.all import *
from Cryptodome.Cipher import Salsa20
import socket
import base64

def arping2tex(ipdest):
    if len(sys.argv) == 2:
        print("Usage: arping2tex <net>\n eg: arping2text 192.168.1.0/24")
        sys.exit(1)

    conf.verb = 0
    ans, unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ipdest), timeout=2)

    print(r"\begin{tabular}{|l|l|}")
    print(r"\hline")
    print(r"MAC & IP\\")
    print(r"\hline")
    for snd, rcv in ans:
        print(rcv.sprintf(r"%Ether.src% & %ARP.psrc%\\"))
    print(r"\hline")
    print(r"\end{tabular}")
    #arping2tex("192.168.1.0/24")

def build_icmp(ip):
    paquet = IP(dst=ip) / ICMP(type=8, code=0)
    return paquet

def testSnort():
    ipDest="192.168.1.49"

    #llegirme les icmp rules a veure que diuen

    send(IP(dst=ipDest) / ICMP() / "testICMPpacket", count=100)
    #a=IP(ttl=10, dst=ipDest)/ICMP(type=8, code=0)
    #str(a)
    #a.ttl=(10,19)
    #a.show()
    #send(a)
#
    #def generator(self, n, filename):
    #    time = 0.00114108 * n + 0.157758
    #    minutes = time / 60
#
    #    print('Generating packets, it will take %s seconds, moreless (%s, minutes)' % (time, minutes))
#
    #    pkgs = [IP(dst='10.0.0.1') / ICMP() for i in range(n)]
    #    wrpcap(filename, pkgs)
#
    #    print('%s packets generated.' % (n))

def propiaip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))
    ip = s.getsockname()[0]
    s.close()
    return ip

def treballenbits(iteracio):

    #           ESTRUCTURA MISSATGE IP
    #  0     4     8            16   19                   32
    #  |  v  | IHL |    TOS 	|       Total length      |
    #  |     Identification     |Flags|  Fragment offset  |
    #  |    TTL    |  Protocol	|     Header Checksum     |
    #  |                 Source  address                  |
    #  |              Destination  address                |
    #  | ...

    #Aqui aprofitarem les capçaleras Flags i Fragment offset per
    #enviar informació codificada i guanyar mes ample de banda.
    # Aqui guanyem 2 bytes

    #Aixo provoca modificar: Enviament i recepcio. Veure bits com va
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
                                                                    #seria una opció bits inici i final que fos una cadena de caràcters en el missatge.
                                                                    #mirar que tal es podria fer i com.
    # NOVA MODIFICACIÓ
    #  Enviament    0                     6       7     8           #  Enviament    0                     14     15    16
    #  byte ctr --> |     6 bits SEQ      | Start | End |           #  byte ctr --> |     14 bits SEQ     | Start | End |
    #  Recepcio     0                     6       7     8           #  Recepcio     0                     14     15    16
    #  byte ctr --> |     6 bits ACK      | Start | End |           #  byte ctr --> |     14 bits ACK     | Start | End |

    #Això provoca modificar: -Capçalera okey(), -sumar EXP(veure que es fa), -treball en bits(), .veure capcalera prev com va

    #IP --> flags offset fraq

    # mascaras:     -sumar 1 SEQ/ACK    --> ADD 00000100 - sumar 4
    #               -sumar 1 #ACK/#SEQ  --> ADD 00000100 - sumar 4
    #               -start a 1          --> ADD 00000010 - sumar 2
    #               -end a 1            --> ADD 00000001 - sumar 1
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

def extreureControl(info): #no es fa servir
    info = format(info, 'b')
    ctr = [info[-8:-5], info[-5:-2], info[-2], info[-1]]
    return ctr

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
    print(" |         ESTEGANOGRAFIA        | ")
    print("  -------------------------------  ")
    print(" |   1. Enviar DADES             | ")
    print(" |   2. Rebre DADES              | ")
    print(" |   3. Assignar clau privada    | ")
    print(" |   4. Sortir                   | ")
    print("")
    aux = input('Que vols fer ? ')
    return int(aux)

def encriptar(missatgeSecret):

    #print("Vull enviar: " + missatgeSecret + " que ocupa: " + str(len(missatgeSecret)) + " bytes.")

    bytesPerDatagrama = 6

    print("-----------------ENCRIPTACIO-----------------------")

    multiple = (len(missatgeSecret)+8) % bytesPerDatagrama
    if not(multiple == 0):
        missatgeSecret = missatgeSecret + " "*(bytesPerDatagrama-multiple)
    print(len(missatgeSecret))
    print(missatgeSecret)
    missatgeSecretBytes = bytes(missatgeSecret, 'utf-8')
    contrasenya = b'123uabtfg2022123'
    #print("La contrasenya ocupa: " + str(len(contrasenya)))
    #

    xifrador = Salsa20.new(key=contrasenya)
    missatgeEnviar = xifrador.nonce + xifrador.encrypt(missatgeSecretBytes)
    #print("El missatge secret codificat ocupa: " + str(len(missatgeEnviar[8:])) + " bytes.")
    print("Contingut a enviar: " + str(missatgeEnviar) + " i ocupa: " + str(len(missatgeEnviar)) + " bytes.")

    return missatgeEnviar

def encriptarFoto(missatgeSecret):

    #print("Vull enviar: " + missatgeSecret + " que ocupa: " + str(len(missatgeSecret)) + " bytes.")

    bytesPerDatagrama = 6

    print("-----------------ENCRIPTACIO-----------------------")

    multiple = (len(missatgeSecret)+8) % bytesPerDatagrama
    if not(multiple == 0):
        missatgeSecret = missatgeSecret + bytes(" "*(bytesPerDatagrama-multiple), 'utf-8')
    print(len(missatgeSecret))
    print(missatgeSecret)
    missatgeSecretBytes = missatgeSecret
    contrasenya = b'123uabtfg2022123'
    #print("La contrasenya ocupa: " + str(len(contrasenya)))
    #

    xifrador = Salsa20.new(key=contrasenya)
    missatgeEnviar = xifrador.nonce + xifrador.encrypt(missatgeSecretBytes)
    #print("El missatge secret codificat ocupa: " + str(len(missatgeEnviar[8:])) + " bytes.")
    print("Contingut a enviar: " + str(missatgeEnviar) + " i ocupa: " + str(len(missatgeEnviar)) + " bytes.")

    return missatgeEnviar

def desencriptar(missatgeRebut):

    print("----------------DESENCRIPTACIO----------------------")
    contrasenya = b'123uabtfg2022123'
    soroll = missatgeRebut[:8]
    missatgeXifrat = missatgeRebut[8:]
    desxifrador = Salsa20.new(key=contrasenya, nonce=soroll)
    missatgeDesxifrat = desxifrador.decrypt(missatgeXifrat)
    missatgeDesxifratText = str(missatgeDesxifrat, 'utf-8')

    espai = True #eliminar espais extres si es que existeixen.
    index = -1
    while espai:
        if(missatgeDesxifratText[index]) == " ":
            aux = list(missatgeDesxifratText)
            del(aux[index])
            missatgeDesxifratText = "".join(aux)
        else:
            espai = False

    #print("He rebut: " + missatgeDesxifratText + " que ocupa: " + str(len(missatgeDesxifratText)) + " bytes.")

    return missatgeDesxifratText

def desencriptarFoto(missatgeRebut):

    print("----------------DESENCRIPTACIO----------------------")
    contrasenya = b'123uabtfg2022123'
    soroll = missatgeRebut[:8]
    missatgeXifrat = missatgeRebut[8:]
    desxifrador = Salsa20.new(key=contrasenya, nonce=soroll)
    missatgeDesxifrat = desxifrador.decrypt(missatgeXifrat)
    missatgeDesxifratText = str(missatgeDesxifrat, 'utf-8')

    espai = True #eliminar espais extres si es que existeixen.
    index = -1
    while espai:
        if(missatgeDesxifratText[index]) == " ":
            aux = list(missatgeDesxifratText)
            del(aux[index])
            missatgeDesxifratText = "".join(aux)
        else:
            espai = False

    #print("He rebut: " + missatgeDesxifratText + " que ocupa: " + str(len(missatgeDesxifratText)) + " bytes.")

    return bytes(missatgeDesxifratText, 'utf-8')

def enviarMissatgeControlFinestra(missatgeSecret):

    def analitzar(paquet):
        nonlocal capcaleraPrev
        nonlocal offset
        nonlocal finestra
        nonlocal finestraMax
        nonlocal n_iteracions
        nonlocal fi
        okey = False
        font = "192.168.1.43"

        if paquet[IP].dst == font:
            part1 = paquet[IP].id
            offset = part1
            if(offset + finestraMax >= n_iteracions):
                finestra = n_iteracions - offset
            else:
                finestra = finestraMax

            if part1 >= 32768:
                fi = True

            okey = True

        return okey

    ipDest = "192.168.1.49" #################
    capcaleraPrev = 2

    bytesPerDatagrama = 4
    n = len(missatgeSecret) % bytesPerDatagrama

    finestraMax = 2
    finestra = finestraMax
    resposta = False

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
            ###############
            #part1
            #part23 = int.from_bytes(missatgeSecret[i * bytesPerDatagrama:i * bytesPerDatagrama + 2], byteorder='big')
            #aux = bytesToFlags(part23)
            #if (aux != 0):
            #    part2 = int(bytesToFlags(part23), 2)
            #else:
            #    part2 = 0
            #part3 = int(bytesToFrag(part23), 2)
            #part4 = int.from_bytes(missatgeSecret[i * bytesPerDatagrama + 2:i * bytesPerDatagrama + 4], byteorder='big')
            #part5 = int.from_bytes(missatgeSecret[i * bytesPerDatagrama + 4:i * bytesPerDatagrama + 6], byteorder='big')

            #paquet = IP(dst=ipDest, id=part1, flags=part2, frag=part3) / ICMP(id=part4, seq=part5)
            #################

            # part1
            part4 = int.from_bytes(missatgeSecret[(i+offset) * bytesPerDatagrama:(i+offset) * bytesPerDatagrama + 2], byteorder='big')
            part5 = int.from_bytes(missatgeSecret[(i+offset) * bytesPerDatagrama + 2:(i+offset) * bytesPerDatagrama + 4], byteorder='big')

            paquet = IP(dst=ipDest, id=part1) / ICMP(id=part4, seq=part5)
            send(paquet)
            packetsToSend.append(paquet)

            #send(paquet)
            #print("Paquet enviat")
            finestra = finestra - 1
            i = i + 1

        #sendp(packetsToSend)
        #print("Paquets enviats")

        while (finestra == 0 and fi != True): #& timeout
            #print("TimeIn")
            #resposta = False
            resposta = sniff(filter="icmp[0]=0 and src {0}".format(ipDest), count=1, prn=analitzar, timeout=5) #timeout
            #print("TimeOut")
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

        font = "192.168.1.43"
        desti = "192.168.1.49"

        if paquet[IP].src == font and paquet[IP].dst == desti: #POSAR DST ADEQUAT
            #print("Rebem 6 bytes")
            capcalera = paquet[IP].id
            #part2 = int(paquet[IP].flags)
            #part3 = paquet[IP].frag
            #part23 = (flagsandfragToBytes(part2, part3)).to_bytes(length=2, byteorder='big')
            part4 = paquet[ICMP].id.to_bytes(length=2, byteorder='big')
            part5 = paquet[ICMP].seq.to_bytes(length=2, byteorder='big')

            if capcalera >= 32768:
                final = True
                capcalera = capcalera - 32768
                print("Rebem el final")

            if capcaleraOkey(capcalera, capcaleraEsp):
                #missatgeSecret += part23 + part4 + part5
                missatgeSecret += part4 + part5
                capcaleraEsp = capcaleraEsp + 1
                finestra = finestra - 1
            else:
                paquetsDesordenats.append(paquet)

            if (finestra == 0 or final):
                ultimPaquet = paquet

            #paquetResposta = IP(dst=font, id = capcalera) / ICMP(type=0, id=paquet[ICMP].id, seq=paquet[ICMP].seq)
            #send(paquetResposta)

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
                part4 = paquet[ICMP].id.to_bytes(length=2, byteorder='big')
                part5 = paquet[ICMP].seq.to_bytes(length=2, byteorder='big')

                #missatgeSecret += part23 + part4 + part5
                missatgeSecret += part4 + part5
                capcaleraEsp = capcaleraEsp + 1
                finestra = finestra - 1

                if (finestra == 0 or final):
                    ultimPaquet = paquet

                paquetsDesordenats.remove(paquet)

    ##################################################################
    missatgeSecret = b""
    final = False
    capcaleraEsp = 0

    maxFinestra = 2
    finestra = maxFinestra
    paquetsDesordenats = []

    ultimPaquet = ""

    font = "192.168.1.43"
    desti = "192.168.1.49"

    while not final:
        sniff(filter="icmp[0]=8", count=maxFinestra, prn=analitzar)
        if len(paquetsDesordenats) > 0:
            checkDesordenats()
        if (finestra == 0 or final):
            if final:
                capcaleraEsp = capcaleraEsp + 32768
            paquetResposta = IP(dst=font, id=capcaleraEsp) / ICMP(type=0, id=ultimPaquet[ICMP].id, seq=ultimPaquet[ICMP].seq)
            send(paquetResposta)
            finestra = maxFinestra

    print("El missatge rebut codificat es: " + str(missatgeSecret))
    return missatgeSecret

def rebreMissatgeOffline():

    def analitzar(paquet):
        nonlocal missatgeSecret

        if paquet[Ether].type == 2048: #type = ETHERNET
            if paquet[IP].src == "192.168.1.43" and paquet[IP].dst == "192.168.1.49" and paquet[IP].proto == 1:
                part1 = paquet[ICMP].id.to_bytes(length=2, byteorder='big')
                part2 = paquet[ICMP].seq.to_bytes(length=2, byteorder='big')
                missatgeSecret += part1 + part2
                #missatgeSecret = missatgeSecret, paquet[ICMP].id, paquet[ICMP].seq

    missatgeSecret = b""
    sniff(offline='Analitzar.pcap', prn=analitzar)

    print("El missatge rebut codificat es: " + str(missatgeSecret))
    return missatgeSecret

if __name__ == '__main__':

    #ipsrc = propiaip() ##desmarcar per propia IP
    #print(ipsrc)

    #function = menu()
    function = 5
    if function == 1:
        print("Enviar dades")

        #msgSecret = input('Quin missatge vols enviar ? ')
        msgSecret = "TestEnviamentProvaAmbFinestra"
        missatgeCodificat = encriptar(msgSecret)
        enviarMissatgeControlFinestra(missatgeCodificat)

    elif function == 2:
        print("Rebre dades")

        missatgeRebutCodificat = rebreMissatgeControlFinestra()
        missatgeRebutDesodificat = desencriptar(missatgeRebutCodificat)
        print("El missatge rebut descodificat es: " + missatgeRebutDesodificat + " i ocupa " + str(len(missatgeRebutDesodificat)) + " bytes")

    elif function == 3:
        print("Canviar parametres")

        #Implementar canviar Clauprivada i IPs

    elif function == 4:

        #IDEA
        #Agafar d'un .txt les IPs src i desti
        #En un .txt tenir un registre dels missatges enviats i rebuts
        #Possibilitat de eliminar entrades del registre

        #ipDest = "192.168.1.200"
        #paquetResposta = IP(dst=ipDest, flags= 0b101, frag= 0b0000000000010) / ICMP()
        #paquetRespostaP = IP(dst=ipDest, flags=16388) / ICMP()
        #ls(paquetRespostaP[IP])
        #print(int(paquetRespostaP[IP].flags))
        #print(paquetRespostaP[IP].frag)

        #num = 45601
        #print(num)
       # parta = bytesToFlags(num)
      #  print(parta)
     #   print(int(parta, 2))
    #    partb = bytesToFrag(num)
   #     print(partb)
  #      partab = flagsandfragToBytes(parta, partb)
 #       print(partab)
#        print(bin(partab))

        #n_iteracions = 3
        #for i in range(n_iteracions):
        #    print (i)
        #    if i == n_iteracions-1: #ultima iteració
        #        print("Okey")
        #informacio = extreureControl(0b01000101+64)
        #informacio = treballenbits(1)
        #print(capçaleraOkey(38, 4))
        #print(informacio)
        #print(int.from_bytes(informacio, byteorder='big'))

        #testSnort()
        # paquet = IP(dst=ipDest, id=part1, flags=part2, frag=part3) / ICMP(id=part4, seq=part5)
        #paquet = IP(dst="192.168.1.49", id=15, flags=0, frag=0) / ICMP()
        #send(paquet)

        print("A reveure")
        exit()

    elif function == 5:

        print("Enviar foto")
        image = open('black-and-white.png', 'rb')
        image_read = image.read()
        image_64_encode = base64.encodebytes(image_read)

        missatgeCodificat = encriptarFoto(image_64_encode)
        enviarMissatgeControlFinestra(missatgeCodificat)

    elif function == 6:
        print("Rebre foto")

        missatgeRebutCodificat = rebreMissatgeControlFinestra()

        #txt = b'\\xf9[oJ\\x8c\\x10F\\xdd\\x13\\xd5\\xa5\\x03\\xbf\\t\\nw0;\\xc9`\\xf6\\x9a\\xe5\\xe1\\x873\\x0e\\xf2\\x9e\\xeb\\xef\\x0f\\xb4\\xac\\xa6\\xac\\xb3uG\\x0e\\xca\\x0e\\xf1/\\x90\\x14\\xed\\xc7\\xae\\x88\\x9a\\xde\\xe1\\x9a\\xc7\\x8dr\\xb4~\\xbcA\\xe7\\xd3\\xf0\\xfa\\xa1:D\\xce\\x0c\\xc7 \\xa6\\x99jc\\xf7Z\\x1a\\xa0\\xb5Q\\xb7\\xba`+wn\\xae\\x1ay\\x06~;\\xdf\\xfeJ\\xe2o\\xbc\\x08\\xac!\\x9cX\\xed\\xd0Tdf\\xb0!A\\xfd-\\xea:E\\xc8\\xf6\\xe3\\x0e\\x9c\\x00\\xdd\\xff\\x12\\xa3y#\\xe4\\x9e}6:\\xbb\\x15=>\\xa7U\\xc2\\x0c\\x0e\\x10\\xab\\xce\\xdc\\xa9\\xbf\\x8b\\x90\\xab\\xe9s\\xf7\\x95\\x06\\x99d\\xb9\\x9f\\xdf<!\\xe9*\\xc2\\xc7JI6G\\t}X^\\xab7u\\xf5\\x05\\xa8\\xdcZ5y\\xf3Q\\xc7\\x80n\\xae,v\\xb8?\\xce\\x04\\xba"A\\xadR\\x82KelQ@\\x9c\\x1f\\x8a+y\\xea\\xc2:\\xd4\\xddkt\\xbb\\xa4\\xc5\\x16A\\xf03\\xd1\\xafV\\xa8\\xee\\xaeK\\xc4\\xe7\\xe5@\\xe6\\xb7\\xf0M\\x15:\\xd3\\xc4\\xee;\\x9a-\\xf2E\\x1b\\x11[g\\xad\\xfc\\x9cG\\xc9\\xba\\xcf\\r\\x80\\xcd\\xebK\\x0b\\xd2d\\r\\x05\\xcfn\\xc9L\\xa0\\xa4\\x99\\xbcxk5\\xe4\\xf5\\x00\\x9c\\xf9\\xa7yB\\\\p\\xea\\xdf\\x0cM\\xf11\\x05\\x84\\xf1y\\x97V-\\x1fg`\\xd5A\\x82\\x12\\xc0\\xa7d\\xa8\\xa0\\x97A%\\x872\\xbb\\x80#\\x16\\xfa\\x9d\\xf4&{\\x0e\\x17j}9\\x10\\xbb:\\x9c\\xd3\\x00D\\xb6"(ci>z\\xa0DN\\x97\\xa3\\xda\\xda?\\xaf\\x0e\\\'\\xa7\\xd9i\\x95\\x04o2NO\\x86\\xe7\\xf2\\xe7\\xdd\\x98h\\xe0\\xd06\\xf6k\\xc7\\xfb\\xaaU\\x94\\xc5\\rz\\xb1\\xab\\x10\\xfc\\xf9A\\x17O/f\\xee\\x14kK\\xd4\\x80J.d\\x9friU&@\\xf6\\x19\\x80M\\x16j\\x99.\\x13MtlT\\xc3\\xa3\\x98\\xee*I\\x17\\xdc\\xc4\\x1fkD\\xb4\\xe9\\x9fi\\xb6\\xa5\\\\\\xfd\\xf6Z\\xb7\\xb9\\x0e{ 4+"CJV\\x89\\xb1\\xb1[\\xf8\\xc2+\\x19=d\\xdayf+\\xc7\\xdb\\x0fu\\xa8a}cD\\xa9\\xb1\\x14\\xc2\\x1e\\xe8\\xfar\\x90\\n\\xe7\\x0c\\x7fE\\xe5\\xb6\\x91g\\xd6gG\\xff ~\\x06z\\x80\\xc3\\x9a\\xc0\\x08<\\xdb\\xe8\\x98prv\\x96t( \\xd8\\xc3\\x1c"7\\x9e\\x88\\xff\\xd5?&= \\tB\\xa3Bww>v\\x84\\xe3\\x82\\xa3\\x81{\\xb9-=\\xd8\\xe4t|\\x9e\\xb0u\\x04LN\\x03I\\xb3\\xfb\\xf3C\\x82+\\xaetH\\xb9\\xea_\\xe6\\xeb\\xc3Z1\\x7fc\\xe5\\xdc8\\xed\\x88\\x8a\\xa3\\x93P\\xc8\\x91F\\xfd\\xea\\x07\\xb6\\x9dy\\xa9\\xbe,\\xf7H\\xa8]\\x84\\xaaN\\xc8Dq\\xf3\\xf1\\x05\\x93\\xeb\\xe3\\x848\\x18 \\xc5Q\\x12\\x99\\x87\\x9d\\xfb\\xaazh \\xa0\\xcd\\xdf\\xb2Q\\x8b\\xc4\\xca^\\xa1\\xdd\\xad\\xe8\\xaa\\xa6N\\xf7\\x82\\xd7SW&o\\x86\\xde\\xc4\\xe3\\xd2\\x1a>\\xca\\x166+\\x06\\x8c\\xf6\\x93|\\xe3d\\x06\\x9aA\\xddH\\xb22U\\x96\\x88FA\\xef\\xca\\xb0A\\x94\\x8dW\\x1f)\\xb2:\\x00s\\x12\\xb8\\xa3\\x88o\\x9c\\xc1L\\xdf\\xe5/\\xe4n\\xe0\\xc3,"Gi\\x12\\x8b\\xc5=\\tc\\xe9^ O^\\xa2\\xeauki\\xae<\\xca\\x81\\xe9\\xf1\\x0c\\xcf\\xa3\\xffr\\xdc\\xa1M\\xd0\\x97+\\xf5*\\xd9?\\x05\\xa6\\x8a\\xad\\xc7\\xdeP\\xdc\\xf7s\\xf2V\\xd6\\x11:\\xcc\\x1b\\x0b\\xbe\\x1d\\x15f*\\xfc`\\xa5\\xc0S\\xb0\\xb5\\xd3\\xe1\\xd2\\x17\\xe6\\x94A\\x11\\x0cw\\xcf\\x93RT\\xbf\\x84!\\xf8a\\x99j\\x0f\\x17\\x8bk\\x12\\xba\\x8f\\xd0K\\x9fr\\x14\\x18\\xc2\\xaf\\x87\\xed\\xc9\\x1aq\\xf3z\\x0ey\\x7f\\xce\\xe8d\\x82g\\xa1\\x7fY_\\xf9\\xb9\\xa3\\xf1\\xbc\\xd1x\\xa0\\xda\\xd4\\xc1n\\xc8\\x05\\xd2\\x82v\\x18\\xd0\\xe7\\xac\\x97n\\xcbT\\x156fi\\x93xE\\x0f\\x02\\xd6\\xe9\\x96\\x92\\xca\\xf6W\\x19\\x7fPA9\\xc8n\\xd3\\xddR\\xe8\\x8es\\xa7\\x86^\\xea\\xb8\\xbdQ\\x18\\xb2\\xaa\\xe1\\xce\\xa7=I\\xeb\\xac\\x9b4\\r\\xc66\\xe2u&\\xc2\\x07\\x18U\\xd8i`H\\xeb\\xe7\\xae\\xca\\xfb\\x84\\xd8I\\xd8n8\\x07vm\\xa8\\x16H\\xc0*\\xec\\xd5\\xa2!\\xf8\\xac\\x99\\xce\\xa5h\\xad\\x8f\\xddOD\\xf5\\\'\\xeep\\x19\\x11\\xb3^\\xfeR\\xb4kea\\x82U\\xb2Quw\\xbf\\xf3\\x93\\xef\\x96$\\x92D\\xeef?3\\x13\\x07/\\x08\\xd5C-\\x1fGR\\x10[K\\xe4\\x1e\\x04\\xf9\\x9b\\x02\\xb6\\xd6G\\xb9U\\x05\\x9fg\\x9c\\xcf\\xed\\xe5@\\x98\\x08\\x93#\\xf4\\x86\\xa1\\x02\\xdf\\xda\\xd1\\xa1\\xca\\x08ag\\xab\\xba\\x9e\\x81\\xce.J\\xb1]\\r \\xb3\\x9b\\xe0\\xfc\\x19\\x84\\x10\\xfb\\x07"\\x8c<\\x88\\x19w\\xe1[\\x83\\x85\\xf5\\xd4\\x07\\x18^\\xc8\\xf0\\x90fj\\xfbJ\\x0fD\\xff\\xb3{\\x1a \\xf8\\x9c+\\xf0\\x17\\xd6~\\x8df\\xde\\xb8\\xc3\\x16\\x1e\\xc4\\xfa\\x02\\x8e\\xf9\\xe3\\x12]T\\xdbK\\x8b\\x16Z\\x03\\xe8&\\xd3\\x98M\\xcd8o\\x17zN\\x1f\\x19\\xec\\xa1\\xfe\\xc2\\xb4\\xcf5Ap\\xe0\\xc6\\x1f\\x8a\\xfb\\xd5\\xe10\\x8d;b\\xdd\\x88\\xae<\\xd7Qn\\x8f+\\xf9A\\xe9\\x92/\\xb9K\\x10;\\x01\\x98X\\x17\\xba\\xcd=]F\\xfc\\xcd9C\\xdaj{N\\xdd\\xd0)\\xf39\\x843\\xa7\\xd64\\xc0*Y\\xab\\xaen\\xccs\\x8b\\x82\\x8f\\xd4e\\xe4\\xfc6F\\xc0\\xb4\\x1df\\xb9\\x0b\\xef\\x1c\\xb6\\x9a\\xf0\\xc8\\xd9o\\xde\\xa0\\x13h\\x8d\\x14\\x19\\x14f\\x0c\\xa5\\x0bx\\xf5\\xa2g8\\xc7\\xbam\\x1fc0u\\xb0\\x921\\xcb"\\xb7\\x8fF\\x17\\x19H\\x1a\\x8c\\x99\\x86\\xcf\\x95\\\\\\x84\\xb8\\xd0\\x9dA,&\\x1c=+\\xcf\\xcc\\xdf#\\xb8J\\xd7\\xd8\\x18l*&s^\\xed\\x9c\\xeb\\x8f\\xbfv\\xe0\\xb9;\\xc5W\\x03\\xb3\\xf8@\\xb2\\xeb7\\xb30\\xc7\\x89\\x1b\\xf0K2\\xac=\\x7f1g\\xe2a\\xec\\\'KG\\x93\\xa7([h\\x08\\x87\\xb7\\xf53O\\xa7\\x0c\\x8e8\\xf1\\xb4\\x8c\\xbc\\x87\\xeb\\xd1\\x99\\x19\\x81\\xdc\\xa2$\\xc4X\\x98\\x17\\xc0ms\\x9b\\xca\\x89\\x8b\\xe7\\x0b\\xb8\\x95\\xd0\\xff\\xca\\xc6\\xfc\\xeau\\x1a\\xf9%_s\\x84B\\x92 \\xdb\\x9d\\x87\\xd2\\xb0G%\\xf1\\xc8\\xe6\\x8f\\x83\\xbc\\x04\\x02<\\x08\\x12\\x08\\xed|\\x98\\xfe\\x8b(l\\xfb\\xc6\\xa6\\xf7\\xe4\\x8d\\xf2pm\\xa36W[\\xb6"\\xd4+\\x1a\\x7f\\x15\\xb0\\xe7@5\\xac\\xc4@56\\xf2\\xac\\xa6\\x19C>\\x0e\\x82)\\xcc3\\xa4\\xee\\xe4\\x8cK\\x19\\\'\\xda\\x9d\\xd5C\\x94\\xc2\\\\\\\'\\x0e\\x92y\\xdb\\x89\\xa1\\xb2\\xe2\\x8fX\\xa9Q\\x15\\x0f\\xc6{u\\xb4\\x93p\\x8e\\xe1h\\\'U0\\x08\\xd8\\x1aQ_\\x02\\xac\\xf7S%7 [\\xb2j?%~\\x19\\xbb\\x96\\x1a\\xbd\\xdd\\xa5\\x08\\x1c\\x03\\x9e\\xee\\x83\\xa1\\xf1\\xfd\\xba\\xeep0\\xec\\xdc\\xacNU|\\xfdUR\\x8c\\x97l\\xca(\\x1dT\\xdf?\\xf27;5\\xa824y|\\x8d\\xc4\\xb1\\x1e\\xfc\\x9a\\xda\\x08\\xd5\\xa0z\\xe7(\\xf2\\xe5i8?Z$8\\xd5-\\x99\\x133\\xb5\\x84\\xa0\\x0e\\xb0lD\\xfc\\\'\\xaa~)\\x9daR\\xd0\\xd4Sa\\xe4\\x1c$6`)\\x8bL\\xe55\\x93xz\\xdaJ/\\x1f"Ue\\x02\\x93\\xd8\\x89~\\xe7;DW\\xb8J.L\\x95\\xfaj\\xf2\\x87\\x08k\\x93MT&\\xd7\\xba.^v4\\xa4\\xe0jd\\xb7\\x9b\\\\\\xbe\\x90\\xee3\"\\x82\\x96z\\xa4\\x10\\xafU\\x9a\\xe5\\xdb\\x04\\xe6\\xde#D\\xd5YQ6bd1\\xca\\x11\\x16\\xa6\\x84\\xee\\xa4\\xfb\\xa7\\x01\\x04\\xd5\\xd2\\xb9\\x99\\xb4Wz=\\xc9\\xe7n/\\xc6\\x8f\\xe4\\x8f]\\x1a\\x80\\xf827\\xc7_\\x9d\\x98\\xea\\xbf}\\xc3\\x95/F\\xa4\\xf9YT\\x86\\xc7\\xc6\\xe0\\x13\\xc9m\\xdd6p\\x88\\xc8R-3\\x04q:\\xf4\\xab\\xee\\x9e!\\xb4q[Q\\xb8!\\x93rtx-\\x1c\\x0fZ<8M\\x12\\xbf\\x8f\\xd5\\x9b^[\\x13\\xf8\\x88^\\x94\\x0eVq\\x89Z\\x940l\\xc9%\\xdf\\xc0h\\x18\\xac\\x89\\xd3\\xac8\\n\\x0c\\xce\\x0e\\x02\\\'3n\\xdf\\xc3\\xf2\\xf9\\x184VyVhS\\x96m\\r^e\\xcd\\x00\\xf7\\xed\\x00\\x11U\\x9f\\xdc\\x16\\x7fe\\xd0\\xb9\\xba\\xf2(\\xce\\x98{U\\x85\\xa0\\xae\\x98\\xbe\\xa5mRk6 \\x8b\\xf9%\\x08\\x890%\\xe8\\n\\x08!\\x9a<^\\xfe\\x9c\\x18A-\\xc4|r\\x18\\xb7\\xce\\x9e\\xc8\\x8a\\tn\\xb6\\x84\\x1f\\x9e\\x08j\\x8c\\x91\\xdap\\xb0\\xad\\xae#\\x01+Sp\\xf8\\x99@\\xce\\r`\\xc4\\xe1Gt\\xb8\\x96\\\\\\x05\\xd0#\\xfa\\xd4j\\xb4\\xec\\x9a\\x1d\\xc9\\x00\\x92\\x840\\xf3$\\xe5\\xd7\\x94c\\xf5\\xe5\\x1cu/n\\x90f:/\\xc7g\\x0ee\\x8b\\xb5\\x037\\x9c\\x12\\x87\\xc9\\xcc\\xa3\\xd3\\xbcZ&U!lm\\x18\\x07\\xd9z3m\\xc7c<\\xc4R\\xc7\\x0cBsW\\xe0t@*\\xc1\\xc9o\\x90\\x80>k+i\\xbe.\\x8aL\\x19](\\xf7N\\x0f\\xa1\\xb8u\\xbe\\xe2u/)\\xbc\\xad?\\xfe\\xa4\\xf9\\x9f\\x03\\xa7\\x02\\x92\\xeej\\xb9\\x861\\x8c\\xd6K\\xe4E\\x86o\\xda\\x82\\x0e\\xa8|\\x15Z\\xf3\\xb2Z\\xee\\x83\\xc3\\x16\\xe2\\xd4\\x89A\\xca\\xd1y\\x88\\x12\\xea?\\xdd>B\\x1eG-p\\xbd\\xb2\\x17l\\xc65\\xccs6\\xed6\\x1c\\x13G\\x87\\xcc\\xf6o\\x18n\\x0e\\xb8\\xe3\\x08\\xe35f"CU\\xc6\\xfc\\xa93\\x010e\\xde\\xba\\xb0\\xb1s|\\xca\\x0c\\xb3\\xbe\\xbf\\xf6^\\x0648\\x8d\\xdf\\xf0\\xf1\\xc9\\xa0\\x91\\x93\\x14\\xd8\\xd7X\\xf4-\\xdb\\xb1\\xeb\\xdb\\xfc\\t;\\x00\\xad\\x11\\x94=\\xb7\\xb5I#\\xe2\\x0c?\\xb9V\\xb5\\x8e\\xd6\\x85.\\xa8\\xff\\x13\\xcb\\xb7\\xa7}\\xf6\\xd6\\xc6\\xd85\\xd9m7\\xe3bd^\\xf3\\xb9Z#\\xc9\\x9b\\xe9\\xc1\\xc8c\\xb6\\xb6\\xe6\\xd5\\x00\\xb3\\x8cS\\x93\\xd5\\x08\\x0eF\\x11n\\xf4\\xda\\xb4/\\xd6\\xc6\\x8e\\xb4,\\xc4P\\xb2\\x17peY+\\x1e\\xe73\\xee\\x07\\xa1\\xcd\\xda\\xba\\x91\\xd5$\\x87\\x18\\xc3p\\x9b\\xeb|\\xafF\\xb8\\xcc\\xb9(\\x11\\xc0\\xd6\\xb6\\xc8\\x02|<\\xe1\\x19\\x89\\x99x7\\xc2\\\'/\\xb6\\x1e\\xdd&-\\xb2\\xcb7\\x08\\xb9\\xad\\x1c\\x02\\xd2\\x9f\\xf4\\xd1vC\\xf2$(EO\\x8a~\\x8cR1\\x8b\\x1c\\x19i\\x17o\\\'\\x18\\x7f2:\\x03v\\xba\\xe5\\\\\\xcb\\xf1\\x07\\x01OJ}\\x10+\\x84\\\'\\xc1\\x9f.e>\\xd53b;\\xc5\\xa5l\\xbe\\xf5\\xa2\\xc2\\xff\\xd9va\"\\xe5\\x9e \\x8b]\\x87\\x13\\xb3\\x1e\\x80\\xac\\xba]\\xb2\\xeb\\xf3\\xe5\\xc1\\xf3\\\\\\x1a\\xb1\\rr\\xb6\\x9b\\x08\\xd0\\x9cc\\xaa\\x12PWq\\xff\\x94\\xff\\x11URO\\xdd/\\xf8\\xdd\\x08\\x19\\xbb\\x9dY\\x91\\x02 \\x12\\x80g\\xfb\\x96PfE\\x99:\\xe6oT\\xd0\\x8c?\\xbb8\\x93\\xe2\\xa1\\xae\\x19:\\xf5\\x17\\x8b\\xee\\xb5?5\\xff\\xe5\\xa1[\\x86\\xde\\x96sL\\xe1\\xe7O\\xf0U\\x97GeO\\x06\\xd6/CQU\\xcc\\x0c+y\\\\v\\\'\\x11\\xc0^\\x97W%\\x07\\x8e4\\xf5\\xbd=\\xc1\\xde[d5\\x1a\\x9e\\xb3o\\xf8\\xc5\\xe7\\xd1q\\xb7\\x02\\xc6\\xdc\\x0e\\x1a+g\\x99\\xc1,wu2\\xfb\\\'\\x9b\\xb0\\xc6\\x8f\\xcf\\xe5<\\x96\\xa6\\x14<\\xa1\\xf7\\xfa\\x00 \\r\\x9f\\xd9\\x174B\\xb7\\x95\\xb2\\x07\\x1f\\xaee\\xb5\\x8a\\x99c\\x8f\\xff\\xc2\\x7f\\xbc\\xf8\\xd5{\\xf6\\xa1\\xde\\r\\xbdS\\x84$\\x8fc#2\\xeaH\\xfdl\\xef\\x01\\xca\\xce+K\\xe5\\\\\\x93\\x1c2\\xe3\\x82-r:\\r\\x8e\\xad\\xfd\\x83J\\xacM\\xb8\\x10\\xd3\\xd8_y9\\x0f\\xce\\x7f\\xcfQ\\xed\\x1f\\x87\\\'\\xe6\\xd1\\xf4:\\x11\\xb2zp\\x07\\x07\\x80J\\xcaA\\x1esBNr\\xbc\\x1e,\\xe1\\x1e\\xb1\\xdc\\xd1\\x98\\xb3d Q\\xfa\\tM,\\xda\\xc0\\x80\\x98UE\\xcad9\\xb0\\t\\x9a\\x00\\xf0\\xe3\\x0e.r#n\\xd8\\xe4\\xb6\\x07GS]B\\x07\\xb4\\xefr\\x93E.IF\\xf1\\xec\\x19\\xce\\xa2\\xde\\x88u\\x0c]\\x01\\xc1&O\\xe9\\xb8\\xdaXr\\xbf\\xe4\\xa7!?\\xf5\\xaa8\\x8f\\x85z\\x1c\\x11\\xf1=\\xb3\\xf8\\x12\\x0e\\xb3\\x1d\\x9a\\xfe\\x12P\\x0f/b_\\xc2\\xff\\xcfW?FBu\\xcf\\xca\\x86{\\xd6k~P\\xc1\\xc9R\\xcc\\xce\\xf9Y]\\x8c\\xc6\\x81Yy/\\x9f\\xc9\\x13\\x1b\\x16\\xde\\xee\\x97\\x10\\xd4\\xbc\\x93\\xfd\\xdc\\xa1\\xba$&\\x14\\xfe\\xea,`\\x96\\xa8\\xf4\\xf0\\xe5[,|?T\\x05\\x10\\xb1\\xda\\x7f\\r\\xaf>@By\\xa2D>\\x94\\x071\\xa9{o\\x92\\x83?]\\xe2\\x0f\\xce\\xfd+\\x96Y*\\xf4\\x16\\n\\x8b\\xf4\\xe4\\x815\\x92\\xe0K s\\xb9\\x10\\xc7\\xd0%\\xc1={vk\\x9cxs\\x9f\\xc6\\xf9\\x97\\x0f\\xf2\\xf1ZgI\\xa6g\\x02\\x01k\\xff\\xa3a\\xae \\xc8s\\x9c\\xd6\\x95\\x97m7\\xc4\\x8d\\xd5;\\xba\\x85\\n\\xf4\\xb1\\xf4aG\\xfd\\xf8\\xc0C\\x15\\xc1\\xf3\\xb9%\\x9at\\xaf[DE\\xcf\\xd8H\\xa1M\\xcc*\\x1d\\xfd\\x7fD\\x1e\\x8d<6\\x82\\x81\\x9e\\xe0C\\xed\\xf7\\x8bep\\xab\\xdb\\xa0\\x198\\xba\\xc5)\\xa7\\x8d9\\x82\\x98H\\x94\\x98\\xa8\\xa5\\xe5\\\\O\\x05x\\xdeF\\x021+\\t\\xa1>\\xa8\\xe5\\xd0\\xfa\\x80\\xa9\\xd85\\x17\\x1b\\xc6\\xd7\\xedA\\xf2\\xa5\\x1e\\xac)\\x84\\xe7\\x18\\x00\\xfe\\xe7<aaz\\xd6\\xd4u\\x8di\\xe1\\x90\\xa4|\\xdb'
        missatgeRebutDesodificat = desencriptarFoto(missatgeRebutCodificat)

        image_64_decode = base64.decodebytes(missatgeRebutDesodificat)
        image_result = open('res.png', 'wb')  # create a writable image and write the decoding result
        image_result.write(image_64_decode)