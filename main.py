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

    print("Vull enviar: " + missatgeSecret + " que ocupa: " + str(len(missatgeSecret)) + " bytes.")

    bytesPerDatagrama = 5

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
        if (finestra == 0):
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

        missatgeCodificat = encriptar(image_64_encode)
        enviarMissatgeControlFinestra(missatgeCodificat)

    elif function == 6:
        print("Rebre foto")

        missatgeRebutCodificat = rebreMissatgeControlFinestra()
        missatgeRebutDesodificat = desencriptar(missatgeRebutCodificat)

        image_64_decode = base64.decodebytes(missatgeRebutDesodificat)
        image_result = open('res.png', 'wb')  # create a writable image and write the decoding result
        image_result.write(image_64_decode)