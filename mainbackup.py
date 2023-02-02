from scapy.all import *
from Cryptodome.Cipher import Salsa20
import socket

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
    ipDest="192.168.1.42"

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
    suma = 4
    start = 2

    if iteracio > 63: #2^6 màxim nombre d'elements de SEQ
        iteracio = iteracio % 8
        base = base + suma * iteracio

    else:
        if iteracio == 0:
            base = base + start
        else:
            base = base + suma * iteracio

    return base

def capcaleraOkey(cap, capPrev): #Comprovem si la SEQ rebuda es la SEQ esperada
    okey = True

    cap = format(cap, 'b')
    if len(cap) < 8:
        cap = "0" * (8 - len(cap)) + cap
    capPrev = format(capPrev, 'b')
    if len(capPrev) < 8:
        capPrev = "0" * (8 - len(capPrev)) + capPrev

    if not (cap[-8:-2] == capPrev[-8:-2]):
        okey = False

    return okey

def sumarSEQACK(aux): #no es fa servir
    suma = 0b00100000
    return aux + suma

def sumarEXP(aux):
    base = 224
    sumaexp = 4

    limit = format(aux, 'b')
    if limit[-5:-2] == "111":
        resultat = base
    else:
        resultat = aux + sumaexp

    return resultat

def establirFi(aux):
    end = 1
    return aux + end

def extreureControl(info): #no es fa servir
    info = format(info, 'b')
    ctr = [info[-8:-5], info[-5:-2], info[-2], info[-1]]
    return ctr

def extreuInformacioA(nombre):

    base = 0b000

    if nombre > 8191:
        mascara = 57344 #0b1110000000000000
        resposta = bin(nombre & mascara)
        resposta = resposta[:-13]
    else:
        resposta = base

    return resposta

def extreuInformacioB(nombre):

    base = 0b0000000000000
    mascara = 8191 #0b0001111111111111

    resposta = nombre & mascara

    return bin(resposta)

def unificaInformacio(numA, numB):

    unificacio = int(numA, 2) << 13
    unificacio = unificacio | int(numB, 2)

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
        okey = False
        font = "192.168.1.42" ############################
        desti = "192.168.1.45"

        if paquet[IP].src == font and paquet[IP].dst == desti:  # POSAR DST ADEQUAT
            part1 = paquet[ICMP].id.to_bytes(length=2, byteorder='big')

            capcalera = part1[0]

            if capcaleraOkey(capcalera, capcaleraPrev):
                okey = True
                capcaleraPrev = capcalera

        return okey

    ipDest = "192.168.1.42" #################
    capcaleraPrev = 2

    bytesPerDatagrama = 5
    n = len(missatgeSecret) % bytesPerDatagrama

    finestra = 4

    resposta = False

    if n == 0: #fa falta ?
        n_iteracions = len(missatgeSecret) / bytesPerDatagrama  # +4 per afegir el nonce
    else:
        n_iteracions = ((bytesPerDatagrama-n)+len(missatgeSecret)) / bytesPerDatagrama   # +4 per afegir el nonce

    for i in range(int(n_iteracions)):

        if resposta:
            resposta = False

        part1 = treballenbits(i)

        if i == n_iteracions-1: #ultima iteració
            part1 = establirFi(part1)

        part1 = int.from_bytes((part1.to_bytes(length=1, byteorder='big') + missatgeSecret[i*bytesPerDatagrama:i*bytesPerDatagrama+1]), byteorder='big')
        part2 = int.from_bytes(missatgeSecret[i*bytesPerDatagrama+1:i*bytesPerDatagrama+3], byteorder='big')
        part34 = int.from_bytes(missatgeSecret[i*bytesPerDatagrama+3:i*bytesPerDatagrama+5], byteorder='big')
        part3 = extreuInformacioA(part34)
        part4 = extreuInformacioB(part34)
        # IP(flags=0bXXX, frag=0bXXXXXXXXXXXXX)

        paquet = IP(dst=ipDest, flags=part3, frag=part4) / ICMP(id=part1, seq=part2)
        send(paquet)

        while not resposta:
            print("Esperant resposta")
            resposta = sniff(filter="icmp[0]=0", count=1, prn=analitzar)

def enviarMissatgeControl(missatgeSecret):

    def analitzar(paquet):
        nonlocal capcaleraPrev
        okey = False
        font = "192.168.1.42"
        desti = "192.168.1.45"

        if paquet[IP].src == font and paquet[IP].dst == desti:  # POSAR DST ADEQUAT
            part1 = paquet[ICMP].id.to_bytes(length=2, byteorder='big')

            capcalera = part1[0]

            if capcaleraOkey(capcaleraPrev, capcalera):
                okey = True
                capcaleraPrev = capcalera

        return okey

    ipDest = "192.168.1.42" #################
    capcaleraPrev = 2
    n = len(missatgeSecret) % 3

    resposta = False

    if n == 0:
        n_iteracions = len(missatgeSecret) / 3  # +4 per afegir el nonce
    else:
        n_iteracions = ((3-n)+len(missatgeSecret)) / 3   # +4 per afegir el nonce

    for i in range(int(n_iteracions)):

        if resposta:
            resposta = False

        part1 = treballenbits(i)

        if i == n_iteracions-1: #ultima iteració
            part1 = establirFi(part1)

        part1 = part1.to_bytes(length=1, byteorder='big') + missatgeSecret[i*3:i*3+1]
        part2 = missatgeSecret[i*3+1:i*3+3]
        paquet = IP(dst=ipDest) / ICMP(id=(int.from_bytes(part1, byteorder='big')),
                                       seq=int.from_bytes(part2, byteorder='big'))
        send(paquet)

        while not resposta:
            print("Esperant resposta")
            resposta = sniff(filter="icmp[0]=0", count=1, prn=analitzar)

def enviarMissatge(missatgeSecret): #no actualitzat

    ipDest = "192.168.1.42"

    n = len(missatgeSecret) % 4
    if n == 0:
        n_iteracions = len(missatgeSecret) / 4  # +4 per afegir el nonce
    else:
        n_iteracions = ((4-n)+len(missatgeSecret)) / 4   # +4 per afegir el nonce

    for i in range(int(n_iteracions)):
        part1 = missatgeSecret[i*4:i*4+2]
        part2 = missatgeSecret[i*4+2:i*4+4]
        paquet = IP(dst=ipDest) / ICMP(id=(int.from_bytes(part1, byteorder='big')),
                                       seq=int.from_bytes(part2, byteorder='big'))
        #print("")
        #print("Paquet ICMP a enviar")
        #print("")
        #ls(paquet[ICMP])
        send(paquet)
        #print("Dos bytes del missatge: " + str(part1) + "en un enter: " + str(int.from_bytes(part1, byteorder='big')))
        #print("Dos bytes del missatge: " + str(part2) + "en un enter: " + str(int.from_bytes(part2, byteorder='big')))

        #aux2 = int.from_bytes(aux1[0:2], byteorder='big')
        #aux3 = aux2.to_bytes(length=2, byteorder='big')

def rebreMissatgeControlFinestra():

    def analitzar(paquet):
        nonlocal missatgeSecret
        nonlocal final
        nonlocal capcaleraPrev
        font = "192.168.1.45"
        desti = "192.168.1.42"

        if paquet[IP].src == font and paquet[IP].dst == desti: #POSAR DST ADEQUAT
            #print("Rebem 3 bytes")
            part1 = paquet[ICMP].id.to_bytes(length=2, byteorder='big')
            part2 = paquet[ICMP].seq.to_bytes(length=2, byteorder='big')
            capcalera = part1[0]
            part3 = int(paquet[IP].flags)
            part4 = paquet[IP].frag
            part34 = (unificaInformacio(part3, part4)).to_bytes(length=2, byteorder='big')

            if capcaleraOkey(capcalera, capcaleraPrev):
                missatgeSecret += part1[1].to_bytes(length=1, byteorder='big') + part2 + part34
                capcalera = sumarEXP(capcalera)
                capcaleraPrev = capcalera

            else:
                capcalera = capcaleraPrev

            resposta = capcalera.to_bytes(length=1, byteorder='big') + part1[1].to_bytes(length=1, byteorder='big')

            paquetResposta = IP(dst=font) / ICMP(type=0, id=(int.from_bytes(resposta, byteorder='big')),
                                                 seq=paquet[ICMP].seq)
            send(paquetResposta)

            if capcalera % 2 == 1:
                final = True
                print("Rebem el final")

    missatgeSecret = b""
    final = False
    capcaleraPrev = 0

    while not final:
        sniff(filter="icmp[0]=8", count=1, prn=analitzar)

    print("El missatge rebut codificat es: " + str(missatgeSecret))
    return missatgeSecret

def rebreMissatgeControl():

    def analitzar(paquet):
        nonlocal missatgeSecret
        nonlocal final
        nonlocal capcaleraPrev
        font = "192.168.1.45"
        desti = "192.168.1.42"

        if paquet[IP].src == font and paquet[IP].dst == desti: #POSAR DST ADEQUAT
            #print("Rebem 3 bytes")
            part1 = paquet[ICMP].id.to_bytes(length=2, byteorder='big')
            part2 = paquet[ICMP].seq.to_bytes(length=2, byteorder='big')
            capcalera = part1[0]

            if capcaleraOkey(capcalera, capcaleraPrev):
                missatgeSecret += part1[1].to_bytes(length=1, byteorder='big') + part2
                capcalera = sumarEXP(capcalera)
                capcaleraPrev = capcalera

            else:
                capcalera = capcaleraPrev

            resposta = capcalera.to_bytes(length=1, byteorder='big') + part1[1].to_bytes(length=1, byteorder='big')
            paquetResposta = IP(dst=font) / ICMP(type=0, id=(int.from_bytes(resposta, byteorder='big')), seq=paquet[ICMP].seq)
            send(paquetResposta)

            if capcalera % 2 == 1:
                final = True
                print("Rebem el final")

    missatgeSecret = b""
    final = False
    capcaleraPrev = 0
    while not final:
        sniff(filter="icmp[0]=8", count=1, prn=analitzar)

    print("El missatge rebut codificat es: " + str(missatgeSecret))
    return missatgeSecret

def rebreMissatge(): #no actualitzat

    def analitzar(paquet):
        nonlocal missatgeSecret

        if paquet[IP].src == "192.168.1.42" and paquet[IP].dst == "192.168.1.45":
            part1 = paquet[ICMP].id.to_bytes(length=2, byteorder='big')
            part2 = paquet[ICMP].seq.to_bytes(length=2, byteorder='big')
            missatgeSecret += part1 + part2
            #missatgeSecret = missatgeSecret, paquet[ICMP].id, paquet[ICMP].seq

    missatgeSecret = b""
    sniff(filter="icmp[0]=8", count=4, prn=analitzar)

    print("El missatge rebut codificat es: " + str(missatgeSecret))
    return missatgeSecret

def rebreMissatgeOffline():

    def analitzar(paquet):
        nonlocal missatgeSecret

        if paquet[Ether].type == 2048: #type = ETHERNET
            if paquet[IP].src == "192.168.1.45" and paquet[IP].dst == "192.168.1.42" and paquet[IP].proto == 1:
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

    function = menu()
    if function == 1:
        print("Enviar dades")

        msgSecret = input('Quin missatge vols enviar ? ')
        missatgeCodificat = encriptar(msgSecret)
        #enviarMissatgeControl(missatgeCodificat)
        enviarMissatge(missatgeCodificat)

    elif function == 2:
        print("Rebre dades")

        missatgeRebutCodificat = rebreMissatgeControl()
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

        num = 45601
        print(num)
        parta = extreuInformacioA(num)
        print(parta)
        print(int(parta, 2))
        partb = extreuInformacioB(num)
        print(partb)
        partab = unificaInformacio(parta, partb)
        print(partab)
        print(bin(partab))

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

        print("A reveure")
        exit()
