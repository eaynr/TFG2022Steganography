# This is a sample Python script.
from scapy.all import *
from Cryptodome.Cipher import Salsa20
import socket

# Press Mayús+F10 to execute it or replace it with your code.
# Press Double Shift to search everywhere for classes, files, tool windows, actions, and settings.

def prova2():
    send(IP(dst="1.2.3.4") / ICMP())
    sendp(Ether() / IP(dst="1.2.3.4", ttl=(1, 4)), iface="eth1")

def prova3(pkt):
    ans, unans = sr(pkt)
    ans.nsummary()
    unans.nsummary()

    p = sr1(pkt / "XXXXXX")
    p.show()

def prova4(ipdesti):
    p = sr1(IP(dst=ipdesti) / ICMP())
    if p:
        p.show()

def arp_monitor_callback(pkt):
    if ARP in pkt and pkt[ARP].op in (1, 2):  # who-has or is-at
        return pkt.sprintf("%ARP.hwsrc% %ARP.psrc%")
    # sniff(prn=arp_monitor_callback, filter="arp", store=0)

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

def generator(self, n, filename):

    time = 0.00114108 * n + 0.157758
    minutes = time / 60

    print('Generating packets, it will take %s seconds, moreless (%s, minutes)' % (time, minutes))

    pkgs = [IP(dst='10.0.0.1') / ICMP() for i in range(n)]
    wrpcap(filename, pkgs)

    print('%s packets generated.' % (n))

def build_icmp(ip):
    paquet = IP(dst=ip) / ICMP(type=8, code=0)
    return paquet

def propiaip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))
    ip = s.getsockname()[0]
    s.close()
    return ip

def treballenbits(iteracio):

    #           ESTRUCTURA MISSATGE ICMP
    #  0           8            16                        32
    #  |    Type   |    Code	|        Checksum         |
    #  |       Identifier	    |     Sequence Number     |

    #           ESTRUCTURA MISSATGE SECRET DESSITJAT
    #  0           8            16                        32
    #  |    Type   |    Code	|        Checksum         |
    #  | 1byte ctr | 1byte info | 1byte info | 1byte info |
    #
    #  Enviament    0           3            6       7     8
    #  byte ctr --> | 3bits SEQ | 3bits #ACK | Start | End |
    #  Recepcio     0           3            6       7     8
    #  byte ctr --> | 3bits ACK | 3bits #SEQ | Start | End |

    # mascaras:     -sumar 1 SEQ/ACK    --> ADD 00100000 - sumar 32
    #               -sumar 1 #ACK/#SEQ  --> ADD 00000100 - sumar 4
    #               -start a 1          --> ADD 00000010 - sumar 2
    #               -end a 1            --> ADD 00000001 - sumar 1
    base = 0b0
    suma = 32
    sumaexp = 4
    start = 2

    if iteracio == 0:
        base = base + start
    else:
        base = base + suma * iteracio
        base = base + sumaexp * iteracio

    return base

def capçaleraOkey(cap, capPrev): #Comprovem si la SEQ rebuda es la SEQ esperada
    okey = True

    cap = format(cap, 'b')
    capPrev = format(capPrev, 'b')

    if not(cap[-8:-5] == capPrev[-5:-2]):
        okey = False

    return okey

def sumarSEQACK(aux):
    suma = 0b00100000
    return aux + suma

def sumarEXP(aux):
    sumaexp = 4
    return aux + sumaexp

def establirFi(aux):
    end = 1
    return aux + end

def extreureControl(info):
    info = format(info, 'b')
    ctr = [info[-8:-5], info[-5:-2], info[-2], info[-1]]
    return ctr

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

    print("-----------------ENCRIPTACIO-----------------------")
    missatgeSecretBytes = bytes(missatgeSecret, 'utf-8')
    contrasenya = b'123uabtfg2021123'
    #print("La contrasenya ocupa: " + str(len(contrasenya)))
    #

    xifrador = Salsa20.new(key=contrasenya)
    missatgeEnviar = xifrador.nonce + xifrador.encrypt(missatgeSecretBytes)
    #print("El missatge secret codificat ocupa: " + str(len(missatgeEnviar[8:])) + " bytes.")
    print("Contingut a enviar: " + str(missatgeEnviar) + " i ocupa: " + str(len(missatgeEnviar)) + " bytes.")

    return missatgeEnviar

def desencriptar(missatgeRebut):

    print("----------------DESENCRIPTACIO----------------------")
    contrasenya = b'123uabtfg2021123'
    soroll = missatgeRebut[:8]
    missatgeXifrat = missatgeRebut[8:]
    desxifrador = Salsa20.new(key=contrasenya, nonce=soroll)
    missatgeDesxifrat = desxifrador.decrypt(missatgeXifrat)
    missatgeDesxifratText = str(missatgeDesxifrat, 'utf-8')

    #print("He rebut: " + missatgeDesxifratText + " que ocupa: " + str(len(missatgeDesxifratText)) + " bytes.")

    return missatgeDesxifratText

def enviarMissatgeControl(missatgeSecret):

    def analitzar(paquet):
        nonlocal capcaleraPrev
        okey = False
        font = "192.168.1.42" ############################
        desti = "192.168.1.45"

        if paquet[IP].src == font and paquet[IP].dst == desti:  # POSAR DST ADEQUAT
            part1 = paquet[ICMP].id.to_bytes(length=2, byteorder='big')

            capcalera = int.from_bytes(part1[0], byteorder='big')

            if capçaleraOkey(capcaleraPrev, capcalera):
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
            resposta = sniff(filter="icmp[0]=0", count=1, prn=analitzar)

def enviarMissatge(missatgeSecret):

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

def rebreMissatgeControl():

    def analitzar(paquet):
        nonlocal missatgeSecret
        nonlocal final
        nonlocal capcaleraPrev
        font = "192.168.1.45"
        desti = "192.168.1.42"

        if paquet[IP].src == font and paquet[IP].dst == desti: #POSAR DST ADEQUAT
            part1 = paquet[ICMP].id.to_bytes(length=2, byteorder='big')
            part2 = paquet[ICMP].seq.to_bytes(length=2, byteorder='big')


            capcalera = int.from_bytes(part1[0], byteorder='big')

            if capcalera % 2 == 1:
                final = True

            if capçaleraOkey(capcalera, capcaleraPrev):
                missatgeSecret += part1[1] + part2
                capcalera = sumarEXP(capcalera)
                capcaleraPrev = capcalera
            else:
                capcalera = capcaleraPrev

            resposta = capcalera.to_bytes(length=1, byteorder='big') + part1[1]

            paquetResposta = IP(dst=font) / ICMP(type=0, id=(int.from_bytes(resposta, byteorder='big')),
                                                 seq=paquet[ICMP].seq)

            send(paquetResposta)

    missatgeSecret = b""
    final = False
    capcaleraPrev = 4
    while not final:
        sniff(filter="icmp[0]=8", count=1, prn=analitzar)


    print("El missatge rebut codificat es: " + str(missatgeSecret))
    return missatgeSecret

def rebreMissatge():

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


    function = menu()
    if function == 1:
        print("Enviar dades")

        msgSecret = input('Quin missatge vols enviar ? ')
        missatgeCodificat = encriptar(msgSecret)
        enviarMissatge(missatgeCodificat)

    elif function == 2:
        print("Rebre dades")

        missatgeRebutCodificat = rebreMissatge()
        missatgeRebutDesodificat = desencriptar(missatgeRebutCodificat)
        print("El missatge rebut descodificat es: " + missatgeRebutDesodificat + " i ocupa " + str(len(missatgeRebutDesodificat)) + " bytes")

    elif function == 3:
        print("Canviar clau privada")

    elif function == 4:

        #ipDest = "192.168.1.200"
        #prova3(build_icmp(ipDest))
        #arping2tex("192.168.1.0/24")
        #paquetResposta = IP(dst=ipDest) / ICMP(type=0)
        #send(paquetResposta)
        #ls(paquetResposta[ICMP])
        n_iteracions = 3
        for i in range(n_iteracions):
            print (i)

            if i == n_iteracions-1: #ultima iteració
                print("Okey")

        #informacio = extreureControl(0b01000101+64)
        #print(0b01000101+1)
        #print(informacio[0])
        #print(informacio[1])
        #print(informacio[2])
        #print(informacio[3])

        #informacio = treballenbits(1)

        print(capçaleraOkey(38, 4))

        #print(informacio)
        #print(int.from_bytes(informacio, byteorder='big'))
        print("A reveure")
        exit()

    #arping2tex("192.168.1.0/24")

    #ipDest = "192.168.1.42"

    #paquet = build_icmp(ipDest)
    #prova3(paquet)

    #ip = IP(dst="www.google.es")
    #ip.show()

