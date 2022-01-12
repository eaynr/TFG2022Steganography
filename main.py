# This is a sample Python script.
from scapy.all import *
from Cryptodome.Cipher import Salsa20

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

        # Press the green button in the gutter to run the script.

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


        #aux3 = aux1[0:4]
        #for i in range(3):
        #    print(aux1[i*4:i*4+2])
        #    print(aux1[i*4+2:i*4+4])


    elif function == 4:

        ipDest = "192.168.1.200"
        prova3(build_icmp(ipDest))
        #arping2tex("192.168.1.0/24")
        print("A reveure")
        exit()

    #arping2tex("192.168.1.0/24")

    #ipDest = "192.168.1.42"

    #paquet = build_icmp(ipDest)
    #prova3(paquet)

    #ip = IP(dst="www.google.es")
    #ip.show()

