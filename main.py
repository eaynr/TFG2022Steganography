# This is a sample Python script.
from scapy.all import *
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from Cryptodome.Cipher import Salsa20

# Press Mayús+F10 to execute it or replace it with your code.
# Press Double Shift to search everywhere for classes, files, tool windows, actions, and settings.


def print_hi(name):
    # Use a breakpoint in the code line below to debug your script.
    print(f'Hi, {name}')  # Press Ctrl+F8 to toggle the breakpoint.


def prova0():
    ip_layer = IP(dst="192.168.1.46")
    icmp_layer = ICMP(seq=9999)
    packet = ip_layer / icmp_layer
    send(packet)


def prova1():
    a = sniff(count=10)
    a.nsummary()


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
    pkt = IP(dst=ip) / ICMP() / "Missatge molt molt molt molt secret"

    return pkt

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

if __name__ == '__main__':

    function = menu()
    if function == 1:
        print("Enviar dades")
        #arping2tex("192.168.1.0/24")
        ipDest = "192.168.1.200"
        paquet = build_icmp(ipDest)
        ls(paquet)
        #prova3(paquet)

    elif function == 2:
        print("Rebre dades")

        missatgeSecret = input('Quin missatge vols enviar ? ')
        print("Vull enviar: " + missatgeSecret + " que ocupa: " + str(len(missatgeSecret)) + " bytes.")
        n = len(missatgeSecret)%8
        if n == 0:
            n_segments = len(missatgeSecret)/8 + 1 #+1 per afegir el nonce
        else:
            n_segments = len(missatgeSecret) / 8 + 1 +1 #+1 per afegir el nonce

        print("-----------------ENCRIPT-----------------------")
        plaintext = bytes(missatgeSecret, 'utf-8')
        secret = b'123uabtfg2021123'
        print("La contrasenya ocupa: " + str(len(secret)))

        cipher = Salsa20.new(key=secret)
        msg = cipher.nonce + cipher.encrypt(plaintext)

        print("El missatge secret codificat ocupa: " + str(len(msg[8:])) + " bytes.")
        print("Contingut a enviar: " + str(msg) + " i ocupa: " + str(len(msg)) + " bytes.")

        print("-----------------DECRIPT------------------------")
        msg_nonce = msg[:8]
        ciphertext = msg[8:]
        cipher2 = Salsa20.new(key=secret, nonce=msg_nonce)
        plaintext2 = cipher2.decrypt(ciphertext)
        secretD = str(plaintext2, 'utf-8')

        print("He rebut: " + secretD + " que ocupa: " + str(len(secretD)) + " bytes.")

    elif function == 3:
        print("Canviar clau privada")

    elif function == 4:
        arping2tex("192.168.1.0/24")
        print("A reveure")
        exit()

    #arping2tex("192.168.1.0/24")

    #ipDest = "192.168.1.42"

    #paquet = build_icmp(ipDest)
    #prova3(paquet)

    #ip = IP(dst="www.google.es")
    #ip.show()
