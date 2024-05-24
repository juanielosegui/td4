# Archivo armado para incluir las funciones auxiliares
# que vamos a usar en main.py

import random
import sys
import socket
from scapy.layers.inet import IP
from scapy.layers.inet import TCP, UDP
from scapy.layers.dns import DNS, DNSQR
import scapy.all as scapy

# verificar que el input del usuario sea valido
def chequearDominioValido(nombreDominio):
    i:int = 0
    contador_www:int = 0
    contador_puntos:int = 0
    tld_valido:bool = False

    # armamos las condiciones
    while i < len(nombreDominio):
        if '.' not in nombreDominio:
            tld_valido = False
            return tld_valido
        if nombreDominio[i] == 'w':
            # deberia ser igual a tres
            contador_www += 1

        if nombreDominio[i] == '.':
            # deberia ser igual a dos
            contador_puntos += 1
            guardo_ultimo_punto:int = i

        i += 1

    # si la pagina termina .com, .edu, .net etc...
    if nombreDominio[guardo_ultimo_punto+1:] in ('edu', 'net', 'org', 'com'):
        tld_valido = True
    else:
        tld_valido = False

    # chequeo que todo se cumpla
    if contador_www == 3 and contador_puntos == 2 and tld_valido:
        return True
    else:
        return False
    
def dnsSolver(nombreDominio, rootServers):
    rand:int = random.randint(0,len(rootServers)-1)
    IPs:list = []
    i = 0
    while i < len(rootServers):
        request = IP(dst = rootServers[i]) / UDP(dport = 53) / DNS(rd = 1, qd = DNSQR(qname = nombreDominio, qtype='A'))
        response = scapy.sr1(request, verbose = 0)

        if response and DNS in response and response[DNS].an:
            IPs.append(response[DNS].an.rdata)
            print("IPs encontradas:", IPs)
        i =+ 1

    return IPs
    