# Archivo armado para incluir las funciones auxiliares
# que vamos a usar en main.py

import scapy, socket, sys

# verificar que el input del usuario sea valido
def chequear_dominio_valido(nombre_dominio):
    i:int = 0
    contador_www:int = 0
    contador_puntos:int = 0
    tld_valido:bool = False

    # armamos las condiciones
    while i < len(nombre_dominio):
        if nombre_dominio[i] == 'w':
            # deberia ser igual a tres
            contador_www += 1

        if nombre_dominio[i] == '.':
            # deberia ser igual a dos
            contador_puntos += 1
            guardo_ultimo_punto:int = i

        i += 1

    # si la pagina termina .com, .edu, .net etc...
    if nombre_dominio[guardo_ultimo_punto+1:] in ('edu', 'net', 'org', 'com'):
        tld_valido = True
    else:
        tld_valido = False

    # chequeo que todo se cumpla
    if contador_www == 3 and contador_puntos == 2 and tld_valido:
        return True
    else:
        return False
    
a = IP(ttl=10)