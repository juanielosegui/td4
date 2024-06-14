from scapy.all import DNS, DNSQR
import socket
import time
import random

# Entrada de usuario para el dominio y el servidor raíz
domain: str = input("Ingresa el dominio: ")
root_server: str = input("Ingrese root server (198.41.0.4, 199.9.14.201, 192.33.4.12, 199.7.91.13, 192.203.230.10, 192.5.5.241, 192.112.36.4, 198.97.190.53, 192.36.148.17, 192.58.128.30, 193.0.14.129, 199.7.83.42, 202.12.27.33): ")

# Función para construir una consulta DNS
def build_dns_query(domain, query_type='A') -> bytes:
    dns_query = DNS(rd=0, qd=DNSQR(qname=domain, qtype=query_type))
    return bytes(dns_query)

# Función para enviar una consulta DNS y recibir la respuesta
def send_dns_query(domain, server, query_type='A'):
    query = build_dns_query(domain, query_type)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(2)
    try:
        sock.sendto(query, (server, 53))
        response, _ = sock.recvfrom(512)
    except socket.timeout:
        return None
    finally:
        sock.close()
    return response

def resolve(domain, server, visited_servers=set(), resolved_cnames=set()) -> list:
    resolved_ips: set = set()
    visited_servers.add(server)

    response = send_dns_query(domain, server)
    if response:
        dns_response = DNS(response)
        if dns_response.rcode == 0:
            if dns_response.an:
                for i in range(dns_response.ancount):
                    dns_record = dns_response.an[i]
                    if dns_record.type == 1:
                        resolved_ips.add(dns_record.rdata)
                    elif dns_record.type == 5:
                        cname_target = dns_record.rdata.decode()
                        print(f"Resolviendo CNAME {domain} a {cname_target}")
                        if cname_target not in resolved_cnames:
                            resolved_cnames.add(cname_target)
                            cname_ips: list = resolve(cname_target, root_server, visited_servers, resolved_cnames)
                            resolved_ips.update(cname_ips)
            else:
                authority_domains: list = []
                if dns_response.ns:
                    for i in range(dns_response.nscount):
                        dns_record = dns_response.ns[i]
                        if dns_record.type == 2:
                            authority_domains.append(dns_record.rdata.decode())

                additional_ips: dict = {}
                if dns_response.ar:
                    for i in range(dns_response.arcount):
                        dns_record = dns_response.ar[i]
                        if dns_record.type == 1:
                            additional_ips[dns_record.rrname.decode()] = dns_record.rdata

                for auth_domain in authority_domains:
                    if auth_domain in additional_ips:
                        auth_ip = additional_ips[auth_domain]
                        if auth_ip not in visited_servers:
                            authority_ips = resolve(domain, auth_ip, visited_servers, resolved_cnames)
                            resolved_ips.update(authority_ips)
                            break

                if not resolved_ips:
                    for auth_domain in authority_domains:
                        authority_ips: list = resolve(auth_domain, root_server, visited_servers, resolved_cnames)
                        for auth_ip in authority_ips:
                            if auth_ip not in visited_servers:
                                additional_ips = resolve(domain, auth_ip, visited_servers, resolved_cnames)
                                resolved_ips.update(additional_ips)
                                break
    else:
        print(f"Sin respuesta desde {server}")

    return list(resolved_ips)

if __name__ == "__main__":
    if not root_server:
        root_servers_list = [
            "198.41.0.4", "199.9.14.201", "192.33.4.12", "199.7.91.13", "192.203.230.10", "192.5.5.241", 
            "192.112.36.4", "198.97.190.53", "192.36.148.17", "192.58.128.30", "193.0.14.129", "199.7.83.42", 
            "202.12.27.33"
        ]
        root_server = random.choice(root_servers_list)
        print(f"No se ingresó ningún servidor raíz. Usando servidor raíz aleatorio: {root_server}")

    start_time = time.time()
    resolved_ips = resolve(domain, root_server)
    end_time = time.time()

    if resolved_ips:
        print(f"Dirección(es) IP resuelta(s) para {domain}: {resolved_ips}")
    else:
        print("No se pudo resolver el dominio.")

    print(f"Tiempo total de resolución: {end_time - start_time} segundos")
