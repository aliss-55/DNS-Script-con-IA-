import shodan
import dns.message
import dns.query
import dns.flags
import getpass
import socket

# --- FUNCIONES DE ESCANEO AVANZADO ---

def verificar_recursividad(ip):
    try:
        query = dns.message.make_query('www.google.com', dns.rdatatype.A)
        query.flags |= dns.flags.RD
        response = dns.query.udp(query, ip, timeout=2)
        return bool(response.flags & dns.flags.RA)
    except Exception:
        return False

def verificar_amplificacion(ip):
    try:
        query = dns.message.make_query('google.com', dns.rdatatype.ANY)
        response = dns.query.udp(query, ip, timeout=2)
        size = len(response.to_wire())
        return size > 512
    except Exception:
        return False

def escanear_ip(ip):
    print(f"\n[+] Escaneando IP: {ip}")
    recursivo = verificar_recursividad(ip)
    amplifica = verificar_amplificacion(ip)
    print(" - Recursividad DNS:", "✅" if recursivo else "❌")
    print(" - Vulnerabilidad a amplificación:", "⚠️ Sí" if amplifica else "✅ No")

# --- BÚSQUEDA SHODAN BÁSICA ---

def buscar_dns_publicos(api, query="port:53"):
    print("\n[🔍] Buscando servidores DNS públicos en Shodan...")
    try:
        resultados = api.search(query, limit=10)  # puedes cambiar el límite
        ips = [match['ip_str'] for match in resultados['matches']]
        print(f"Encontradas {len(ips)} IPs con puerto 53 abierto:")
        for i, ip in enumerate(ips, 1):
            print(f" {i}. {ip}")
        return ips
    except Exception as e:
        print("❌ Error buscando en Shodan:", e)
        return []

# --- FLUJO PRINCIPAL ---

def main():
    print("=== Auditoría DNS Básica y Avanzada con Shodan ===")
    api_key = getpass.getpass("🔐 Ingresa tu API Key de Shodan: ")
    api = shodan.Shodan(api_key)

    ips_shodan = buscar_dns_publicos(api)

    # Selección y escaneo
    if ips_shodan:
        opcion = input("\n¿Deseas escanear las IPs encontradas? (s/n): ").lower()
        if opcion == "s":
            for ip in ips_shodan:
                escanear_ip(ip)
        else:
            custom = input("Ingresa otras IPs separadas por coma para escanear: ").split(",")
            for ip in map(str.strip, custom):
                if ip:
                    escanear_ip(ip)
    else:
        print("No se encontraron IPs desde Shodan. Puedes ingresar manualmente.")
        custom = input("Ingresa IPs separadas por coma: ").split(",")
        for ip in map(str.strip, custom):
            if ip:
                escanear_ip(ip)

if __name__ == "__main__":
    main()
