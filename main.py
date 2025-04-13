import shodan
import dns.message
import dns.query
import dns.flags
import dns.exception

def get_api_key():
    return input("🔑 Ingresa tu API Key de Shodan: ").strip()

def search_dns_servers(api_key, query="port:53 country:CO"):
    api = shodan.Shodan(api_key)
    try:
        print(f"\n🔎 Buscando servidores DNS con: '{query}' ...\n")
        results = api.search(query)
        servers = [match['ip_str'] for match in results['matches']]
        print(f"🌐 Se encontraron {len(servers)} servidores.\n")
        return servers
    except shodan.APIError as e:
        print(f"❌ Error en la API de Shodan: {e}")
        return []

def check_recursion(ip):
    try:
        query = dns.message.make_query('google.com', dns.rdatatype.A)
        response = dns.query.udp(query, ip, timeout=3)
        if response.flags & dns.flags.RA:
            return True
    except dns.exception.DNSException:
        pass
    return False

def check_amplification(ip):
    try:
        query = dns.message.make_query('google.com', dns.rdatatype.ANY)
        response = dns.query.udp(query, ip, timeout=3)
        if len(response.to_wire()) > 512:
            return True
    except dns.exception.DNSException:
        pass
    return False

def main():
    api_key = get_api_key()
    servers = search_dns_servers(api_key)

    for ip in servers:
        print(f"📡 Analizando servidor: {ip}")
        is_recursive = check_recursion(ip)
        is_amplifiable = check_amplification(ip)

        print(f"    🔁 Recursividad: {'✅' if is_recursive else '❌'}")
        print(f"    📈 Amplificación: {'⚠️' if is_amplifiable else '❌'}")
        print("-" * 40)

if __name__ == "__main__":
    main()
