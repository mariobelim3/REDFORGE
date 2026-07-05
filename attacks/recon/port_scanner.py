#!/usr/bin/env python3
"""
REDFORGE — Phase 1: Port Scanner
Technique: T1046 — Network Service Discovery
Author: mariobelim3
"""

import socket                                      # biblioteca para ligações de rede
import json                                        # para guardar o output em formato JSON
import sys                                         # para ler argumentos da linha de comandos
from datetime import datetime                      # para registar timestamps
from concurrent.futures import ThreadPoolExecutor, as_completed  # para correr múltiplos scans em paralelo

# ── Configuração ──────────────────────────────────────────────────────────────

# Lista de portos mais comuns a escanear (FTP, SSH, HTTP, MySQL, RDP, etc.)
DEFAULT_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139,
    143, 443, 445, 993, 995, 1723, 3306, 3389,
    5900, 6200, 8080, 8443
]

TIMEOUT = 1.0       # segundos a esperar por resposta antes de desistir do porto
MAX_THREADS = 100   # número máximo de portos a testar em simultâneo

# ── Scanner ───────────────────────────────────────────────────────────────────

def scan_port(target: str, port: int) -> dict | None:
    """Tenta ligar ao porto — devolve resultado ou None se fechado."""

    try:
        # cria um socket TCP (AF_INET = IPv4, SOCK_STREAM = TCP)
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(TIMEOUT)                  # define o tempo máximo de espera
            result = s.connect_ex((target, port))  # tenta ligar — devolve 0 se aberto

            if result == 0:                        # porto aberto
                banner = grab_banner(s, target, port)  # tenta identificar o serviço
                return {
                    "port": port,
                    "state": "open",
                    "banner": banner               # ex: "Apache/2.2.8" ou vazio
                }

    except (socket.timeout, ConnectionRefusedError, OSError):
        pass       # porto fechado ou sem resposta — ignora e continua

    return None    # porto não está acessível


def grab_banner(sock: socket.socket, target: str, port: int) -> str:
    """Tenta obter o banner do serviço (identifica versão e tecnologia)."""

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(TIMEOUT)
            s.connect((target, port))
            s.sendall(b"HEAD / HTTP/1.0\r\n\r\n")          # envia pedido HTTP simples
            return s.recv(1024).decode(errors="ignore").strip()[:200]  # lê resposta (máx 200 chars)
    except Exception:
        return ""  # se não houver banner, devolve string vazia


def run_scan(target: str, ports: list[int] = DEFAULT_PORTS) -> dict:
    """Motor principal — corre o scan completo e devolve resultado estruturado."""

    # cabeçalho informativo no terminal
    print(f"\n[*] REDFORGE — Port Scanner")
    print(f"[*] Alvo   : {target}")
    print(f"[*] Portos : {len(ports)}")
    print(f"[*] Início : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{'─' * 45}")

    open_ports = []  # lista onde vamos guardar os portos abertos encontrados

    # ThreadPoolExecutor corre até MAX_THREADS scans em paralelo
    # em vez de testar um porto de cada vez (muito mais rápido)
    with ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:

        # submete uma tarefa de scan para cada porto
        futures = {executor.submit(scan_port, target, port): port for port in ports}

        # à medida que cada tarefa termina, processa o resultado
        for future in as_completed(futures):
            result = future.result()
            if result:                             # se o porto estava aberto
                open_ports.append(result)
                # mostra preview do banner se existir
                banner_preview = f" — {result['banner'][:60]}" if result["banner"] else ""
                print(f"[+] Porto {result['port']:>5}/tcp   ABERTO{banner_preview}")

    # ordena os portos abertos por número (do mais baixo para o mais alto)
    open_ports.sort(key=lambda x: x["port"])

    # monta o resultado final em dicionário — será convertido para JSON
    output = {
        "mitre_technique": "T1046",                        # técnica MITRE mapeada
        "target": target,                                  # IP do alvo
        "timestamp": datetime.now().isoformat(),           # data e hora do scan
        "ports_scanned": len(ports),                       # total de portos testados
        "open_ports": open_ports,                          # lista detalhada de portos abertos
        "summary": {
            "total_open": len(open_ports),                 # contagem rápida
            "ports": [p["port"] for p in open_ports]       # lista simples dos números
        }
    }

    # rodapé com resumo
    print(f"{'─' * 45}")
    print(f"[*] Portos abertos : {len(open_ports)}")
    print(f"[*] Fim            : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")

    return output


# ── Main ──────────────────────────────────────────────────────────────────────

if __name__ == "__main__":

    # verifica se o utilizador passou o IP do alvo como argumento
    if len(sys.argv) < 2:
        print("Uso: python port_scanner.py <alvo>")
        print("Exemplo: python port_scanner.py 192.168.1.10")
        sys.exit(1)

    target = sys.argv[1]       # lê o IP passado na linha de comandos
    results = run_scan(target) # corre o scan e guarda o resultado

    # define o caminho do ficheiro de output com IP e timestamp no nome
    output_file = f"reports/scan_{target}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"

    # guarda o resultado em JSON formatado (indent=4 para ficar legível)
    with open(output_file, "w") as f:
        json.dump(results, f, indent=4)

    print(f"[*] Resultados guardados em: {output_file}")