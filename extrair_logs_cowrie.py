import requests
import json
import time
from datetime import datetime, timedelta, timezone

# ==================== CONFIGURAÇÕES ====================
GRAFANA_URL = "http://192.168.56.30:3000" 
TOKEN = "INSIRA SEU TOKEN AQUI"

LOGQL_QUERY = '{job="cowrie"}'

# Fuso horário estrito UTC
START_DATE = datetime(2026, 8, 9, 0, 0, 0, tzinfo=timezone.utc)
END_DATE = datetime(2026, 9, 19, 23, 59, 59, tzinfo=timezone.utc)
OUTPUT_FILE = "cowrie_loki_bruto_completo.json"
# =======================================================

# Sessão com Keep-Alive para reutilização de TCP Sockets
session = requests.Session()
session.headers.update({
    "Authorization": f"Bearer {TOKEN}",
    "Content-Type": "application/json"
})

def descobrir_endpoint_valido():
    """Identifica o proxy do Grafana garantindo rotas de alta velocidade."""
    print(f"[*] Conectando ao Grafana em {GRAFANA_URL}...")
    
    ds_uid = None
    ds_id = None
    
    try:
        res = session.get(f"{GRAFANA_URL}/api/datasources", timeout=10)
        res.raise_for_status()
        for ds in res.json():
            if ds.get("type") == "loki":
                ds_uid = ds.get("uid")
                ds_id = ds.get("id")
                print(f"[+] Loki encontrado: '{ds.get('name')}' (UID: {ds_uid} | ID: {ds_id})")
                break
    except Exception as e:
        print(f"[!] Erro ao listar datasources do Grafana: {e}")

    candidatos = []
    if ds_uid:
        candidatos.append(("Grafana Proxy (UID)", f"{GRAFANA_URL}/api/datasources/proxy/uid/{ds_uid}/api/v1/query_range"))
        candidatos.append(("Grafana Proxy (UID /loki)", f"{GRAFANA_URL}/api/datasources/proxy/uid/{ds_uid}/loki/api/v1/query_range"))
    if ds_id:
        candidatos.append(("Grafana Proxy (ID)", f"{GRAFANA_URL}/api/datasources/proxy/{ds_id}/api/v1/query_range"))
    
    candidatos.append(("Loki Direto (Porta 3100)", "http://192.168.56.30:3100/loki/api/v1/query_range"))

    test_params = {
        "query": LOGQL_QUERY,
        "start": str(int(START_DATE.timestamp() * 1e9)),
        "end": str(int((START_DATE + timedelta(hours=1)).timestamp() * 1e9)),
        "limit": 1
    }

    print("[*] Validando rota de comunicação...")
    for nome, url in candidatos:
        try:
            r = session.get(url, params=test_params, timeout=10)
            if r.status_code == 200:
                print(f"[✔] Rota ativa configurada: {nome}\n    URL: {url}\n")
                return url
        except Exception:
            pass

    raise Exception("Nenhum endpoint do Loki respondeu.")

def extrair_logs_otimizado(endpoint_url):
    total_logs = 0
    current_day = START_DATE
    CHUNK_DAYS = 1  # Bloco diário adaptativo
    
    start_bench = time.time()
    print(f"[*] Iniciando extração otimizada em bloco adaptativo...")
    print(f"[*] Janela temporal: {START_DATE.strftime('%d/%m/%Y')} a {END_DATE.strftime('%d/%m/%Y')}\n")
    
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f_out:
        while current_day < END_DATE:
            next_day = min(current_day + timedelta(days=CHUNK_DAYS), END_DATE)
            
            chunk_start_ns = int(current_day.timestamp() * 1e9)
            chunk_end_ns = int(next_day.timestamp() * 1e9)
            
            curr_start_ns = chunk_start_ns
            day_logs = 0

            # Sub-loop de paginação por nanosegundo (somente se exceder 5000 logs no dia)
            while curr_start_ns < chunk_end_ns:
                params = {
                    "query": LOGQL_QUERY,
                    "start": str(curr_start_ns),
                    "end": str(chunk_end_ns),
                    "limit": 5000,
                    "direction": "FORWARD"
                }

                res_ok = False
                for tentativa in range(1, 4):
                    try:
                        # Timeout flexível: 10s conexão, 60s resposta para grandes volumes
                        res = session.get(endpoint_url, params=params, timeout=(10, 60))
                        if res.status_code == 200:
                            res_ok = True
                            break
                        else:
                            time.sleep(2)
                    except requests.exceptions.RequestException:
                        time.sleep(3)

                if not res_ok:
                    print(f"  └─ [AVISO] Falha ao consultar o dia {current_day.strftime('%d/%m/%Y')}. Avançando...")
                    break

                data = res.json()
                results = data.get("data", {}).get("result", [])
                
                batch_entries = []
                for stream in results:
                    for entry in stream.get("values", []):
                        # entry[0] é o timestamp em nanosegundos, entry[1] é a string do log
                        batch_entries.append((int(entry[0]), entry[1]))

                qtd = len(batch_entries)
                if qtd == 0:
                    break  # Fim dos registros para este dia

                # Garante ordenação cronológica se houver múltiplos streams
                batch_entries.sort(key=lambda x: x[0])
                
                # Prepara o bloco de texto para escrita em lote no disco
                lines_buffer = [item[1] + "\n" for item in batch_entries]
                f_out.write("".join(lines_buffer))
                
                day_logs += qtd
                total_logs += qtd
                
                max_ts_ns = batch_entries[-1][0]

                # Se o lote atingiu 5.000, indica que há mais registros no mesmo dia
                if qtd >= 5000:
                    curr_start_ns = max_ts_ns + 1
                    print(f"  └─ [PAGINANDO] Dia {current_day.strftime('%d/%m')} atingiu 5.000 logs. Buscando próxima página (ns={curr_start_ns})...")
                else:
                    break  # Dia concluído

            print(f"  └─ [{current_day.strftime('%d/%m/%Y')}] Coletados: {day_logs:>5} logs | Total acumulado: {total_logs:>7}")
            current_day = next_day

    elapsed = time.time() - start_bench
    print(f"\n[✔] Extração concluída em {elapsed:.1f} segundos!")
    print(f"[✔] Total final de registros salvos: {total_logs}")

if __name__ == "__main__":
    endpoint = descobrir_endpoint_valido()
    extrair_logs_otimizado(endpoint)
