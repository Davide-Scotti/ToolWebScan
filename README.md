# 🔐 Advanced Security Scanner Platform

Piattaforma completa di security scanning che integra i migliori tool open-source professionali con una dashboard web interattiva.

## 🎯 Features

- **Orchestratore intelligente**: Coordina automaticamente multipli security tools
- **Dashboard Web**: Interfaccia grafica per visualizzare vulnerabilità
- **Container Docker**: Ambiente completo pre-configurato
- **Report aggregati**: Risultati unificati da tutti i tool
- **Scansioni programmate**: Avvia scansioni dalla dashboard

## 🛠️ Tool Integrati

| Tool | Descrizione | Tipo |
|------|-------------|------|
| **OWASP ZAP** | Scanner completo web application | Spider + Active Scan |
| **Nuclei** | Template-based scanner ultra-veloce | 5000+ templates |
| **Nikto** | Web server vulnerability scanner | Config + Security |
| **SQLMap** | SQL Injection specialist | Database security |
| **Testssl.sh** | SSL/TLS security testing | Encryption audit |
| **Wapiti** | Web application scanner | Crawling + Injection |

## 📁 Struttura del Progetto

```
security-scanner/
├── Dockerfile              # Container con tutti i tool
├── docker-compose.yml      # Orchestrazione servizi
├── requirements.txt        # Dipendenze Python
├── orchestrator.py         # Script principale orchestratore
├── dashboard.py            # Web dashboard Flask
├── scan_results/          # Directory risultati (auto-creata)
│   ├── summary_*.json     # Report aggregati
│   ├── zap_*.json         # Output ZAP
│   ├── nuclei_*.json      # Output Nuclei
│   └── ...
└── README.md              # Questo file
```

## 🚀 Quick Start

### Metodo 1: Docker (Consigliato)

```bash
# 1. Clona o crea la directory del progetto
mkdir security-scanner && cd security-scanner

# 2. Crea i file (Dockerfile, docker-compose.yml, orchestrator.py, dashboard.py, requirements.txt)

# 3. Build del container
docker-compose build

# 4. Avvia il servizio
docker-compose up -d

# 5. Accedi alla dashboard
# Apri browser: http://localhost:5000
```

### Metodo 2: Manuale (senza Docker)

```bash
# Installa i tool (Ubuntu/Debian)
sudo apt-get update
sudo apt-get install -y python3 python3-pip default-jdk perl

# Installa ZAP
wget https://github.com/zaproxy/zaproxy/releases/download/v2.14.0/ZAP_2.14.0_Linux.tar.gz
tar -xzf ZAP_2.14.0_Linux.tar.gz -C /opt

# Installa Nuclei
wget https://github.com/projectdiscovery/nuclei/releases/download/v3.1.0/nuclei_3.1.0_linux_amd64.zip
unzip nuclei_3.1.0_linux_amd64.zip -d /usr/local/bin

# Installa Nikto
git clone https://github.com/sullo/nikto.git
ln -s $(pwd)/nikto/program/nikto.pl /usr/local/bin/nikto

# Installa SQLMap
git clone https://github.com/sqlmapproject/sqlmap.git
ln -s $(pwd)/sqlmap/sqlmap.py /usr/local/bin/sqlmap

# Installa testssl.sh
git clone https://github.com/drwetter/testssl.sh.git
ln -s $(pwd)/testssl.sh/testssl.sh /usr/local/bin/testssl.sh

# Installa dipendenze Python
pip3 install -r requirements.txt

# Avvia dashboard
python3 dashboard.py
```

## 📊 Utilizzo

### Dashboard Web

1. **Avvia la dashboard**:
   ```bash
   docker-compose up -d
   # oppure
   python3 dashboard.py
   ```

2. **Accedi alla dashboard**: http://localhost:5000

3. **Avvia una scansione**:
   - Inserisci URL target (es: `http://testphp.vulnweb.com`)
   - Clicca "Start Scan"
   - Monitora il progresso

4. **Visualizza risultati**:
   - Dashboard mostra statistiche aggregate
   - Clicca su una scansione per dettagli
   - Esporta report in JSON

### Command Line

```bash
# Scansione completa via CLI
docker exec -it security_scanner python3 orchestrator.py http://target.com

# Scansione con output personalizzato
docker exec -it security_scanner python3 orchestrator.py http://target.com -o /scanner/my_results
```

## 🎨 Dashboard Features

### Homepage
- **Statistiche globali**: Total scans, vulnerabilità trovate
- **Conteggio per severità**: Critical, High, Medium, Low
- **Form di scansione**: Avvia nuove scansioni
- **Lista scansioni recenti**: Accesso rapido

### Dettagli Scansione
- **Summary**: Target, durata, tool eseguiti
- **Vulnerabilità**: Lista completa con filtri
- **Per Tool**: Breakdown per scanner
- **Export**: Download report JSON

## 📋 API Endpoints

La dashboard espone API REST:

```
GET  /api/scans                  # Lista tutte le scansioni
GET  /api/scan/<scan_id>         # Dettagli scansione
GET  /api/vulnerabilities/<id>   # Vulnerabilità specifiche
POST /api/start_scan             # Avvia nuova scansione
GET  /api/scan_status/<id>       # Status scansione attiva
GET  /api/statistics             # Statistiche aggregate
GET  /api/export/<scan_id>       # Export JSON
GET  /health                     # Health check
```

### Esempio API Call

```bash
# Avvia scansione via API
curl -X POST http://localhost:5000/api/start_scan \
  -H "Content-Type: application/json" \
  -d '{"target_url": "http://testphp.vulnweb.com"}'

# Ottieni statistiche
curl http://localhost:5000/api/statistics
```

## 🔒 Sicurezza e Legalità

### ⚠️ IMPORTANTE

**Questo tool è SOLO per:**
1. ✅ Sistemi di tua proprietà
2. ✅ Ambienti di test autorizzati
3. ✅ Scopi educativi con permesso scritto

**È ILLEGALE:**
❌ Testare sistemi senza autorizzazione
❌ Utilizzare per attacchi malevoli
❌ Violare privacy altrui

### Ethical Hacking

Il tool include controlli etici:
- ✅ Richiesta conferma prima di ogni scan
- ✅ Warning per domini non locali
- ✅ Logging completo di tutte le operazioni

### Siti di Test Legali

Puoi testare su:
- http://testphp.vulnweb.com
- http://testhtml5.vulnweb.com
- http://testasp.vulnweb.com
- https://portswigger.net/web-security
- https://www.hackthissite.org

## 📊 Tipologie di Vulnerabilità Rilevate

- **Injection**: SQL, Command, LDAP, XPath
- **XSS**: Reflected, Stored, DOM-based
- **Broken Authentication**: Session management, password policies
- **Sensitive Data Exposure**: SSL/TLS issues, headers mancanti
- **XML External Entities (XXE)**
- **Broken Access Control**: IDOR, privilege escalation
- **Security Misconfiguration**: Default configs, verbose errors
- **CSRF**: Token mancanti, SameSite cookies
- **Known Vulnerabilities**: CVE, outdated software
- **Directory Traversal**: Path injection

## 🔧 Configurazione Avanzata

### Timeout Personalizzati

Modifica `orchestrator.py`:

```python
# Cambia timeout per tool specifici
timeout=600  # 10 minuti (default)
timeout=1800 # 30 minuti per scansioni profonde
```

### Tool Selettivi

Commenta tool non necessari in `orchestrator.py`:

```python
# Disabilita ZAP per scan veloci
# if available_tools.get("zap"):
#     self.run_zap_scan()
```

### Custom Templates Nuclei

```bash
# Aggiungi template personalizzati
docker exec -it security_scanner nuclei -ut
```

## 📈 Performance

**Tempi Medi di Scansione**:
- Sito piccolo (< 50 pagine): 5-10 minuti
- Sito medio (50-200 pagine): 15-30 minuti
- Sito grande (> 200 pagine): 30-60 minuti

**Ottimizzazioni**:
- Nuclei è il più veloce (1-2 min)
- ZAP è il più completo ma lento (10-30 min)
- SQLMap test approfonditi richiedono più tempo

## 🐛 Troubleshooting

### Dashboard non si avvia

```bash
# Verifica porte disponibili
netstat -tuln | grep 5000

# Cambia porta se necessario
docker-compose up -d -p 5001:5000
```

### Tool non trovati

```bash
# Verifica installazione
docker exec -it security_scanner which nuclei
docker exec -it security_scanner which zap.sh

# Reinstalla se necessario
docker-compose build --no-cache
```

### Scansione bloccata

```bash
# Controlla logs
docker logs security_scanner

# Riavvia container
docker-compose restart
```

## 📚 Risorse Utili

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [OWASP ZAP Documentation](https://www.zaproxy.org/docs/)
- [Nuclei Templates](https://github.com/projectdiscovery/nuclei-templates)
- [Web Security Academy](https://portswigger.net/web-security)

## 🤝 Contributing

Contributi benvenuti! Per aggiungere nuovi tool:

1. Aggiungi installazione in `Dockerfile`
2. Crea metodo `run_<tool>_scan()` in `orchestrator.py`
3. Aggiungi parser risultati
4. Aggiorna documentazione

## 📝 License

Questo progetto è per scopi educativi. Usa responsabilmente.

## 🙏 Credits

Integra i seguenti progetti open-source:
- OWASP ZAP
- ProjectDiscovery Nuclei
- Nikto
- SQLMap
- testssl.sh

---

**⚠️ Disclaimer**: Gli sviluppatori non sono responsabili per uso improprio. Usa solo su sistemi autorizzati.