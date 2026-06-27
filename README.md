
# Buggy - Offensive Security Automation Suite

**Buggy** é uma plataforma modular de bug bounty e pentest automatizado, projetada para reduzir em até 4 dias o tempo de information gathering e testes manuais. Construída para funcionar offline-first, sem dependência de APIs pagas, utilizando ferramentas consolidadas como `subfinder`, `dnsx`, `amass` e o scanner de alta performance **Dirpy v2 Go**.

> **Autor:** [Lucas Lucachak](https://github.com/lucachak)  
> **Licença:** MIT  
> **Status:** Em desenvolvimento ativo  
> **Stack:** Python 3.10+ (orquestrador) + Go (Dirpy v2 scanner)

---

## Filosofia

- **Zero APIs pagas.** Sem Shodan, sem VirusTotal. Apenas ferramentas locais e código próprio.
- **Modular.** Cada módulo é independente. Teste, mantenha e expanda sem quebrar o resto.
- **Alta performance.** Dirpy v2 em Go atinge 13.000+ req/s.
- **Testado.** Testes unitários com `pytest` desde o início.
- **Feito por um hacker, para hackers.**

---

## 📸 Demo

```
$ python Buggy.py -t http://localhost:8000 -m recon --skip-deps

██████╗   ██╗   ██╗   ██████╗    ██████╗   ██╗   ██╗
██╔══██╗  ██║   ██║  ██╔════╝   ██╔════╝   ╚██╗ ██╔╝
██████╔╝  ██║   ██║  ██║  ███╗  ██║  ███╗   ╚████╔╝
██╔══██╗  ██║   ██║  ██║   ██║  ██║   ██║    ╚██╔╝
██████╔╝  ╚██████╔╝  ╚██████╔╝  ╚██████╔╝     ██║
╚═════╝    ╚═════╝    ╚═════╝    ╚═════╝      ╚═╝

[>] Starting Reconnaissance on http://localhost:8000

🔍  Buggy Recon  —  target: localhost

────────────────────────────────────────────────────────────
  [1/4] SUBDOMAIN ENUMERATION
  [i] Local target — skipping external enumeration.

  [2/4] DNS RESOLUTION
  [i] Local target — skipping DNS resolution.

  [3/4] ORIGIN IP DISCOVERY
  [i] Local target — skipping origin IP discovery.

  [4/4] DIRECTORY BRUTEFORCE  (Dirpy v2 Go)
  ▶ Wordlist: default.txt  (4613 words)  |  Threads: 50
  ▶ Busting: http://localhost:8000

  [200]  /admin/
  [200]  /api/
  [301]  /api  → /api/
  [403]  /config/
  [200]  /login/
  [200]  /dashboard/

  [✔] 6 paths discovered across 1 target(s)  (27.8s)

  ✅  Recon complete in 28.0s
       Subdomains      : 1
       Live IPs        : 1
       Origin IPs      : 0
       Paths found     : 6

  📄  Report saved:
      TXT  →  ./localhost_recon_20260625_143922.txt
      JSON →  ./localhost_recon_20260625_143922.json
```

---

## 🚀 Quick Start

### Instalação com um comando

```bash
git clone https://github.com/lucachak/Buggy.git
cd Buggy
chmod +x install.sh
./install.sh
```

### Com virtual environment

```bash
./install.sh --venv
source .venv/bin/activate
```

### Usar

```bash
# Alvo externo (recon completo)
./buggy -t testphp.vulnweb.com -m recon

# Alvo local (pula enumeração externa)
./buggy -t http://localhost:8000 -m recon --skip-deps

# Dir busting recursivo
./buggy -t http://localhost:8000 -m recon --recursive --threads 100

# Ajuda
./buggy --help
```

---

## Estrutura de Módulos

| # | Módulo | Status | Função |
| :---: | :--- | :---: | :--- |
| 1 | `Reconnaissance` | ✅ Ativo | Subdomínios, DNS, CDN bypass, dir busting |
| 2 | `SurfaceMapping` | 🧱 Em breve | Mapeamento de superfície de ataque |
| 3 | `Infra` | 🧱 Em breve | Testes de infraestrutura e configuração |
| 4 | `AutheAndAutho` | 🧱 Em breve | Testes de autenticação e autorização |
| 5 | `BusinessLogic` | 🧱 Em breve | Falhas de lógica de negócio |
| 6 | `InjectionAttk` | 🧱 Em breve | SQLi, CMDi, SSTI e outras injeções |
| 7 | `ServerSide(SSRF)` | 🧱 Em breve | Server-Side Request Forgery |
| 8 | `XSSAndClient` | 🧱 Em breve | XSS, CSRF, client-side attacks |
| 9 | `Report` | 🧱 Em breve | Geração automática de relatórios |

---

## Funcionalidades (atual)

### Módulo 1: Reconnaissance
- **Subdomain enumeration:** crt.sh, subfinder, amass, assetfinder
- **DNS resolution:** dnsx com registro A, AAAA, CNAME, MX, TXT
- **Origin IP discovery:** Bypass de CDN/Cloudflare, SecurityTrails
- **Dir busting:** Dirpy v2 Go scanner com 13.000+ req/s
- **Recursive scan:** Segue diretórios automaticamente até profundidade configurável
- **Report:** Exportação automática em TXT e JSON

### Utilitário: OS_info
- Detecção automática de sistema operacional (Windows/Linux/macOS)
- Instalação automática de dependências (apt, pacman, yay, paru, dnf, brew)
- Suporte a AUR helpers em distros Arch-based

### Dirpy v2 Go
- Scanner de diretórios standalone em Go
- Recursivo com profundidade configurável
- Exportação JSON/CSV
- Wordlist built-in (70+ paths) + suporte a wordlist externa
- Código aberto, cross-platform

---

## 📂 Estrutura do Projeto

```
Buggy/
├── Buggy.py                    # Entry point
├── install.sh                  # Instalador one-command
├── Makefile                    # Atalhos
├── requirements.txt
├── modules/
│   ├── OS_info.py              # Detecção de SO + instalador de pacotes
│   ├── Reconnaissance/
│   │   ├── Discovery.py        # Pipeline completa de recon
│   │   ├── Dirpy/              # Dirpy v2 Go source
│   │   │   ├── cmd/dirpy/
│   │   │   ├── internal/
│   │   │   │   ├── scanner/    # HTTP client + worker pool
│   │   │   │   ├── urlbuilder/ # Construção de URLs
│   │   │   │   ├── wordlist/   # Wordlist built-in
│   │   │   │   └── output/     # Terminal + JSON/CSV
│   │   │   ├── go.mod
│   │   │   ├── Makefile
│   │   │   └── wordlist/default.txt
│   │   └── DirGO/              # Binário compilado
│   ├── SurfaceMapping/
│   ├── Infra/
│   ├── AutheAndAutho/
│   ├── BusinessLogic/
│   ├── InjectionAttk/
│   ├── ServerSide(SSRF)/
│   ├── XSSAndClient/
│   └── Report/
└── tests/
    └── test_discovery.py
```

---

## Instalação manual

```bash
# Clone o repositório
git clone https://github.com/lucachak/Buggy.git
cd Buggy

# Instale as dependências Python
pip install -r requirements.txt

# Build do Dirpy Go
cd modules/Reconnaissance/Dirpy
make build
cd ../../..

# Ferramentas externas necessárias (instale manualmente se não usar install.sh):
# - subfinder, dnsx, amass, assetfinder
# - curl, jq, sed, sort, dig, grep
```

---

## Uso Rápido

```bash
# Recon completo
python Buggy.py -t example.com -m recon

# Recon com dir busting recursivo
python Buggy.py -t example.com -m recon --recursive --threads 100

# Pular verificação de dependências (útil em dev)
python Buggy.py -t http://localhost:8000 -m recon --skip-deps

# Sem banner
python Buggy.py -t example.com -m recon --no-banner

# Testes unitários
pytest tests/ -v
```

---

## ⚡ Dirpy v2 Go (standalone)

```bash
cd modules/Reconnaissance/Dirpy

# Build
make build

# Scan simples
./DirGo -u http://localhost:8000

# Com wordlist customizada e recursão
./DirGo -u http://localhost:8000 -w wordlist/default.txt -r -depth 3

# Exportar JSON
./DirGo -u http://localhost:8000 --json results.json --output-dir scans/
```

---

## 📄 Output

Relatórios são gerados automaticamente após cada scan:

```
localhost_recon_20260625_143922.txt   # Legível
localhost_recon_20260625_143922.json  # Machine-parseable
```

---

## 🗺️ Roadmap

- [x] Módulo Recon (Dirpy + Discovery)
- [x] Estrutura base com 9 módulos
- [x] Testes unitários com pytest
- [x] Dirpy v2 Go (alta performance)
- [x] Dir busting recursivo
- [x] Instalador one-command (install.sh)
- [x] Cross-platform (Linux, macOS)
- [x] Detecção de alvo local (pula enumeração externa)
- [ ] SurfaceMapping
- [ ] Infra
- [ ] AutheAndAutho
- [ ] BusinessLogic
- [ ] InjectionAttk
- [ ] ServerSide (SSRF)
- [ ] XSSAndClient
- [ ] Report
- [ ] Suporte a múltiplos targets
- [ ] Web UI
- [ ] Docker image

---

## Tecnologias

- **Python 3.10+** — Orquestrador principal
- **Go 1.21+** — Dirpy v2 scanner de alta performance
- **pytest** — Testes unitários
- **subfinder, dnsx, amass, assetfinder** — Enumeração externa
- **curl, jq, sed, sort, dig, grep** — Processamento de dados

---

## Por que "Buggy"?

Porque caçar bugs é o objetivo. E porque toda ferramenta começa cheia de bugs — assumimos isso e testamos pra resolver.

---

## ⚠️ Disclaimer

Esta ferramenta é para **ethical hacking e bug bounty apenas**.  
Não use contra alvos que você não possui ou não tem permissão explícita para testar.  
O autor não é responsável por uso indevido.

---

## Contribuições

Pull requests são bem-vindos. Para mudanças grandes, abra uma issue primeiro para discutir.

---

## Contato

- **GitHub:** [lucachak](https://github.com/lucachak)
- **LinkedIn:** [Adicionar link]
- **Línguas:** Húngaro, Português, Inglês, Russo

---
