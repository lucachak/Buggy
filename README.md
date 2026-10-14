# Buggy - Offensive Security Automation Suite

**Buggy** é um scanner modular para reconhecimento, mapeamento de superfície e validações de segurança web em ambientes autorizados. Ele organiza os resultados por execução, aplica controles de escopo e produz achados JSON e relatório HTML. Não substitui revisão manual: vários módulos usam heurísticas e os achados precisam ser confirmados.

> **Autor:** [Lucas Lucachak](https://github.com/lucachak)  
> **Licença:** MIT  
> **Status:** Em desenvolvimento ativo  
> **Stack:** Python 3.10+ (orquestrador) + Go (Dirpy v2 scanner)

---

## Filosofia

- **Safe by default.** TLS validado, redirects presos ao escopo, rate limit e bloqueio de requisições que alteram estado.
- **Sem APIs obrigatórias.** A integração opcional com Shodan só é usada quando CLI e chave estão configuradas.
- **Modular.** Cada módulo é independente. Teste, mantenha e expanda sem quebrar o resto.
- **Carga controlável.** Concorrência, timeout e taxa são configuráveis; respeite sempre as regras do programa.
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
chmod +x Install.sh
./Install.sh
```

### Com virtual environment

```bash
./Install.sh --venv
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
python Buggy.py --help
```

---

## Estrutura de Módulos

| # | Módulo | Status | Função |
| :---: | :--- | :---: | :--- |
| 1 | `Reconnaissance` | ✅ Ativo | Subdomínios, DNS, CDN bypass, dir busting |
| 2 | `SurfaceMapping` | ✅ Ativo | Mapeamento de superfície de ataque |
| 3 | `Infra` | ✅ Ativo | Headers, CORS e exposição de arquivos |
| 4 | `AutheAndAutho` | ✅ Ativo | Heurísticas de autenticação, IDOR e SSO |
| 5 | `BusinessLogic` | ✅ Ativo | HPP e mass assignment heurístico |
| 6 | `InjectionAttk` | ✅ Ativo | SQLi, CMDi, SSTI e XXE |
| 7 | `ServerSide_SSRF` | ✅ Ativo | SSRF, path traversal e LFI |
| 8 | `XSSAndClient` | ✅ Ativo | XSS, CSRF e open redirect |
| 9 | `Report` | ✅ Ativo | Relatório HTML consolidado |
| 10 | `CVEIntelligence` | ✅ Ativo | Correlação NVD/KEV/EPSS e priorização |
| 11 | `Validation` | ✅ Ativo | Plano, aprovação, sandbox e validators seguros |
| 12 | `WebUI` | ✅ Ativo | API e dashboard locais com acompanhamento em tempo real |

---

## Funcionalidades (atual)

### Módulo 1: Reconnaissance
- **Subdomain enumeration:** crt.sh, subfinder, amass, assetfinder
- **DNS resolution:** dnsx com registro A, AAAA, CNAME, MX, TXT
- **Origin IP discovery:** Bypass de CDN/Cloudflare, SecurityTrails
- **Dir busting:** Dirpy v2 em Go com concorrência, timeout e saída JSON
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
├── Install.sh                  # Instalador one-command
├── Makefile                    # Atalhos
├── requirements.txt
├── modules/
│   ├── OS_info.py              # Detecção de SO + instalador de pacotes
│   ├── Reconnaissance/
│   │   ├── Discovery.py        # Pipeline completa de recon
│   │   ├── DirGO/              # Código-fonte e binário do Dirpy v2
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
│   ├── ServerSide_SSRF/
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
cd modules/Reconnaissance/DirGO
make build
cd ../../..

# Ferramentas externas necessárias (instale manualmente se não usar Install.sh):
# - subfinder, dnsx, amass, assetfinder
# - curl, jq, sed, sort, dig, grep
```

---

## Uso Rápido

```bash
# Recon completo
python Buggy.py -t example.com -m recon

# Fluxo completo no perfil seguro (padrão)
python Buggy.py -t https://app.example.com -m all -o output/app-scan

# Testes ativos com POST/JSON/XML — somente quando autorizados
python Buggy.py -t https://app.example.com -m injection \
  -o output/app-scan --profile standard --rate 5

# Autorizar explicitamente outro host encontrado no mapeamento
python Buggy.py -t https://app.example.com -m xss \
  -o output/app-scan --allow-host api.example.com

# Recon com dir busting recursivo
python Buggy.py -t example.com -m recon --recursive --threads 100

# Pular verificação de dependências (útil em dev)
python Buggy.py -t http://localhost:8000 -m recon --skip-deps

# Correlacionar CVEs, criar plano e executar checks seguros automaticamente
python Buggy.py -t https://app.example.com -m cve -o output/app-scan
python Buggy.py -t https://app.example.com -m plan -o output/app-scan
python Buggy.py -m execute -o output/app-scan

# Dashboard/API somente local
python Buggy.py -m ui --ui-port 8787

# Sem banner
python Buggy.py -t example.com -m recon --no-banner

# Testes unitários
pytest tests/ -v
```

Na primeira abertura da UI, use **Iniciar demonstração** para criar um scan
guiado com inventário, CVEs, plano e resultados de exemplo. O onboarding usa
dados locais, não inicia o scanner, não acessa alvos e permanece somente leitura.
Scans reais exibem status e logs automaticamente durante a execução por um
atualizador local, sem CDN ou dependência de internet; ao terminar, a página
recarrega uma vez para apresentar os artefatos finais. A timeline mostra
as fases concluídas, ativa e pendentes. **Cancelar execução** encerra com `SIGTERM`
somente processos iniciados pela instância atual da UI e persiste `cancelled`.
Em **Ajustar desempenho**, cada projeto permite configurar workers, requisições
por minuto, timeout, verificação de dependências, recursão e profundidade. A UI
estima a duração da lista base; cada diretório confirmado pode acrescentar outra
passada quando a recursão estiver ativa.

Para aplicações SPA, o SurfaceMapping lê os assets reais declarados por
`script`, `modulepreload` e referências internas dos bundles. Rotas `/api` e
`/rest` são resolvidas apenas dentro do host autorizado, preservando quando
possível o método HTTP observado. O relatório separa cobertura, observações e
vulnerabilidades confirmadas; zero entradas dinâmicas é marcado como resultado
inconclusivo, não como aplicação segura.

### Perfis e hardening

- `--profile safe` é o padrão: permite reconhecimento e testes GET, mas bloqueia POST, JSON e XML.
- `--profile standard` habilita validações que podem alterar estado. Use contas e dados de teste.
- O escopo de rede é o host de `--target`. Hosts extras exigem `--allow-host` explícito.
- TLS é verificado por padrão. `--insecure` existe apenas para laboratórios com certificado inválido.
- Headers de bypass não são enviados por padrão; `--waf-bypass` é opt-in.
- `--rate`, `--threads` e `--timeout` limitam a carga. Regras do programa têm precedência.
- `--recursive --max-depth N` revisita diretórios confirmados. O Dirpy calibra
  templates de soft 404 na raiz e em cada profundidade antes de expandir a lista.
- Validators `safe` usam apenas provas não destrutivas e são executados automaticamente; eles indicam aplicabilidade, não exploração confirmada.
- Validators de risco maior permanecem bloqueados até aprovação explícita vinculada ao plano.

Execute `python Buggy.py -h` para ver módulos, defaults, exemplos e o fluxo recomendado.

---

## ⚡ Dirpy v2 Go (standalone)

```bash
cd modules/Reconnaissance/DirGO

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
- [x] Instalador one-command (Install.sh)
- [x] Cross-platform (Linux, macOS)
- [x] Detecção de alvo local (pula enumeração externa)
- [x] SurfaceMapping
- [x] Infra
- [x] AutheAndAutho
- [x] BusinessLogic
- [x] InjectionAttk
- [x] ServerSide (SSRF)
- [x] XSSAndClient
- [x] Report
- [ ] Suporte a múltiplos targets
- [x] Web UI local
- [x] Inteligência de CVEs e priorização
- [x] Registry, aprovação, sandbox e validators HTTP seguros
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
