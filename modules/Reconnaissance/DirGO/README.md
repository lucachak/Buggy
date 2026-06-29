# DirGO

A web directory brute-force scanner written in **pure Go** — zero external dependencies.

Reescrito do zero a partir do Dirpy (Python) para ganhar performance real e portabilidade máxima. Um único binário compilado, sem intérprete, sem virtualenv, sem PyPI — roda em qualquer lugar que Go compile.

---

## O que faz

Envia requisições HTTP/HTTPS a um alvo, anexando caminhos de uma wordlist para descobrir diretórios e arquivos ocultos em servidores web. Técnica padrão em assessments de segurança web e fases de reconhecimento em CTFs.

```
  200   12345 B    42.3ms  http://target.com/admin
  301       0 B     8.1ms  http://target.com/dashboard  → /dashboard/
  403     512 B    15.0ms  http://target.com/.env
```

---

## Por que reescrever em Go?

O Dirpy original implementava a stack HTTP manualmente em Python — sockets crus, TLS na mão, threading. Funcionava, e o exercício teve valor didático real.

Mas Python tem um teto: o GIL limita paralelismo verdadeiro, e distribuir a ferramenta significa depender de um intérprete instalado com a versão certa.

Go resolve os dois problemas de forma limpa:

- **Goroutines** substituem threads sem o custo do GIL — concorrência real com `sync.WaitGroup` e channels
- **Compilação cross-platform** gera um único binário estático para Linux, macOS e Windows
- **stdlib** cobre tudo: `net/http`, `crypto/tls`, `encoding/json`, `encoding/csv` — sem `go.sum` com dependências externas

---

## Arquitetura

```
cmd/dirpy/main.go          ← entry point, parsing de flags
internal/
  scanner/scanner.go       ← engine principal, goroutines, probe, recursão
  scanner/result.go        ← struct Result
  urlbuilder/urlbuilder.go ← normalização de URLs e expansão de portas
  wordlist/wordlist.go     ← leitura de arquivo + expansão de extensões
  wordlist/builtin.go      ← wordlist embutida (fallback sem -w)
  output/output.go         ← banner, progresso, colorização ANSI
```

---

## Features

- HTTP e HTTPS (TLS via `crypto/tls`, sem verificação de cert por padrão)
- Concorrência real com goroutines e channels (`-t`, padrão: 50 workers)
- Scan recursivo em diretórios descobertos (`-r`, profundidade configurável com `-depth`)
- Suporte a múltiplas portas por alvo (`-p 80,443,8080`)
- Expansão de extensões por caminho (`-x php,txt,bak`)
- Fingerprint de tecnologia via headers HTTP (`-tech`)
- Filtro de status codes para suprimir (`-c`, padrão: 404)
- Exportação para JSON e CSV (`-json`, `-csv`)
- Wordlist embutida — funciona sem `-w`
- Exportação da wordlist built-in (`--export-wordlist`)
- Modo verbose e modo silent
- Zero dependências externas — `go.sum` vazio

---

## Instalação

**Compilar do fonte:**

```bash
git clone https://github.com/lucachak/Buggy.git
cd Buggy/modules/Reconnaissance/DirGO
make build
```

**Cross-compile para todas as plataformas:**

```bash
make build-all
```

Gera binários para Linux (amd64/arm64), macOS (amd64/arm64) e Windows (amd64).

**Requisitos:** Go 1.21+

---

## Uso

```bash
# Scan básico (wordlist embutida)
./DirGo -u http://target.com

# Com wordlist externa
./DirGo -u http://target.com -w wordlist.txt

# HTTPS + extensões
./DirGo -u https://target.com -w wordlist.txt -x php,bak,txt

# Múltiplas portas
./DirGo -u http://target.com -p 80,8080,8443

# Scan recursivo com profundidade máxima 3
./DirGo -u http://target.com -w wordlist.txt -r -depth 3

# Fingerprint de tecnologia + export JSON
./DirGo -u http://target.com -w wordlist.txt -tech -json results.json

# Modo silencioso (só o resumo final)
./DirGo -u http://target.com -w wordlist.txt -silent

# Exportar a wordlist embutida
./DirGo --export-wordlist minha-wordlist.txt
```

### Flags

| Flag | Descrição | Padrão |
|------|-----------|--------|
| `-u` | URL ou host alvo | obrigatório |
| `-w` | Caminho para wordlist | wordlist embutida |
| `-p` | Portas (vírgula): `80,443,8080` | — |
| `-x` | Extensões (vírgula): `php,txt,bak` | — |
| `-c` | Status codes a **filtrar** (suprimir) | `404` |
| `-t` | Número de workers (goroutines) | `50` |
| `-timeout` | Timeout por requisição (segundos) | `10.0` |
| `-retry` | Tentativas em caso de timeout | `1` |
| `-r` | Scan recursivo em diretórios | `false` |
| `-depth` | Profundidade máxima de recursão (`0` = ilimitado) | `0` |
| `-tech` | Fingerprint via headers HTTP | `false` |
| `-json` | Salvar resultados em JSON | — |
| `-csv` | Salvar resultados em CSV | — |
| `-output-dir` | Diretório para os arquivos de saída | `output/` |
| `-v` | Verbose (exibe erros e timeouts) | `false` |
| `-silent` | Silent mode (só resumo final) | `false` |
| `--export-wordlist` | Exportar wordlist embutida para arquivo | — |

---

## Wordlists

O DirGO já inclui uma wordlist embutida que funciona sem nenhuma flag adicional. Para customizar:

- [SecLists](https://github.com/danielmiessler/SecLists) — `Discovery/Web-Content/common.txt` é um bom ponto de partida
- [dirb wordlists](https://github.com/v0re/dirb/tree/master/wordlists)

---

## O que aprendi na reescrita

- Por que goroutines + channels escalam melhor que threads Python para I/O bound
- Como o Go resolve distribuição de binários de forma que o Python simplesmente não consegue
- A diferença entre paralelismo real (Go) e concorrência limitada pelo GIL (CPython)
- Como implementar recursão de scan sem condições de corrida usando `sync.Mutex` e controle de visitados
- Por que `atomic.Int64` é preferível a mutex para contadores simples de alta frequência

---

## Disclaimer

Ferramenta destinada **exclusivamente a testes de segurança autorizados** — CTFs, ambientes de laboratório (HackTheBox, TryHackMe, DVWA) e sistemas que você possui ou tem permissão escrita explícita para testar.

Escanear sistemas sem autorização é ilegal na maioria das jurisdições. O autor não se responsabiliza por uso indevido.

---

## Autor

**Lucas Lucachak** — [github.com/lucachak](https://github.com/lucachak) · [portfólio](https://portifolio-vercel-inky.vercel.app)