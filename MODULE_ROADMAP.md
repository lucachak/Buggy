# Buggy — Roadmap de módulos avançados

Este documento é o contrato de implementação dos módulos avançados do Buggy.
Um módulo só muda para **concluído** depois de possuir integração na CLI/pipeline,
persistência de resultados, documentação e testes automatizados aprovados.

## Estados

- `planejado`: arquitetura definida, implementação ainda não iniciada.
- `em andamento`: implementação ou integração incompleta.
- `concluído`: critérios de aceite atendidos e testes aprovados.

## Ordem obrigatória

| # | Módulo | Estado | Integração prevista |
|---|---|---|---|
| 1 | CVEIntelligence + RiskPrioritizer | concluído | Consome inventário do SurfaceMapping e produz `intelligence/cves.json` |
| 2 | Validator Registry | concluído | Associa CVEs a validators locais revisados e tipados por risco |
| 3 | NucleiAdapter | concluído | Executa apenas templates permitidos/assinados e importa evidências |
| 4 | Approval + Sandbox | concluído | Gera plano, exige aprovação conforme risco e isola executores |
| 5 | FastAPI | concluído | Expõe projetos, scans, achados, planos e aprovações |
| 6 | Dashboard Web local | concluído | Interface local para operação e acompanhamento em tempo real |
| 7 | Safe HTTP Validators | concluído | Validators não destrutivos para CVEs HTTP selecionadas |

## 1. CVEIntelligence + RiskPrioritizer

Responsabilidades:

- normalizar produtos e versões detectados;
- correlacionar inventário com CPE/CVE;
- enriquecer CVEs com NVD, CISA KEV e EPSS;
- manter cache local com timestamp e origem;
- classificar aplicabilidade como `possible`, `likely`, `confirmed`,
  `not_vulnerable` ou `inconclusive`;
- priorizar usando CVSS, KEV, EPSS e exposição do ativo.

Critérios de conclusão:

- [x] módulo executável isoladamente pela CLI;
- [x] integração opcional após SurfaceMapping no pipeline completo;
- [x] funcionamento offline usando cache ou inventário sem enriquecimento;
- [x] saída JSON estável e versionada;
- [x] testes de normalização, correlação, priorização, cache e falhas de rede.

Integração concluída em 2026-08-16: o SurfaceMapping agora preserva versões
expostas em headers, `all` executa a inteligência logo após mapear a superfície,
e o relatório HTML ganhou uma seção de CVEs priorizadas. Fontes externas falham
de forma degradada e o cache permite operação offline.

## 2. Validator Registry

Registry declarativa contendo ID, CVEs suportadas, risco, métodos HTTP,
pré-condições, timeout, possibilidade de rollback e implementação. Nenhum código
obtido da internet será executado diretamente.

Integração concluída em 2026-08-16: specs são validadas, imports Python ficam
restritos a `modules.Validators`, snapshots recebem digest determinístico e o
módulo `plan` cruza o registry com `intelligence/cves.json`. Apenas validators
`safe` recebem aprovação automática; os demais permanecem `proposed`.

## 3. NucleiAdapter

Integração por subprocesso sem shell, pinagem de templates, allowlist de tags,
verificação de assinatura e importação de JSONL. `code`, `headless` e templates
não assinados ficam desabilitados por padrão.

Integração concluída em 2026-08-16: o módulo `nuclei` exige manifesto local,
SHA-256 pinado e assinatura, rejeita protocolos `code`, `headless`, `javascript`
e `file`, usa subprocesso sem shell, bloqueia redirects e descarta resultados
fora do host autorizado. A ausência do binário/templates resulta em `skipped`,
nunca em fallback inseguro.

## 4. Approval + Sandbox

Cada execução gera um plano imutável. Validators `standard`, `intrusive` ou
`lab-exploit` exigem aprovação adequada. Processos recebem timeout, limites de
recursos, ambiente mínimo e egress restrito ao alvo/OOB autorizado.

Integração concluída em 2026-08-16: aprovações HMAC são vinculadas ao `plan_id`
e digest do registry, têm validade e arquivos `0600`. O worker roda em processo
separado, sem shell, com ambiente mínimo, timeout e limites POSIX de CPU, memória,
arquivos e processos. O cliente HTTP mantém escopo de host; isolamento de rede em
nível de kernel continua sendo responsabilidade de container/namespace externo.
Validators `lab-exploit` ainda exigem `--lab-mode` e alvo privado.

## 5. FastAPI

API local para projetos, regras de escopo, scans, achados, CVEs, planos,
aprovações e cancelamento. Bind padrão em `127.0.0.1` e sem exposição externa.

Integração concluída em 2026-08-16: projetos e scans persistem em SQLite,
criação de projeto exige confirmação explícita de autorização, parâmetros têm
limites Pydantic e processos são iniciados sem shell. A API expõe resumo, CVEs,
plano, aprovação e execução; `Buggy -m ui` faz bind fixo em `127.0.0.1`.

## 6. Dashboard Web local

Dashboard server-rendered para reduzir dependências: projetos, novo scan,
superfície, CVEs priorizadas, plano de validação, aprovação e logs atualizados
por polling same-origin.

Integração concluída em 2026-08-16: o dashboard local cria projetos e scans,
acompanha estado e logs, apresenta CVEs e planos e permite aprovações. Formulários
mutáveis exigem CSRF, logs não confiáveis são escapados e respostas recebem CSP,
`X-Frame-Options`, `nosniff` e política de referrer. Testes ASGI e smoke test com
servidor real em `127.0.0.1` foram aprovados. O acompanhamento usa JavaScript
servido pelo próprio Buggy, sem CDN, mostra a etapa atual e permite cancelar
processos iniciados pela instância corrente.

## 7. Safe HTTP Validators

Primeiro conjunto de validators baseado em provas HTTP não destrutivas. Cada
validator terá fixtures locais, evidência mínima, resultado determinístico e
nenhuma tentativa de persistência, shell ou coleta de dados além do necessário.

Integração concluída em 2026-08-16: CVE-2021-41773 e CVE-2021-42013 recebem
checagem de aplicabilidade pela versão exposta do Apache, enquanto
CVE-2017-12615 usa versão do Tomcat e capacidades anunciadas por `OPTIONS`.
Os checks usam somente `GET`/`OPTIONS`, nunca enviam traversal, comandos ou
uploads e nunca retornam `confirmed`. O registry os adiciona ao plano como
`safe`, o executor os roda automaticamente no worker isolado e persiste um par
request/result separado por CVE. Testes unitários, integração completa do fluxo
inteligência → plano → execução e a suíte global foram aprovados.
