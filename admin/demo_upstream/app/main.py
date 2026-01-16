import html
import sqlite3
import base64
import urllib.parse
import httpx
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse
from fastapi.templating import Jinja2Templates

from .settings import settings

app = FastAPI(title="Demo Upstream", default_response_class=HTMLResponse)
templates = Jinja2Templates(directory=str(Path(__file__).parent / "templates"))
BASE_DIR = Path(__file__).parent
FILES_ROOT = BASE_DIR / "templates"


def get_db() -> sqlite3.Connection:
    conn = sqlite3.connect(settings.db_path)
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    conn = get_db()
    conn.execute(
        "CREATE TABLE IF NOT EXISTS items (id INTEGER PRIMARY KEY, name TEXT, description TEXT)"
    )
    conn.execute(
        "CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT, password TEXT, role TEXT)"
    )
    conn.execute(
        "CREATE TABLE IF NOT EXISTS comments (id INTEGER PRIMARY KEY, post_id INTEGER, content TEXT)"
    )
    cur = conn.execute("SELECT COUNT(*) as c FROM items")
    if cur.fetchone()["c"] == 0:
        conn.executemany(
            "INSERT INTO items (name, description) VALUES (?, ?)",
            [
                ("laptop", "gaming laptop"),
                ("phone", "smartphone"),
                ("tablet", "android tablet"),
            ],
        )
    cur = conn.execute("SELECT COUNT(*) as c FROM users")
    if cur.fetchone()["c"] == 0:
        conn.executemany(
            "INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
            [
                ("admin", "secret123", "admin"),
                ("user1", "pass1", "user"),
                ("guest", "guest", "guest"),
            ],
        )
    cur = conn.execute("SELECT COUNT(*) as c FROM comments")
    if cur.fetchone()["c"] == 0:
        conn.executemany(
            "INSERT INTO comments (post_id, content) VALUES (?, ?)",
            [
                (1, "great product"),
                (1, "recommend"),
                (2, "not bad"),
            ],
        )
    conn.commit()
    conn.close()


@app.on_event("startup")
async def startup_event() -> None:
    init_db()


@app.get("/health", response_class=PlainTextResponse)
async def health() -> str:
    return "ok"


@app.get("/")
async def home(request: Request) -> Any:
    return templates.TemplateResponse(
        "index.html",
        {"request": request, "insecure": settings.insecure_demo},
    )


# === XSS endpoints ===

@app.get("/search")
async def search(request: Request, q: str = "") -> Any:
    if settings.insecure_demo:
        content = f"Results for: {q}"
    else:
        content = f"Results for: {html.escape(q)}"
    return templates.TemplateResponse(
        "search.html",
        {"request": request, "content": content, "insecure": settings.insecure_demo},
    )


@app.get("/echo")
async def echo(msg: str = "") -> HTMLResponse:
    if settings.insecure_demo:
        return HTMLResponse(f"<html><body>Echo: {msg}</body></html>")
    return HTMLResponse(f"<html><body>Echo: {html.escape(msg)}</body></html>")


@app.get("/redirect")
async def redirect_endpoint(url: str = "/") -> HTMLResponse:
    if settings.insecure_demo:
        return HTMLResponse(f'<html><body><a href="{url}">Click here</a></body></html>')
    safe_url = "/" if url.startswith("javascript:") else html.escape(url)
    return HTMLResponse(f'<html><body><a href="{safe_url}">Click here</a></body></html>')


@app.get("/profile")
async def profile(name: str = "guest", bio: str = "") -> HTMLResponse:
    if settings.insecure_demo:
        return HTMLResponse(f"""
        <html><body>
        <h1>Profile: {name}</h1>
        <p>Bio: {bio}</p>
        </body></html>
        """)
    return HTMLResponse(f"""
    <html><body>
    <h1>Profile: {html.escape(name)}</h1>
    <p>Bio: {html.escape(bio)}</p>
    </body></html>
    """)


@app.get("/comment")
async def comment(text: str = "", author: str = "anon") -> HTMLResponse:
    if settings.insecure_demo:
        return HTMLResponse(f"<div class='comment'><b>{author}</b>: {text}</div>")
    return HTMLResponse(f"<div class='comment'><b>{html.escape(author)}</b>: {html.escape(text)}</div>")


# === SQL Injection endpoints ===

@app.get("/api/items", response_class=JSONResponse)
async def api_items(id: str = Query("1")) -> Any:
    conn = get_db()
    try:
        if settings.insecure_demo:
            query = f"SELECT * FROM items WHERE id = {id}"
            rows = conn.execute(query).fetchall()
        else:
            rows = conn.execute("SELECT * FROM items WHERE id = ?", (id,)).fetchall()
        return [dict(r) for r in rows]
    except sqlite3.Error as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    finally:
        conn.close()


@app.get("/api/users", response_class=JSONResponse)
async def api_users(username: str = "") -> Any:
    conn = get_db()
    try:
        if settings.insecure_demo:
            query = f"SELECT id, username, role FROM users WHERE username = '{username}'"
            rows = conn.execute(query).fetchall()
        else:
            rows = conn.execute(
                "SELECT id, username, role FROM users WHERE username = ?", (username,)
            ).fetchall()
        return [dict(r) for r in rows]
    except sqlite3.Error as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    finally:
        conn.close()


@app.get("/api/comments", response_class=JSONResponse)
async def api_comments(post_id: str = "1", order: str = "id") -> Any:
    conn = get_db()
    try:
        if settings.insecure_demo:
            query = f"SELECT * FROM comments WHERE post_id = {post_id} ORDER BY {order}"
            rows = conn.execute(query).fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM comments WHERE post_id = ? ORDER BY id", (post_id,)
            ).fetchall()
        return [dict(r) for r in rows]
    except sqlite3.Error as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    finally:
        conn.close()


@app.get("/api/login", response_class=JSONResponse)
async def api_login(user: str = "", pwd: str = "") -> Any:
    conn = get_db()
    try:
        if settings.insecure_demo:
            query = f"SELECT * FROM users WHERE username='{user}' AND password='{pwd}'"
            row = conn.execute(query).fetchone()
        else:
            row = conn.execute(
                "SELECT * FROM users WHERE username=? AND password=?", (user, pwd)
            ).fetchone()
        if row:
            return {"status": "ok", "user": row["username"], "role": row["role"]}
        return {"status": "fail"}
    except sqlite3.Error as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    finally:
        conn.close()


# === Path Traversal endpoints ===

@app.get("/api/files", response_class=PlainTextResponse)
async def api_files(path: str = "index.html") -> Any:
    if settings.insecure_demo:
        target = FILES_ROOT / path
    else:
        safe_files = {"index.html", "search.html"}
        if path not in safe_files:
            raise HTTPException(status_code=403, detail="forbidden")
        target = FILES_ROOT / path
    
    if not target.exists():
        raise HTTPException(status_code=404, detail="not found")
    try:
        return target.read_text(encoding="utf-8")
    except:
        raise HTTPException(status_code=400, detail="read error")


@app.get("/api/download")
async def api_download(file: str = "") -> PlainTextResponse:
    if settings.insecure_demo:
        target = Path("/app") / file
        if target.exists():
            try:
                return PlainTextResponse(target.read_text())
            except:
                return PlainTextResponse("binary file")
    raise HTTPException(status_code=404, detail="not found")


@app.get("/api/include")
async def api_include(page: str = "home") -> HTMLResponse:
    if settings.insecure_demo:
        target = FILES_ROOT / f"{page}.html"
        if target.exists():
            return HTMLResponse(target.read_text())
    return HTMLResponse("<p>Page not found</p>")


# === Other vuln endpoints ===

@app.get("/api/eval")
async def api_eval(expr: str = "1+1") -> JSONResponse:
    if settings.insecure_demo:
        try:
            result = eval(expr)
            return JSONResponse({"result": str(result)})
        except:
            return JSONResponse({"error": "eval failed"})
    return JSONResponse({"error": "disabled"})


@app.get("/api/decode")
async def api_decode(data: str = "", encoding: str = "base64") -> JSONResponse:
    try:
        if encoding == "base64":
            decoded = base64.b64decode(data).decode()
        elif encoding == "url":
            decoded = urllib.parse.unquote(data)
        else:
            decoded = data
        return JSONResponse({"decoded": decoded})
    except:
        return JSONResponse({"error": "decode failed"})


# === SSRF endpoints ===

@app.get("/api/fetch")
async def api_fetch(url: str = "") -> JSONResponse:
    """SSRF vulnerable endpoint - fetches arbitrary URLs"""
    if not url:
        return JSONResponse({"error": "url parameter required"})
    
    if settings.insecure_demo:
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                resp = await client.get(url)
                return JSONResponse({
                    "status": resp.status_code,
                    "content_length": len(resp.content),
                    "content_preview": resp.text[:500] if resp.text else ""
                })
        except Exception as e:
            return JSONResponse({"error": str(e)})
    else:
        # Safe version - only allow whitelisted domains
        allowed_domains = ["example.com", "api.github.com"]
        from urllib.parse import urlparse
        parsed = urlparse(url)
        if parsed.netloc not in allowed_domains:
            return JSONResponse({"error": "domain not allowed"})
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                resp = await client.get(url)
                return JSONResponse({"status": resp.status_code})
        except Exception as e:
            return JSONResponse({"error": str(e)})


@app.get("/api/proxy")
async def api_proxy(dest: str = "", method: str = "GET") -> JSONResponse:
    """SSRF vulnerable proxy endpoint"""
    if not dest:
        return JSONResponse({"error": "dest parameter required"})
    
    if settings.insecure_demo:
        try:
            async with httpx.AsyncClient(timeout=5.0, follow_redirects=True) as client:
                if method.upper() == "POST":
                    resp = await client.post(dest)
                else:
                    resp = await client.get(dest)
                return JSONResponse({
                    "url": str(resp.url),
                    "status": resp.status_code,
                    "headers": dict(resp.headers),
                    "body": resp.text[:1000]
                })
        except Exception as e:
            return JSONResponse({"error": str(e)})
    return JSONResponse({"error": "proxy disabled"})


@app.get("/api/webhook")
async def api_webhook(callback: str = "", data: str = "test") -> JSONResponse:
    """SSRF via webhook callback"""
    if not callback:
        return JSONResponse({"error": "callback url required"})
    
    if settings.insecure_demo:
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                resp = await client.post(callback, json={"data": data})
                return JSONResponse({"sent": True, "status": resp.status_code})
        except Exception as e:
            return JSONResponse({"error": str(e)})
    return JSONResponse({"error": "webhooks disabled"})


@app.get("/api/avatar")
async def api_avatar(image_url: str = "") -> JSONResponse:
    """SSRF via image URL - common in profile picture uploads"""
    if not image_url:
        return JSONResponse({"error": "image_url required"})
    
    if settings.insecure_demo:
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                resp = await client.get(image_url)
                content_type = resp.headers.get("content-type", "")
                return JSONResponse({
                    "fetched": True,
                    "content_type": content_type,
                    "size": len(resp.content)
                })
        except Exception as e:
            return JSONResponse({"error": str(e)})
    return JSONResponse({"error": "remote avatars disabled"})


# === Command Injection endpoints ===

@app.get("/api/ping")
async def api_ping(host: str = "127.0.0.1") -> JSONResponse:
    """Command injection vulnerable endpoint"""
    import subprocess
    
    if settings.insecure_demo:
        try:
            # VULNERABLE: directly passing user input to shell
            result = subprocess.run(
                f"ping -c 1 {host}",
                shell=True,
                capture_output=True,
                text=True,
                timeout=5
            )
            return JSONResponse({
                "stdout": result.stdout,
                "stderr": result.stderr,
                "returncode": result.returncode
            })
        except Exception as e:
            return JSONResponse({"error": str(e)})
    else:
        # Safe version - validate input
        import re
        if not re.match(r'^[\d.]+$', host):
            return JSONResponse({"error": "invalid host"})
        try:
            result = subprocess.run(
                ["ping", "-c", "1", host],
                capture_output=True,
                text=True,
                timeout=5
            )
            return JSONResponse({"stdout": result.stdout})
        except Exception as e:
            return JSONResponse({"error": str(e)})


@app.get("/api/dns")
async def api_dns(domain: str = "example.com") -> JSONResponse:
    """Another command injection endpoint via nslookup"""
    import subprocess
    
    if settings.insecure_demo:
        try:
            result = subprocess.run(
                f"nslookup {domain}",
                shell=True,
                capture_output=True,
                text=True,
                timeout=5
            )
            return JSONResponse({"output": result.stdout})
        except Exception as e:
            return JSONResponse({"error": str(e)})
    return JSONResponse({"error": "dns lookup disabled"})


@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException) -> JSONResponse:
    return JSONResponse(status_code=exc.status_code, content={"detail": exc.detail})
