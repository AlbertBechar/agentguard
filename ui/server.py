"""
ui/server.py -- λεπτό FastAPI πάνω στο ui/service.py + σερβίρισμα του στατικού frontend (ui/static/).

    python ui/server.py [--port 8765] [--open]
    uvicorn ui.server:app --host 127.0.0.1 --port 8765

Ασφάλεια: δένει ΜΟΝΟ στο 127.0.0.1· ελέγχει Host/Origin (DNS rebinding / cross-site)· τα POST δέχονται μόνο application/json·
κάθε σφάλμα γίνεται JSON {"error": {"code", "message"}} στα ελληνικά· το traceback γράφεται ΜΟΝΟ στο log (χωρίς μυστικά).
"""
from __future__ import annotations

import argparse
import contextlib
import logging
import socket
import sys
import threading
import traceback
import webbrowser
from pathlib import Path
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from fastapi import Body, FastAPI, Request  # noqa: E402
from fastapi.exceptions import RequestValidationError  # noqa: E402
from fastapi.responses import JSONResponse, Response  # noqa: E402
from fastapi.staticfiles import StaticFiles  # noqa: E402
from starlette.exceptions import HTTPException as StarletteHTTPException  # noqa: E402

from ui import envfile, service  # noqa: E402
from ui.service import UIError, scrub  # noqa: E402

LOG = logging.getLogger("agentguard.ui")
STATIC_DIR = Path(__file__).resolve().parent / "static"
LOCAL_HOSTS = {"127.0.0.1", "localhost", "::1"}
DEFAULT_PORT = 8765
CSP = ("default-src 'self'; img-src 'self' data:; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; "
       "form-action 'self'")

@contextlib.asynccontextmanager
async def _lifespan(_app):
    """Στην εκκίνηση του server (όχι στο import): φόρτωση του AI_STUDIO_API_KEY από το .env της ρίζας, αν λείπει από το περιβάλλον."""
    names = envfile.load_env()
    if names:
        LOG.warning("loaded from .env: %s", ", ".join(names))      # μόνο ονόματα, ποτέ τιμές
    yield


app = FastAPI(title="AgentGuard Policy Copilot UI", docs_url=None, redoc_url=None, openapi_url=None, lifespan=_lifespan)


def _error(status: int, code: str, message: str) -> JSONResponse:
    return JSONResponse({"error": {"code": code, "message": message}}, status_code=status)


# ---------------------------------------------------------------------------
# Middleware: Host/Origin, τύπος περιεχομένου, κεφαλίδες ασφαλείας
# ---------------------------------------------------------------------------

@app.middleware("http")
async def _protect(request: Request, call_next):
    host = request.headers.get("host", "")
    try:
        hostname = urlsplit("//" + host).hostname
    except ValueError:
        hostname = None
    if hostname not in LOCAL_HOSTS:
        return _error(403, "host_not_allowed", "Η υπηρεσία απαντά μόνο σε τοπικές διευθύνσεις (127.0.0.1 / localhost).")
    if request.method not in ("GET", "HEAD", "OPTIONS"):
        origin = request.headers.get("origin")
        if origin and origin.split("://", 1)[-1] != host:
            return _error(403, "origin_not_allowed", "Το αίτημα προήλθε από άλλη ιστοσελίδα και απορρίφθηκε.")
        has_body = request.headers.get("content-length", "0") not in ("", "0") or "transfer-encoding" in request.headers
        if has_body and not request.headers.get("content-type", "").lower().startswith("application/json"):
            return _error(415, "content_type", "Τα αιτήματα πρέπει να στέλνονται ως application/json.")
    response = await call_next(request)
    response.headers["Content-Security-Policy"] = CSP
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Cache-Control"] = "no-store" if request.url.path.startswith("/api/") else "no-cache"
    return response


# ---------------------------------------------------------------------------
# Σφάλματα -> πάντα JSON στα ελληνικά
# ---------------------------------------------------------------------------

@app.exception_handler(UIError)
async def _on_ui_error(request: Request, exc: UIError):
    return JSONResponse(exc.payload(), status_code=exc.status)


@app.exception_handler(RequestValidationError)
async def _on_validation(request: Request, exc: RequestValidationError):
    return _error(422, "request_invalid", "Το αίτημα δεν έχει τη σωστή μορφή (περίμενα αντικείμενο JSON με τα απαιτούμενα πεδία).")


@app.exception_handler(StarletteHTTPException)
async def _on_http(request: Request, exc: StarletteHTTPException):
    texts = {404: ("not_found", "Δεν βρέθηκε η σελίδα ή η υπηρεσία που ζητήθηκε."),
             405: ("method_not_allowed", "Η μέθοδος αυτή δεν επιτρέπεται εδώ.")}
    code, message = texts.get(exc.status_code, ("http_error", "Το αίτημα δεν μπόρεσε να εξυπηρετηθεί."))
    return _error(exc.status_code, code, message)


@app.exception_handler(Exception)
async def _on_unhandled(request: Request, exc: Exception):
    LOG.error("unhandled error on %s %s:\n%s", request.method, request.url.path,
              scrub("".join(traceback.format_exception(type(exc), exc, exc.__traceback__))))
    return _error(500, "internal_error", "Παρουσιάστηκε εσωτερικό σφάλμα. Δοκίμασε ξανά· αν επιμένει, δες το log του server.")


# ---------------------------------------------------------------------------
# API (συγχρονισμένες συναρτήσεις: τρέχουν σε νήματα, όχι στον event loop)
# ---------------------------------------------------------------------------

@app.get("/api/status")
def api_status():
    return service.status()


@app.get("/api/presets")
def api_presets():
    return {"presets": service.list_presets()}


@app.post("/api/tools/parse")
def api_tools_parse(body: dict = Body(...)):
    return service.parse_tools(body.get("text"))


@app.post("/api/session")
def api_session(body: dict = Body(...)):
    return service.create_session(body)


@app.post("/api/session/{sid}/questions")
def api_questions(sid: str):
    return service.get_questions(sid)


@app.get("/api/session/{sid}/dry-run")
def api_dry_run(sid: str):
    return {"dry_run": service.get_dry_run(sid)}


@app.post("/api/session/{sid}/answers")
def api_answers(sid: str, body: dict = Body(...)):
    return service.submit_answers(sid, body.get("answers"))


@app.post("/api/session/{sid}/generate")
def api_generate(sid: str):
    return service.generate(sid)


@app.post("/api/session/{sid}/approve")
def api_approve(sid: str, body: dict = Body(...)):
    return service.approve(sid, body.get("by"), body.get("confirm"))


@app.get("/api/session/{sid}/snippet/{lang}")
def api_snippet(sid: str, lang: str):
    return service.snippet(sid, lang)


@app.get("/api/session/{sid}/download/{name}")
def api_download(sid: str, name: str):
    data, filename, media = service.download(sid, name)
    return Response(content=data, media_type=media, headers={"Content-Disposition": f'attachment; filename="{filename}"'})


@app.post("/api/session/{sid}/try")
def api_try(sid: str, body: dict = Body(...)):
    return service.try_decision(sid, body)


@app.post("/api/attack/run")
def api_attack(body: dict = Body(...)):
    return service.attack_run(body)


@app.get("/api/results")
def api_results():
    return service.results()


if STATIC_DIR.is_dir():
    app.mount("/", StaticFiles(directory=str(STATIC_DIR), html=True), name="static")   # τελευταίο: να μη σκιάζει το /api


# ---------------------------------------------------------------------------
# Εκκίνηση
# ---------------------------------------------------------------------------

def _port_free(port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        return s.connect_ex(("127.0.0.1", port)) != 0


def main(argv=None) -> int:
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8")
    parser = argparse.ArgumentParser(description="AgentGuard Policy Copilot -- web UI (μόνο στο 127.0.0.1)")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT, help=f"θύρα (προεπιλογή {DEFAULT_PORT})")
    parser.add_argument("--open", action="store_true", help="άνοιγμα του browser μόλις ξεκινήσει ο server")
    args = parser.parse_args(argv)
    if not 1 <= args.port <= 65535:
        sys.stdout.write("[FAIL] η θύρα πρέπει να είναι από 1 έως 65535.\n")
        return 2
    if not _port_free(args.port):
        sys.stdout.write(f"[FAIL] η θύρα {args.port} είναι ήδη σε χρήση. Δοκίμασε άλλη: python ui/server.py --port {args.port + 1}\n")
        return 2
    import uvicorn
    url = f"http://127.0.0.1:{args.port}/"
    sys.stdout.write(f"[OK] AgentGuard Studio: {url}   (Ctrl+C για έξοδο)\n")
    sys.stdout.flush()
    if args.open:
        threading.Timer(1.0, lambda: webbrowser.open(url)).start()
    uvicorn.run(app, host="127.0.0.1", port=args.port, log_level="warning", access_log=False)
    return 0


if __name__ == "__main__":
    sys.exit(main())
