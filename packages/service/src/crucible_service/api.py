"""The service's HTTP interface.

    POST /v2/keys                     {"registration": <base64 COSE_Sign1>} -> {"receipt"}
    POST /v2/batches                  {"batch": <base64 COSE_Sign1>}        -> {"receipt"}
    GET  /v2/receipts/{entry_hash}    -> {"receipt"}, the same one the append returned
    GET  /v2/checkpoint               -> {"tree_size", "checkpoint": <base64 COSE_Sign1>}
    GET  /v2/consistency?first&second -> {"first", "second", "proof"}
    GET  /v2/pubkey                   -> the service's public key
    GET  /v2/sessions/{id}/verify     -> the SPEC.md §7 report for that session
    GET  /v2/sessions/{id}/export     -> that session as crucible-chain/2 JSON lines, for
                                         `crucible-verify` to re-run with the key out of band
    GET  /                            -> the README (with --release-dir)
    GET  /install.sh                  -> the README's install as one script, for `curl ... | sh` (with --release-dir)
    GET  /client/                     -> the release's wheels, each with its sha256
    GET  /client/simple/[{project}/]  -> the same wheels as a PEP 503 index, the one the README installs from
    GET  /client/{file}               -> one of those wheels; /client/RELEASE.json, the release manifest;
                                         /client/constraints.txt, the client's third-party versions
    GET  /v2/health                   -> {"status", "service", "log_id", "tree_size"[, "last_pass"]};
                                         503 when the last liveness pass is older than the interval

Every refusal is ``{"error": <code>, "detail": <why>, ...}``. Over a rate limit
(``limits.py``) the answer is 429 ``rate_limited`` with ``Retry-After``. A chain break
says where (``at``) and where the client should continue
(``next_expected_seq``). An unreachable journal or signer is 503 with
``Retry-After``, and no receipt was issued. If the entry was appended but its
checkpoint could not yet be signed, the 503 says so (``receipt_pending``, with
the ``leaf_index``); sending the same request again returns its receipt.
"""

from __future__ import annotations

import base64
import html
import json
import time
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse, PlainTextResponse
from pydantic import BaseModel, ConfigDict
from starlette.exceptions import HTTPException

from crucible_core.canonical import is_digest

from .journal import JournalError
from .limits import Buckets, Limits, retry_after
from .log import LogError, ReceiptPending, Refusal
from .service import Service

MAX_BODY = 2 * 1024 * 1024
RETRY_AFTER = "5"


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class Registration(_Strict):
    registration: str


class BatchBody(_Strict):
    batch: str


def _error(status: int, code: str, detail: str, *, after: str | None = None, **extra) -> JSONResponse:
    headers = {"Retry-After": after or RETRY_AFTER} if status in (429, 503) else None
    return JSONResponse(status_code=status, content={"error": code, "detail": detail, **extra}, headers=headers)


class Limited(Exception):
    def __init__(self, what: str, wait: float) -> None:
        super().__init__(what)
        self.what, self.wait = what, wait




class _BodyLimit:
    """Refuses a body over ``MAX_BODY``, whether it declares its length or is chunked."""

    def __init__(self, app) -> None:
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        length = dict(scope["headers"]).get(b"content-length")
        if length is not None and (not length.isdigit() or int(length) > MAX_BODY):
            return await _error(413, "too_large", f"a request body is at most {MAX_BODY} bytes")(scope, receive, send)
        seen = 0

        async def limited():
            nonlocal seen
            message = await receive()
            if message["type"] == "http.request":
                seen += len(message.get("body", b""))
                if seen > MAX_BODY:
                    raise HTTPException(413, f"a request body is at most {MAX_BODY} bytes")
            return message

        return await self.app(scope, limited, send)


class Liveness:
    """The health gate (SPEC.md §5 Liveness): healthy only while the liveness probe's last
    pass is recent. A service just started has one interval to see its first pass."""

    def __init__(self, status: Path, interval: float, *, clock=time.time) -> None:
        self.status, self.interval, self.clock = status, interval, clock
        self.started = clock()

    def check(self) -> tuple[bool, int | None, str]:
        try:
            data = json.loads(self.status.read_text(encoding="utf-8"))
            last = data.get("last_pass") if isinstance(data, dict) else None
        except (OSError, ValueError):
            last = None
        now = self.clock()
        if isinstance(last, int) and not isinstance(last, bool):
            age = now - last / 1e6
            if age <= self.interval:
                return True, last, "ok"
            return False, last, f"the last liveness pass was {int(age // 60)} minutes ago"
        if now - self.started <= self.interval:
            return True, None, "ok (no liveness pass yet; the service started recently)"
        return False, None, "no liveness pass has been recorded"


class Release:
    """What a stranger needs from this address (docs/v1-audit.md §5 step 11): the README,
    and the client's wheels from the release the service runs, each checked against the
    sha256 its manifest records before it is served.

    The wheels are also a PEP 503 index (``/client/simple/``). The README installs
    with that index first and uv's first-index strategy, so a crucible-* name is
    resolved only here, never from a public index where anyone could claim it;
    each wheel pins its crucible-* dependencies to the release's version.
    ``published`` is where the service's key and log id are published apart from
    this machine (the status host), which the README tells the stranger to use. The
    installer (``install.sh``, when the release holds one) is the README's install as one
    script; it checks the key this service presents against the one published there."""

    def __init__(self, directory: Path, *, published: str) -> None:
        self.manifest = json.loads((directory / "RELEASE.json").read_text(encoding="utf-8"))
        self.readme = (directory / "README.md").read_text(encoding="utf-8")
        installer = directory / "install.sh"
        self.installer = installer.read_text(encoding="utf-8") if installer.is_file() else None
        self.published = published.rstrip("/")
        self.constraints = (directory / "constraints.txt").read_bytes()
        if sha256_bytes(self.constraints) != self.manifest["client_constraints_sha256"]:
            raise ValueError(f"{directory / 'constraints.txt'} does not hash to the sha256 its release records")
        self.files: dict[str, tuple[Path, str]] = {}
        self.projects: dict[str, list[str]] = {}
        for package, wheel in sorted(self.manifest["wheels"].items()):
            path = directory / "wheels" / wheel["file"]
            if sha256_file(path) != wheel["sha256"]:
                raise ValueError(f"{path} does not hash to the {wheel['sha256']} its release records")
            self.files[wheel["file"]] = (path, wheel["sha256"])
            self.projects.setdefault(package, []).append(wheel["file"])

    def render(self, service: Service, template: str | None = None) -> str:
        """The README (or ``template``) with this service's address, key, log and release filled in."""
        log = service.log
        values = {"service": log.service, "service_url": f"https://{log.service}", "key_id": log.signer.key_id,
                  "log_id": log.log_id, "version": str(self.manifest["version"]), "published": self.published}
        text = self.readme if template is None else template
        for name, value in values.items():
            text = text.replace("{" + name + "}", value)
        return text

    def index(self) -> str:
        rows = "".join(
            f'<li><a href="{html.escape(name)}#sha256={digest.removeprefix("sha256:")}">{html.escape(name)}</a>'
            f" <code>{digest}</code></li>\n"
            for name, (_path, digest) in sorted(self.files.items())
        )
        tag = html.escape(str(self.manifest.get("tag")))
        return (f"<!doctype html>\n<html><head><meta charset=\"utf-8\"><title>Crucible client {tag}</title></head>\n"
                f"<body><h1>Crucible client, release {tag}</h1>\n<ul>\n{rows}</ul></body></html>\n")

    def simple(self, project: str | None = None) -> str | None:
        """A PEP 503 page: the projects, or one project's wheels (None: not a project here)."""
        if project is None:
            links = "".join(f'<a href="{html.escape(p)}/">{html.escape(p)}</a>\n' for p in sorted(self.projects))
        elif project in self.projects:
            links = "".join(
                f'<a href="../../{html.escape(f)}#sha256={self.files[f][1].removeprefix("sha256:")}">{html.escape(f)}</a>\n'
                for f in self.projects[project]
            )
        else:
            return None
        return f"<!doctype html>\n<html><head><meta name=\"pypi:repository-version\" content=\"1.0\"></head><body>\n{links}</body></html>\n"


def sha256_bytes(data: bytes) -> str:
    import hashlib

    return "sha256:" + hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    import hashlib

    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return "sha256:" + h.hexdigest()


def create_app(service: Service, *, liveness: Liveness | None = None, release: Release | None = None,
               limits: Limits | None = None) -> FastAPI:
    app = FastAPI(title="crucible-service", docs_url=None, redoc_url=None, openapi_url=None)
    app.add_middleware(_BodyLimit)
    log = service.log

    def limit(buckets: Buckets | None, name: str, what: str) -> None:
        if limits is not None and buckets is not None and (wait := buckets.take(name)) is not None:
            raise Limited(what, wait)

    def address(request: Request) -> str:
        if limits is None:
            return ""
        return limits.address(request.client.host if request.client else None, request.headers.get("x-forwarded-for"))

    @app.exception_handler(Limited)
    async def limited(_request, exc: Limited):
        return _error(429, "rate_limited", f"too many requests from {exc.what}; send it again after the Retry-After",
                      after=retry_after(exc.wait))

    @app.exception_handler(HTTPException)
    async def http_error(_request, exc: HTTPException):
        codes = {404: "not_found", 405: "method_not_allowed", 413: "too_large"}
        return _error(exc.status_code, codes.get(exc.status_code, "http_error"), str(exc.detail))

    @app.exception_handler(Refusal)
    async def refused(_request, exc: Refusal):
        return _error(exc.status, exc.code, exc.detail, **exc.extra)

    @app.exception_handler(ReceiptPending)
    async def pending(_request, exc: ReceiptPending):
        return _error(503, "receipt_pending", f"{exc.detail}; send the same request again for its receipt",
                      leaf_index=exc.index)

    @app.exception_handler(JournalError)
    async def journal_down(_request, exc: JournalError):
        return _error(503, "journal_unavailable", f"the journal could not be reached, and no receipt was issued: {exc}")

    @app.exception_handler(LogError)
    async def log_broken(_request, exc: LogError):
        return _error(503, "log_unavailable", f"the journal holds something this service will not sign over, "
                                              f"so it accepts nothing until an operator looks: {exc}")

    @app.exception_handler(RequestValidationError)
    async def malformed(_request, exc: RequestValidationError):
        return _error(400, "malformed_request", "the request body does not have the required fields",
                      fields=[".".join(str(p) for p in e.get("loc", ())) for e in exc.errors()])

    reads = limits.read if limits is not None else None

    @app.post("/v2/keys")
    def register(body: Registration, request: Request):
        where = address(request)
        limit(limits and limits.batch_address, where, f"the address {where}")
        # A new key's leaf is charged to the address; registering a held key again appends nothing.
        new_key = (lambda: limit(limits.register, where, f"the address {where} (new keys)")) if limits else None
        return {"receipt": service.register(body.registration, admit=new_key)}

    @app.post("/v2/batches")
    def ingest(body: BatchBody, request: Request):
        where = address(request)
        limit(limits and limits.batch_address, where, f"the address {where}")
        # Charged only once the batch verifies against a registered key: a forger who knows a
        # key id cannot spend that key's allowance, and only registered key ids become names.
        per_key = (lambda kid: limit(limits.batch_key, kid, "this key")) if limits else None
        return {"receipt": service.ingest(body.batch, admit=per_key)}

    @app.get("/v2/receipts/{entry_hash}")
    def receipt(entry_hash: str, request: Request):
        limit(reads, address(request), f"the address {address(request)}")
        if not is_digest(entry_hash):
            raise Refusal("malformed_request", "an entry hash is a sha256 digest", 400)
        log.refresh()
        index = log.by_hash.get(entry_hash)
        if index is None:
            raise Refusal("unknown_entry", f"no entry {entry_hash} in this log", 404)
        return {"receipt": service.receipt_for(index)}

    @app.get("/v2/checkpoint")
    def checkpoint(request: Request):
        limit(reads, address(request), f"the address {address(request)}")
        log.refresh()
        size, env = log.checkpoint()
        return {"tree_size": size, "checkpoint": base64.b64encode(env).decode("ascii")}

    @app.get("/v2/consistency")
    def consistency(first: int, second: int, request: Request):
        limit(reads, address(request), f"the address {address(request)}")
        log.refresh()
        return {"first": first, "second": second, "proof": log.consistency(first, second)}

    @app.get("/v2/pubkey")
    def pubkey():
        return log.signer.public().to_dict()

    def held(session: str):
        record = service.session_record(session)
        if record is None:
            raise Refusal("unknown_session", f"this log holds no batch of session {session!r}", 404)
        return record

    @app.get("/v2/sessions/{session}/verify")
    def verify_session(session: str, request: Request):
        limit(reads, address(request), f"the address {address(request)}")
        return held(session).verify(log.signer.public()).to_json()

    @app.get("/v2/sessions/{session}/export")
    def export_session(session: str, request: Request):
        limit(reads, address(request), f"the address {address(request)}")
        return PlainTextResponse(held(session).export(), media_type="application/x-ndjson")

    if release is not None:
        from fastapi.responses import FileResponse, HTMLResponse, JSONResponse as Json

        @app.get("/")
        def readme():
            return PlainTextResponse(release.render(service), media_type="text/plain; charset=utf-8")

        @app.get("/install.sh")
        def installer():
            if release.installer is None:
                raise Refusal("not_found", "this release holds no installer", 404)
            return PlainTextResponse(release.render(service, release.installer), media_type="text/plain; charset=utf-8")

        @app.get("/client/")
        def client_index():
            return HTMLResponse(release.index())

        @app.get("/client/RELEASE.json")
        def client_manifest():
            return Json(release.manifest)

        @app.get("/client/constraints.txt")
        def client_constraints():
            return PlainTextResponse(release.constraints, media_type="text/plain; charset=utf-8")

        @app.get("/client/simple/")
        def simple_root():
            return HTMLResponse(release.simple())

        @app.get("/client/simple/{project}/")
        def simple_project(project: str):
            page = release.simple(project)
            if page is None:  # not a project of this release: the installer looks in the next index
                raise Refusal("not_found", f"{project!r} is not a project of this release", 404)
            return HTMLResponse(page)

        @app.get("/client/{name}")
        def client_file(name: str):
            if name not in release.files:
                raise Refusal("not_found", f"{name!r} is not a file of this release", 404)
            path, digest = release.files[name]
            return FileResponse(path, media_type="application/octet-stream", headers={"X-Content-SHA256": digest})

    @app.get("/v2/health")
    def health():
        log.refresh()
        body = {"status": "ok", "service": log.service, "log_id": log.log_id, "tree_size": log.size}
        if liveness is not None:
            ok, last, detail = liveness.check()
            body["last_pass"] = last
            if not ok:
                return _error(503, "stale", detail, **{k: v for k, v in body.items() if k != "status"})
        return body

    return app


__all__ = ["MAX_BODY", "Limits", "create_app"]
