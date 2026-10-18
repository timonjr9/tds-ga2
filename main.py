"""TDS GA2 - one FastAPI app covering Q3, Q4, Q5, Q7, Q8, Q10, Q11, Q12, Q13, Q14."""
import base64, hashlib, json, os, re, statistics, time, uuid
from collections import defaultdict, deque
from datetime import datetime, timezone

import jwt  # PyJWT
from fastapi import FastAPI, Request, Header, Query
from fastapi.responses import JSONResponse, PlainTextResponse, Response

EMAIL = "24f1001566@ds.study.iitm.ac.in"
EXAM_ORIGIN = "https://exam.sanand.workers.dev"
START = time.time()
app = FastAPI()

# ---------------------------------------------------------------- CORS (per path)
STRICT = {
    "/stats": {"https://dash-k89htg.example.com", EXAM_ORIGIN},
    "/ping": {"https://app-npke02.example.com", EXAM_ORIGIN},
}
EXPOSE = "X-Request-ID, X-Process-Time, Retry-After"

def allowed_origin(path, origin):
    if not origin:
        return None
    if path in STRICT:
        return origin if origin in STRICT[path] else None
    return "*"

# ---------------------------------------------------------------- metrics + logs
REQ_COUNT = defaultdict(int)  # (method, path, status) -> n
LOGS = deque(maxlen=1000)

@app.middleware("http")
async def everything(request: Request, call_next):
    path, origin = request.url.path, request.headers.get("origin")
    acao = allowed_origin(path, origin)
    rid = request.headers.get("x-request-id") or str(uuid.uuid4())
    request.state.request_id = rid
    t0 = time.perf_counter()

    if request.method == "OPTIONS" and request.headers.get("access-control-request-method"):
        if origin and not acao:
            resp = PlainTextResponse("CORS origin not allowed", status_code=400)
        else:
            resp = Response(status_code=204)
            resp.headers["Access-Control-Allow-Origin"] = acao or "*"
            resp.headers["Access-Control-Allow-Methods"] = "GET, POST, PUT, DELETE, OPTIONS"
            resp.headers["Access-Control-Allow-Headers"] = request.headers.get(
                "access-control-request-headers", "*") or "*"
            resp.headers["Access-Control-Max-Age"] = "600"
            if acao and acao != "*":
                resp.headers["Vary"] = "Origin"
    else:
        try:
            resp = await call_next(request)
        except Exception as e:  # never leak a bare 500 without CORS
            resp = JSONResponse({"error": str(e)}, status_code=500)
        if acao:
            resp.headers["Access-Control-Allow-Origin"] = acao
            resp.headers["Access-Control-Expose-Headers"] = EXPOSE
            if acao != "*":
                resp.headers["Vary"] = "Origin"

    resp.headers["X-Request-ID"] = rid
    resp.headers["X-Process-Time"] = f"{time.perf_counter() - t0:.6f}"
    REQ_COUNT[(request.method, path, resp.status_code)] += 1
    LOGS.append({"level": "info", "ts": datetime.now(timezone.utc).isoformat(),
                 "path": path, "method": request.method, "status": resp.status_code,
                 "request_id": rid})
    print(json.dumps(LOGS[-1]), flush=True)  # structured JSON log line
    return resp

@app.get("/")
def root():
    return {"ok": True, "email": EMAIL}

# ---------------------------------------------------------------- Q3 /stats
@app.get("/stats")
def stats(values: str = ""):
    nums = [int(x) for x in values.replace(" ", "").split(",") if x != ""]
    if not nums:
        return JSONResponse({"error": "no values"}, status_code=400)
    return {"email": EMAIL, "count": len(nums), "sum": sum(nums), "min": min(nums),
            "max": max(nums), "mean": statistics.fmean(nums)}

# ---------------------------------------------------------------- Q4 /verify
PUBKEY = """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA2okOHspNjgA+2rTLbeuY
cxiP/hG8C6Sb9iwg3yiLAA4HCnpITcbWCSelbvbYGuc3EbNy4xFyf5Cbj5DHJMID
EkryOgyd2giIIIBOUBj8S63uGcnRpOBh9NFatfNwheKuzsPuVNldu6A9cNteNpXc
WyJjG2axVfmq7i6SuKr1JoWYG7xTTAvKPujSl4OtsQfO3h5NepzdfXpr28oNnzfW
ed+zclR6BcmNNo/WVfJ4xyCLSf0BCOgdTgW6PdaChd1l9VDetJZVEgC5tkyvXsfI
SI6iyrYbKR0NEBSqq4XkadEjsCs4F1RncsS4LlgniT7GlkL9Mce3b0wGLs9/7ZIX
dQIDAQAB
-----END PUBLIC KEY-----"""
ISS, AUD = "https://idp.exam.local", "tds-3wjysnpu.apps.exam.local"

@app.post("/verify")
async def verify(request: Request):
    try:
        body = await request.json()
        claims = jwt.decode(body["token"], PUBKEY, algorithms=["RS256"], audience=AUD,
                            issuer=ISS, options={"require": ["exp", "iss", "aud"]})
    except Exception:
        return JSONResponse({"valid": False}, status_code=401)
    return {"valid": True, "email": claims.get("email"), "sub": claims.get("sub"),
            "aud": claims.get("aud")}

# ---------------------------------------------------------------- Q5 /effective-config
DEFAULTS = {"port": "8000", "workers": "1", "debug": "false", "log_level": "info",
            "api_key": "default-secret-000"}
YAML_LAYER = {"workers": "8", "debug": "false"}
DOTENV = {"APP_DEBUG": "false"}
OS_ENV = {"APP_WORKERS": "12", "APP_DEBUG": "true", "APP_LOG_LEVEL": "debug",
          "APP_API_KEY": "key-wfkive2tds"}
ALIASES = {"num_workers": "workers"}

def norm(k):
    k = k.strip().lower()
    if k.startswith("app_"):
        k = k[4:]
    return ALIASES.get(k, k)

def env_layer(d):
    return {norm(k): v for k, v in d.items()}

@app.get("/effective-config")
def effective_config(request: Request):
    cfg = dict(DEFAULTS)
    for layer in (YAML_LAYER, env_layer(DOTENV), env_layer(OS_ENV)):
        cfg.update({norm(k): str(v) for k, v in layer.items()})
    for s in request.query_params.getlist("set"):
        if "=" in s:
            k, v = s.split("=", 1)
            cfg[norm(k)] = v
    out = {}
    for k, v in cfg.items():
        if k in ("port", "workers"):
            out[k] = int(v)
        elif k == "debug":
            out[k] = str(v).strip().lower() in ("true", "1", "yes", "on")
        else:
            out[k] = str(v)
    out["api_key"] = "****"
    return out

# ---------------------------------------------------------------- Q7 /analytics
API_KEY = "ak_7ih8pc2293xuabl7lti8dh5a"

@app.post("/analytics")
async def analytics(request: Request, x_api_key: str | None = Header(None)):
    if x_api_key != API_KEY:
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    events = (await request.json()).get("events", [])
    per_user = defaultdict(float)
    for e in events:
        a = float(e.get("amount", 0) or 0)
        if a > 0:
            per_user[e["user"]] += a
    return {"email": EMAIL, "total_events": len(events),
            "unique_users": len({e.get("user") for e in events}),
            "revenue": round(sum(per_user.values()), 6),
            "top_user": max(per_user, key=per_user.get) if per_user else None}

# ---------------------------------------------------------------- Q8 observability
@app.get("/work")
def work(n: int = 1):
    s = 0
    for i in range(max(0, n) * 1000):
        s += i
    return {"email": EMAIL, "done": n}

@app.get("/metrics")
def metrics():
    lines = ["# HELP http_requests_total Total HTTP requests",
             "# TYPE http_requests_total counter"]
    for (m, p, s), n in REQ_COUNT.items():
        lines.append(f'http_requests_total{{method="{m}",path="{p}",status="{s}"}} {n}')
    lines.append(f"http_requests_total {sum(REQ_COUNT.values())}")  # unlabelled total
    return PlainTextResponse("\n".join(lines) + "\n",
                             media_type="text/plain; version=0.0.4")

@app.get("/healthz")
def healthz():
    return {"status": "ok", "uptime_s": time.time() - START}

@app.get("/logs/tail")
def logs_tail(limit: int = 20):
    return list(LOGS)[-max(1, limit):]

# ---------------------------------------------------------------- Q10 /extract
CUR = {"$": "USD", "€": "EUR", "£": "GBP"}

def regex_extract(text):
    vendor = None
    m = re.search(r"(?:vendor|from|supplier|seller|billed by|issued by)\s*[:\-]\s*(.+)", text, re.I)
    if m:
        vendor = m.group(1).strip().splitlines()[0].strip()
    if not vendor:
        m = re.search(r"([A-Z][\w&\-]*(?:\s+[A-Z][\w&\-]*)*\s+(?:Industries|Corp|Inc|LLC|Ltd|GmbH|Co)\.?(?:\s+Ltd\.?)?)", text)
        vendor = m.group(1) if m else ""
    amount, currency = None, None
    money = r"(USD|EUR|GBP|[$€£])?\s*([0-9][0-9,]*(?:\.[0-9]+)?)\s*(USD|EUR|GBP)?"
    for pat in (r"(?:total\s+(?:amount\s+)?due|amount\s+due|balance\s+due|grand\s+total)[^0-9$€£A-Z]{0,30}" + money,
                r"(?<!sub)(?<!sub-)\btotal\b[^0-9$€£A-Z]{0,30}" + money,
                money):
        m = re.search(pat, text, re.I)
        if m:
            amount = float(m.group(2).replace(",", ""))
            c = m.group(1) or m.group(3)
            if c:
                currency = CUR.get(c, c.upper())
            break
    if not currency:
        m = re.search(r"\b(USD|EUR|GBP)\b|([$€£])", text)
        currency = (m.group(1) or CUR[m.group(2)]) if m else "USD"
    date = None
    m = re.search(r"due[^0-9]{0,30}(\d{4}-\d{2}-\d{2})", text, re.I) or re.search(r"(\d{4}-\d{2}-\d{2})", text)
    if m:
        date = m.group(1)
    return {"vendor": vendor or "", "amount": amount or 0.0, "currency": currency, "date": date or ""}

def llm_extract(text):
    import httpx
    token = os.environ.get("AIPIPE_TOKEN")
    if not token:
        return None
    prompt = ("Extract invoice fields from the text. Reply ONLY with JSON having keys vendor (string), "
              "amount (number, the TOTAL DUE), currency (3-letter uppercase), date (payment DUE date, YYYY-MM-DD).\n\n" + text)
    r = httpx.post("https://aipipe.org/openai/v1/chat/completions", timeout=20,
                   headers={"Authorization": f"Bearer {token}"},
                   json={"model": "gpt-4.1-nano", "response_format": {"type": "json_object"},
                         "messages": [{"role": "user", "content": prompt}]})
    d = json.loads(r.json()["choices"][0]["message"]["content"])
    return {"vendor": str(d["vendor"]), "amount": float(d["amount"]),
            "currency": str(d["currency"]).upper()[:3], "date": str(d["date"])[:10]}

@app.post("/extract")
async def extract(request: Request):
    try:
        body = await request.json()
        text = body.get("text") if isinstance(body, dict) else None
    except Exception:
        text = None
    if not isinstance(text, str) or not text.strip():
        return JSONResponse({"detail": "text is required"}, status_code=422)
    try:
        res = llm_extract(text)
        if res:
            return res
    except Exception:
        pass
    return regex_extract(text)

# ---------------------------------------------------------------- rate limiter
BUCKETS = defaultdict(deque)

def limited(scope, client, limit, window=10.0):
    """Returns seconds to wait if over limit, else None (and records the hit)."""
    if not client:
        return None
    now, q = time.time(), BUCKETS[(scope, client)]
    while q and now - q[0] >= window:
        q.popleft()
    if len(q) >= limit:
        return max(1, int(window - (now - q[0])) + 1)
    q.append(now)
    return None

# ---------------------------------------------------------------- Q11 /orders
TOTAL_ORDERS, RATE_R = 59, 20
IDEMP = {}

def too_many(wait):
    return JSONResponse({"error": "rate limited"}, status_code=429,
                        headers={"Retry-After": str(wait)})

@app.post("/orders")
async def create_order(request: Request, idempotency_key: str | None = Header(None),
                       x_client_id: str | None = Header(None)):
    if (w := limited("orders", x_client_id, RATE_R)):
        return too_many(w)
    try:
        body = await request.json()
    except Exception:
        body = {}
    if idempotency_key and idempotency_key in IDEMP:
        return JSONResponse(IDEMP[idempotency_key], status_code=201)
    oid = ("ord_" + hashlib.sha256(idempotency_key.encode()).hexdigest()[:16]
           if idempotency_key else "ord_" + uuid.uuid4().hex[:16])
    order = {"id": oid, "status": "created", "item": body}
    if idempotency_key:
        IDEMP[idempotency_key] = order
    return JSONResponse(order, status_code=201)

@app.get("/orders")
def list_orders(limit: int = 10, cursor: str | None = None,
                x_client_id: str | None = Header(None)):
    if (w := limited("orders", x_client_id, RATE_R)):
        return too_many(w)
    limit = max(1, min(limit, 100))
    start = 0
    if cursor:
        try:
            start = int(base64.urlsafe_b64decode(cursor.encode()).decode())
        except Exception:
            return JSONResponse({"error": "bad cursor"}, status_code=400)
    ids = range(start + 1, min(start + limit, TOTAL_ORDERS) + 1)
    end = start + len(ids)
    nxt = base64.urlsafe_b64encode(str(end).encode()).decode() if end < TOTAL_ORDERS else None
    return {"items": [{"id": i, "status": "created"} for i in ids], "next_cursor": nxt}

# ---------------------------------------------------------------- Q12 /ping
@app.get("/ping")
def ping(request: Request, x_client_id: str | None = Header(None)):
    if (w := limited("ping", x_client_id, 11)):
        return too_many(w)
    return {"email": EMAIL, "request_id": request.state.request_id}

# ---------------------------------------------------------------- Q13 / Q14 static answers
@app.get("/q13")
def q13():
    return {"A": {"text": "Report job-c512b436: café\nReady ✓", "complete": True, "error": None},
            "B": {"text": "Partial job-c512b436", "complete": False, "error": None},
            "C": {"text": "Draft job-c512b436", "complete": False, "error": "model unloaded"}}

@app.get("/q14")
def q14():
    return {"A": {"steps": ["L3", "L4", "L5"], "seconds": 34},
            "B": {"steps": ["L1", "L2", "L3", "L4", "L5"], "seconds": 75},
            "C": {"steps": [], "seconds": 0},
            "D": {"steps": [], "seconds": 0},
            "E": {"steps": ["L4", "L5"], "seconds": 34}}
