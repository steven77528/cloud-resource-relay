"""Fixed read-only upstream routes and administrator-owned resource scopes."""

from urllib.parse import parse_qsl, urlsplit
import re

from .common import ProviderError


SUPPORTED_KINDS = {
    "qiniu": {"balance", "billing_snapshot", "resource_packages_month", "resource_packages",
              "kodo_usage", "cdn_usage", "cdn_status"},
    "huifu": {"balance", "settlements"},
    "asign": {"company_verification"},
    "wechat": {"api_quota", "charge_packages", "annual_review", "js_errors", "performance"},
}
SCOPE_KEYS = {
    ("qiniu", "kodo_usage"): "buckets",
    ("qiniu", "cdn_usage"): "domains",
    ("qiniu", "cdn_status"): "domains",
    ("wechat", "api_quota"): "cgi_paths",
    ("wechat", "charge_packages"): "spu_ids",
    ("asign", "company_verification"): "company_selectors",
    ("huifu", "settlements"): "orders",
}
OPEN_ENDPOINTS = {"https://oapi.asign.cn", "https://prev.asign.cn"}


def _deny():
    raise ProviderError("permission_denied")


def _fields(value, required, optional=()):
    if not isinstance(value, dict) or not set(required) <= set(value) or set(value) - set(required) - set(optional):
        _deny()


def _text(value, limit=256):
    if (not isinstance(value, str) or not value or len(value) > limit
            or any(ord(char) < 32 or ord(char) == 127 for char in value)):
        _deny()
    return value


def _pattern(value, pattern):
    if not re.fullmatch(pattern, _text(value)):
        _deny()


def _integer(value, minimum=0, maximum=1000000, *, query=False):
    if query:
        _pattern(value, r"0|[1-9][0-9]{0,9}")
        value = int(value)
    if type(value) is not int or not minimum <= value <= maximum:
        _deny()


def _selector(value):
    if not isinstance(value, dict) or len(value) != 1 or not set(value) <= {"account", "creditCode", "companyName"}:
        _deny()
    _text(next(iter(value.values())))


def _order(value):
    _fields(value, {"org_req_date", "org_req_seq_id"})
    _pattern(value["org_req_date"], r"[0-9]{8}")
    _pattern(value["org_req_seq_id"], r"[A-Za-z0-9_.:-]{1,128}")


def validate_scope(provider, kind, scope):
    try:
        if provider not in SUPPORTED_KINDS or kind not in SUPPORTED_KINDS[provider]:
            _deny()
        key = SCOPE_KEYS.get((provider, kind))
        _fields(scope, {key} if key else set())
        if key is None:
            return
        values = scope[key]
        if not isinstance(values, list) or not 1 <= len(values) <= 10000:
            _deny()
        for value in values:
            if key == "company_selectors":
                _selector(value)
            elif key == "orders":
                _order(value)
            elif key == "domains":
                _pattern(value, r"[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?")
            elif key == "cgi_paths":
                _pattern(value, r"/(?:[A-Za-z0-9_.-]+/)*[A-Za-z0-9_.-]+")
                if ".." in value.split("/") or "/sns/" in value:
                    _deny()
            else:
                _text(value)
        if len({repr(value) for value in values}) != len(values):
            _deny()
    except Exception:
        raise ProviderError("permission_denied") from None


def _qiniu(kind, host, path, method, query, body, scope):
    finance = {"balance": "/billing-api/v1/account/balance-overview",
               "billing_snapshot": "/billing-api/v2/bill/snapshot",
               "resource_packages_month": "/billing-api/v1/respack/month-overview",
               "resource_packages": "/billing-api/v1/respack/list"}
    if kind in finance:
        if (host, path, method) != ("api.qiniu.com", finance[kind], "GET"):
            _deny()
        if kind == "balance":
            _fields(query, set())
        elif kind == "billing_snapshot":
            _fields(query, {"date"})
            _pattern(query["date"], r"[0-9]{4}-[0-9]{2}-[0-9]{2}T00:00:00")
        else:
            _fields(query, {"page", "page_size"})
            _integer(query["page"], 1, 10000, query=True)
            _integer(query["page_size"], 1, 200, query=True)
    elif kind == "kodo_usage":
        if host != "api.qiniuapi.com" or path not in {"/v6/space", "/v6/count"} or method != "GET":
            _deny()
        _fields(query, {"begin", "end", "g", "bucket"})
        for field in ("begin", "end"):
            _pattern(query[field], r"[0-9]{14}")
        if query["g"] != "5min" or query["bucket"] not in scope["buckets"]:
            _deny()
    elif kind in {"cdn_usage", "cdn_status"}:
        paths = ({"/v2/tune/monitoring/flow", "/v2/tune/monitoring/bandwidth"}
                 if kind == "cdn_usage" else {"/v2/tune/loganalyze/statuscode"})
        if host != "fusion.qiniuapi.com" or path not in paths or method != "POST" or query:
            _deny()
        fields = {"domains", "startDate", "endDate"}
        _fields(body, fields | ({"granularity"} if kind == "cdn_usage" else {"freq", "region", "isp"}))
        for field in ("startDate", "endDate"):
            _pattern(body[field], r"[0-9]{4}-[0-9]{2}-[0-9]{2}")
        if kind == "cdn_usage":
            domains = _text(body["domains"], 16384).split(";")
            if body["granularity"] != "5min":
                _deny()
        else:
            domains = body["domains"]
            if (body["freq"], body["region"], body["isp"]) != ("5min", "global", "all"):
                _deny()
        if (not isinstance(domains, list) or not 1 <= len(domains) <= 50
                or any(not isinstance(item, str) or item not in scope["domains"] for item in domains)):
            _deny()
    else:
        _deny()


def _wechat(kind, host, path, method, query, body, scope):
    routes = {"api_quota": {("POST", "/cgi-bin/openapi/quota/get")},
              "charge_packages": {("GET", "/wxa/charge/usage/get")},
              "annual_review": {("GET", "/cgi-bin/account/getaccountbasicinfo"),
                                ("POST", "/cgi-bin/account/getaccountbasicinfo")},
              "js_errors": {("POST", "/wxaapi/log/jserr_list")},
              "performance": {("POST", "/wxaapi/log/get_performance")}}
    if host != "api.weixin.qq.com" or (method, path) not in routes[kind]:
        _deny()
    if kind == "charge_packages":
        _fields(query, {"spuId", "offset", "limit"})
        if query["spuId"] not in scope["spu_ids"]:
            _deny()
        _integer(query["offset"], 0, 1000000, query=True)
        _integer(query["limit"], 1, 20, query=True)
        return
    _fields(query, set())
    if kind == "api_quota":
        _fields(body, {"cgi_path"})
        if body["cgi_path"] not in scope["cgi_paths"]:
            _deny()
    elif kind == "annual_review":
        if body is not None and body != {}:
            _deny()
    elif kind == "js_errors":
        _fields(body, {"appVersion", "errType", "startTime", "endTime", "keyword", "openid",
                       "orderby", "desc", "offset", "limit"})
        _text(body["appVersion"], 128)
        if (body["errType"] not in {"0", "1", "2", "3"} or body["keyword"] != "" or body["openid"] != ""
                or body["orderby"] != "pv" or body["desc"] != "1"):
            _deny()
        for field in ("startTime", "endTime"):
            _pattern(body[field], r"[0-9]{4}-[0-9]{2}-[0-9]{2}")
        _integer(body["offset"])
        _integer(body["limit"], 1, 30)
    else:
        _fields(body, {"cost_time_type", "default_start_time", "default_end_time", "device",
                       "networktype", "scene", "is_download_code"})
        _integer(body["cost_time_type"], 1, 3)
        for field in ("default_start_time", "default_end_time"):
            _integer(body[field], 1, 9999999999)
        for field in ("device", "networktype", "scene", "is_download_code"):
            _text(body[field], 128)


def _asign(account, kind, origin, path, method, query, body, scope):
    if kind != "company_verification" or query:
        _deny()
    endpoint = account.get("endpoint", "https://oapi.asign.cn")
    if (account.get("api_mode") != "openapi" or endpoint not in OPEN_ENDPOINTS
            or origin != endpoint):
        _deny()
    if (method, path) != ("POST", "/user/getCompUser"):
        _deny()
    _selector(body)
    if body not in scope["company_selectors"]:
        _deny()


def _huifu(account, kind, host, path, method, query, body, scope):
    expected = "/v2/trade/acctpayment/balance/query" if kind == "balance" else "/v2/trade/settlement/query"
    if (host, path, method) != ("api.huifu.com", expected, "POST") or query:
        _deny()
    required = {"req_date", "req_seq_id", "acct_date"} if kind == "balance" else {"org_req_date", "org_req_seq_id"}
    _fields(body, required, {"huifu_id"})
    if "huifu_id" in body and body["huifu_id"] != account.get("huifu_id"):
        _deny()
    if kind == "balance":
        for field in ("req_date", "acct_date"):
            _pattern(body[field], r"[0-9]{8}")
        _pattern(body["req_seq_id"], r"[A-Za-z0-9_.:-]{1,128}")
    else:
        order = {field: body[field] for field in required}
        _order(order)
        if order not in scope["orders"]:
            _deny()


def validate_upstream(account, operation, request):
    """Deny before signing unless route, parameters and resources are pre-authorized."""
    try:
        provider, kind, scope = account["provider"], operation["kind"], operation.get("scope", {})
        validate_scope(provider, kind, scope)
        _fields(request, {"method", "url", "body"})
        method, url, body = request["method"], request["url"], request["body"]
        if method not in {"GET", "POST"} or (body is not None and not isinstance(body, dict)):
            _deny()
        if method == "GET" and body is not None:
            _deny()
        _text(url, 8192)
        if any(ord(char) < 33 or ord(char) > 126 or char == "\\" for char in url) or "#" in url:
            _deny()
        parsed = urlsplit(url)
        if (parsed.scheme != "https" or not parsed.hostname or parsed.username is not None
                or parsed.password is not None or parsed.netloc != parsed.hostname or parsed.fragment):
            _deny()
        pairs = parse_qsl(parsed.query, keep_blank_values=True, strict_parsing=True, max_num_fields=20)
        query = dict(pairs)
        if len(query) != len(pairs):
            _deny()
        if provider == "qiniu":
            _qiniu(kind, parsed.hostname, parsed.path, method, query, body, scope)
        elif provider == "wechat":
            _wechat(kind, parsed.hostname, parsed.path, method, query, body, scope)
        elif provider == "asign":
            _asign(account, kind, "https://" + parsed.netloc, parsed.path, method, query, body, scope)
        else:
            _huifu(account, kind, parsed.hostname, parsed.path, method, query, body, scope)
    except Exception:
        raise ProviderError("permission_denied") from None
