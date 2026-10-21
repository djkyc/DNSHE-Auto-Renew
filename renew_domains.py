#!/usr/bin/env python3
"""DNSHE 免费子域名多账号自动续期。

多账号通过 DNSHE_ACCOUNTS JSON 数组配置；不设置时兼容原来的单账号环境变量。
每个账号独立执行，所有账号的原格式报告汇总后统一推送。

接口行为依据官方文档《DNSHE免费域名API使用文档（V2.0)》:
https://my.dnshe.com/knowledgebase/13/DNSHE免费域名API使用文档V2.0.html
"""

import os
import re
import sys
import json
import time
import traceback
from dataclasses import dataclass, field, replace
from datetime import datetime, timedelta, timezone
from typing import Any, List, Optional

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

DEFAULT_BASE_URL = "https://api005.dnshe.com/index.php?m=domain_hub"

TELEGRAM_API_BASE = "https://api.telegram.org"

TELEGRAM_MESSAGE_LIMIT = 4096

REQUEST_TIMEOUT = (10, 30)

DEFAULT_THRESHOLD_DAYS = 180

DEFAULT_MIN_INTERVAL = 2

DEFAULT_TZ_OFFSET_HOURS = 8.0

# 文档：per_page 上限 500，超过会被服务端截到 500。取上限可减少大账户的
# 翻页次数，也就减少了触发限流的概率。
PAGE_SIZE = 500
MAX_PAGES = 100

LIST_FIELDS = "id,subdomain,rootdomain,full_domain,status,expires_at,never_expires"

EXPIRY_FORMATS = ('%Y-%m-%d %H:%M:%S', '%Y-%m-%d %H:%M', '%Y-%m-%d')

BENIGN_ERROR_CODES = frozenset({'renewal_not_yet_available'})

# 官方文档「Common Error Codes」里对使用者有行动指引的那几条，翻译成下一步该做什么。
ERROR_HINTS = {
    'auth_invalid_credentials': 'API Key/Secret 无效，请到 DNSHE 后台重新创建',
    'auth_ip_not_allowed': '当前出口 IP 不在该密钥的白名单内',
    'api_access_disabled': 'DNSHE 后台已关闭 API 访问',
    'quota_exceeded': '账户额度不足',
    'rate_limit_exceeded': '触发接口频率限制，请调大 DNSHE_MIN_INTERVAL',
    'provider_operation_failed': '上游 DNS 服务商操作失败，稍后重试',
    'internal_error': 'DNSHE 服务端内部错误',
    'subdomain_not_found': '域名不存在或不属于当前 API Key',
    'not_found': '资源不存在',
    'bad_request': '请求参数有误',
}

# 实测线上接口的 status 返回 "Registered"（首字母大写），而文档写的是 active/suspended/expired。
# 两种口径都按正常状态处理，其余一律在报告里显式标注。
NORMAL_STATUSES = frozenset({'active', 'registered'})

_TRUE_WORDS = frozenset({'1', 'true', 'yes', 'y', 'on', 't'})
_FALSE_WORDS = frozenset({'0', 'false', 'no', 'n', 'off', 'f', '', 'none', 'null'})


class ApiError(RuntimeError):
    """DNSHE 接口调用失败（含响应结构不符合预期）。"""


def to_bool(value, default=False, label=''):
    """把接口返回值稳妥地转成布尔。

    不能直接用 bool()：PHP 后端把 tinyint 序列化成字符串是常见行为，
    而 bool("0") / bool("false") 都是 True —— 对 never_expires 来说，
    这个误判会让域名被永久跳过、报告还显示「永不过期」，属于最坏的静默失效。
    """
    if isinstance(value, bool):
        return value
    if value is None:
        return default
    if isinstance(value, (int, float)):
        return value != 0

    text = str(value).strip().lower()
    if text in _TRUE_WORDS:
        return True
    if text in _FALSE_WORDS:
        return False

    warn(f"{label or '布尔字段'}={value!r} 无法识别，按 {default} 处理")
    return default


def parse_id(value):
    """把 id 归一成 int；无法转换时返回 None（交给上层报「缺少 id」）。

    接口有时把数字序列化成字符串（"12"），原样透传给续期接口虽然大概率
    能用，但一旦服务端做严格类型校验就会失败，且报错指向不明。
    """
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return None


def configure_streams():
    """报告含 emoji，非 UTF-8 终端（如 Windows GBK）下 print 会抛 UnicodeEncodeError。"""
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, 'reconfigure', None)
        if reconfigure is not None:
            try:
                reconfigure(encoding='utf-8', errors='replace')
            except ValueError:
                pass


def warn(message):
    print(f"警告: {message}", file=sys.stderr)


def parse_tz_offset(raw, default_hours=DEFAULT_TZ_OFFSET_HOURS):
    """解析形如 '+8' / '8' / '-5' / '+5.5' 的时区偏移，非法值回退到默认。"""
    if raw is None or not str(raw).strip():
        return timezone(timedelta(hours=default_hours))
    try:
        hours = float(str(raw).strip())
    except ValueError:
        warn(f"DNSHE_TZ_OFFSET={raw!r} 不是合法数字，回退到 UTC+{default_hours:g}")
        return timezone(timedelta(hours=default_hours))
    if not -24 < hours < 24:
        warn(f"DNSHE_TZ_OFFSET={raw!r} 超出范围，回退到 UTC+{default_hours:g}")
        return timezone(timedelta(hours=default_hours))
    return timezone(timedelta(hours=hours))


def env_number(env, name, default, cast):
    raw = env.get(name)
    if raw is None or not str(raw).strip():
        return default
    try:
        return cast(str(raw).strip())
    except ValueError:
        warn(f"{name}={raw!r} 不是合法数值，回退到默认值 {default}")
        return default


def format_offset(tz):
    """把 tzinfo 渲染成 'UTC+8' 这类可读文本，用于在报告里显式声明时区假设。"""
    total_minutes = int(tz.utcoffset(None).total_seconds() // 60)
    sign = '+' if total_minutes >= 0 else '-'
    hours, minutes = divmod(abs(total_minutes), 60)
    return f"UTC{sign}{hours}" + (f":{minutes:02d}" if minutes else "")


@dataclass(frozen=True)
class Config:
    api_key: str = ""
    api_secret: str = ""
    wechat_api_url: str = ""
    wechat_auth_token: str = ""
    telegram_bot_token: str = ""
    telegram_chat_id: str = ""
    base_url: str = DEFAULT_BASE_URL
    threshold_days: int = DEFAULT_THRESHOLD_DAYS
    min_interval: float = DEFAULT_MIN_INTERVAL
    tz: timezone = field(default_factory=lambda: timezone(timedelta(hours=DEFAULT_TZ_OFFSET_HOURS)))

    @classmethod
    def from_env(cls, env=None):
        env = os.environ if env is None else env

        def text(name):
            return (env.get(name) or '').strip()

        return cls(
            api_key=text('DNSHE_API_KEY'),
            api_secret=text('DNSHE_API_SECRET'),
            wechat_api_url=text('WECHAT_API_URL'),
            wechat_auth_token=text('WECHAT_AUTH_TOKEN'),
            telegram_bot_token=text('TELEGRAM_BOT_TOKEN'),
            telegram_chat_id=text('TELEGRAM_CHAT_ID'),
            base_url=text('DNSHE_API_BASE_URL') or DEFAULT_BASE_URL,
            threshold_days=env_number(env, 'DNSHE_RENEW_THRESHOLD_DAYS',
                                      DEFAULT_THRESHOLD_DAYS, int),
            min_interval=env_number(env, 'DNSHE_MIN_INTERVAL',
                                    DEFAULT_MIN_INTERVAL, float),
            tz=parse_tz_offset(env.get('DNSHE_TZ_OFFSET')),
        )

    def missing_credentials(self):
        """返回缺失的必需环境变量名，用于启动时 fail-fast。"""
        return [name for name, value in (('DNSHE_API_KEY', self.api_key),
                                        ('DNSHE_API_SECRET', self.api_secret))
                if not value]


class Throttle:
    """保证相邻两次 API 调用间隔不小于 min_interval，避免撞 60 次/分钟限流。"""

    def __init__(self, min_interval, sleep=time.sleep, clock=time.monotonic):
        self.min_interval = min_interval
        self._sleep = sleep
        self._clock = clock
        self._last = None

    def wait(self):
        if self.min_interval <= 0:
            return
        if self._last is not None:
            remaining = self.min_interval - (self._clock() - self._last)
            if remaining > 0:
                self._sleep(remaining)
        self._last = self._clock()


def build_session(retry):
    session = requests.Session()
    adapter = HTTPAdapter(max_retries=retry)
    session.mount('https://', adapter)
    session.mount('http://', adapter)
    return session


def read_retry():
    """只读请求可以放心对连接错误、读超时、5xx、429 全面重试。"""
    return Retry(total=4, connect=3, read=3, status=3,
                 status_forcelist=(429, 500, 502, 503, 504),
                 allowed_methods=frozenset(['GET']),
                 backoff_factor=2, respect_retry_after_header=True)


def renew_retry():
    """续期会扣积分且不保证幂等，只重试确定没有产生副作用的情形。

    connect 错误发生在请求发出之前，429 是服务端明确拒收，两者都安全。
    读超时和 5xx 不重试——服务端可能已经扣过积分，重试会重复消耗。
    """
    return Retry(total=3, connect=3, read=0, status=2,
                 status_forcelist=(429,),
                 allowed_methods=frozenset(['POST']),
                 backoff_factor=2, respect_retry_after_header=True)


def notify_retry():
    """重复推送只是轻微骚扰，收不到通知才是真问题，所以推送重试更激进。"""
    return Retry(total=3, connect=2, read=2, status=2,
                 status_forcelist=(429, 500, 502, 503, 504),
                 allowed_methods=frozenset(['POST']),
                 backoff_factor=1, respect_retry_after_header=True)


def describe_error(payload, fallback='未知错误'):
    """按官方统一错误结构拼出可读信息：error_code + message + details。

    文档里 422 的 days_until_window / seconds_until_window 是「还要等多久」
    这个最有用的信息，不能只留一句「尚未进入窗口」。
    """
    if not isinstance(payload, dict):
        return fallback

    message = payload.get('message') or payload.get('error') or fallback
    code = payload.get('error_code')
    text = f"{message} [{code}]" if code else str(message)

    details = payload.get('details')
    details = details if isinstance(details, dict) else {}

    def pick(key):
        """顶层与 details 两处都找：不同错误码把字段放在不同层级。"""
        for source in (details, payload):
            if source.get(key) is not None:
                return source[key]
        return None

    extra = [f"{k}={pick(k)}" for k in ('limit', 'remaining', 'reset_at')
             if pick(k) is not None]
    if extra:
        text += f" ({', '.join(extra)})"

    days = pick('days_until_window')
    if days is not None:
        text += f"，还需等待 {days} 天"
    elif pick('seconds_until_window') is not None:
        text += f"，还需等待约 {max(1, int(pick('seconds_until_window')) // 86400)} 天"

    hint = ERROR_HINTS.get(code)
    if hint:
        text += f" —— {hint}"
    return text


def is_failure_payload(payload):
    return payload.get('success') is False or bool(payload.get('error_code'))


class DnsheClient:
    def __init__(self, config, throttle=None, list_session=None, renew_session=None):
        self.config = config
        self.throttle = throttle or Throttle(config.min_interval)
        self.list_session = list_session or build_session(read_retry())
        self.renew_session = renew_session or build_session(renew_retry())

    def _headers(self):
        return {
            "X-API-Key": self.config.api_key,
            "X-API-Secret": self.config.api_secret,
            "Content-Type": "application/json",
        }

    @staticmethod
    def _payload(resp, what):
        """解析响应体；解析不了时抛出带状态码的接口异常。"""
        try:
            payload = resp.json()
        except ValueError:
            raise ApiError(
                f"{what}返回非 JSON 内容 (HTTP {resp.status_code}): "
                f"{(resp.text or '')[:300]}"
            ) from None

        if not isinstance(payload, dict):
            raise ApiError(f"{what}返回格式异常: 预期 JSON 对象，实际为 {type(payload).__name__}")

        if resp.status_code >= 400:
            detail = describe_error(payload, fallback=(resp.text or '')[:200])
            raise ApiError(f"{what}失败 (HTTP {resp.status_code}): {detail}")

        if is_failure_payload(payload):
            raise ApiError(f"{what}失败: {describe_error(payload)}")

        return payload

    def _request(self, session, method, params=None, body=None, what='DNSHE API'):
        self.throttle.wait()
        url = self.config.base_url
        try:
            resp = session.request(
                method,
                url,
                params=params,
                json=body,
                headers=self._headers(),
                timeout=REQUEST_TIMEOUT,
            )
        except requests.RequestException as e:
            raise ApiError(f"{what}网络请求失败: {e}") from e

        return self._payload(resp, what)

    def fetch_subdomains(self):
        """分页读取全部子域名；防止服务端忽略 page 参数造成无限循环。"""
        all_items = []
        seen_ids = set()

        for page in range(1, MAX_PAGES + 1):
            params = {
                "action": "list_subdomains",
                "page": page,
                "per_page": PAGE_SIZE,
                "fields": LIST_FIELDS,
            }
            payload = self._request(
                self.list_session, "GET", params=params, what=f"获取域名列表第 {page} 页"
            )

            data = payload.get("data")
            if isinstance(data, dict):
                items = data.get("items")
                if items is None:
                    items = data.get("subdomains")
                meta = data.get("pagination") or data.get("meta") or {}
            elif isinstance(data, list):
                items = data
                meta = {}
            else:
                items = payload.get("items") or payload.get("subdomains") or []
                meta = payload.get("pagination") or payload.get("meta") or {}

            if not isinstance(items, list):
                raise ApiError(f"域名列表第 {page} 页结构异常：items 不是数组")

            if not items:
                break

            new_items = []
            for item in items:
                if not isinstance(item, dict):
                    continue
                item_id = parse_id(item.get("id"))
                if item_id is not None:
                    if item_id in seen_ids:
                        continue
                    seen_ids.add(item_id)
                new_items.append(item)

            all_items.extend(new_items)

            # 先看服务端明确的分页元数据。
            total_pages = meta.get("total_pages") or meta.get("last_page")
            current_page = meta.get("current_page") or page
            if total_pages is not None:
                try:
                    if int(current_page) >= int(total_pages):
                        break
                    continue
                except (TypeError, ValueError):
                    pass

            # 没有分页元数据时，短页通常表示结束。
            if len(items) < PAGE_SIZE:
                break
        else:
            raise ApiError(f"域名列表超过最大分页数 {MAX_PAGES}，为避免漏数据已停止")

        return all_items

    def fetch_quota(self):
        """查询账户积分；具体字段因后端版本可能不同，统一交给 quota_line 兼容。"""
        payload = self._request(
            self.list_session, "GET",
            params={"action": "get_quota"},
            what="查询账户积分",
        )
        data = payload.get("data")
        return data if isinstance(data, dict) else payload

    def renew(self, subdomain_id):
        """提交续期请求。只在 connect/明确 429 时重试，避免重复扣积分。"""
        payload = self._request(
            self.renew_session, "POST",
            body={"action": "renew_subdomain", "id": subdomain_id},
            what=f"续期域名 ID {subdomain_id}",
        )
        data = payload.get("data")
        return data if isinstance(data, dict) else payload


@dataclass
class DomainView:
    subdomain_id: Optional[int]
    label: str
    status: str
    expires_raw: Any
    expires_at: Optional[datetime]
    never_expires: bool
    days_remaining: Optional[int]
    problem: Optional[str] = None


def parse_expiry(value, tz):
    """解析 DNSHE 常见到期时间格式，返回带指定时区的 datetime。"""
    if value is None or not str(value).strip():
        return None

    text = str(value).strip()
    for fmt in EXPIRY_FORMATS:
        try:
            parsed = datetime.strptime(text, fmt)
            return parsed.replace(tzinfo=tz)
        except ValueError:
            continue

    try:
        parsed = datetime.fromisoformat(text.replace('Z', '+00:00'))
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=tz)
        return parsed.astimezone(tz)
    except ValueError:
        return None


def inspect_domain(raw, index, now, tz):
    """把 API 原始对象转成统一视图；字段异常显式报告，绝不静默跳过。"""
    if not isinstance(raw, dict):
        return DomainView(None, f"第 {index + 1} 条记录", "unknown", None,
                          None, False, None, "域名记录不是 JSON 对象")

    subdomain_id = parse_id(raw.get("id"))
    subdomain = raw.get("full_domain")
    if not subdomain:
        label_parts = [raw.get("subdomain"), raw.get("rootdomain")]
        subdomain = ".".join(str(x) for x in label_parts if x)
    label = str(subdomain or f"第 {index + 1} 条记录")

    status = str(raw.get("status") or "unknown").strip().lower()
    never_expires = to_bool(raw.get("never_expires"), default=False,
                            label=f"{label}.never_expires")

    expires_raw = raw.get("expires_at")
    expires_at = parse_expiry(expires_raw, tz)
    problem = None

    if subdomain_id is None:
        problem = "缺少有效的域名 ID，无法续期"
    elif status not in NORMAL_STATUSES:
        problem = f"状态为 {raw.get('status')!r}，不是正常状态"

    if not never_expires and expires_raw and expires_at is None:
        problem = f"无法解析到期时间 {expires_raw!r}"

    days_remaining = (expires_at - now.astimezone(tz)).days if expires_at else None
    return DomainView(subdomain_id, label, status, expires_raw, expires_at,
                      never_expires, days_remaining, problem)


def describe_remaining(view, now):
    if view.expires_at is None:
        return "到期时间未知"
    days = (view.expires_at - now.astimezone(view.expires_at.tzinfo)).days
    if days < 0:
        return f"已过期 {-days} 天"
    return f"剩余 {days} 天"


def decide(view, threshold_days, now):
    """决定域名操作：invalid / never / skip / renew。"""
    if view.problem:
        return 'invalid'
    if view.never_expires:
        return 'never'
    if view.expires_at is None:
        view.problem = "到期时间缺失，无法安全判断是否应续期"
        return 'invalid'

    days = (view.expires_at - now.astimezone(view.expires_at.tzinfo)).days
    if days < 0:
        view.problem = f"域名已过期（{describe_remaining(view, now)}），跳过自动续期"
        return 'invalid'
    if days > threshold_days:
        return 'skip'
    return 'renew'


def expiry_line(view, now):
    if view.never_expires:
        expiry = "永不过期"
    elif view.expires_at:
        expiry = view.expires_at.strftime('%Y-%m-%d %H:%M:%S')
    else:
        expiry = f"无法识别（原始值：{view.expires_raw!r}）"

    remaining = describe_remaining(view, now) if not view.never_expires else "永久"
    status = view.status or "unknown"
    note = f"；异常：{view.problem}" if view.problem else ""
    return f"- {view.label} | 状态：{status} | 到期：{expiry} | {remaining}{note}"


def mark(view, line):
    """在续期结果行后补上域名 ID，便于到 DNSHE 后台定位。"""
    return f"{line} [ID={view.subdomain_id}]" if view.subdomain_id is not None else line


def format_charge(value):
    if value is None:
        return "扣除积分未知"
    try:
        amount = float(value)
    except (TypeError, ValueError):
        return f"扣除积分 {value}"
    if amount.is_integer():
        return f"扣除积分 {int(amount)}"
    return f"扣除积分 {amount:g}"


def quota_line(quota):
    """兼容不同版本积分字段；查不到字段时保留原始结构，避免虚报为 0。"""
    if not isinstance(quota, dict):
        return f"账户积分：查询结果格式异常（{str(quota)[:120]}）"

    available = next((quota[k] for k in (
        'available', 'balance', 'remaining', 'credits', 'points', 'quota'
    ) if quota.get(k) is not None), None)
    total = next((quota[k] for k in ('total', 'total_quota', 'limit')
                  if quota.get(k) is not None), None)

    parts = [f"可用 {available}" if available is not None else None,
             f"总额 {total}" if total is not None else None]
    summary = "，".join(p for p in parts if p) or str(quota)[:120]

    try:
        if available is not None and float(available) <= 0:
            return f"⚠️ 账户积分：{summary}（积分已耗尽，付费续期将失败）"
    except (TypeError, ValueError):
        pass
    return f"账户积分：{summary}"


class WeChatNotifier:
    """调用用户自建的微信通知接口。"""

    def __init__(self, api_url, auth_token, session=None):
        self.api_url = (api_url or '').strip()
        self.auth_token = (auth_token or '').strip()
        self.session = session or build_session(notify_retry())

    def send(self, content):
        """HTTP 200 视为接口接收成功；异常在此处理，不中断其他通知通道。"""
        if not self.api_url or not self.auth_token:
            print("未完整配置自建微信推送，跳过微信通知")
            return True

        try:
            resp = self.session.post(
                self.api_url,
                headers={
                    "Authorization": self.auth_token,
                    "Content-Type": "application/json",
                },
                json={"content": content},
                timeout=REQUEST_TIMEOUT,
            )
            if resp.status_code == 200:
                print("自建微信推送成功")
                return True
            detail = redact((resp.text or '')[:300], (self.auth_token,))
            warn(f"自建微信推送失败 (HTTP {resp.status_code}): {detail}")
            return False
        except Exception as e:
            warn(f"自建微信推送异常: {redact(e, (self.auth_token,))}")
            return False


def utf16_len(text):
    """按 UTF-16 码元计长度。

    Telegram 的 4096 上限是 UTF-16 code unit，不是 Python 的字符数：
    BMP 外的 emoji（😀🎉🚀 等）在 UTF-16 里占 2 个码元，用 len() 会低估，
    切出来的消息可能超限被拒（400 MESSAGE_TOO_LONG）。
    """
    return len(text.encode('utf-16-le')) // 2


def split_message(content, limit=TELEGRAM_MESSAGE_LIMIT):
    """把超长报告切成若干条不超过 limit 个 UTF-16 码元的消息。

    优先在最近的换行处断开，避免把一行域名记录切成两半；
    单行本身就超限时才在行内硬切。
    """
    chunks = []
    remaining = content
    while utf16_len(remaining) > limit:
        # 先定位「不超过 limit 个码元」的最长前缀，再在其中找换行
        hard = _utf16_prefix_len(remaining, limit)
        cut = remaining.rfind('\n', 0, hard + 1)
        if cut <= 0:
            cut = hard
        chunks.append(remaining[:cut])
        remaining = remaining[cut:].lstrip('\n')
    chunks.append(remaining)
    return chunks


def _utf16_prefix_len(text, limit):
    """返回不超过 limit 个 UTF-16 码元的最长前缀长度（按字符计）。"""
    used = 0
    for index, char in enumerate(text):
        used += 2 if ord(char) > 0xFFFF else 1
        if used > limit:
            return index
    return len(text)


def redact(text, secrets=()):
    """把日志文本里出现的密钥替换成占位符。

    requests 的连接异常消息会带上完整 URL，而 Telegram 的 URL 里就嵌着
    bot token（/bot<token>/sendMessage）。公开仓库的 Actions 日志人人可见，
    不脱敏等于把 token 直接写进日志。
    """
    result = str(text)
    for secret in secrets:
        # 太短的串（如测试里的单字符 token）做全局替换会把正常文本也切碎，
        # 反而毁掉错误信息。真实 token 都远超这个长度。
        if secret and len(secret) >= 8:
            result = result.replace(secret, '<已脱敏>')
    # 兜底：即使没拿到 token 值，也把 /bot<...>/ 这种形状抹掉
    result = re.sub(r'/bot[^/\s]+/', '/bot<已脱敏>/', result)
    return result


def telegram_error_detail(resp, bot_token=''):
    """提取错误响应体里的原因。

    Telegram 的 4xx/5xx 响应体带 JSON description（如「bot was blocked by
    the user」），比状态码本身有用得多；非 JSON 时退回原文片段。
    """
    try:
        payload = resp.json()
    except ValueError:
        return redact((resp.text or '')[:200], (bot_token,))
    if isinstance(payload, dict) and payload.get('description'):
        return redact(str(payload['description']), (bot_token,))
    return redact(str(payload)[:200], (bot_token,))


class TelegramNotifier:
    """通过 Telegram Bot API 推送，纯文本发送，超长报告自动分段顺序发送。

    不用 parse_mode：报告含 emoji、域名和接口错误原文，Markdown 转义
    易漏易错且没有收益。
    """

    def __init__(self, bot_token, chat_id, session=None):
        self.bot_token = bot_token
        self.chat_id = chat_id
        self.session = session or build_session(notify_retry())

    def send(self, content):
        """返回是否全部发送成功。本方法绝不抛异常，否则会吞掉它要上报的错误。"""
        if not self.bot_token or not self.chat_id:
            print("未配置 Telegram Bot Token 或 Chat ID，跳过推送")
            return True

        url = f"{TELEGRAM_API_BASE}/bot{self.bot_token}/sendMessage"
        ok = True
        for index, chunk in enumerate(split_message(content), start=1):
            data = {"chat_id": self.chat_id, "text": chunk}
            try:
                resp = self.session.post(url, json=data, timeout=REQUEST_TIMEOUT)
                resp.raise_for_status()
                try:
                    result = resp.json()
                except ValueError:
                    warn(f"Telegram 返回非 JSON 内容: "
                         f"{redact((resp.text or '')[:200], (self.bot_token,))}")
                    ok = False
                    continue
                # Telegram 约定 ok=true 为成功；ok=false 时 description 带原因。
                # 响应不是 dict 时不能直接 .get()，否则 AttributeError 会被
                # 下面的 except 吞成「推送失败」，看不出真实原因。
                if not isinstance(result, dict):
                    warn(f"Telegram 第 {index} 段响应格式异常: "
                         f"{redact(str(result)[:200], (self.bot_token,))}")
                    ok = False
                elif not result.get('ok'):
                    warn(f"Telegram 第 {index} 段推送未成功: "
                         f"{redact(str(result.get('description', result)), (self.bot_token,))}")
                    ok = False
            except Exception as e:
                # raise_for_status 抛出的 HTTPError 带着响应体，里面的
                # description 才是 403/400 的真正原因，不能只报状态码
                err_resp = getattr(e, 'response', None)
                if err_resp is not None:
                    warn(f"Telegram 第 {index} 段推送失败 "
                         f"(HTTP {err_resp.status_code}): "
                         f"{telegram_error_detail(err_resp, self.bot_token)}")
                else:
                    # 连接异常的消息里带着含 token 的 URL，必须脱敏
                    warn(f"Telegram 第 {index} 段推送失败: "
                         f"{redact(e, (self.bot_token,))}")
                ok = False
        if ok:
            print("Telegram 推送成功")
        return ok


class CompositeNotifier:
    """把报告分发给所有已配置的通知通道。

    失败语义：只要有「任一」通道送达就算送达。一个通知通道成功、另一个
    通道偶发失败时，不应把已成功送达的整轮运行误报为失败。全部通道都失败才算推送失败。

    - 未配置任何通道：提示后视为成功
    - 所有已配置通道都失败：返回 False，让进程以退出码 1 收场
    """

    def __init__(self, channels):
        self.channels = channels

    def send(self, content):
        if not self.channels:
            print("未配置任何通知通道，跳过推送")
            return True
        # 不能用 all(...)：all() 遇到第一个 False 就短路，后面的通道根本不会
        # 被调用。一个通道挂掉时，其他备份通道仍必须尝试发送。
        results = [channel.send(content) for channel in self.channels]
        delivered = any(results)
        if not delivered:
            warn(f"所有 {len(results)} 个通知通道均推送失败")
        elif not all(results):
            warn("部分通知通道推送失败，但报告已通过其余通道送达")
        return delivered


def build_notifier(config):
    """按 Config 装配所有已配置的通知通道，供主流程与异常兜底共用。"""
    channels = []
    if config.wechat_api_url and config.wechat_auth_token:
        channels.append(WeChatNotifier(config.wechat_api_url, config.wechat_auth_token))
    elif config.wechat_api_url or config.wechat_auth_token:
        warn("WECHAT_API_URL 与 WECHAT_AUTH_TOKEN 需同时配置，已忽略不完整的微信推送配置")
    if config.telegram_bot_token and config.telegram_chat_id:
        channels.append(TelegramNotifier(config.telegram_bot_token, config.telegram_chat_id))
    elif config.telegram_bot_token or config.telegram_chat_id:
        warn("TELEGRAM_BOT_TOKEN 与 TELEGRAM_CHAT_ID 需同时配置，已忽略不完整的 Telegram 配置")
    return CompositeNotifier(channels)


def build_message(config, quota_text, renewal_results, expiry_lines, has_failure, now=None):
    parts = []

    # 首行带运行时间，方便区分每次运行产生的报告。
    if now is not None:
        parts.append(f"运行时间：{now.astimezone(config.tz).strftime('%Y-%m-%d %H:%M:%S')} "
                     f"({format_offset(config.tz)})")
        parts.append("")

    if quota_text:
        parts.append(quota_text)
        parts.append("")

    parts.append("=== 本次续期结果 ===")
    if renewal_results:
        parts.extend(renewal_results)
    else:
        parts.append(f"（所有域名剩余天数 >= {config.threshold_days}天，本次无需续期）")

    if has_failure:
        parts.append("")
        parts.append("⚠️ 存在失败项，请查看 GitHub Actions 日志并人工处理")

    parts.append("")
    parts.append("=== 所有域名到期时间 ===")
    parts.extend(expiry_lines)
    parts.append("")
    parts.append(f"（共 {len(expiry_lines)} 个域名；到期时间按 {format_offset(config.tz)} 解读）")
    return "\n".join(parts)


@dataclass
class RenewOutcome:
    """一次续期尝试的结果。new_expiry 非空时可用于刷新到期时间清单。"""
    line: str
    failed: bool
    new_expiry: Optional[str] = None


def renew_one(client, view):
    """续期单个域名。"""
    try:
        payload = client.renew(view.subdomain_id)
    except ApiError as e:
        # 只兜接口层错误；编程错误（AttributeError/TypeError 等）应当抛出，
        # 否则会被伪装成「请求异常」，掩盖真正的 bug。
        return RenewOutcome(f"❌ {view.label}: 请求异常 ({e})", True)
    except requests.RequestException as e:
        return RenewOutcome(f"❌ {view.label}: 网络异常 ({e})", True)

    if payload.get('success'):
        new_expiry = payload.get('new_expires_at') or ''
        charge = format_charge(payload.get('charged_amount', 0))
        remaining = payload.get('remaining_days')
        tail = f"，剩余 {remaining}天" if remaining is not None else ""
        shown = new_expiry or '未知'
        return RenewOutcome(
            f"✅ {view.label}: 续期成功 (新到期 {shown}{tail}, {charge})",
            False,
            new_expiry or None,
        )

    detail = describe_error(payload)
    if payload.get('error_code') in BENIGN_ERROR_CODES:
        # 尚未进入续期窗口，属预期结果，不计入失败
        return RenewOutcome(f"⏭️ {view.label}: 暂不可续期 ({detail})", False)
    return RenewOutcome(f"❌ {view.label}: 续期失败 ({detail})", True)


def run(config, client, notifier, now=None):
    """执行一轮续期，返回进程退出码：0 全部正常，1 存在需人工关注的问题。"""
    now = now or datetime.now(timezone.utc)

    try:
        subdomains = client.fetch_subdomains()
    except Exception as e:
        message = f"❌ 获取域名列表失败，本次未执行任何续期: {e}"
        print(message, file=sys.stderr)
        notifier.send(message)
        return 1

    # 积分只是辅助信息，查不到不该让整轮续期失败
    try:
        quota_text = quota_line(client.fetch_quota())
    except Exception as e:
        quota_text = f"账户积分：查询失败（{e}）"

    renewal_results: List[str] = []
    expiry_lines: List[str] = []
    has_failure = False

    for index, raw in enumerate(subdomains):
        view = inspect_domain(raw, index, now, config.tz)
        expiry_lines.append(expiry_line(view, now))
        action = decide(view, config.threshold_days, now)

        if action == 'invalid':
            has_failure = True
            renewal_results.append(f"❌ {view.label}: {view.problem}")
        elif action == 'never':
            renewal_results.append(mark(view, f"⏭️ {view.label}: 已设置为永不过期，跳过续期"))
        elif action == 'skip':
            renewal_results.append(mark(view, (
                f"⏭️ {view.label}: {describe_remaining(view, now)} "
                f"> {config.threshold_days}天，尚未进入续期窗口，跳过"
            )))
        else:
            outcome = renew_one(client, view)
            renewal_results.append(mark(view, outcome.line))
            has_failure = has_failure or outcome.failed
            if outcome.new_expiry:
                # 续期成功后刷新到期清单，避免第二段显示续期前的旧时间
                view.expires_raw = outcome.new_expiry
                view.expires_at = parse_expiry(outcome.new_expiry, config.tz)
                view.days_remaining = (
                    (view.expires_at - now).days if view.expires_at else None
                )
                expiry_lines[-1] = expiry_line(view, now)

    message = build_message(config, quota_text, renewal_results, expiry_lines, has_failure, now)
    print(message)
    # 推送失败同样算失败：报告发不出去等于没有告警通道
    pushed = notifier.send(message)
    return 0 if (not has_failure and pushed) else 1


class CaptureNotifier:
    """收集每个账号的原格式报告，最后统一推送，避免多账号触发通知频率限制。"""

    def __init__(self):
        self.messages = []

    def send(self, content):
        self.messages.append(content)
        return True


def load_account_credentials(env=None):
    """读取 DNSHE_ACCOUNTS JSON 数组；未配置时回退到原单账号模式。"""
    env = os.environ if env is None else env
    raw = (env.get("DNSHE_ACCOUNTS") or "").strip()

    if not raw:
        config = Config.from_env(env)
        missing = config.missing_credentials()
        if missing:
            raise ValueError(
                f"缺少必需的环境变量: {', '.join(missing)}。"
                "请配置 DNSHE_ACCOUNTS，或继续使用 DNSHE_API_KEY / DNSHE_API_SECRET。"
            )
        return [{"name": "默认账号", "api_key": config.api_key,
                 "api_secret": config.api_secret}], config

    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValueError(f"DNSHE_ACCOUNTS 不是有效 JSON：{exc}") from None

    if not isinstance(data, list) or not data:
        raise ValueError("DNSHE_ACCOUNTS 必须是非空 JSON 数组")

    accounts = []
    used_names = set()

    for index, item in enumerate(data, start=1):
        if not isinstance(item, dict):
            raise ValueError(f"DNSHE_ACCOUNTS 第 {index} 项必须是 JSON 对象")

        name = str(item.get("name") or f"账号{index}").strip() or f"账号{index}"
        api_key = str(item.get("api_key") or "").strip()
        api_secret = str(item.get("api_secret") or "").strip()

        if not api_key or not api_secret:
            raise ValueError(f"{name} 缺少 api_key 或 api_secret")

        if name in used_names:
            name = f"{name}-{index}"
        used_names.add(name)

        accounts.append({
            "name": name,
            "api_key": api_key,
            "api_secret": api_secret,
        })

    # 共享配置（时区、续期阈值、通知渠道、API URL、限速等）仍从原环境变量读取。
    return accounts, Config.from_env(env)


def main():
    configure_streams()

    try:
        accounts, base_config = load_account_credentials()
    except Exception as e:
        message = f"❌ DNSHE 多账号配置错误: {e}"
        print(message, file=sys.stderr)
        try:
            # 即使账号 JSON 有误，也尽可能使用原环境变量中的通知配置告警。
            build_notifier(Config.from_env()).send(message)
        except Exception:
            pass
        return 1

    notifier = build_notifier(base_config)
    missing_notifications = (
        not (base_config.wechat_api_url and base_config.wechat_auth_token)
        and not (base_config.telegram_bot_token and base_config.telegram_chat_id)
    )
    if missing_notifications:
        print("未配置通知通道；报告将仅输出到终端。")

    print(f"DNSHE 多账号自动续期开始：共 {len(accounts)} 个账号")
    print(f"续期窗口：到期剩余时间小于等于 {base_config.threshold_days} 天")
    print(f"时区：{format_offset(base_config.tz)}")

    # 账号间共享节流器，避免多账号轮询时叠加请求速率。
    shared_throttle = Throttle(base_config.min_interval)
    captured_reports = []
    overall_failure = False

    for index, account in enumerate(accounts, start=1):
        account_name = account["name"]
        print(f"\n========== 账号 {index}/{len(accounts)}：{account_name} ==========")

        # 只替换该账号凭据；其余配置、筛选规则、报告模板、重试策略全部沿用原脚本。
        account_config = replace(
            base_config,
            api_key=account["api_key"],
            api_secret=account["api_secret"],
        )
        capture = CaptureNotifier()

        try:
            client = DnsheClient(account_config, throttle=shared_throttle)
            result = run(account_config, client, capture)
            if result != 0:
                overall_failure = True
        except Exception:
            # 隔离账号级异常，继续处理后续账号。
            detail = traceback.format_exc()
            safe_detail = redact(detail, (
                account["api_key"], account["api_secret"],
                base_config.telegram_bot_token, base_config.wechat_auth_token,
            ))
            print(f"❌ 账号 {account_name} 执行异常:\n{safe_detail}", file=sys.stderr)
            capture.messages.append(
                f"⚠️ 账号：{account_name}\n"
                f"续期脚本异常中断，本账号本次未完成。\n\n"
                f"{safe_detail[-1500:]}"
            )
            overall_failure = True

        if not capture.messages:
            # run() 理论上总会产出消息；若未来修改导致没有消息，显式记录而非静默略过。
            capture.messages.append(
                f"⚠️ 账号：{account_name}\n本账号没有生成报告，请检查执行日志。"
            )
            overall_failure = True

        # 每个账号内部的报告正文保持原样，只在报告前加账号标识，便于汇总后区分。
        for message in capture.messages:
            captured_reports.append(f"【DNSHE 账号：{account_name}】\n\n{message}")

    combined_message = "\n\n" + ("\n\n" + "=" * 36 + "\n\n").join(captured_reports)
    print("\n========== 多账号汇总通知 ==========\n")
    print(combined_message)

    pushed = notifier.send(combined_message)
    if not pushed:
        print("❌ 所有已配置通知通道均未能成功送达。", file=sys.stderr)
        overall_failure = True

    print("\nDNSHE 多账号自动续期结束")
    return 1 if overall_failure else 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except SystemExit:
        raise
    except Exception:
        configure_streams()
        detail = traceback.format_exc()
        print(detail, file=sys.stderr)
        try:
            build_notifier(Config.from_env()).send(
                f"⚠️ 续期脚本异常中断，本次续期未完成\n\n{detail[-1500:]}")
        except Exception:
            pass
        sys.exit(1)
