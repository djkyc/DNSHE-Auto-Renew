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
    pushplus_token: str = ""
    pushplus_topic: str = ""
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
            pushplus_token=text('PUSHPLUS_TOKEN'),
            pushplus_topic=text('PUSHPLUS_TOPIC'),
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
