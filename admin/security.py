"""安全：管理后台 JWT 登录 + API Key 校验与配额判断。"""
import base64
import hashlib
import hmac
import os
import time
from datetime import datetime, timedelta

import jwt
from fastapi import Header, HTTPException

from admin.config import settings
from admin.db import SessionLocal
from admin.models import ApiKey


# ---------------------------------------------------------------------------
# 管理后台登录
# ---------------------------------------------------------------------------

#: 密码指纹缓存：(指纹, 取到时的 monotonic 时间)。
#: verify_admin_token 会在**每个**管理接口请求上调用，必须避免每次打一次 SQLite；
#: 5 秒的窗口对「改完密码立刻失效」这个诉求完全够用，改密码时会主动失效缓存。
_STAMP_CACHE: tuple[str, float] = ("", 0.0)
_STAMP_TTL = 5.0


def invalidate_password_stamp() -> None:
    """密码变更后主动失效缓存，让旧令牌立刻不可用。"""
    global _STAMP_CACHE
    _STAMP_CACHE = ("", 0.0)


def _password_stamp() -> str:
    """把「当前后台密码哈希」压成一个短指纹，塞进 JWT。

    作用：改密码后，此前签发的所有令牌立即失效（无需重启、无需黑名单）。
    只取哈希的前 16 位做 SHA256，既不泄漏哈希本身，也足够区分。
    """
    global _STAMP_CACHE
    val, ts = _STAMP_CACHE
    if val and (time.monotonic() - ts) < _STAMP_TTL:
        return val
    try:
        from admin.server import _get_stored_hash
        h = _get_stored_hash() or ""
    except Exception:
        h = ""
    stamp = hashlib.sha256(h.encode("utf-8")).hexdigest()[:16] if h else ""
    _STAMP_CACHE = (stamp, time.monotonic())
    return stamp


def create_admin_token() -> str:
    exp = datetime.utcnow() + timedelta(hours=settings.JWT_EXPIRE_HOURS)
    return jwt.encode({"sub": settings.ADMIN_USERNAME, "exp": exp, "pv": _password_stamp()},
                      settings.JWT_SECRET, algorithm="HS256")


def verify_admin_token(token: str | None):
    if not token:
        raise HTTPException(status_code=401, detail="未登录")
    try:
        payload = jwt.decode(token, settings.JWT_SECRET, algorithms=["HS256"])
        local_runtime = os.getenv("WORKBUDDY_DESKTOP") == "1" or os.getenv("WORKBUDDY_ANDROID") == "1"
        if "exp" not in payload and not (local_runtime and payload.get("local_shell") is True):
            raise HTTPException(status_code=401, detail="无效令牌")
        if payload.get("sub") != settings.ADMIN_USERNAME:
            raise HTTPException(status_code=401, detail="无效令牌")
        # 改密码即失效：令牌里的密码指纹必须与当前密码一致。
        # 老令牌（本机制上线前签发）没有 pv 字段，直接判为无效，要求重新登录。
        pv = payload.get("pv")
        if pv is None or pv != _password_stamp():
            raise HTTPException(status_code=401, detail="密码已变更，请重新登录")
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="无效令牌")


def require_admin(x_admin_token: str = Header(default=None, alias="X-Admin-Token")):
    """FastAPI 依赖：校验管理后台令牌。"""
    verify_admin_token(x_admin_token)
    return True


# ---------------------------------------------------------------------------
# 管理后台密码（PBKDF2 哈希存储，杜绝明文泄漏）
# ---------------------------------------------------------------------------

_PBKDF2_ITER = 100_000


def hash_password(pw: str) -> str:
    """返回可持久化的哈希串：pbkdf2$<iter>$<salt_b64>$<dk_b64>。"""
    salt = os.urandom(16)
    dk = hashlib.pbkdf2_hmac("sha256", pw.encode("utf-8"), salt, _PBKDF2_ITER)
    return "pbkdf2$" + str(_PBKDF2_ITER) + "$" + \
        base64.b64encode(salt).decode() + "$" + base64.b64encode(dk).decode()


def verify_password(pw: str, stored: str) -> bool:
    """校验密码；兼容旧明文存储（首次读取时由 server 统一迁移为哈希）。"""
    if not stored:
        return False
    if not stored.startswith("pbkdf2$"):
        return hmac.compare_digest(pw, stored)  # 旧明文兜底
    try:
        _, iter_s, salt_b64, hash_b64 = stored.split("$", 3)
        salt = base64.b64decode(salt_b64)
        expected = base64.b64decode(hash_b64)
        cand = hashlib.pbkdf2_hmac("sha256", pw.encode("utf-8"), salt, int(iter_s))
        return hmac.compare_digest(cand, expected)
    except Exception:
        return False


def hash_key(key: str) -> str:
    return hashlib.sha256(key.encode("utf-8")).hexdigest()


def get_key_row(db, api_key: str) -> ApiKey | None:
    return db.query(ApiKey).filter(ApiKey.key_hash == hash_key(api_key)).first()


def check_quota(key: ApiKey) -> None:
    """超额则直接拒绝，提示『积分已耗尽』。"""
    if key.status != "active":
        raise HTTPException(status_code=403, detail={"error": {"message": "API Key 已停用", "type": "key_disabled"}})
    if not key.unlimited and key.credit_used >= key.credit_limit:
        raise HTTPException(
            status_code=402,
            detail={"error": {"message": "当前 API Key 的额度已用完，请调整此 Key 的限额或联系管理员", "type": "quota_exceeded", "code": "key_quota_exceeded", "source": "gateway"}},
        )
