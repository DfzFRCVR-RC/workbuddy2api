"""用 API Key 自查额度余额的公开接口。

背景：项目原有的额度查询只存在于管理后台（`GET /api/keys/{id}/usage`，
需要 `X-Admin-Token`）。客户端软件要显示余额时，不可能拿后台 JWT，
所以这里补一个用 API Key 自证的只读接口。

安全边界（有意收窄）：
  * 只返回**当前 Key 自己**的额度数字，不含账号池、模型、余额分布；
  * 校验方式与 `/v1/*` 完全一致（`hash_key` 比对 `api_keys.key_hash`），
    已停用（revoked）的 Key 一律 401，不泄漏其存在性；
  * 不写 usage_logs —— 查余额不该计入调用量，否则客户端定时轮询
    会把「已用额度」推高，形成自我污染。
"""
from typing import Optional

from fastapi import APIRouter, Depends, Header, HTTPException
from sqlalchemy.orm import Session

from admin.db import get_db
from admin.security import get_key_row

router = APIRouter(tags=["credits"])


def _resolve_key(db: Session, x_api_key: Optional[str], authorization: Optional[str]):
    """同时接受 X-API-Key / X-Api-Key / Authorization: Bearer，与 /v1 保持一致。"""
    raw = x_api_key
    if not raw and authorization and authorization.startswith("Bearer "):
        raw = authorization[7:].strip()
    if not raw:
        raise HTTPException(
            status_code=401,
            detail={"error": {"message": "缺少 API Key", "type": "auth_error"}},
        )
    key = get_key_row(db, raw)
    # 无效与已停用返回同一个 401，避免探测 Key 是否存在
    if not key or key.status != "active":
        raise HTTPException(
            status_code=401,
            detail={"error": {"message": "无效 API Key", "type": "auth_error"}},
        )
    return key


@router.get("/credits")
@router.get("/v1/credits")
def credits(
    db: Session = Depends(get_db),
    x_api_key: Optional[str] = Header(default=None, alias="X-API-Key"),
    x_api_key_lower: Optional[str] = Header(default=None, alias="X-Api-Key"),
    authorization: Optional[str] = Header(default=None),
):
    """返回当前 Key 的额度、已用、剩余与百分比。

    字段说明（客户端常见取值路径）：
      total_usage     已用额度（= credit_used）
      total_granted   额度上限（unlimited 时为 null）
      total_available 剩余额度（unlimited 时为 null）
    """
    key = _resolve_key(db, x_api_key or x_api_key_lower, authorization)

    used = round(float(key.credit_used or 0), 4)
    unlimited = bool(key.unlimited)
    # 无限额时返回一个足够大的占位数字，而不是 null。
    # 原因：RikkaHub 等客户端用 evaluateJsonExpr 取值，null 会被转成空字符串，
    # 界面直接显示一片空白；给个 999999 至少让「剩余」位置有可见数字。
    limit = 999999.0 if unlimited else round(float(key.credit_limit or 0), 4)
    remaining = (999999.0 if unlimited
                 else round(max(0.0, (key.credit_limit or 0) - used), 4))
    percent = None if (unlimited or not limit) else round(used / limit * 100, 2)

    return {
        # 顶层扁平字段：多数客户端用 data.xxx 取值
        "total_usage": used,
        "total_granted": limit,
        "total_available": remaining,
        "usage_percent": percent,
        "unlimited": unlimited,
        "status": key.status,
        # 常见包装字段，兼容 one-api / new-api 风格取值
        "object": "credit_summary",
        "data": {
            "total_usage": used,
            "total_granted": limit,
            "total_available": remaining,
            "usage_percent": percent,
            "unlimited": unlimited,
            "status": key.status,
        },
    }
