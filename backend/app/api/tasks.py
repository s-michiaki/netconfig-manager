from celery.result import AsyncResult
from fastapi import APIRouter, Depends

from app.api.deps import require
from app.core.permissions import Perm
from app.worker import celery_app

router = APIRouter()


@router.get("/{task_id}", dependencies=[Depends(require(Perm.COLLECT))])
async def get_task_status(task_id: str):
    """Celeryタスクの状態を返す（PENDING / STARTED / RETRY / SUCCESS / FAILURE）"""
    res = AsyncResult(task_id, app=celery_app)
    body: dict = {"task_id": task_id, "state": res.state, "result": None}
    if res.state == "SUCCESS":
        body["result"] = res.result if isinstance(res.result, dict) else None
    elif res.state in ("FAILURE", "RETRY"):
        body["result"] = {"success": False, "error": str(res.result)}
    return body
