# 全モデルをここで読み込み、Base.metadata に登録する
# （base.py から device.py を import すると循環importになるため、ここに集約）
from app.models.activity import ActivityLog
from app.models.api_token import ApiToken
from app.models.audit import AuditLog, TerminalSession
from app.models.base import Base
from app.models.command_run import CommandResult, CommandRun
from app.models.compliance import ComplianceException, ComplianceResult, ComplianceRule
from app.models.device import (
    CollectLog,
    ConfigBaseline,
    ConfigComment,
    ConfigReview,
    ConfigSnapshot,
    CredentialProfile,
    Device,
    DeviceGroup,
    JumpHost,
    Schedule,
)
from app.models.ignore_rule import ConfigIgnoreRule
from app.models.mail import MailServer
from app.models.monitoring import FwHitStatus, FwRuleHit, IfSample, MonInterface, SnmpSetting
from app.models.notification import NotificationSetting, ReportSend, UserGroup, UserGroupMember
from app.models.ping import PingMonitor, PingResult, PingTarget
from app.models.topology import TopologyMap
from app.models.user import User

__all__ = [
    "ActivityLog",
    "ApiToken",
    "AuditLog",
    "Base",
    "CollectLog",
    "CommandResult",
    "CommandRun",
    "ComplianceException",
    "ComplianceResult",
    "ComplianceRule",
    "ConfigBaseline",
    "ConfigComment",
    "ConfigIgnoreRule",
    "ConfigReview",
    "ConfigSnapshot",
    "CredentialProfile",
    "Device",
    "DeviceGroup",
    "FwHitStatus",
    "FwRuleHit",
    "IfSample",
    "JumpHost",
    "MailServer",
    "MonInterface",
    "NotificationSetting",
    "PingMonitor",
    "PingResult",
    "PingTarget",
    "ReportSend",
    "Schedule",
    "SnmpSetting",
    "TerminalSession",
    "TopologyMap",
    "User",
    "UserGroup",
    "UserGroupMember",
]
