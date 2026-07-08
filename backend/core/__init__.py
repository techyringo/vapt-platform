"""
VAPT Multi-Agent System — Core Engine

This package provides the foundational data models, state machine, scope
enforcer, configuration loader, and orchestrator that power the VAPT
multi-agent pipeline.
"""

from core.models import (
    Severity,
    ScanMode,
    ScanPhase,
    AgentType,
    Target,
    Finding,
    AgentTask,
    ScanResult,
    ScopeConfig,
)
from core.state import ScanStateMachine
from core.scope import ScopeManager
from core.config import AppConfig, ToolConfig, RateLimitConfig
from core.orchestrator import Orchestrator

__all__ = [
    # Enumerations
    "Severity",
    "ScanMode",
    "ScanPhase",
    "AgentType",
    # Data models
    "Target",
    "Finding",
    "AgentTask",
    "ScanResult",
    "ScopeConfig",
    # Sub-systems
    "ScanStateMachine",
    "ScopeManager",
    "AppConfig",
    "ToolConfig",
    "RateLimitConfig",
    "Orchestrator",
]