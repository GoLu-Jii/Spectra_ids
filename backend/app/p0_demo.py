"""ASGI entry point for the explicitly configured P0 SIH demonstration."""

from .config.orchestrator import P0_RUNTIME_CONFIGURATION
from .config.runtime import RuntimeConfig
from .main import app, configure_zeek_runtime
from .runtime_factory import create_orchestrator


orchestrator = create_orchestrator(P0_RUNTIME_CONFIGURATION)
configure_zeek_runtime(orchestrator, RuntimeConfig.from_env())
