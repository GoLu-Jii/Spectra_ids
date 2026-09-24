from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

RuntimeMode = Literal["LIVE", "REPLAY", "TEST"]


@dataclass(frozen=True)
class RuntimeConfig:
    mode: RuntimeMode = "TEST"
    zeek_log_dir: Path = Path("var/log/zeek")
    log_files: tuple[str, ...] = ("conn.log", "dns.log", "ssl.log", "tls.log", "packet.log")
    poll_interval_seconds: float = 0.25
    max_bytes_per_file_poll: int = 65536
    max_pending_line_bytes: int = 1048576
    flush_on_shutdown: bool = True

    def __post_init__(self) -> None:
        if self.mode not in {"LIVE", "REPLAY", "TEST"}:
            raise ValueError(f"Unsupported runtime mode: {self.mode!r}")
        if not self.log_files or any(Path(name).name != name for name in self.log_files):
            raise ValueError("log_files must contain filenames only")
        supported = {"conn.log", "dns.log", "ssl.log", "tls.log", "packet.log"}
        if any(name not in supported for name in self.log_files):
            raise ValueError("log_files may contain only supported Zeek log filenames")
        if self.poll_interval_seconds <= 0:
            raise ValueError("poll_interval_seconds must be positive")
        if min(self.max_bytes_per_file_poll, self.max_pending_line_bytes) < 1:
            raise ValueError("Runtime buffer limits must be positive")

    @classmethod
    def from_env(cls) -> "RuntimeConfig":
        mode = os.getenv("SPECTRA_RUNTIME_MODE", "TEST").upper()
        names = tuple(
            item.strip() for item in os.getenv(
                "SPECTRA_ZEEK_LOG_FILES", "conn.log,dns.log,ssl.log,tls.log,packet.log"
            ).split(",") if item.strip()
        )
        return cls(
            mode=mode,  # type: ignore[arg-type]
            zeek_log_dir=Path(os.getenv("SPECTRA_ZEEK_LOG_DIR", "var/log/zeek")),
            log_files=names,
            poll_interval_seconds=float(os.getenv("SPECTRA_TAIL_INTERVAL_SECONDS", "0.25")),
            max_bytes_per_file_poll=int(os.getenv("SPECTRA_TAIL_MAX_BYTES_PER_FILE_POLL", "65536")),
            max_pending_line_bytes=int(os.getenv("SPECTRA_TAIL_MAX_PENDING_LINE_BYTES", "1048576")),
            flush_on_shutdown=os.getenv("SPECTRA_FLUSH_ON_SHUTDOWN", "true").lower() in {"1", "true", "yes"},
        )
