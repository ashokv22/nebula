import logging
import re
import sys
import traceback
from logging.handlers import WatchedFileHandler
from pathlib import Path

DEFAULT_LOG_PATH = "/var/log/nebula/nebula.log"
_IDENTIFIER_PATH = re.compile(
    r"(?i)(/leads/|/requests/|/users/)([^/?\s]+)"
)


class SafeAccessFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        if record.name == "uvicorn.access" and isinstance(record.args, tuple):
            args = list(record.args)
            path_index = 2 if len(args) >= 5 else 1 if len(args) >= 2 else None
            if path_index is not None and isinstance(args[path_index], str):
                args[path_index] = _IDENTIFIER_PATH.sub(r"\1[REDACTED]", args[path_index])
                record.args = tuple(args)
        return True


class SafeFormatter(logging.Formatter):
    def formatException(self, exc_info) -> str:
        exception_type = type(exc_info[1]).__name__
        frames = traceback.extract_tb(exc_info[2], limit=8)
        trace = " <- ".join(
            f"{Path(frame.filename).name}:{frame.lineno}:{frame.name[:80]}"
            for frame in frames
        )
        return f"{exception_type}" + (f" at {trace}" if trace else "")


def configure_logging(
    log_path: str = DEFAULT_LOG_PATH,
    console_stream=None,
) -> None:
    Path(log_path).parent.mkdir(parents=True, exist_ok=True)

    root = logging.getLogger()
    for handler in root.handlers[:]:
        root.removeHandler(handler)
        handler.close()
    root.setLevel(logging.DEBUG)

    formatter = SafeFormatter(
        "%(asctime)s %(levelname)s %(name)s: %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S%z",
    )
    file_handler = WatchedFileHandler(log_path, encoding="utf-8")
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(formatter)
    file_handler.addFilter(SafeAccessFilter())
    console_handler = logging.StreamHandler(
        console_stream if console_stream is not None else sys.stderr
    )
    console_handler.setLevel(logging.INFO)
    console_handler.setFormatter(formatter)
    console_handler.addFilter(SafeAccessFilter())
    root.addHandler(file_handler)
    root.addHandler(console_handler)

    uvicorn_loggers = {
        "uvicorn": logging.getLogger("uvicorn"),
        "uvicorn.error": logging.getLogger("uvicorn.error"),
        "uvicorn.access": logging.getLogger("uvicorn.access"),
    }
    for name, registered in root.manager.loggerDict.items():
        if name.startswith("uvicorn.") and isinstance(registered, logging.Logger):
            uvicorn_loggers[name] = registered

    for logger in uvicorn_loggers.values():
        for handler in logger.handlers[:]:
            logger.removeHandler(handler)
            handler.close()
        logger.setLevel(logging.DEBUG)
        logger.propagate = True

    for name in ("httpx", "httpcore"):
        logging.getLogger(name).setLevel(logging.WARNING)


def log_sanitized_exception(logger: logging.Logger, message: str, exc: Exception) -> None:
    logger.error(
        "%s exception_type=%s",
        message,
        type(exc).__name__,
        exc_info=(type(exc), exc, exc.__traceback__),
    )
