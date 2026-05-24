import contextvars
import json
import logging
import os


# https://stackoverflow.com/a/56944256/2251364
class CustomFormatter(logging.Formatter):
    grey = "\x1b[38;20m"
    blue = "\x1b[34;20m"
    yellow = "\x1b[33;20m"
    red = "\x1b[31;20m"
    bold_red = "\x1b[31;1m"
    reset = "\x1b[0m"
    format = "%(asctime)s - %(name)s - %(levelname)s - %(message)s (%(filename)s:%(lineno)d)"

    FORMATS = {
        logging.DEBUG: grey + format + reset,
        logging.INFO: blue + format + reset,
        logging.WARNING: yellow + format + reset,
        logging.ERROR: red + format + reset,
        logging.CRITICAL: bold_red + format + reset,
    }

    def format(self, record):
        log_fmt = self.FORMATS.get(record.levelno)
        formatter = logging.Formatter(log_fmt)
        return formatter.format(record)


color_handler = logging.StreamHandler()


# ---------------------------------------------------------------------------
# Optional JSON formatter + request-id contextvar.
#
# These additions are OPT-IN and do not alter any existing behavior:
#   - `request_id_var` defaults to "-" so non-Flask callers (CLI, daemons) can
#     log freely without touching it.
#   - `JsonFormatter` is only installed when LIBINV_LOG_FORMAT=json is set.
# ---------------------------------------------------------------------------
request_id_var: contextvars.ContextVar[str] = contextvars.ContextVar(
    "libinv_request_id", default="-"
)


class JsonFormatter(logging.Formatter):
    """One JSON object per log record. Includes the contextvar request_id."""

    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "time": self.formatTime(record, datefmt="%Y-%m-%dT%H:%M:%S%z"),
            "level": record.levelname,
            "name": record.name,
            "message": record.getMessage(),
            "module": record.module,
            "lineno": record.lineno,
            "request_id": request_id_var.get(),
        }
        if record.exc_info:
            payload["exc_info"] = self.formatException(record.exc_info)
        return json.dumps(payload, default=str)


def install_json_formatter_if_configured() -> bool:
    """If LIBINV_LOG_FORMAT=json, install the JsonFormatter on the root handler.

    Returns True iff the formatter was installed.
    """
    if os.environ.get("LIBINV_LOG_FORMAT", "").lower() != "json":
        return False
    fmt = JsonFormatter()
    root = logging.getLogger()
    if not root.handlers:
        root.addHandler(logging.StreamHandler())
    for handler in root.handlers:
        handler.setFormatter(fmt)
    return True
