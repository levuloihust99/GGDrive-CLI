import contextvars
from dataclasses import dataclass
from typing import Text, Optional, Any


@dataclass
class AppContext:
    oauth_local_port: int = 8080
    max_local_run_retry: int = 3
    include_pattern: Optional[Text] = None
    ignore_pattern: Optional[Text] = None
    include_over_ignore: Optional[Text] = None
    client_secrets_file: Text = "client_secrets.json"
    token_file: Text = "token.json"
    creds: Any = None
    service: Any = None


__context = contextvars.ContextVar("app_ctx", default=None)


def get() -> AppContext | None:
    return __context.get()


def ensure_context() -> AppContext:
    current_context = __context.get()
    if current_context is None:
        __context.set(AppContext())
    return __context.get()


def set(
    oauth_local_port: Optional[int] = None,
    max_local_run_retry: Optional[int] = None,
    include_pattern: Optional[Text] = None,
    ignore_pattern: Optional[Text] = None,
    client_secrets_file: Optional[Text] = None,
    token_file: Optional[Text] = None,
    creds: Any = None,
    service: Any = None,
):
    app_ctx = ensure_context()
    if oauth_local_port is not None:
        app_ctx.oauth_local_port = oauth_local_port
    if max_local_run_retry is not None:
        app_ctx.max_local_run_retry = max_local_run_retry
    if include_pattern is not None:
        app_ctx.include_pattern = include_pattern
    if ignore_pattern is not None:
        app_ctx.ignore_pattern = ignore_pattern
    if client_secrets_file is not None:
        app_ctx.client_secrets_file = client_secrets_file
    if token_file is not None:
        app_ctx.token_file = token_file
    if creds is not None:
        app_ctx.creds = creds
    if service is not None:
        app_ctx.service = service
