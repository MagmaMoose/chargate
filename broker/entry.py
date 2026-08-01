"""Cloudflare Python Worker entrypoint for the Chargate token broker.

The Worker runtime hands each invocation an ``env`` object carrying vars and
secrets. It is published on a ContextVar before anything else runs so
``app.config.load_config`` sees the live values without ``env`` being threaded
through every signature.

Handlers live in a class named ``Default`` extending ``WorkerEntrypoint``. The
module-level ``on_fetch`` form was replaced by the class form in August 2025, and
a Worker still exporting the old shape is rejected at upload with "The uploaded
script has no registered event handlers" (code 10068) — the upload succeeds, the
runtime just finds nothing to call.

``workers`` and the ASGI bridge live in the runtime, not in the dependency set, so
both are imported defensively — this module must still import under plain CPython
for linting and tests.
"""

from __future__ import annotations

from typing import Any

from app.config import cf_env

try:  # provided by the Workers Python runtime, absent everywhere else
    from workers import WorkerEntrypoint  # type: ignore[import-not-found]
except ImportError:  # pragma: no cover - exercised only off-Worker

    class WorkerEntrypoint:  # type: ignore[no-redef]
        """Stand-in so this module imports for linting and tests.

        Off-Worker there is no runtime to bind ``env``/``ctx``, and nothing outside
        a Worker instantiates this.
        """

        env: Any = None
        ctx: Any = None


class Default(WorkerEntrypoint):
    """Every entrypoint this Worker exposes. The class name is what the runtime looks for."""

    async def fetch(self, request: Any) -> Any:
        """HTTP: bridge the incoming request into the ASGI app."""
        cf_env.set(self.env)

        # Imported inside the handler, not at module scope. A cold start pays for it
        # either way, and keeping it out of module import means a broken import shows
        # up as a 500 with a traceback rather than as a Worker the runtime reports as
        # having no handlers at all — a much longer walk from symptom to cause.
        import asgi  # type: ignore[import-not-found]

        from app.main import app

        return await asgi.fetch(app, request, self.env)
