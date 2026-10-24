import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path


class LoggingConfigurationTests(unittest.TestCase):
    def test_debug_file_info_console_safe_trace_and_external_rotation(self):
        with tempfile.TemporaryDirectory() as directory:
            log_path = Path(directory) / "nebula.log"
            script = textwrap.dedent(
                """
                import io
                import logging
                import sys
                from logging.handlers import WatchedFileHandler
                from pathlib import Path
                from core.logging_config import configure_logging, log_sanitized_exception

                log_path = Path(sys.argv[1])
                console = io.StringIO()
                uvicorn_access = logging.getLogger("uvicorn.access")
                uvicorn_access.addHandler(logging.StreamHandler(io.StringIO()))
                uvicorn_access.propagate = False
                uvicorn_child = logging.getLogger("uvicorn.protocols.http")
                uvicorn_child.addHandler(logging.StreamHandler(io.StringIO()))
                uvicorn_child.propagate = False
                configure_logging(str(log_path), console)
                configure_logging(str(log_path), console)
                assert len(logging.getLogger().handlers) == 2
                assert not uvicorn_access.handlers
                assert not uvicorn_child.handlers
                assert uvicorn_access.propagate
                assert uvicorn_child.propagate
                logger = logging.getLogger("smoke.application")
                logger.debug("debug-only")
                logger.info("visible-info")
                try:
                    raise ValueError("SYNTHETIC_PRIVATE_EXCEPTION_VALUE")
                except ValueError as exc:
                    log_sanitized_exception(logger, "sanitized failure", exc)
                logging.getLogger("uvicorn.access").info(
                    '%s - "%s %s HTTP/%s" %d',
                    "127.0.0.1",
                    "POST",
                    "/leads/2977/analyze?env=uat&days=7",
                    "1.1",
                    502,
                )

                assert any(isinstance(h, WatchedFileHandler) for h in logging.getLogger().handlers)
                assert logging.getLogger().level == logging.DEBUG
                assert "debug-only" not in console.getvalue()
                assert "visible-info" in console.getvalue()
                assert "2977" not in console.getvalue()
                old_path = log_path.with_suffix(".old")
                log_path.rename(old_path)
                logger.info("after-external-rotation")
                assert "after-external-rotation" in log_path.read_text()
                assert log_path.read_text().count("after-external-rotation") == 1
                assert "debug-only" in old_path.read_text()
                assert old_path.read_text().count("debug-only") == 1
                assert "SYNTHETIC_PRIVATE_EXCEPTION_VALUE" not in old_path.read_text()
                assert "ValueError" in old_path.read_text()
                assert "2977" not in old_path.read_text()
                assert "[REDACTED]" in old_path.read_text()
                print("logging smoke passed")
                """
            )
            result = subprocess.run(
                [sys.executable, "-c", script, str(log_path)],
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("logging smoke passed", result.stdout)


if __name__ == "__main__":
    unittest.main()
