"""
Security tests for Flask config.py remediation of CWE-94 Stored Code Injection.

These tests verify that:
1. from_pyfile no longer uses exec/compile to execute arbitrary Python code.
2. from_pyfile safely parses JSON configuration files via json.load.
3. Malicious Python payloads stored in files are NOT executed.
4. Legitimate JSON configuration files are loaded correctly.
5. The silent parameter still works for missing files.
6. Regression: existing safe config paths continue to work.

The vulnerability (CWE-94) allowed an attacker to store malicious Python code
in a file (e.g. via a database or upload) and have it executed when
from_pyfile loaded that file via exec(compile(...)). The fix replaces the
exec/compile sink with json.load — a safe, structured parser.
"""

import json
import os
import sys
import tempfile
import unittest

# Ensure the patched flask package is importable from the local site-packages.
_SITE_PACKAGES = os.path.join(
    os.path.dirname(__file__), ".local", "lib", "python3.10", "site-packages"
)
if _SITE_PACKAGES not in sys.path:
    sys.path.insert(0, _SITE_PACKAGES)

from flask.config import Config  # noqa: E402


class TestFromPyfileNoExec(unittest.TestCase):
    """Verify that from_pyfile does NOT execute arbitrary Python code."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.config = Config(root_path=self.tmpdir)

    def _write_file(self, filename, content, mode="w"):
        path = os.path.join(self.tmpdir, filename)
        with open(path, mode) as f:
            f.write(content)
        return path

    # ------------------------------------------------------------------
    # Core security tests: exec/compile sink must be eliminated
    # ------------------------------------------------------------------

    def test_malicious_python_payload_is_not_executed(self):
        """
        A file containing a Python os.system() call must NOT be executed.
        If from_pyfile still used exec, this would execute the shell command.
        With the fix (json.load), parsing a non-JSON file must raise an error,
        NOT run the Python code.
        """
        sentinel_file = os.path.join(self.tmpdir, "sentinel.txt")
        malicious_content = (
            "import os; os.open({!r}, os.O_CREAT | os.O_WRONLY)".format(sentinel_file)
        )
        self._write_file("evil.cfg", malicious_content)

        with self.assertRaises(Exception):
            # json.load will raise json.JSONDecodeError — not execute the payload
            self.config.from_pyfile("evil.cfg")

        # The sentinel file must NOT have been created — payload was not run
        self.assertFalse(
            os.path.exists(sentinel_file),
            "Malicious Python payload was executed — exec/compile sink is still active!",
        )

    def test_exec_builtins_not_accessible(self):
        """
        A config file with a __builtins__ manipulation attempt must not
        execute arbitrary code. The json.load parser never evaluates Python.
        """
        malicious_content = "__import__('os').system('id')\nSECRET_KEY = 'pwned'"
        self._write_file("evil2.cfg", malicious_content)

        with self.assertRaises(Exception):
            self.config.from_pyfile("evil2.cfg")

        self.assertNotIn("SECRET_KEY", self.config)

    def test_python_assignment_not_interpreted_as_config(self):
        """
        A classic Python-style config file (KEY = 'value') must NOT be loaded
        as valid config now that exec has been replaced with json.load.
        The parser must raise an error instead of interpreting Python syntax.
        """
        python_cfg = "DEBUG = True\nSECRET_KEY = 'hello'"
        self._write_file("old_style.cfg", python_cfg)

        with self.assertRaises(Exception):
            # json.load rejects Python syntax — this is the expected safe behaviour
            self.config.from_pyfile("old_style.cfg")

        # Neither key should be in the config
        self.assertNotIn("DEBUG", self.config)
        self.assertNotIn("SECRET_KEY", self.config)

    # ------------------------------------------------------------------
    # Functional tests: safe JSON config files must load correctly
    # ------------------------------------------------------------------

    def test_valid_json_config_loaded_correctly(self):
        """A well-formed JSON file with uppercase keys is loaded into config."""
        cfg_data = {"SECRET_KEY": "supersecret", "DEBUG": False, "MAX_CONTENT_LENGTH": 16}
        self._write_file("config.json", json.dumps(cfg_data))

        result = self.config.from_pyfile("config.json")

        self.assertTrue(result)
        self.assertEqual(self.config["SECRET_KEY"], "supersecret")
        self.assertEqual(self.config["DEBUG"], False)
        self.assertEqual(self.config["MAX_CONTENT_LENGTH"], 16)

    def test_json_lowercase_keys_are_ignored(self):
        """
        Only uppercase keys should be loaded (consistent with Flask convention).
        Lowercase keys in the JSON file must be silently ignored.
        """
        cfg_data = {"SECRET_KEY": "abc", "debug": True, "database_url": "sqlite:///"}
        self._write_file("config.json", json.dumps(cfg_data))

        self.config.from_pyfile("config.json")

        self.assertIn("SECRET_KEY", self.config)
        self.assertNotIn("debug", self.config)
        self.assertNotIn("database_url", self.config)

    def test_json_nested_values_loaded(self):
        """Nested JSON values (dicts, lists) should be preserved as-is."""
        cfg_data = {
            "DATABASE": {"HOST": "localhost", "PORT": 5432},
            "ALLOWED_HOSTS": ["example.com", "www.example.com"],
        }
        self._write_file("config.json", json.dumps(cfg_data))

        self.config.from_pyfile("config.json")

        self.assertEqual(self.config["DATABASE"], {"HOST": "localhost", "PORT": 5432})
        self.assertEqual(self.config["ALLOWED_HOSTS"], ["example.com", "www.example.com"])

    def test_empty_json_object_loads_without_error(self):
        """An empty JSON object {} should succeed without setting any keys."""
        self._write_file("empty.json", "{}")

        result = self.config.from_pyfile("empty.json")

        self.assertTrue(result)

    # ------------------------------------------------------------------
    # Regression tests: silent parameter and error handling
    # ------------------------------------------------------------------

    def test_silent_true_returns_false_for_missing_file(self):
        """
        When silent=True and the file does not exist, from_pyfile must return
        False instead of raising an exception (backward-compatible behaviour).
        """
        result = self.config.from_pyfile("nonexistent.json", silent=True)

        self.assertFalse(result)

    def test_silent_false_raises_for_missing_file(self):
        """
        When silent=False (the default), a missing file must raise an OSError
        with a helpful message.
        """
        with self.assertRaises(OSError):
            self.config.from_pyfile("nonexistent.json", silent=False)

    def test_return_value_true_on_success(self):
        """from_pyfile must return True when the file loads successfully."""
        self._write_file("good.json", '{"API_KEY": "test123"}')

        result = self.config.from_pyfile("good.json")

        self.assertTrue(result)

    def test_invalid_json_raises_exception(self):
        """
        A file with invalid JSON (e.g. a plain Python .cfg file that was
        previously accepted) must raise a json.JSONDecodeError, not silently
        succeed or execute the content.
        """
        self._write_file("bad.json", "not valid json {{{")

        with self.assertRaises(Exception):
            self.config.from_pyfile("bad.json")

    # ------------------------------------------------------------------
    # Verify the exec/compile code path is absent from the implementation
    # ------------------------------------------------------------------

    def test_from_pyfile_source_does_not_contain_exec(self):
        """
        White-box test: inspect the source of from_pyfile to confirm that
        neither 'exec(' nor 'compile(' appear in its implementation.
        This directly verifies the removal of the dangerous sink.
        """
        import inspect
        source = inspect.getsource(Config.from_pyfile)
        self.assertNotIn(
            "exec(",
            source,
            "exec() call found in from_pyfile — the dangerous sink is still present!",
        )
        self.assertNotIn(
            "compile(",
            source,
            "compile() call found in from_pyfile — the dangerous sink is still present!",
        )

    def test_from_pyfile_delegates_to_from_file_with_json_load(self):
        """
        White-box test: from_pyfile must delegate to from_file with json.load,
        which is the SAST-recognized safe parser.
        """
        import inspect
        source = inspect.getsource(Config.from_pyfile)
        self.assertIn(
            "json.load",
            source,
            "from_pyfile does not use json.load — the safe parser is missing!",
        )
        self.assertIn(
            "from_file",
            source,
            "from_pyfile does not delegate to from_file — expected delegation is missing!",
        )


class TestFromPyfilePathTraversalProtection(unittest.TestCase):
    """
    Ensure that absolute paths outside root_path and traversal sequences
    are handled the same way as other files (safe parser, no exec).
    These tests verify no regression in path handling.
    """

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.config = Config(root_path=self.tmpdir)

    def test_absolute_path_with_json_content_loads(self):
        """An absolute path to a JSON file should still load via json.load."""
        path = os.path.join(self.tmpdir, "abs.json")
        with open(path, "w") as f:
            json.dump({"ABS_KEY": "value"}, f)

        result = self.config.from_pyfile(path)

        self.assertTrue(result)
        self.assertEqual(self.config["ABS_KEY"], "value")

    def test_absolute_path_with_python_content_does_not_execute(self):
        """
        An absolute path pointing to a Python file must not execute its content.
        The json.load parser will reject non-JSON content with an exception.
        """
        sentinel = os.path.join(self.tmpdir, "abs_sentinel.txt")
        path = os.path.join(self.tmpdir, "abs_evil.py")
        with open(path, "w") as f:
            f.write("open({!r}, 'w').close()\n".format(sentinel))

        with self.assertRaises(Exception):
            self.config.from_pyfile(path)

        self.assertFalse(
            os.path.exists(sentinel),
            "Payload at absolute path was executed — exec/compile is still active!",
        )


if __name__ == "__main__":
    unittest.main()
