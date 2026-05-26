"""
Settings integration test — verifies that IDSMiddleware is correctly
registered in the Django MIDDLEWARE list and INSTALLED_APPS.

We read the settings.py file directly (via importlib) in a subprocess-safe
way so that conftest.py's minimal Django setup does not interfere.
"""

import ast
import os

# Path to the real settings file
_SETTINGS_FILE = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "..", "blog_page", "settings.py")
)


def _read_settings_list(var_name: str) -> list:
    """Parse settings.py with ast and extract a list variable by name."""
    tree = ast.parse(open(_SETTINGS_FILE).read())
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id == var_name:
                    if isinstance(node.value, ast.List):
                        return [
                            elt.value if isinstance(elt, ast.Constant) else ""
                            for elt in node.value.elts
                        ]
    return []


def _read_settings_dict_keys(var_name: str, sub_key: str) -> list:
    """Parse settings.py and extract keys of a nested dict entry."""
    tree = ast.parse(open(_SETTINGS_FILE).read())
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id == var_name:
                    if isinstance(node.value, ast.Dict):
                        for k, v in zip(node.value.keys, node.value.values):
                            if isinstance(k, ast.Constant) and k.value == sub_key:
                                if isinstance(v, ast.Dict):
                                    return [
                                        kk.value for kk in v.keys
                                        if isinstance(kk, ast.Constant)
                                    ]
    return []


class TestSettingsIntegration:
    def test_ids_middleware_in_middleware_list(self):
        """IDSMiddleware must appear in the MIDDLEWARE setting."""
        middleware = _read_settings_list("MIDDLEWARE")
        assert "ids_middleware.middleware.IDSMiddleware" in middleware, (
            f"IDSMiddleware not found in MIDDLEWARE. Got: {middleware}"
        )

    def test_ids_middleware_app_in_installed_apps(self):
        """ids_middleware app must be in INSTALLED_APPS."""
        apps = _read_settings_list("INSTALLED_APPS")
        assert "ids_middleware.apps.IdsMiddlewareConfig" in apps, (
            f"IdsMiddlewareConfig not found in INSTALLED_APPS. Got: {apps}"
        )

    def test_ids_middleware_is_last_in_middleware(self):
        """IDSMiddleware should be the last entry in MIDDLEWARE."""
        middleware = _read_settings_list("MIDDLEWARE")
        assert middleware, "MIDDLEWARE list is empty"
        assert middleware[-1] == "ids_middleware.middleware.IDSMiddleware", (
            f"IDSMiddleware should be last. Last entry: {middleware[-1]}"
        )

    def test_ids_middleware_logger_configured(self):
        """ids_middleware logger must be configured in LOGGING."""
        logger_keys = _read_settings_dict_keys("LOGGING", "loggers")
        assert "ids_middleware" in logger_keys, (
            f"ids_middleware logger not found in LOGGING. Got loggers: {logger_keys}"
        )
