"""Shared pytest fixtures for scanner and CLI/API integration tests."""

import os
import shutil
import tempfile

import pytest


@pytest.fixture
def temp_plugin_dir():
    """Create a temporary directory that looks like a WP plugin."""
    tmp = tempfile.mkdtemp()

    # Create the plugin readme with a valid WordPress header
    readme_file = os.path.join(tmp, "readme.txt")
    with open(readme_file, "w") as f:
        f.write("\n\n=== Test Plugin ===\n")
        f.write("Stable tag: 1.2.3\n")

    # Create a main plugin file
    plugin_file = os.path.join(tmp, "test-plugin.php")
    with open(plugin_file, "w") as f:
        f.write("<?php\n/*\nPlugin Name: Test Plugin\n*/\n")

    yield tmp

    shutil.rmtree(tmp)

@pytest.fixture
def vulnerable_plugin(temp_plugin_dir):
    """Add some vulnerabilities to the temp plugin."""
    vuln_file = os.path.join(temp_plugin_dir, "vuln.php")
    with open(vuln_file, "w") as f:
        f.write("<?php\n")
        f.write("eval($_GET['cmd']); // RCE\n")
        f.write("$wpdb->query(\"SELECT * FROM users WHERE id = \" . $id); // SQLi\n")
        f.write("echo $_POST['user_input']; // XSS\n")
    return temp_plugin_dir
