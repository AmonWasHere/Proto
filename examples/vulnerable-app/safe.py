"""A safe look-alike, so the report can show what is *not* flagged."""

import subprocess


def run_argv(user_input):
    # argv form: no shell involved, not a command-injection sink
    return subprocess.run([user_input])
