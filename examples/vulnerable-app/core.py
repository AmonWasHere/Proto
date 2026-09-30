"""The sink lives one call away from the route handler."""

import os


def run_command(command):
    # command injection: untrusted input reaches a shell sink
    return os.system(command)
