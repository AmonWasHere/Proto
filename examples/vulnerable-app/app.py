"""A tiny, intentionally vulnerable Flask app used to demo RewardAudit.

Nothing here is production code; it exists to exercise the analyzer, the
codebase graph, the coverage report, and the verifier.
"""

import os

from flask import Flask

from core import run_command

app = Flask(__name__)


@app.route("/run")
def handler():
    # untrusted value read from the environment (a taint source)
    command = os.environ["CMD"]
    return run_command(command)


@app.route("/health")
def health():
    return "ok"


if __name__ == "__main__":
    app.run(port=int(os.getenv("PORT", "5000")))
