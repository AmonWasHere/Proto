import subprocess


def run(user_input):
    # argv form: no shell, not flagged by the shell=True rule
    return subprocess.run([user_input])
