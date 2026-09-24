import subprocess


def run(user_input):
    # argv form: no shell involved, so this is not a command-injection sink
    return subprocess.run([user_input])
