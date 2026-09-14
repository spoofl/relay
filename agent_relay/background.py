"""Detaching from the terminal so the relay keeps running in the background."""

import os


READY = "ready "


class Launch:
    """One-shot report to whoever started the relay."""

    def __init__(self, channel, detached):
        self.channel = channel
        self.detached = detached

    def ready(self, message):
        self.send(READY + message if self.detached else message)

    def failed(self, message):
        self.send(message)

    def send(self, message):
        # The launching shell is gone once startup has been reported, so every
        # outcome is sent at most once and a closed channel is not an error.
        if self.channel is None:
            return
        try:
            os.write(self.channel, message.encode())
        except OSError:
            pass
        os.close(self.channel)
        self.channel = None


def detach():
    """Fork into a new session; only the background relay returns.

    The launching shell waits for the startup report, so a relay that
    cannot bind its listener keeps its message and its exit status instead of
    disappearing into the log.
    """
    reader, writer = os.pipe()
    child = os.fork()
    if child:
        os.close(writer)
        os.waitpid(child, 0)  # the middle process exits as soon as it forks again
        with os.fdopen(reader) as pipe:
            outcome = pipe.read()
        if outcome.startswith(READY):
            os.write(1, outcome[len(READY):].encode())
            os._exit(0)
        os.write(2, (outcome or "Relay could not start: it stopped during startup\n").encode())
        os._exit(1)
    os.close(reader)
    os.setsid()  # leave the terminal's session so closing it cannot stop the relay
    if os.fork():
        os._exit(0)  # only a session leader can acquire a terminal, and it exits here
    return writer


def redirect(log):
    """Point stdin, stdout, and stderr away from the terminal; return the old stderr."""
    terminal = os.dup(2)
    null = os.open(os.devnull, os.O_RDWR)
    output = null if log is None else log
    os.dup2(null, 0)
    os.dup2(output, 1)
    os.dup2(output, 2)
    os.close(null)
    return terminal


def begin(detached, log_path):
    """Move console output where it was asked for and return the startup report."""
    log = os.open(log_path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600) if log_path else None
    channel = detach() if detached else None
    if detached or log is not None:
        terminal = redirect(log)
        if detached:
            os.close(terminal)  # the launching shell reads the pipe instead
        else:
            channel = terminal  # keep startup failures visible on the quietened terminal
    if log is not None:
        os.close(log)
    return Launch(channel, detached)
