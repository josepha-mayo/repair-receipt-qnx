"""Deterministic ELM327-compatible bench for the QNX serial capture path."""

from contextlib import suppress
import socket
from threading import Thread
import time

PROFILES = {"normal", "gapped", "setup-failure", "late-reply", "link-loss", "motion-change"}
SETUP = ("ATE0", "ATL0", "ATS0", "ATH0", "ATCAF1", "ATM0", "ATTP6", "ATSH7E0", "ATCRA7E8")
SAMPLE_COMMANDS = ("010D", "0105", "010C", "010D")
ALLOWED = {*SETUP, *SAMPLE_COMMANDS}
FAULT_COMMANDS = {
    "late-reply": SETUP + SAMPLE_COMMANDS * 2 + SAMPLE_COMMANDS[:2],
    "link-loss": SETUP + SAMPLE_COMMANDS * 5,
}
SAMPLES = (
    (100, 790, 0), (106, 805, 0), (108, 800, 0), (107, 815, 0),
    (101, 1450, 13), (99, 1825, 25), (98, 1950, 35),
)


class AdapterBench:
    def __init__(self, profile):
        if profile not in PROFILES:
            raise ValueError("Unknown diagnostic bench profile.")
        self.profile = profile
        self.listener = None
        self.connection = None
        self.commands = []
        self.error = None
        self.late_prompt_sent = False

    def __enter__(self):
        self.listener = socket.socket()
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen(1)
        self.listener.settimeout(15)
        self.port = self.listener.getsockname()[1]
        self.worker = Thread(target=self.run, daemon=True)
        self.worker.start()
        return self

    def __exit__(self, *_args):
        self.listener.close()
        if self.connection is not None:
            with suppress(OSError):
                self.connection.shutdown(socket.SHUT_RDWR)
        self.worker.join(timeout=2)

    def run(self):
        try:
            connection, _ = self.listener.accept()
            self.connection = connection
            with connection:
                self.exchange(connection)
        except (ConnectionResetError, BrokenPipeError):
            return
        except (OSError, ValueError) as error:
            self.error = error

    def check_commands(self):
        self.worker.join(timeout=2)
        if self.error or any(command not in ALLOWED for command in self.commands):
            raise RuntimeError("The OBD bench observed an invalid serial exchange.")
        if self.profile in FAULT_COMMANDS and tuple(self.commands) != FAULT_COMMANDS[self.profile]:
            raise RuntimeError("The guest continued asking for readings after a failed serial exchange.")
        if self.profile == "late-reply" and not self.late_prompt_sent:
            raise RuntimeError("The delayed prompt did not reach the guest connection.")

    def exchange(self, connection):
        command = bytearray()
        sample = -1
        setup_index = 0
        step = 0
        while byte := connection.recv(1):
            if byte != b"\r":
                if len(command) == 12:
                    raise ValueError("Unbounded bench command.")
                command.extend(byte)
                continue
            command_text = command.decode("ascii")
            command.clear()
            if len(self.commands) == 64:
                raise ValueError("Unexpected number of bench commands.")
            self.commands.append(command_text)
            if setup_index < len(SETUP):
                if command_text != SETUP[setup_index]:
                    connection.sendall(b"?\r>")
                    continue
                setup_index += 1
                reply = b"?\r" if self.profile == "setup-failure" and command_text == "ATTP6" else b"OK\r"
                if command_text == "ATE0":
                    reply = b"ATE0\r" + reply
            else:
                if command_text != SAMPLE_COMMANDS[step]:
                    raise ValueError("Unexpected PID sequence in a sample.")
                if step == 0:
                    sample += 1
                closing_speed = step == len(SAMPLE_COMMANDS) - 1
                reply, usable = self.pid_reply(command_text, sample, closing_speed)
                step = (step + 1) % len(SAMPLE_COMMANDS) if usable else 0
                if self.profile == "link-loss" and sample == 4 and closing_speed:
                    connection.sendall(b"410D")
                    return
                if self.profile == "late-reply" and sample == 2 and command_text == "0105":
                    connection.sendall(reply)
                    time.sleep(0.65)
                    connection.sendall(b">")
                    self.late_prompt_sent = True
                    continue
            connection.sendall(reply)
            connection.sendall(b">")

    def pid_reply(self, command, sample, closing_speed):
        if not 0 <= sample < len(SAMPLES):
            return b"NO DATA\r", False
        if self.profile == "gapped" and command == "0105":
            if sample == 2:
                return b"NO DATA\r", False
            if sample == 6:
                return b"41058A\r41058B\r", False
        temperature, rpm, speed = SAMPLES[sample]
        if closing_speed and speed:
            speed += 2
        if self.profile == "motion-change" and sample == 2 and not closing_speed:
            speed = 12
        responses = {
            "0105": f"41 05 {temperature + 40:02X}",
            "010C": f"410C{rpm * 4:04X}",
            "010D": f"410D{speed:02X}",
        }
        return (responses[command] + "\r").encode("ascii"), True
