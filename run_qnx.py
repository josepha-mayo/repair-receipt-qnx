"""Run the self-contained Repair Receipt experiment in a fresh QNX guest."""

import argparse
from contextlib import nullcontext
import json
from pathlib import Path
from queue import Empty, Queue
import re
import secrets
import shutil
import socket
import subprocess
import sys
from threading import Thread
import time

from obd_bench import AdapterBench
from shop_request import BENCH_SOURCE, FILE_SOURCES, guest_bytes, matches_claim, matches_driver_claim


ROOT = Path(__file__).resolve().parent
FIXTURES = ("trip-a", "trip-b", "moving", "gap", "kit-obd", "scope-control")
MAX_RECORDING = 4 * 1024 * 1024
RECORDING_DOMAIN = b"Repair Receipt CSV stage v1"
PRIVATE_REVIEW_EVENTS = {
    b"RR_ISSUER_SETUP": b"RR_ISSUER_SETUP [private boot token]\n",
    b"RR_ISSUER ": b"RR_ISSUER [issuer key]\n",
    b"RR_COVERAGE ": b"RR_COVERAGE [driver-only guidance]\n",
    b"RR_EVALUATION_US ": b"RR_EVALUATION_US [private timing]\n",
    b"RR_PREVIEW ": b"RR_PREVIEW [private preview]\n",
    b"RR_RECEIPT ": b"RR_RECEIPT import [signed receipt]\n",
}
BENCH_START = (
    "devc-ser8250 -u3 3e8,5\n"
    "if ! waitfor /dev/ser3 5 || ! chmod 0600 /dev/ser3; then\n"
    "    echo RR_INVALID adapter_unavailable > /dev/ser2\n"
    "    exit 1\n"
    "fi\n"
)


def prepare(workspace, recording, boot_token=None, request=None, bench=False, template=False, sealed=None,
            *, policy_binary=None):
    binary = (ROOT / "build/repair-receipt").resolve(strict=True)
    policy = (policy_binary or ROOT / "build/secpol.bin").resolve(strict=True)
    if any(char in str(path) for path in (workspace, binary, policy) for char in '"\r\n'):
        raise ValueError("Invalid image workspace path.")
    if recording and (not recording.is_file() or recording.stat().st_size > MAX_RECORDING):
        raise ValueError("Choose a regular CSV file of at most 4 MiB.")
    workspace.mkdir(mode=0o700, parents=True)
    snippets = workspace / "local" / "snippets"
    snippets.mkdir(parents=True)
    (snippets / "ifs_files.receipt").write_text(
        f'bin/secpolpush\n[perms=0444] secpol.bin = "{policy.as_posix()}"\n', encoding="utf-8"
    )
    system = f'[perms=0555] bin/repair-receipt = "{binary.as_posix()}"\n'
    sources = {
        fixture: ROOT / "fixtures" / f"{fixture}.csv" for fixture in FIXTURES
    }
    if bench or template or sealed is not None:
        sources = {}
    elif recording:
        staged = workspace / "recording.csv"
        shutil.copyfile(recording, staged)
        sources = {"import": staged}
    for fixture, path in sources.items():
        source = path.as_posix()
        system += f'[uid=0 gid=0 perms=0400] receipt-private/{fixture}.csv = "{source}"\n'
    if sealed is not None:
        encrypted = workspace / "import.aesgcm"
        encrypted.write_bytes(sealed)
        system += f'[uid=0 gid=0 perms=0400] receipt-private/import.aesgcm = "{encrypted.as_posix()}"\n'
    if template:
        system += "[type=dir uid=0 gid=0 perms=0755] receipt-private\n"
    if boot_token is not None:
        token = workspace / "boot-token"
        token.write_bytes(boot_token)
        system += f'[uid=0 gid=0 perms=0400] receipt-private/boot-token = "{token.as_posix()}"\n'
    if request is not None:
        request_file = workspace / "request.bin"
        request_file.write_bytes(guest_bytes(request))
        system += f'[uid=0 gid=0 perms=0400] receipt-private/request.bin = "{request_file.as_posix()}"\n'
    (snippets / "system_files.receipt").write_text(system, encoding="utf-8")
    live = recording is not None or sealed is not None or bench or template
    device = "/dev/ser2" if live else "/dev/ser1"
    arguments = "--approved-fixture-run"
    if live:
        mode = "--review-signed" if boot_token is not None else "--review-import"
        if request is not None:
            mode = "--review-request"
        if bench:
            mode = "--review-obd-bench"
        arguments = f"{mode} < {device}"
    startup = ""
    if live:
        startup = "random -s /data/var/random/rnd-seed\nwaitfor /dev/random 5\n"
    if bench:
        startup += BENCH_START
    if template:
        startup += (
            "if ! waitfor /dev/hd1 6 || ! chmod 0600 /dev/hd1 || "
            "! mount -r -t qnx6 /dev/hd1 /system/receipt-private; then\n"
            "    echo RR_EXIT=job_disk_failed > /dev/ser2\n"
            "    exit 1\n"
            "fi\n"
            "if [ -f /system/receipt-private/bench ]; then\n" +
            "".join("    " + line + "\n" for line in BENCH_START.splitlines()) +
            "    rr_mode=--review-obd-bench\n"
            "elif [ -f /system/receipt-private/request.bin ]; then\n"
            "    rr_mode=--review-request\n"
            "else\n"
            "    rr_mode=--review-signed\n"
            "fi\n"
        )
        arguments = '"$rr_mode" < /dev/ser2'
    (snippets / ("startup_postfs.receipt" if live else "post_start.receipt")).write_text(
        startup +
        f'if /proc/boot/secpolpush > {device} 2>&1; then\n'
        f'    on -T receipt_owner_t /system/bin/repair-receipt {arguments} > {device} 2>&1\n'
        f'    echo RR_EXIT=$? > {device}\n'
        'else\n'
        f'    echo RR_EXIT=policy_failed > {device}\n'
        'fi\n' + ("exit 0\n" if live else ""),
        encoding="utf-8",
    )


def build_image(workspace, recording, boot_token=None, request=None, bench=False, template=False, sealed=None,
                *, policy_binary=None):
    prepare(workspace, recording, boot_token, request, bench, template, sealed, policy_binary=policy_binary)
    image = ["mkqnximage", "--type=qemu", "--arch=x86_64", "--hostname=repair-receipt",
             "--ssh-ident=none", "--noprompt", "--build"]
    if sys.platform == "win32":
        image = ["cmd", "/d", "/c", *image]
    with (workspace / "image-build.log").open("wb") as log:
        subprocess.run(image, cwd=workspace, stdin=subprocess.DEVNULL, stdout=log,
                       stderr=subprocess.STDOUT, check=True, timeout=180)


def build_template(path, *, policy_binary=None):
    build_image(path, None, template=True, policy_binary=policy_binary)
    return path


def prepare_job_disk(workspace, sealed, boot_token, request, bench):
    workspace.mkdir(mode=0o700, parents=True)
    (workspace / "boot-token").write_bytes(boot_token)
    (workspace / "job-disk").write_bytes(b"")
    contents = [
        "[num_sectors=16065]",
        "[uid=0 gid=0 perms=0444] job-disk = job-disk",
        "[uid=0 gid=0 perms=0400] boot-token = boot-token",
    ]
    if request is not None:
        (workspace / "request.bin").write_bytes(guest_bytes(request))
        contents.append("[uid=0 gid=0 perms=0400] request.bin = request.bin")
    if bench:
        (workspace / "bench").write_bytes(b"")
        contents.append("[uid=0 gid=0 perms=0400] bench = bench")
    else:
        (workspace / "import.aesgcm").write_bytes(sealed)
        contents.append("[uid=0 gid=0 perms=0400] import.aesgcm = import.aesgcm")
    (workspace / "job.build").write_text("\n".join(contents) + "\n", encoding="utf-8")
    with (workspace / "image-build.log").open("wb") as log:
        subprocess.run(["mkqnx6fsimg", "job.build", "job.qnx6"], cwd=workspace, stdin=subprocess.DEVNULL,
                       stdout=log, stderr=subprocess.STDOUT, check=True, timeout=30)


def drive_option(path, disk_format, index):
    return f"file={str(path).replace(',', ',,')},format={disk_format},if=ide,index={index}"


def qemu_command(qemu, *serial_ports, image=None):
    ports = [argument for port in serial_ports for argument in ("-serial", port)]
    output = image / "output" if image is not None else Path("output")
    return [str(qemu), "-accel", "tcg", "-cpu", "max", "-smp", "2", "-m", "1024",
            "-kernel", str(output / "ifs.bin"), "-snapshot",
            "-drive", drive_option(output / "disk-qemu.vmdk", "vmdk", 0),
            "-nic", "none", "-display", "none", "-monitor", "none", *ports,
            "-no-reboot"]


def stop_guest(guest):
    if guest.poll() is None:
        guest.terminate()
        try:
            guest.wait(timeout=5)
        except subprocess.TimeoutExpired:
            guest.kill()
            guest.wait(timeout=5)


def run(workspace, qemu):
    build_image(workspace, None)
    serial = workspace / "serial.log"
    flags = subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0
    with (workspace / "qemu.log").open("wb") as log:
        guest = subprocess.Popen(
            qemu_command(qemu, "file:serial.log"),
            cwd=workspace, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=log,
            creationflags=flags,
        )
        try:
            deadline = time.monotonic() + 120
            while time.monotonic() < deadline:
                if serial.is_file():
                    lines = serial.read_bytes().splitlines()
                    if b"RR_DONE" in lines and b"RR_EXIT=0" in lines:
                        return serial
                    if any(line.startswith((b"RR_FAIL ", b"RR_EXIT=")) for line in lines):
                        raise RuntimeError(f"Native run failed. See {serial}")
                if guest.poll() is not None:
                    raise RuntimeError(f"QEMU exited early. See {workspace / 'qemu.log'}")
                time.sleep(0.25)
            raise TimeoutError(f"No result. See {serial}")
        finally:
            stop_guest(guest)


def collect_review(guest, transport, serial, decide, seed=None, boot_token=None, request=None,
                   bench=False, job_disk=False, recording_key=None, on_disconnect=None, *, source=None,
                   on_coverage=None, on_evaluation=None):
    expected_source = BENCH_SOURCE if bench else source
    lines = Queue()
    signed = seed is not None

    def read_serial():
        try:
            with transport.makefile("rb") as incoming:
                for line in incoming:
                    event = line.lstrip(b"\x11\x13").rstrip(b"\r\n")
                    diagnostic = next((redacted for marker, redacted in PRIVATE_REVIEW_EVENTS.items()
                                       if marker in line), line)
                    serial.write(diagnostic)
                    serial.flush()
                    if event.startswith(b"RR_"):
                        lines.put(event)
        except ConnectionResetError:
            pass
        finally:
            if on_disconnect is not None:
                on_disconnect()
            lines.put(None)

    reader = Thread(target=read_serial, daemon=True)
    reader.start()
    preview = receipt = issuer = None
    coverage = None
    share = denied = boundary = key_denied = done = False
    raw_withheld = False
    provisioned = False
    recorded = False
    adapter_denied = False
    job_disk_denied = False
    authenticated_recording = False
    plaintext_absent = False
    withheld = set()
    deadline = time.monotonic() + 120
    try:
        while True:
            try:
                line = lines.get(timeout=max(0, deadline - time.monotonic()))
            except Empty as error:
                raise TimeoutError("No result from QNX. See serial.log.") from error
            if line is None:
                raise RuntimeError("QNX stopped before completing review. See serial.log.")
            if line.startswith(b"RR_ISSUER_SETUP "):
                if not signed or provisioned or not secrets.compare_digest(
                    line.removeprefix(b"RR_ISSUER_SETUP "), boot_token
                ):
                    raise RuntimeError("The signer provisioning channel did not verify.")
                transport.sendall(seed.hex().encode("ascii") + b"\n")
                if recording_key is not None:
                    transport.sendall(recording_key.hex().encode("ascii") + b"\n")
                provisioned = True
            elif line.startswith(b"RR_ISSUER ") and signed and issuer is None:
                issuer = line.removeprefix(b"RR_ISSUER ")
                if not provisioned or not re.fullmatch(rb"[a-f0-9]{64}", issuer):
                    raise RuntimeError("Invalid issuer public key from QNX.")
            elif re.fullmatch(rb"RR_CAPTURE_COMPLETE [0-9]+ [0-9]+", line):
                recorded = True
            elif line == b"RR_RECORDING_AUTHENTICATED":
                authenticated_recording = True
            elif on_evaluation is not None and line.startswith(b"RR_EVALUATION_US "):
                measurement = re.fullmatch(rb"RR_EVALUATION_US ([0-9]{1,12})", line)
                if measurement is None:
                    raise RuntimeError("QNX reported an invalid evaluation time.")
                on_evaluation(int(measurement[1]))
            elif line.startswith(b"RR_COVERAGE "):
                limits = re.fullmatch(rb"RR_COVERAGE ([0-3]) ([0-3])", line)
                if issuer is None or preview is not None or coverage is not None or not limits:
                    raise RuntimeError("Invalid driver guidance from QNX.")
                coverage = {context: int(value) for context, value in zip(("idle", "moving"), limits.groups())
                            if value != b"0"}
            elif line.startswith(b"RR_PREVIEW ") and preview is None:
                preview = line.removeprefix(b"RR_PREVIEW ")
                if signed and issuer is None:
                    raise RuntimeError("QNX preview missing the issuer key.")
                if bench and not recorded:
                    raise RuntimeError("QNX did not verify the bench capture.")
                if recording_key is not None and not authenticated_recording:
                    raise RuntimeError("QNX did not authenticate the staged recording.")
                if request is not None and not matches_claim(preview, request, expected_source):
                    raise RuntimeError("QNX preview does not match the requested scope or recording source.")
                if signed and request is None and not matches_driver_claim(preview, expected_source):
                    raise RuntimeError("QNX preview does not match the driver-started review format.")
                if coverage is not None:
                    claim = json.loads(preview)
                    incomplete = {context for context in ("idle", "moving")
                                  if claim.get(context) == "insufficient_evidence"}
                    if coverage.keys() != incomplete:
                        raise RuntimeError("The driver guidance does not match the QNX findings.")
                    if on_coverage is not None:
                        on_coverage(coverage)
                share = decide(preview, issuer)
                transport.sendall(b"share\n" if share else b"decline\n")
                deadline = time.monotonic() + 15
            elif line.startswith(b"RR_RECEIPT import "):
                receipt = line.removeprefix(b"RR_RECEIPT import ")
            elif line == b"RR_UNAPPROVED refused":
                denied = True
            elif line == b"RR_BOUNDARY raw_channel_denied raw_file_denied":
                boundary = True
            elif line == b"RR_KEY_BOUNDARY vault_memory_denied":
                key_denied = True
            elif line == b"RR_CAPTURE_ACCESS adapter_denied":
                adapter_denied = True
            elif line == b"RR_JOB_DISK_BOUNDARY raw_device_denied":
                job_disk_denied = True
            elif line == b"RR_PLAINTEXT_BOUNDARY no_staged_file":
                plaintext_absent = True
            elif line.startswith(b"RR_SIGN_WITHHELD "):
                withheld.add(line.removeprefix(b"RR_SIGN_WITHHELD "))
            elif line == b"RR_LIVE_RAW_WITHHELD":
                raw_withheld = True
            elif line == b"RR_DONE":
                done = True
            elif line == b"RR_EXIT=0":
                break
            elif line == b"RR_INVALID recording_rejected":
                raise ValueError("QNX rejected the recording. Check the CSV format and sample bounds.")
            elif line == b"RR_INVALID adapter_unavailable":
                raise ValueError("QNX could not initialize the simulated adapter.")
            elif line == b"RR_INVALID recording_authentication_failed":
                raise RuntimeError("QNX rejected the sealed recording before review.")
            elif line.startswith((b"RR_FAIL ", b"RR_EXIT=")):
                raise RuntimeError("QNX failed to complete review. See serial.log.")
        if preview is None or not boundary or not done or (signed and not key_denied):
            raise RuntimeError("Incomplete QNX review. No receipt saved.")
        if signed and (not raw_withheld or withheld != {b"approval_required", b"review_complete"}):
            raise RuntimeError("QNX did not verify the signed review gates.")
        if bench and not adapter_denied:
            raise RuntimeError("QNX did not verify the adapter access boundary.")
        if job_disk and not job_disk_denied:
            raise RuntimeError("QNX did not verify the private job disk boundary.")
        if recording_key is not None and not plaintext_absent:
            raise RuntimeError("QNX did not verify the absence of a plaintext recording file.")
        if share and not denied:
            if signed:
                if bench:
                    version = b"3"
                elif source is not None:
                    version = b"5" if request is not None else b"6"
                else:
                    version = b"2" if request is not None else b"4"
                pattern = (rb'\{"format":"repair-receipt/v' + version + rb'","claim":' + re.escape(preview) +
                           rb',"signature":"[a-f0-9]{128}"\}')
                if receipt and re.fullmatch(pattern, receipt):
                    return receipt
            elif receipt == preview:
                return receipt
        if not share and denied and receipt is None:
            return None
        raise RuntimeError("QNX review response did not match the decision. No receipt saved.")
    finally:
        stop_guest(guest)
        reader.join(timeout=5)


def seal_recording(recording, source=None):
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    if isinstance(recording, Path):
        if not recording.is_file():
            raise ValueError("Choose a regular recording file.")
        with recording.open("rb") as file:
            recording = file.read(MAX_RECORDING + 1)
    if not isinstance(recording, bytes) or not 0 < len(recording) <= MAX_RECORDING:
        raise ValueError("Choose a nonempty CSV recording of at most 4 MiB.")
    key = secrets.token_bytes(32)
    nonce = secrets.token_bytes(12)
    if source is not None:
        recording = FILE_SOURCES[source] + recording
    return nonce + AESGCM(key).encrypt(nonce, recording, RECORDING_DOMAIN), key


def review_native(workspace, qemu, recording, decide, seed=None, request=None, bench=None, image=None,
                  on_disconnect=None, *, source=None, on_coverage=None, on_evaluation=None):
    if request is not None and seed is None:
        raise ValueError("A shop request needs a signing key.")
    if seed is not None and len(seed) != 32:
        raise ValueError("An Ed25519 issuer seed must have 32 bytes.")
    if bench is not None and (recording is not None or request is None):
        raise ValueError("The simulated adapter requires a shop request and no CSV input.")
    if source is not None and (source not in FILE_SOURCES or bench is not None or seed is None):
        raise ValueError("A signed recording source requires a supported CSV review.")
    if image is not None and (seed is None or (recording is None and bench is None)):
        raise ValueError("The prepared guest requires an issuer and a recording source.")
    token = secrets.token_hex(32).encode("ascii") if seed is not None else None
    sealed = recording_key = None
    if seed is not None and bench is None:
        sealed, recording_key = seal_recording(recording, source)
        recording = None
    if image is None:
        build_image(workspace, recording, token, request, bench is not None, sealed=sealed)
    else:
        prepare_job_disk(workspace, sealed, token, request, bench is not None)
    flags = subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0
    adapter_context = AdapterBench(bench) if bench is not None else nullcontext()
    with adapter_context as adapter, socket.socket() as listener, (workspace / "qemu.log").open("wb") as log, \
            (workspace / "serial.log").open("wb") as serial:
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        listener.settimeout(15)
        port = listener.getsockname()[1]
        command = qemu_command(qemu, "file:console.log", f"tcp:127.0.0.1:{port},nodelay=on", image=image)
        if image is not None:
            command.extend(["-drive", drive_option(workspace / "job.qnx6", "raw", 1)])
        if adapter is not None:
            command.extend(["-chardev", f"socket,id=obd,host=127.0.0.1,port={adapter.port},nodelay=on",
                            "-device", "isa-serial,chardev=obd,index=2,iobase=0x3e8,irq=5"])
        with subprocess.Popen(command, cwd=workspace, stdin=subprocess.DEVNULL,
                              stdout=subprocess.DEVNULL, stderr=log, creationflags=flags) as guest:
            try:
                connection, _ = listener.accept()
                listener.close()
                with connection:
                    result = collect_review(guest, connection, serial, decide,
                                            seed=seed, boot_token=token, request=request, bench=bench is not None,
                                            job_disk=image is not None, recording_key=recording_key,
                                            on_disconnect=on_disconnect, source=source, on_coverage=on_coverage,
                                            on_evaluation=on_evaluation)
                    if adapter is not None:
                        adapter.check_commands()
                    return result
            finally:
                stop_guest(guest)


def review(workspace, qemu, recording, receipt):
    if receipt.exists() or not receipt.parent.is_dir():
        raise ValueError("Choose a new receipt file in an existing directory.")

    def decide(preview, _issuer):
        print("Receipt preview from QNX:", preview.decode("ascii"), flush=True)
        try:
            return input("Type share to export this receipt, or press Enter to decline: ") == "share"
        except EOFError:
            return False

    approved = review_native(workspace, qemu, recording, decide)
    if approved is None:
        print("QNX refused sharing. No receipt was created.")
    else:
        with receipt.open("xb") as output:
            output.write(approved)
        print(f"Saved approved receipt to {receipt}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace", type=Path, required=True)
    parser.add_argument("--qemu", type=Path, required=True)
    parser.add_argument("--private-recording", type=Path, help="review a normalized CSV in QNX")
    parser.add_argument("--receipt", type=Path, help="write an approved receipt to this new file")
    args = parser.parse_args()
    if bool(args.private_recording) != bool(args.receipt):
        parser.error("--private-recording and --receipt must be supplied together")
    workspace = args.workspace.resolve()
    qemu = args.qemu.resolve(strict=True)
    if args.private_recording:
        review(workspace, qemu, args.private_recording.resolve(strict=True), args.receipt.resolve())
    else:
        print(run(workspace, qemu))


if __name__ == "__main__":
    try:
        main()
    except (OSError, RuntimeError, ValueError, subprocess.SubprocessError) as error:
        print(f"Repair Receipt: {error}", file=sys.stderr)
        raise SystemExit(1) from None
