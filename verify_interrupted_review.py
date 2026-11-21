"""Force-stop only the Windows driver app and check the private QNX review."""

import argparse
from contextlib import contextmanager
import ctypes
from ctypes import wintypes
import json
import os
from pathlib import Path
import secrets
import subprocess
import sys
from tempfile import TemporaryDirectory
import time
from urllib.request import Request, urlopen

from run_qnx import PRIVATE_REVIEW_EVENTS, ROOT
from shop_request import FILE_SOURCES, UPLOADED_SOURCE, canonical
from verify_prepared_guest import confirm_absent


SAMPLE = b"8731\n0,817,0,107\n1000,823,0,108\n2000,821,0,105\n3000,799,0,99\n"
WAIT_TIMEOUT = 0x102
SYNCHRONIZE = 0x00100000


@contextmanager
def observe_guest(parent_pid, qemu):
    from win_guest_job import PROCESS_TERMINATE, kernel

    kernel.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
    kernel.WaitForSingleObject.restype = wintypes.DWORD
    kernel.TerminateProcess.argtypes = [wintypes.HANDLE, wintypes.UINT]
    kernel.TerminateProcess.restype = wintypes.BOOL
    query = (f'Get-CimInstance Win32_Process -Filter "ParentProcessId={parent_pid}"'
             ' | Select-Object ProcessId,Name | ConvertTo-Json -Compress')
    listing = subprocess.check_output(["powershell.exe", "-NoProfile", "-Command", query], text=True,
                                      creationflags=subprocess.CREATE_NO_WINDOW, timeout=15)
    processes = json.loads(listing or "[]")
    if isinstance(processes, dict):
        processes = [processes]
    pids = [process["ProcessId"] for process in processes if process["Name"].casefold() == qemu.name.casefold()]
    if len(pids) != 1:
        raise RuntimeError("Expected one QEMU process belonging to the test's driver app.")
    guest = kernel.OpenProcess(SYNCHRONIZE | PROCESS_TERMINATE, False, pids[0])
    if not guest:
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        if kernel.WaitForSingleObject(guest, 0) != WAIT_TIMEOUT:
            raise RuntimeError("QEMU was no longer running at the preview.")
        yield lambda milliseconds: kernel.WaitForSingleObject(guest, milliseconds)
    finally:
        try:
            # Reap the specific test process if the containment check fails.
            if kernel.WaitForSingleObject(guest, 0) == WAIT_TIMEOUT:
                if not kernel.TerminateProcess(guest, 1) and kernel.WaitForSingleObject(guest, 0) != 0:
                    raise ctypes.WinError(ctypes.get_last_error())
                if kernel.WaitForSingleObject(guest, 5000) != 0:
                    raise RuntimeError("Could not reap the test's QEMU process.")
        finally:
            kernel.CloseHandle(guest)


def wait_for_review(driver):
    session = {"X-Repair-Session": secrets.token_hex(16)}
    origin = driver.split("/review/", 1)[0]
    upload = Request(driver + "import", data=SAMPLE,
                     headers={**session, "Origin": origin, "Content-Type": "application/octet-stream"})
    with urlopen(upload, timeout=10) as response:
        if response.status != 202:
            raise RuntimeError("The driver app did not accept the recording.")
    deadline = time.monotonic() + 75
    while time.monotonic() < deadline:
        with urlopen(Request(driver + "state", headers=session), timeout=10) as response:
            state = json.load(response)
        if state["stage"] == "review" and state["claim"]["idle"] == "observed":
            return state
        if state["stage"] in {"review", "error"}:
            break
        time.sleep(0.25)
    raise RuntimeError("The test did not reach the expected native preview.")


def verify(qemu):
    with TemporaryDirectory(prefix="rr-parent-exit-") as temporary:
        root = Path(temporary)
        env = {**os.environ, "TEMP": temporary, "TMP": temporary, "TMPDIR": temporary}
        command = [sys.executable, str(ROOT / "live.py"), "--driver-only", "--ephemeral-issuer", "--qemu", str(qemu)]
        with subprocess.Popen(command, env=env, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                              text=True, creationflags=subprocess.CREATE_NO_WINDOW) as app:
            try:
                header = app.stdout.readline()
                if not header.startswith("Driver: "):
                    raise RuntimeError("The driver app did not report its local review link.")
                state = wait_for_review(header.removeprefix("Driver: ").strip())
                with observe_guest(app.pid, qemu) as wait:
                    started = time.monotonic()
                    app.kill()
                    app.wait(timeout=5)
                    if wait(4000) != 0:
                        raise RuntimeError("QEMU survived after force-stopping the driver app.")
                    stopped_ms = round((time.monotonic() - started) * 1000)
            finally:
                if app.poll() is None:
                    app.kill()
                    app.wait(timeout=5)
        files = [file for file in root.rglob("*") if file.is_file()]
        staged, = root.glob("repair-receipt-*/guest/import.aesgcm")
        disk = staged.with_name("job.qnx6")
        trace = staged.with_name("serial.log").read_bytes()
        if staged.stat().st_size != len(SAMPLE) + len(FILE_SOURCES[UPLOADED_SOURCE]) + 28 or not disk.is_file():
            raise RuntimeError("Expected encrypted staging artifacts.")
        for event in (b"RR_EVALUATION_US ", b"RR_COVERAGE ", b"RR_PREVIEW "):
            if [line for line in trace.splitlines(keepends=True) if event in line] != [PRIVATE_REVIEW_EVENTS[event]]:
                raise RuntimeError("Expected only redacted preview events.")
        if b"RR_RECORDING_AUTHENTICATED" not in trace or b"RR_RECEIPT " in trace:
            raise RuntimeError("Expected an authenticated recording at preview before issuance.")
        confirm_absent(files, [SAMPLE, *SAMPLE.splitlines(keepends=True)[1:],
                               canonical(state["claim"]).encode("ascii"), state["issuer"].encode("ascii")])
        return {"forced_driver_exit_at_qnx_preview": True, "qemu_exited": True,
                "guest_stop_observed_ms": stopped_ms, "files_inspected": len(files),
                "staging_ciphertext_bytes": staged.stat().st_size, "job_disk_bytes": disk.stat().st_size,
                "plaintext_in_workspace": False, "private_preview_in_workspace": False, "receipt_issued": False}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--qemu", type=Path, required=True)
    parser.add_argument("--proof", type=Path)
    args = parser.parse_args()
    if sys.platform != "win32":
        parser.error("The parent exit test uses Windows process handles.")
    result = json.dumps(verify(args.qemu.resolve(strict=True)), indent=2) + "\n"
    if args.proof:
        with args.proof.open("x", encoding="utf-8", newline="\n") as output:
            output.write(result)
    print(result, end="")
