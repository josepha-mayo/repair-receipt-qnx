"""Exercise the Windows template cache without QNX SDK or QEMU."""

import os
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch
from zipfile import ZipFile

import template_cache
from template_cache import IMAGE_FILES, MANIFEST, build_or_reuse, restore_template, save_template, template_key


DESCRIPTOR = (b'# Disk DescriptorFile\nversion=1\nencoding="UTF-8"\nparentCID=ffffffff\n'
              b'isNativeSnapshot="no"\ncreateType="monolithicFlat"\n\n# Extent description\n'
              b'RW 10 FLAT "disk-qemu" 0\n')


def fingerprint_controls(root):
    sdk = root / "sdk"
    host = sdk / "host" / "windows"
    target = sdk / "target" / "qnx"
    common = sdk / "host" / "common"
    for directory in (host, target, common, root / "build"):
        directory.mkdir(parents=True)
    builder = common / "mkqnximage.bat"
    tool = host / "mkqnx6fsimg.exe"
    policy = root / "build/secpol.bin"
    installed = target / "procnto"
    for file in (root / "run_qnx.py", root / "build/repair-receipt", policy, builder, tool, installed):
        file.write_bytes(b"synthetic")
    variables = {"QNX_BASE": str(sdk), "QNX_HOST": str(host), "QNX_TARGET": str(target), "BASH_ENV": ""}
    with patch.dict(os.environ, variables), patch.object(template_cache, "ROOT", root), \
            patch.object(template_cache.shutil, "which", side_effect=lambda name: str(
                builder if name == "mkqnximage" else tool)):
        first = template_key()
        assert first and first == template_key()
        original = policy.stat()
        policy.write_bytes(b"Synthetic")
        os.utime(policy, ns=(original.st_atime_ns, original.st_mtime_ns))
        second = template_key()
        assert second and second != first
        installed.write_bytes(b"new SDK contents")
        third = template_key()
        assert third and third != second


def build(workspace):
    output = workspace / "output"
    output.mkdir(parents=True)
    (output / "ifs.bin").write_bytes(b"synthetic boot image")
    (output / "disk-qemu").write_bytes(b"synthetic blank disk")
    (output / "disk-qemu.vmdk").write_bytes(DESCRIPTOR)
    (workspace / "not-an-image").write_bytes(b"ignore this file")
    return workspace


def archive_controls(root):
    issuer = root / "issuer.dpapi"
    cache_destination = root / "qnx-template-cache/template.zip"
    assert template_cache.template_cache_path(issuer) == cache_destination
    assert template_cache.template_cache_path(issuer, cache_destination) is None
    cache = root / "qnx-template.zip"
    workspace = build(root / "fresh")
    key = "test identity"
    save_template(cache, workspace, key)
    with ZipFile(cache) as archive:
        original = {name: archive.read(name) for name in archive.namelist()}
    assert set(original) == {*IMAGE_FILES, MANIFEST}
    restored = root / "ready"
    assert restore_template(cache, restored, key)
    for name in IMAGE_FILES:
        assert (restored / "output" / name).read_bytes() == original[name]
    assert not restore_template(cache, root / "wrong-key", "different identity")

    for name in (MANIFEST, "ifs.bin"):
        with ZipFile(cache, "w") as archive:
            for member, value in original.items():
                archive.writestr(member, b"altered" if member == name else value)
        failed = root / "invalid"
        assert not restore_template(cache, failed, key)
        assert not failed.exists()
    with patch.object(template_cache, "template_key", return_value=key):
        repaired = root / "rebuilt"
        assert build_or_reuse(repaired, cache, build) == repaired
        assert restore_template(cache, root / "repaired-copy", key)

    # A path outside the template is never eligible for publication.
    descriptor = workspace / "output/disk-qemu.vmdk"
    descriptor.write_bytes(DESCRIPTOR.replace(b'"disk-qemu"', b'"../outside"'))
    previous = cache.read_bytes()
    save_template(cache, workspace, key)
    assert cache.read_bytes() == previous


if __name__ == "__main__":
    if os.name != "nt":
        raise SystemExit("This cache test requires Windows DPAPI.")
    with TemporaryDirectory(prefix="rr-template-cache-test-") as temporary:
        root = Path(temporary).resolve()
        fingerprint_controls(root)
        archive_controls(root)
    print("Verified SDK and policy invalidation, Windows manifest integrity, staging and fresh-build recovery.")
