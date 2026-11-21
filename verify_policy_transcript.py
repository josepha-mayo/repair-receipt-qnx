"""Check that the exported codelab transcript contains selected native events."""

from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from verify_policy import EXPORT_DENIAL, EXPORT_GRANT, policy_transcript, verify, without_export_grant


class PolicyTranscript(unittest.TestCase):
    def test_existing_transcript_is_preserved(self):
        with TemporaryDirectory() as scratch:
            output = Path(scratch) / "policy-transcript.md"
            output.write_text("review notes", encoding="utf-8")
            with self.assertRaisesRegex(FileExistsError, "Choose a new filename"):
                verify(None, output)
            self.assertEqual(output.read_text(encoding="utf-8"), "review notes")

    def test_transcript_keeps_only_the_explicit_policy_change_and_recognized_events(self):
        standard = "# local policy comment\n" + EXPORT_GRANT + "\n"
        restricted = without_export_grant(standard)
        with TemporaryDirectory() as scratch:
            workspace = Path(scratch)
            for folder, result in (
                ("policy-denied", EXPORT_DENIAL),
                ("consent-declined", b"RR_UNAPPROVED refused"),
                ("export-approved", b"RR_RECEIPT import [signed receipt]"),
            ):
                directory = workspace / folder
                directory.mkdir()
                (directory / "serial.log").write_bytes(b"private boot path\r\nRR_ISSUER private-example-key\r\n"
                    b"\x11RR_PREVIEW [private preview]\r\n" + result + b"\r\nRR_RECEIPT unbounded text\r\n")
            document = policy_transcript(workspace, "a" * 64, standard, restricted)
        self.assertIn("\n-" + EXPORT_GRANT + "\n", document)
        self.assertEqual(document.count("RR_PREVIEW [private preview]"), 3)
        self.assertLess(document.index(EXPORT_DENIAL.decode("ascii")), document.index("RR_UNAPPROVED refused"))
        self.assertLess(document.index("RR_UNAPPROVED refused"), document.index("RR_RECEIPT import [signed receipt]"))
        for private in ("local policy comment", "private boot path", "private-example-key", "unbounded text"):
            self.assertNotIn(private, document)


if __name__ == "__main__":
    unittest.main()
