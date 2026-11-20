"""Build the standalone shop verifier from the live app's static assets."""

import argparse
import json
from pathlib import Path


def standalone():
    root = Path(__file__).resolve().parent
    assets = root / "web"
    page = (assets / "shop.html").read_text(encoding="utf-8")
    stylesheet = (assets / "shared.css").read_text(encoding="utf-8")
    requests = (assets / "request.js").read_text(encoding="utf-8")
    script = (assets / "shop.js").read_text(encoding="utf-8")
    evidence = json.loads((root / "replay" / "qnx-road-scope-receipts.json").read_text(encoding="utf-8"))
    sample = json.dumps(evidence, ensure_ascii=True, separators=(",", ":")).replace("<", "\\u003c")
    return (
        page.replace('<link rel="stylesheet" href="shared.css">', f'<style>{stylesheet}</style>')
        .replace('  <script defer src="shop.js"></script>\n', "")
        .replace('  <script defer src="request.js"></script>\n', "")
        .replace("</body>", f'<script id="road-evidence" type="application/json">{sample}</script>\n'
                 f"<script>{requests}</script>\n<script>{script}</script>\n</body>")
        .replace(' <a href="verify-receipt.html" download>Save offline verifier</a>', "")
    ).encode("utf-8")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="verify that the bundled HTML matches the source")
    args = parser.parse_args()
    destination = Path(__file__).resolve().parent / "replay" / "verify-receipt.html"
    generated = standalone()
    if args.check:
        if not destination.is_file() or destination.read_bytes() != generated:
            parser.exit(1, "Regenerate the offline verifier with python pack_shop.py.\n")
        print("The bundled offline verifier matches its source.")
    else:
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(generated)
        print(destination)
