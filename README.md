# Repair Receipt

Give a repair shop the answer to a specific question without handing over a recording of the whole drive.

**Try the signed QNX example.** Open the downloaded HTML in a current Chromium browser. Choose **Check idle receipts** to verify two independently issued, identical 342-byte receipts from two published drives. Choose **Check moving receipts** to see where their signed answers differ. **Download proof files** saves the packets and example key for independent verification. [Download the offline verifier](https://github.com/josepha-mayo/repair-receipt-qnx/releases/latest/download/verify-receipt.html) · [Signed QNX evidence](replay/qnx-road-scope-receipts.json)

The first recipe distinguishes whether an intermittent coolant symptom appeared at idle or while moving. That gives a technician a starting point for reproducing the symptom. Each context is reported independently as observed, not observed, or insufficient evidence. The signed claim carries the recipe version and requested findings, with an opaque request ID for shop-initiated checks.

The shop can request just one condition. A request carries an opaque job ID with the recipe and scope, and the signed answer is bound to that request. In a verified idle-only job, changing a trip's **moving** result leaves the signed file byte identical as long as the idle result, request, issuer and input type match.

The QNX evaluator computes findings only for the requested conditions. It still validates each row and checks recording coverage. An unknown interval can withhold a negative finding, and a fully observed crossing remains evidence. Six paired controls check byte equality across idle and moving requests, each with observed, not observed and insufficient-evidence outcomes. [Native scope controls](replay/qnx-scope-matrix-proof.json)

Independent shops and vehicle manufacturers already face decisions about how to share service data. The U.S. GAO documents concerns from independent repair stakeholders about access to wirelessly collected vehicle data. European data protection guidance recommends processing connected-vehicle data locally where possible. This prototype applies that principle to one narrow repair intake question. [GAO report](https://www.gao.gov/products/gao-24-106633) · [EDPB guidelines](https://www.edpb.europa.eu/documents/guideline/guidelines-012020-on-processing-personal-data-in-the-context-of-connected_en)

## Live driver and shop workflow

From a Windows command prompt with 64-bit Python 3.10 or later, QNX SDP 8.0 and QEMU for x86-64 installed, open this folder and run:

```bat
python -m venv .venv
call .venv\Scripts\activate.bat
python -m pip install -r requirements-live.txt
build-qnx.cmd
start-live.cmd --check
start-live.cmd
```

The scripts use the active QNX SDK environment or load it from `%USERPROFILE%\qnx800` if present. The launcher looks for `qemu-system-x86_64` on PATH and then under `C:\QNX\qemu`. Use `start-live.cmd --qemu "C:\path to\qemu-system-x86_64.exe" --open` for another location. `--check` checks the setup without starting the app or creating an issuer profile.

Run `start-live.cmd --self-test` to verify the QNX path with the included demo recordings. It boots a prepared QNX image, verifies four signed receipts and checks that declining produces no receipt. The test uses a temporary issuer and scratch directory.

[Host checks](.github/workflows/host-checks.yml) verify the shop register, the four archived QNX signatures, browser-script syntax and the generated offline verifier on Windows and Ubuntu. To reproduce the receipt and bundle checks locally, run `python verify_shop_register.py` and `python pack_shop.py --check`. The QNX self-test above exercises the live guest.

If Windows reports a path-length error while creating the Python environment, use a short project path such as `C:\src\repair-receipt` and retry.

Open the printed **Driver** URL to save its issuer public key. In the printed **Shop** URL, load the key after confirming its fingerprint and choose **At idle only**. Create and download the request. In the driver page load that file, run a sample or import a CSV, review the finding, then approve or decline. The browser exchanges consent with a private QNX VM over loopback. The VM has no network interface. Approval returns a signed receipt from QNX. The host removes the temporary staging files and job disk after review. Drivers can also initiate a broad review of both operating conditions from the driver page.

After approving a shop-requested review, choose **Download verification packet** and send that file to the shop. It carries the original request, signed receipt and issuer fingerprint. The shop uses its enrolled public key to verify it. Individual receipt and key downloads are also available.

The driver session that starts a review can see the preview, decide and download the issued receipt. Refreshing that tab keeps the session when browser session storage is available. A separate driver session sees only that a review is active until it finishes or expires.

For an incomplete finding, **Recording guidance** explains which requested condition had gaps or too little continuous coverage. The driver sees this guidance in the local review. The shop receives the signed finding and test rule.

Live browser receipts carry a signed input type. The driver and shop see whether QNX evaluated an uploaded CSV, a built-in demo recording, a published road recording or the simulated adapter. The CSV label describes how the app received the data. Older receipts and archived controls without a signed input type still verify and show their source as unspecified.

The app prepares one QNX image in the background at launch. Each review boots a fresh VM, attaches a separate QNX6 job disk with a fresh boot token, and mounts that disk read-only. The host encrypts imported CSV bytes with a new AES-256-GCM key before writing a staging file. The vault receives the key over the token-authenticated local serial link, verifies the complete ciphertext, and evaluates it in an anonymous QNX shared memory object. The exporter is denied access to the encrypted file, the job disk, and vault memory. The app removes the shared image at normal shutdown. [QNX anonymous shared memory](https://qnx.com/developers/docs/8.0/com.qnx.doc.neutrino.prog/topic/shared_memory_anon.html) · [OpenSSL authenticated encryption](https://docs.openssl.org/3.3/man3/EVP_EncryptInit/) · [Prepared-guest benchmark](replay/qnx-prepared-proof.json)

Live review diagnostics log event markers in place of the issuer public key, preview and signed receipt. In an interrupted-review test, the app and QNX guest were stopped at the approval screen. The files left in the test workspace contained encrypted staging data. The scan found neither plaintext sample rows nor the unapproved preview or issuer public key. This check covers app-managed files. The driver’s original CSV stays in its original location, and the host and browser process the input in working memory. [Interrupted-review evidence](replay/qnx-private-staging-proof.json)

The shop can use [the one-file offline verifier](replay/verify-receipt.html) without a QNX installation. Open the signed receipt and a separately trusted issuer public key. For a shop-requested review, also open the original request to confirm the job and scope. The verifier checks the exact fields and Ed25519 signature. A driver-started receipt is labeled as such and can be verified with the trusted key on its own. To rebuild the standalone file, run `python pack_shop.py`.

After verification, the shop can print the requested finding, test rule, input type, full request ID and verified issuer fingerprint for a work order. An unattended driver review expires after five minutes and requires a new approval.

If the browser loses contact with the local app, it pauses approval and download while checking the current review. Each decision is sent once per click. If QEMU exits during the preview, the app ends that review so the driver can start another. If the app itself restarts, open the new Driver link printed in the console.

### File a receipt against a shop request

In the local shop intake, choose a file under **Find a request from a receipt or packet**. The register uses the full request ID to look up the original job, including older requests outside the visible list. It verifies the scope and Ed25519 signature against the key pinned to that request, and checks the request and fingerprint carried by any packet against its own record. The matching work order, signed findings, test rule and source appear above the search and request history. Choose **File verified receipt** to store the answer. The full request ID and issuer fingerprint are available under **Request details**. Selecting a file alone leaves the register unchanged. The first accepted answer stays on file, and selecting the same file again confirms it is already filed.

When a different return verifies for an already filed request, **Two verified receipts** shows the filed and returned findings for each requested condition. It also shows both input types when they differ. The shop can use a new request to file a fresh recording while keeping the original work order evidence.

Use the optional **Work order reference** to match the request to the shop's own record. The reference stays in the local register and carries forward to follow-up requests. The portable request, signed receipt, and verification packet contain no work order reference.

Use **Find by work order** to recover requests by their full saved reference, including older requests outside the recent list. Enter it as saved, including letter case. Results list each matching request and follow-up. Open a request to inspect its own signed findings.

If the signed answer reports insufficient evidence, choose **Create follow-up request**. The register retains the original receipt and creates one linked request for the unanswered conditions using the same recipe and issuer. Download the follow-up and send it to the driver for a fresh capture and approval. A linked request uses a new ID. The exported request file carries only its ID, scope and recipe.

For a filed receipt with findings for all its requested conditions, choose **Create recheck request**. It uses a new ID and the same conditions, threshold, recipe and enrolled issuer. The driver page clears a recording already submitted under a different request when the new request loads. Choose a fresh recording and file its signed receipt. The work-order view and printout summarize how the signed findings compare for each condition. Different capture methods or insufficient coverage are flagged in place of a comparison. The view links to the separate signed files.

After filing, choose **View work-order findings** from the request. Each condition shows the finding from its signed receipt, the test rule, the input source and the shop's filing time. Linked follow-ups appear in the same view. An open follow-up remains visible alongside the earlier finding. The printout includes the issuer fingerprint, full request IDs, exact receipt SHA-256 digests and the optional local work-order reference.

Choose **Download verification files** in the work-order view to save a ZIP with one packet per filed receipt, including the original and any filed follow-ups. Extract the ZIP, select its packet files together in the offline verifier and open a separately trusted copy of the enrolled public key. The verifier checks each packet independently and shows the full request ID and receipt digest alongside each finding. Match the digest to the printed work order to identify the exact filed answer. The ZIP leaves out the local work-order reference.

When different signed receipts share a request ID, the offline verifier flags those attachments and shows both digests. Repeated copies of the same signed receipt appear as ordinary verified files.

After filing, **Download verification packet** saves the original signed receipt, the original request and the enrolled issuer fingerprint as one JSON attachment for the work order. Open it in the standalone verifier with a separately trusted issuer public key. The individual files also remain downloadable.

The shop register survives a restart. It stores job IDs, public keys, scoped receipts and shop filing times in `%LOCALAPPDATA%\RepairReceipt\shop.sqlite3` by default. The times describe activity at the shop. To choose a different database file, pass `--shop-register` to `live.py`.

Open **Register backup** in shop intake and choose **Download register backup** to save a consistent SQLite snapshot while the app is running. The snapshot contains private work order references, the shop's original requests, enrolled public keys and filed receipts. Driver signing keys are managed separately.

To continue from a backup, put a copy in the shop's chosen records folder, then pass its path at startup. For example, run `start-live.cmd --shop-register "C:\Shop\repair-receipt-shop-backup.sqlite3"` and open the printed Shop link. The app reads and writes the specified copy. The original register and the saved backup can stay in place.

### Capture from the simulated OBD-II adapter on QNX

Load a shop request and select **Simulated OBD-II adapter · Live QNX capture** on the driver page. QNX opens a separate UART backed by an ELM327-compatible simulator, collects a nine-second window, then displays the scoped finding for approval. The signed receipt identifies the simulated source. Both the shop register and the standalone verifier display it.

The capture uses a fixed CAN profile and requests only current coolant temperature, engine RPM and vehicle speed. It reads speed before and after coolant and RPM. All four exchanges share a 350 ms budget measured from the scheduled sample time. If the readings disagree on whether the vehicle was stationary, QNX drops the sample. A missing or ambiguous reply also drops the sample. QNX checks the deadline again when the terminating prompt arrives. An interrupted or late exchange ends capture before any further requests. Incomplete coverage withholds negative findings, and a crossing already observed remains evidence. Capture data stays in a root-only file in QNX shared memory during review. The exporter must fail to open both that file and the UART before it can publish the approved receipt. [ELM327 reference](https://www.elmelectronics.com/wp-content/uploads/2017/01/ELM327DS.pdf) · [QNX serial driver](https://qnx.com/developers/docs/8.0/com.qnx.doc.neutrino.utilities/topic/d/devc-ser8250.html)

Run the eight serial capture controls from a QNX SDK prompt.

```bat
python verify_obd_bench.py --qemu C:\QNX\qemu\qemu-system-x86_64.exe
```

The paired timing control sends the same data in both runs. The simulator delays the first three prompts by 60 ms each and the final speed prompt by 50 or 240 ms. The 230 ms of injected delay preserves the findings. The 420 ms case discards the incomplete sample and stops polling even though each reply fits inside 350 ms on its own. These tests use a simulated adapter on a QEMU UART. A physical adapter and vehicle ECU require separate validation. [Native bench evidence](replay/qnx-obd-proof.txt)

For a quick check, open the [signed scoped sample](replay/sample-request-receipt.json) with its [shop request](replay/sample-request.json) and [example issuer key](replay/sample-request-issuer.json). The signed answer was generated by a native QNX test run.

### Enroll a shop before sending the first receipt

In the driver page, open **Enroll your issuer key at the shop** and save the public key. Confirm its SHA-256 fingerprint with the shop through a known channel. The offline shop view displays the same fingerprint when it opens the key. The shop can reuse that public key after a restart of the driver app.

The Windows app creates its issuer store in `%LOCALAPPDATA%\RepairReceipt\issuer.dpapi`. Windows DPAPI protects the persisted seed for the current Windows user. Startup refuses a damaged store so it cannot silently replace a trusted identity. For a separate installation use `python live.py --qemu path-to-qemu --issuer-store path-to-store`. For demonstrations that need a fresh identity each time, add `--ephemeral-issuer` instead. [Windows DPAPI](https://learn.microsoft.com/en-us/windows/win32/api/dpapi/nf-dpapi-cryptprotectdata)

The local host checks a one-time boot token before passing the seed to the QNX vault over the loopback serial connection. The VM image contains the ephemeral token. The signing key is loaded into the vault's process memory. The host checks that QNX uses the enrolled public key and verifies QNX's signature before exposing the downloaded receipt.

For every signed review the vault owns approval and signs the exact preview. A preapproval or repeat issuance call gets `EACCES`. The requesting supervisor receives a bounded receipt only after approval, and the unprivileged exporter is denied access to vault memory and the recording. The shop intake checks the request ID before filing and retains the first accepted answer. [Native scoped trace](replay/qnx-scoped-proof.txt) · [Scope verification codelab](CODELAB.md).

The codelab includes an automated QNX policy check. It holds the recording, request and issuer fixed, then checks export with the grant removed, with consent declined and with both the grant and approval present. [Run the policy check](CODELAB.md#remove-one-channel-grant)

## Recorded proof

Open [the offline replay](replay/repair-receipt.html) and compare Trips A and C to see how their moving temperatures differ. The replay shows both contexts. The scope verification codelab applies an idle-only request to the same two recordings. Select Missing samples to see how the recipe handles uncertainty. The KIT option uses a short slice of a published OBD-II drive. [Read the QNX serial evidence](replay/qnx-proof.txt).

## What ran on QNX

- Three typed processes run on a stock QNX 8.0.0 guest with a loaded application security policy. The trusted owner process can reach the recording vault, while the exporter can only reach the owner's receipt channel.
- The trusted owner reads a raw fixture row from the vault as a positive control. The exporter starts with an unprivileged UID and GID. With the same raw channel address, it gets a kernel access error. A separate test checks that it cannot open the root-only recording.
- The owner refuses an exporter request without local approval. Once authorized, it returns only a bounded response computed in the vault, and it checks the request comes from the expected child.
- The verifier checks the complete sequence, all six exact payloads, and the differing fixture hashes for Trips A and B. The within-guest checks exercise the QNX channel policy and filesystem permissions independently.

New shop requests and driver-started reviews use the sustained-threshold test rule. The default threshold is 105 °C. The shop can choose a whole-degree threshold when it creates a request. A positive finding needs three or more consecutive samples at or above that threshold in the requested condition, spanning at least two seconds. A gap over two seconds, an engine stop, or a change between idle and moving breaks the run. A negative finding needs complete recording coverage and a continuous window in the requested condition that has at least three samples spanning two seconds. Short glimpses of a condition return **insufficient evidence**. A fully observed positive run can survive missing coverage elsewhere in the recording.

Older sample-count requests and receipts remain verifiable under their original rule. Browser CSV receipts with a shop request use `repair-receipt/v5`. Driver-started CSV receipts use `repair-receipt/v6` and carry both findings under the sustained rule. Customized shop requests use `repair-receipt-request/v2`. QNX applies the supplied threshold and includes it in the signed claim. Filing and offline verification check it against the original request. Follow-ups inherit the same threshold, which also appears on the work-order printout. Threshold and timing choices still need vehicle-specific and technician validation. [Native duration controls](replay/qnx-duration-proof.json)

For a synthetic recording at the 4 MiB limit, bounded 8 KiB reads reduced median native evaluation time from 3.27 seconds to 0.40 seconds across five runs per build on the same QEMU host. Median time from encrypted staging to preview fell from 5.71 to 2.63 seconds. The signed receipt hash was unchanged. Both builds rejected embedded NUL bytes and overlong rows. [Native parser measurements](replay/qnx-parser-performance-proof.json)

## Reproduce

In a Windows command prompt with QNX SDP 8.0 loaded, run from this directory. Set the QEMU path to your installation and use a fresh path for the workspace.

```bat
build-qnx.cmd
python run_qnx.py --workspace work\native-run-01 --qemu C:\QNX\qemu\qemu-system-x86_64.exe
python verify.py work\native-run-01\serial.log --output replay
```

The runner builds an x86-64 image with root-only fixture files and boots QEMU without a network interface. The guest runs the approved fixture experiment at boot and the runner shuts it down after collecting the result. The compiled policy targets this test image.

## Reproduce the legacy unsigned CLI review

```bat
python run_qnx.py --workspace work\import-01 --qemu C:\QNX\qemu\qemu-system-x86_64.exe --private-recording fixtures\trip-a.csv --receipt work\approved.json
```

The trusted owner evaluates the import in QNX and displays the exact preview. Type `share` and press Enter to approve, or press Enter to decline. The runner saves a new JSON file only after QNX returns the same bytes through its unprivileged exporter. The host exchanges the preview and decision through a separate QEMU serial port over loopback.

The normalized CSV starts with a recording duration in milliseconds (1 to 86,400,000). Each row has elapsed milliseconds, engine RPM, speed in km/h, and coolant temperature in Celsius. Keep timestamps strictly increasing within the duration. Use `elapsed_ms,,,` for a known missing sample. QNX breaks the run at that row and withholds negative findings if coverage is incomplete. Normalized inputs are limited to 4 MiB. Use a private workspace with the CLI because it stages a copy of the recording. The receipt goes to the separate path you choose.

## Real recording

Marc Weber, *Automotive OBD-II Dataset* (2019), [DOI 10.5445/IR/1000085073](https://doi.org/10.5445/IR/1000085073), [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/). Download the published archive from [RADAR4KIT](https://radar.kit.edu/radar/en/dataset/bCtGxdTklQlfQcAq) and run the importer to regenerate the derived 90-second fixture.

The driver page also opens the metric OBD Auto Doctor export format used in the archive. Choose the CSV directly. The browser drops other columns and converts clock times to elapsed milliseconds before passing the recording to the local QNX service. This path accepts source exports up to 8 MiB, with whole-number RPM, km/h and °C readings and up to 24 hours of data. An identical sample repeated at the same timestamp counts once. A conflicting repeat or a clock reversal of at most one second removes the uncertain overlap and marks a coverage gap. A larger reversal or a reversal before the first timestamp stops the import. The driver can open **Recording guidance** for a notice when a clock gap is carried into QNX. A missing reading after the first complete row also interrupts coverage. The format supplies a timestamp per row of logged values. Individual signals may have different update times. [OBD Auto Doctor export documentation](https://www.obdautodoctor.com/features/) · [Full-drive import checks](replay/qnx-obd-import-proof.json)

```bat
python import_kit.py path\to\OBD-II-Dataset.zip fixtures\kit-obd.csv
```

The importer keeps elapsed milliseconds, RPM, speed, and coolant temperature, retaining complete rows at least one second apart. KIT logged these signals through an OBD-II dongle. The excerpt is a reference run while moving. It supplies no idle evidence.

Two full KIT recordings showed the same idle finding and different moving findings in a test at 95 °C. Under one idle-only request and issuer, QNX returned exactly the same 342-byte signed receipt for both recordings. A separate moving-only request confirmed the difference. All four receipts carry the signed published-road input type. [Paired real-recording results](replay/qnx-road-scope-proof.json)

A 64-receipt QNX sweep across 90–105 °C reproduced that pattern at 95 °C and at 98–100 °C. The idle findings were observed at 95 °C and not observed at 98–100 °C. At 96–97 °C, the idle findings differed and the signed idle receipts differed too. These results cover the two KIT recordings under the test recipe. [Complete results](replay/qnx-road-threshold-sweep.json) · [Reproduce the sweep](CODELAB.md#vary-the-test-threshold)

## Current scope

The signed browser workflow runs against QNX in QEMU on the same host. The archived replay uses captured fixture outputs. The UART path has been tested with a simulated adapter. Physical adapter integration, secure vehicle-side key provisioning and vehicle-specific mechanic validation remain open. The proof covers deterministic signed output and the raw access paths exercised in the configured guest.

## License

The original code, documentation and synthetic fixtures are available under the [MIT License](LICENSE).

The derived KIT excerpt in `fixtures/kit-obd.csv` and its embedded copy in `replay/repair-receipt.html` are available under [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/). The [recording notes](#real-recording) credit Marc Weber, link to the original dataset and describe how the excerpt was trimmed and normalized.
