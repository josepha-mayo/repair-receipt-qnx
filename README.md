# Repair Receipt

Give a repair shop the answer to a specific question without handing over a recording of the whole drive.

**Try the signed QNX examples.** Open the downloaded HTML in a current Chromium browser. It verifies four receipts and shows the idle and moving findings side by side. The two drives share a 342-byte signed idle receipt and return different answers while moving. Select **Check idle receipts** or **Check moving receipts** to choose the packets to download. **Compare startup rules** verifies the one-second allowance on the July 27 drive. **Download proof files** saves the selected packets and their example key. [Download the offline verifier](https://github.com/josepha-mayo/repair-receipt-qnx/releases/latest/download/verify-receipt.html) · [Scoped receipts](replay/qnx-road-scope-receipts.json) · [Startup receipts](replay/qnx-road-startup-receipts.json)

The offline walkthrough also lets you try a mismatched request and return to checking the same signed packet. [Offline codelab steps](CODELAB.md#verify-two-real-drives-offline)

The first recipe reports whether a sustained coolant test threshold was observed with the vehicle stationary or moving. The app labels these contexts **At idle** and **While moving**. QNX uses engine-running samples and separates recorded speeds of 0 km/h and above 0 km/h. Each context is reported independently as observed, not observed, or insufficient evidence. The signed claim carries the recipe version and requested findings, with an opaque request ID for shop-initiated checks.

Manufacturers already use operating conditions when investigating cooling complaints. GM requested observations at idle for a specific Tahoe fleet concern, and Hino describes a cooling complaint seen at higher speeds or under load. A scoped finding gives the shop a starting point for choosing how to reproduce the symptom. Vehicle-specific test conditions and diagnosis stay with the technician. [GM bulletin PIE0368](https://static.nhtsa.gov/odi/tsbs/2016/SB-10094789-2280.pdf) · [Hino tech tip 06-006](https://static.nhtsa.gov/odi/tsbs/2006/MC-10117575-9999.pdf)

The shop can request just one condition. A request carries an opaque job ID with the recipe and scope, and the signed answer is bound to that request. In a verified idle-only job, changing a trip's **moving** result leaves the signed file byte identical as long as the idle result, request, issuer and input type match.

The QNX evaluator computes findings only for the requested conditions. It still validates each row and checks recording coverage, including incomplete samples at the start of an imported CSV. An unknown interval can withhold a negative finding, and a fully observed crossing remains evidence. Six groups of three synthetic recordings check byte equality of the signed receipts and verification packets while changing unrequested RPM, speed, temperature, sampling cadence and recording length. The controls cover idle and moving requests with all three findings. Three different coverage explanations stay with the driver while the shop gets the same signed insufficient-evidence answer. [Native scope controls](replay/qnx-scope-matrix-proof.json)

Independent shops and vehicle manufacturers already face decisions about how to share service data. The U.S. GAO documents concerns from independent repair stakeholders about access to wirelessly collected vehicle data. European data protection guidance recommends processing connected-vehicle data locally where possible. This prototype applies that principle to one narrow repair intake question. [GAO report](https://www.gao.gov/products/gao-24-106633) · [EDPB guidelines](https://www.edpb.europa.eu/documents/guideline/guidelines-012020-on-processing-personal-data-in-the-context-of-connected_en)

## Live driver and shop workflow

Install 64-bit Python 3.10 or later, QNX SDP 8.0 and QEMU for x86-64. Extract or clone into a short path such as `%USERPROFILE%\rr`. A deeply nested path can cause Windows to fail while Python's bundled pip creates the virtual environment. Open Command Prompt in the project folder and run these commands.

```bat
python -m venv .venv
call .venv\Scripts\activate.bat
python -m pip install -r requirements-live.txt
build-qnx.cmd
start-live.cmd --check
start-live.cmd
```

The scripts use the active QNX SDK environment or load it from `%USERPROFILE%\qnx800` if present. The launcher looks for `qemu-system-x86_64` on PATH and then under `C:\QNX\qemu`. Use `start-live.cmd --qemu "C:\path to\qemu-system-x86_64.exe" --open` for another location. `--check` checks the setup without starting the app or creating an issuer profile.

Use `build-qnx.cmd aarch64le` to cross-compile the native evaluator and security policy into `build\aarch64le`. The browser launcher and automated QEMU exercises currently use the x86-64 guest. Booting an AArch64 image requires the QNX QEMU startup package. [QNX image builder reference](https://qnx.com/developers/docs/8.0/com.qnx.doc.neutrino.utilities/topic/m/mkqnximage.html)

Use `start-live.cmd --practice` for a hands-on trial. The driver gets a temporary signing key and the shop starts with an empty register for this session. The app discards the practice register on normal exit. Files you deliberately download remain on your PC.

For a separate workshop installation, install the Python dependencies and run `python live.py --shop-only --open`. That instance serves the local register and verifier using Python and SQLite. On the driver’s Windows PC with QNX and QEMU set up, use `start-live.cmd --driver-only --open`. The driver’s signing key stays on that side, and the workshop keeps the SQLite work orders and enrolled public keys. Exchange the public key, request and verification packet as files. [Two-instance codelab](CODELAB.md#7-run-the-driver-and-shop-separately)

Run `start-live.cmd --self-test` to verify the QNX path with the included demo recordings. It checks four signed receipts, confirms that declining produces no receipt, and repeats an approved review with the exporter channel grant removed. Both policy variants use the same guest executable. The command uses a temporary issuer and scratch directory and requires no browser interaction.

Run `start-live.cmd --policy-lab` to reproduce three native trials with the same recording, request and issuer. Add `--policy-transcript "%TEMP%\repair-receipt-policy-lab.md"` to save selected native serial events and the one-line policy diff. Compare the QNX channel denial, the consent refusal and the successful signed export. [Native policy exercise](CODELAB.md#remove-one-channel-grant)

[Host checks](.github/workflows/host-checks.yml) verify the shop register, the four archived QNX signatures, browser-script syntax and the generated offline verifier on Windows and Ubuntu. To reproduce the receipt and bundle checks locally, run `python verify_shop_register.py` and `python pack_shop.py --check`. The QNX self-test above exercises the live guest.

Open the printed **Driver** URL to save its issuer public key. In the printed **Shop** URL, load the key after confirming its fingerprint and choose **At idle only**. Create and download the request. In the driver page load that file, run a sample or import a CSV, review the finding, then approve or decline. The browser exchanges consent with a private QNX VM over loopback. The VM has no network interface. Approval returns a signed receipt from QNX. The host removes the temporary staging files and job disk after review. Drivers can also initiate a broad review of both operating conditions from the driver page.

The shop can send the **Request SHA-256** from **Request details** through a channel the driver already trusts. The offline request creator shows the same fingerprint beside the saved request. On the driver page, open **Check the shop request fingerprint** and paste it. Repair Receipt compares the canonical request and blocks the start if it differs. A match appears again at consent. The fingerprint is optional for local practice and requests you already trust.

After approving a shop-requested review, choose **Download verification packet** and send that file to the shop. It carries the original request, signed receipt and issuer fingerprint. The shop uses its enrolled public key to verify it. Individual receipt and key downloads are also available.

The driver session that starts a review can see the preview, decide and download the issued receipt. Refreshing that tab keeps the session when browser session storage is available. If another session starts a review first, the original tab can still download its approved packet. The app keeps the last 16 displaced receipts in memory, available only to the issuing sessions until they start their own next review or the app exits. Other sessions see only whether a QNX review is active.

When a new request uses the same normalized upload bytes as an earlier recording, the consent preview identifies the match. If the new scope, threshold or recording rule differs from the last receipt issued for those samples, the driver sees that earlier rule before making a new decision. The app keeps up to 16 recent upload fingerprints and their receipt rules in memory. The notice belongs to the same driver session and the signed packet carries only the new findings and rule. [Reused-recording checks](replay/qnx-recording-reuse-proof.json)

For an incomplete finding, **Recording guidance** explains which requested condition had gaps or too little continuous coverage. QNX shows the location of the first recorded break when it can identify one. For a sustained test with too little continuous coverage, QNX shows the longest usable stretch with at least three readings or says if no stretch had three. The measurements are visible only to the reviewing driver before consent. The shop receives the signed finding and test rule. [Browser and QNX verification](replay/qnx-coverage-detail-proof.json)

Live browser receipts carry a signed input type. The driver and shop see whether QNX evaluated an uploaded CSV, a built-in demo recording, a published road recording or the simulated adapter. The CSV label describes how the app received the data. Older receipts and archived controls without a signed input type still verify and show their source as unspecified.

The app prepares one QNX image in the background at launch. Each review boots a fresh VM, attaches a separate QNX6 job disk with a fresh boot token, and mounts that disk read-only. The host encrypts imported CSV bytes with a new AES-256-GCM key before writing a staging file. The vault receives the key over the token-authenticated local serial link, verifies the complete ciphertext, and evaluates it in an anonymous QNX shared memory object. The exporter is denied access to the encrypted file, the job disk, and vault memory. The app removes the shared image at normal shutdown. [QNX anonymous shared memory](https://qnx.com/developers/docs/8.0/com.qnx.doc.neutrino.prog/topic/shared_memory_anon.html) · [OpenSSL authenticated encryption](https://docs.openssl.org/3.3/man3/EVP_EncryptInit/) · [Prepared-guest benchmark](replay/qnx-prepared-proof.json)

The review template uses QEMU's separate IFS boot path and omits USB support, pre-generated SSH keys and unused disk reserve. In three builds per configuration on one Windows host, the base disk fell from 149.9 MiB to 66.1 MiB, and median time from build start to the first preview fell from 19.75 to 18.42 seconds. All six July 27 reviews produced the same signed receipt. The builder retries with its default profile if it reports an unsupported compact option. [Cold-start measurements](replay/qnx-compact-template-proof.json) · [QNX image builder reference](https://qnx.com/developers/docs/8.0/com.qnx.doc.neutrino.utilities/topic/m/mkqnximage.html)

QEMU gives the x86-64 guest 256 MiB of RAM and two virtual CPUs. In trials on one Windows 11 PC, moving from 1 GiB to 256 MiB reduced QEMU's median committed memory at preview by about 770 MiB. Median peak resident memory through preview went from 226 MiB to 217 MiB. With a prepared template, both configurations took a median of 2.62 seconds to preview a 4 MiB recording. The published drive, 4 MiB control and simulated adapter produced byte-identical signed receipts across all four tested profiles. [Trial results](replay/qnx-guest-memory-proof.json) · [Windows memory counters](https://learn.microsoft.com/en-us/windows/win32/api/psapi/ns-psapi-process_memory_counters)

Live review diagnostics log event markers in place of the issuer public key, driver coverage details, numeric evaluation timing, preview and signed receipt. In an interrupted-review test, the app and QNX guest were stopped at the approval screen. The files left in the test workspace contained encrypted staging data. The scan found neither plaintext sample rows nor the unapproved preview or issuer public key. This check covers app-managed files. The driver’s original CSV stays in its original location, and the host and browser process the input in working memory. [Interrupted-review evidence](replay/qnx-private-staging-proof.json)

On Windows, the host attaches QEMU to a job object before sending any recording or signing keys. If the host process exits during review, Windows stops the attached guest when it closes the job handle. The parent-exit test force-stops only the driver app at the native preview, waits for the guest to exit and checks the remaining workspace for private review data. An abrupt exit can leave encrypted staging files behind. [Parent-exit evidence](replay/qnx-parent-exit-proof.json) · [Windows job objects](https://learn.microsoft.com/en-us/windows/win32/procthread/job-objects)

The shop can use [the one-file offline verifier](replay/verify-receipt.html) without a QNX installation. Open the signed receipt and a separately trusted issuer public key. For a shop-requested review, also open the original request to confirm the job and scope. The verifier checks the exact fields and Ed25519 signature. A driver-started receipt is labeled as such and can be verified with the trusted key on its own. To rebuild the standalone file, run `python pack_shop.py`.

After verifying one receipt, **Where to start** shows which recorded condition met the test rule and which had inadequate coverage. If an uploaded recording had inadequate coverage and you matched the shop's original request separately, save a fresh request for just the missing coverage. It keeps the temperature threshold and recording window and carries its own request ID. Keep that file with the work order so you can verify the driver's next receipt.

Under **Check a separate issuer fingerprint**, enter the full SHA-256 fingerprint you confirmed with the issuer. The offline verifier compares it with the loaded key for single receipts and packet batches. The printout identifies whether the request came from a separate shop file or from the packet itself.

After verification, the shop can print the requested finding, test rule, input type, full request ID and verified issuer fingerprint for a work order. The driver has five minutes from the first consent preview to decide. The countdown comes from the local app and continues through a refresh of the same tab. The app clears the preview and coverage guidance at expiry. Sharing then requires a fresh review and approval.

If the browser loses contact with the local app, it hides the finding and pauses approval and download while it checks the current review. A decision is sent once per explicit activation. If QNX is still waiting and the interruption leaves no focused control, the page returns focus to the receipt so the driver can review it and choose again. If QEMU exits during the preview, the app ends that review so the driver can start another. If the app itself restarts, open the new Driver link printed in the console.

If the initial QNX image build fails, check the local console for the SDK error and choose **Retry QNX preparation**. The app builds into a fresh temporary directory and keeps the selected recording and request in the driver tab. Start the review again when the image is ready. Approval still takes place in a new QNX review.

### File a receipt against a shop request

In the local shop intake, choose a file under **Find a request from a receipt or packet**. The register uses the full request ID to look up the original job, including older requests outside the visible list. It verifies the scope and Ed25519 signature against the key pinned to that request, and checks the request and fingerprint carried by any packet against its own record. The matching work order, signed findings, test rule and source appear above the search and request history. Choose **File verified receipt** to store the answer. The full request ID and issuer fingerprint are available under **Request details**. Selecting a file alone leaves the register unchanged. The first accepted answer stays on file, and selecting the same file again confirms it is already filed.

If the filing response is interrupted, the shop checks whether the register saved the exact receipt. It shows the filed result when confirmed or leaves the receipt ready to retry if the status remains uncertain.

When a different return verifies for an already filed request, **Two verified receipts** shows the filed and returned findings for each requested condition. It also shows both input types when they differ. The shop can use a new request to file a fresh recording while keeping the original work order evidence.

Use the optional **Work order reference** to match the request to the shop's own record. The reference stays in the local register and carries forward to follow-up requests. The portable request, signed receipt, and verification packet contain no work order reference.

**Recording window** defaults to **Entire recording**. For a file that begins before all sensor readings are available, the shop can choose **Allow 1 second for startup**. The signed rule allows missing readings before the first complete sample if it arrives within 1 second. Later gaps still affect coverage. The driver sees the rule and the exact interval QNX excluded during consent. The shop checks the signed rule against its original request. This option applies to recordings. [Startup window exercise](CODELAB.md#request-a-startup-window)

Use **Find by work order** to recover requests by their full saved reference, including older requests outside the recent list. Enter it as saved, including letter case. Results list each matching request and follow-up. Open a request to inspect its own signed findings.

If the shop loses the creation confirmation, choose **Create request** again with the same details in that tab. The register returns the existing request if it already saved it. After reloading the page, use **Find by work order** to recover a request that may have been saved.

If the signed answer reports insufficient evidence, choose **Create follow-up request**. The register retains the original receipt and creates one linked request for the unanswered conditions using the same recipe and issuer. The saved follow-up opens immediately and leaves the current work-order filter in place. Download it and send it to the driver for a fresh capture and approval. The exported request carries a new ID, the requested scope and the test rule.

When the work order has a finding for each original condition, choose **Create recheck request** on the latest filed receipt. The recheck uses a new ID and the original request's conditions, threshold, recipe and enrolled issuer. For example, a moving-only follow-up can complete the first check, and the later recheck still asks for both idle and moving. The driver page clears a recording already submitted under a different request when the new request loads. Choose a fresh recording and file its signed receipt. The work-order view and printout compare the findings stated in the signed receipts. Different or unspecified input types and insufficient recheck coverage are flagged in place of a comparison. The filing times come from the shop register. Confirm capture dates and test conditions before using the receipts to assess a repair.

After filing, choose **View work-order findings** from the request. Each condition shows the finding from its signed receipt, the test rule, the input source and the shop's filing time. The view and printout indicate whether the latest idle and moving findings came from one signed receipt or separate receipts. If the shop is waiting for a follow-up or recheck, the report shows its scope alongside the earlier evidence. Choose **Open pending request** to reach its download. The printout includes the issuer fingerprint, full pending and filed request IDs, exact receipt SHA-256 digests and the optional local work-order reference.

Open **Earlier receipts** to see filed results that are no longer shown in the current or prior finding cards. Choose a receipt to open its exact request and download its verification packet.

If a filed packet came from the wrong recording, open **Wrong recording filed?** in the work-order findings and choose **Withdraw and issue replacement**. The replacement asks for the original conditions under the same rule and keeps the same issuer and work-order reference. It starts with an empty evidence view. The shop can still inspect and export individual signed packets from the withdrawn review. The register marks its printout as withdrawn, refuses late returns to its requests and keeps its receipts out of the replacement's evidence ZIP. Withdrawal is local to the shop register. Copies of the signed packet already shared can still verify offline.

When a filed receipt has incomplete coverage, create the missing-coverage follow-up from the work-order report. The action opens the existing follow-up if another shop tab already created it.

During intake, **Where to start** identifies the operating conditions in which an uploaded CSV met the test rule. It highlights incomplete uploaded coverage separately and asks the shop to confirm the data came from the vehicle. Built-in recordings, published examples, simulated captures and unspecified sources stay in the detailed findings for review. Rechecks show a comparability reminder above the prior and latest findings in the work-order view and printout.

Choose **Download verification files** in the work-order view to save a ZIP with one packet per filed receipt, including the original and any filed follow-ups. Open the ZIP directly in the offline verifier with a separately trusted copy of the enrolled public key. The verifier checks each packet against its request and key. Use the individual JSON packets if the browser cannot open the ZIP or the archive exceeds 512 receipts. Open **Find the filed receipt** and paste the **Receipt SHA-256** line from the printed work order to identify the exact signed answer. The ZIP leaves out the local work-order reference.

Choose **Download receipt list** to save the issuer fingerprint, filed request IDs and exact receipt digests for that version of the work order. Keep a copy with the shop's own records. In the verifier, open **Check a saved receipt list** and load that copy alongside the ZIP or individual packets. The verifier reports missing requests, unexpected requests and different signed receipts for the same request ID. Save a new list when you want to check a later version of the order.

When different signed receipts share a request ID, the offline verifier flags both attachments. After batch verification, open **Find the filed receipt** and paste the full receipt SHA-256 from the shop's copy of the work order. You can paste the printed line with its label. The verifier marks every verified attachment with that exact digest and keeps the rest visible for review.

After filing, **Download verification packet** saves the original signed receipt, the original request and the enrolled issuer fingerprint as one JSON attachment for the work order. Open it in the standalone verifier with a separately trusted issuer public key. The individual files also remain downloadable.

The shop register survives a restart. It stores job IDs, public keys, scoped receipts and shop filing times in `%LOCALAPPDATA%\RepairReceipt\shop.sqlite3` by default. The times describe activity at the shop. To choose a different database file, pass `--shop-register` to `live.py`.

Open **Register backup** in shop intake and choose **Download register backup** to save a consistent SQLite snapshot while the app is running. The snapshot contains private work order references, the shop's original requests, enrolled public keys and filed receipts. Driver signing keys are managed separately.

Opening an earlier Repair Receipt register upgrades its stored rule bindings in one transaction. A restored startup request carries its original rule and ID, and filed receipts retain their original signed bytes.

To continue from a backup, put a copy in the shop's chosen records folder, then pass its path at startup. For example, run `python live.py --shop-only --shop-register "C:\Shop\repair-receipt-shop-backup.sqlite3"` and open the printed Shop link. The app reads and writes the specified copy. The original register and the saved backup can stay in place.

When the shop reads a saved receipt, it checks the signature and request binding against the enrolled issuer key. A failed verification flags that row and hides its finding and receipt export. Other valid rows remain available individually. A work-order report or evidence archive requires every receipt in that linked record to verify. [Backup verification exercise](CODELAB.md#check-a-saved-register)

### Capture from the simulated OBD-II adapter on QNX

Load a shop request and select **Simulated OBD-II adapter · Live QNX capture** on the driver page. QNX opens a separate UART backed by an ELM327-compatible simulator, collects a nine-second window, then displays the scoped finding for approval. The signed receipt identifies the simulated source. Both the shop register and the standalone verifier display it.

The capture uses a fixed 11-bit CAN profile and requests only current coolant temperature, engine RPM and vehicle speed. The adapter keeps response headers visible. QNX checks that each reply contains one eight-byte CAN frame from address `7E8`, with the expected ISO-TP length, mode and PID. It reads speed before and after coolant and RPM. All four exchanges share a 350 ms budget measured from the scheduled sample time. If the readings disagree on whether the vehicle was stationary, QNX drops the sample. A missing or ambiguous reply also drops the sample. QNX checks the deadline again when the terminating prompt arrives. An interrupted or late exchange ends capture before any further requests. Incomplete coverage withholds negative findings, and a crossing already observed remains evidence. Capture data stays in a root-only file in QNX shared memory during review. The exporter must fail to open both that file and the UART before it can publish the approved receipt. [ELM327 datasheet](https://www.elmelectronics.com/wp-content/uploads/2016/07/ELM327DS.pdf) · [QNX serial driver](https://qnx.com/developers/docs/8.0/com.qnx.doc.neutrino.utilities/topic/d/devc-ser8250.html)

Run the twelve serial capture controls from a QNX SDK prompt.

```bat
python verify_obd_bench.py --qemu C:\QNX\qemu\qemu-system-x86_64.exe
```

The paired timing control sends the same data in both runs. The simulator delays the first three prompts by 60 ms each and the final speed prompt by 50 or 240 ms. The 230 ms of injected delay preserves the findings. The 420 ms case discards the incomplete sample and stops polling even though each reply fits inside 350 ms on its own. These tests use a simulated adapter on a QEMU UART. A physical adapter and vehicle ECU require separate validation. [Native bench evidence](replay/qnx-obd-proof.txt)

The responder control leaves the coolant value unchanged and changes the address of the third sample in the idle window from `7E8` to `7E9`. QNX discards that sample and marks idle evidence insufficient. Separate trials exercise a missing header, incorrect ISO-TP length and malformed padding. QNX discards those samples and resumes at the next scheduled tick. [Native bench evidence](replay/qnx-obd-proof.txt)

For a quick check, open the [signed scoped sample](replay/sample-request-receipt.json) with its [shop request](replay/sample-request.json) and [example issuer key](replay/sample-request-issuer.json). The signed answer was generated by a native QNX test run.

### Enroll a shop before sending the first receipt

In the driver page, open **Enroll your issuer key at the shop** and save the public key. Confirm its SHA-256 fingerprint with the shop through a known channel. The offline shop view displays the same fingerprint when it opens the key. The shop can reuse that public key after a restart of the driver app.

The Windows app creates its issuer store in `%LOCALAPPDATA%\RepairReceipt\issuer.dpapi`. Windows DPAPI protects the persisted seed for the current Windows user. Startup refuses a damaged store so it cannot silently replace a trusted identity. For a separate installation use `python live.py --qemu path-to-qemu --issuer-store path-to-store`. Use `--ephemeral-issuer` when you need a temporary driver key with a saved shop register. [Windows DPAPI](https://learn.microsoft.com/en-us/windows/win32/api/dpapi/nf-dpapi-cryptprotectdata)

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

In 20 additional trials per input, median time from encrypted staging to preview was 2.37 and 2.29 seconds for the two normalized KIT drives. The 4 MiB control took a median of 2.71 seconds and its 95th percentile was 2.96 seconds. The slowest preview took 3.43 seconds on the larger KIT recording. Each trial booted a fresh QNX guest from a template that took 23.4 seconds to prepare once. [Raw timings, input hashes and signed receipt hashes](replay/qnx-preview-latency.json)

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

The normalized CSV starts with a recording duration in milliseconds (1 to 86,400,000). Each row has four integers for elapsed milliseconds, engine RPM, speed in km/h, and coolant temperature in Celsius. Keep timestamps strictly increasing within the duration. Use `elapsed_ms,,,` for a known missing sample. QNX breaks the run at that row and withholds negative findings if coverage is incomplete. Normalized inputs are limited to 4 MiB. Use a private workspace with the CLI because it stages a copy of the recording. The receipt goes to the separate path you choose.

## Real recording

Marc Weber, *Automotive OBD-II Dataset* (2019), [DOI 10.5445/IR/1000085073](https://doi.org/10.5445/IR/1000085073), [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/). Download the published archive from [RADAR4KIT](https://radar.kit.edu/radar/en/dataset/bCtGxdTklQlfQcAq) and run the importer to regenerate the derived 90-second fixture.

The driver page also opens the metric OBD Auto Doctor export format used in the archive. Choose the CSV directly. The browser drops other columns and converts clock times to elapsed milliseconds before passing the recording to the local QNX service. This path accepts source exports up to 8 MiB and up to 24 hours of data. An identical sample repeated at the same timestamp counts once. A conflicting repeat or a clock reversal of at most one second removes the uncertain overlap and marks a coverage gap. Across midnight, a late sample that reverses the clock by at most one second uses the same coverage-gap rule. A larger reversal or a reversal before the first timestamp stops the import. The driver can open **Recording guidance** for a notice when a clock gap is carried into QNX. A missing RPM, speed or temperature reading interrupts coverage anywhere in the recording, including the opening rows. The format supplies a timestamp per row of logged values. Individual signals may have different update times. [OBD Auto Doctor export documentation](https://www.obdautodoctor.com/features/) · [Full-drive import checks](replay/qnx-obd-import-proof.json)

The same upload field accepts original metric Torque Pro logs with English dated **Device Time**, **Engine RPM(rpm)**, **Speed (OBD)(km/h)** and **Engine Coolant Temperature(°C)**. The browser converts the clock to relative milliseconds and keeps GPS fields local. Blank and `-` entries become coverage gaps. Two original exports went through browser import, QNX signing and shop filing at a test threshold of 80 °C. [Torque export fields](https://torque-bhp.com/community/main-forum/not-all-tracks-available-in-map-view/) · [Import verification results](replay/qnx-torque-import-proof.json)

For both export formats, positive fractional RPM and speed round up so QNX can distinguish zero from a running engine or moving vehicle. Coolant rounds down so a reading below a whole-degree threshold stays below it. Conflicts at the same timestamp are checked against the original decimal values before projection.

```bat
python import_kit.py path\to\OBD-II-Dataset.zip fixtures\kit-obd.csv
```

The importer keeps elapsed milliseconds, RPM, speed, and coolant temperature, retaining complete rows at least one second apart. KIT logged these signals through an OBD-II dongle. The excerpt is a reference run while moving. It supplies no idle evidence.

Two full KIT recordings showed the same idle finding and different moving findings in a test at 95 °C. Under one idle-only request and issuer, QNX returned exactly the same 342-byte signed receipt for both recordings. On a separate moving-only request, July 26 showed a sustained crossing. July 27 had insufficient evidence because its opening rows were missing readings and there was no fully observed crossing while moving. The shop can request a follow-up limited to that condition. All four receipts carry the signed published-road input type. [Paired real-recording results](replay/qnx-road-scope-proof.json)

The driver page offers both full drives under **Published KIT recordings**. The [July 26 projection](fixtures/kit-july-26.csv) and [July 27 projection](fixtures/kit-july-27.csv) use elapsed time, RPM, speed and coolant temperature, with missing readings carried forward as coverage gaps. The files contain the exact normalized bytes used in the archived QNX experiment. Run `start-live.cmd --road-lab` to verify four new signed receipts locally. [Paired-drive codelab](CODELAB.md#compare-the-published-road-pair)

The original logs contain 47,350 and 16,961 timestamped rows across ten vehicle signals per file. They are 3,037,603 and 1,070,443 bytes uncompressed. Each response in the idle-only example is the same **667-byte verification packet**, including the request, signed receipt and issuer fingerprint. The packet carries no timestamps, source filename or raw sensor values. [Disclosure measurement](replay/qnx-road-disclosure.json) · [Reproduce the measurement](CODELAB.md#measure-what-the-shop-receives)

A 64-receipt QNX sweep across 90–105 °C reproduced that pattern at 95 °C and at 98–100 °C. At 98–100 °C both drives returned insufficient evidence at idle, and July 26 retained a moving observation. At 96–97 °C, the idle findings differed and the signed idle receipts differed too. These results cover the two KIT recordings under the test recipe. [Complete results](replay/qnx-road-threshold-sweep.json) · [Reproduce the sweep](CODELAB.md#vary-the-test-threshold)

To measure answer coverage beyond the two examples, QNX signed both conditions for each of the archive's 81 recordings at 95 °C and 105 °C. At 95 °C, 8 recordings answered both conditions, 14 answered one and 59 had insufficient evidence for both. At the 105 °C default, all 81 had insufficient evidence for both. The results show how often the archive supports an answer under this test recipe. [162-receipt corpus report](replay/qnx-road-corpus-proof.json) · [Reproduce the coverage check](CODELAB.md#measure-archive-wide-answer-coverage)

With the signed startup allowance and the same normalized inputs, 65 of 81 recordings supported both answers at 105 °C. At 95 °C, 66 supported both answers and 2 supported one. All 16 recordings with later gaps kept their original findings at both thresholds. [Startup allowance corpus report](replay/qnx-road-startup-window-proof.json)

## Current scope

The signed browser workflow runs against QNX in QEMU on the same host. The archived replay uses captured fixture outputs. The UART path has been tested with a simulated adapter. Physical adapter integration, secure vehicle-side key provisioning and vehicle-specific mechanic validation remain open. The proof covers deterministic signed output and the raw access paths exercised in the configured guest.

## License

The original code, documentation and synthetic fixtures are available under the [MIT License](LICENSE).

The three derived KIT recordings in `fixtures/kit-obd.csv`, `fixtures/kit-july-26.csv` and `fixtures/kit-july-27.csv`, plus the excerpt embedded in `replay/repair-receipt.html`, are distributed under [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/). The [recording notes](#real-recording) credit Marc Weber, link to the original dataset and describe the normalization and excerpt selection.
