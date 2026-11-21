# QNX codelab · Release one diagnostic finding by consent

Build a QNX 8.0 guest that can return a signed coolant observation from a local recording. You will test which processes can reach the recording, when the vault will issue, and whether changing a withheld finding changes the exported file.

## Verify two real drives offline

Open the downloaded HTML in a current Chromium browser. It contains four receipts issued by QNX for two published drives at a 95 °C test threshold. [Download the offline verifier](https://github.com/josepha-mayo/repair-receipt-qnx/releases/latest/download/verify-receipt.html)

1. Choose **Check idle receipts**. Both findings are observed and both 342-byte receipts are identical. Choose **Check moving receipts**. July 26 shows an observation and July 27 has insufficient evidence.
2. Open **Download proof files**, then save the July 27 packet and the example issuer key. Under **Verification files**, load the packet and key and choose **Verify receipt**. The verifier confirms the signature and the request included in the packet.
3. Under **Create a shop request**, choose **While moving only**, enter **95**, then select **Save request file**. This selects a fresh request with a new ID. Choose **Verify receipt** again to see the mismatch. Select **Clear original request** and verify again to return to checking the packet against its included request.

Open **Check a separate issuer fingerprint** and paste `issuer.fingerprint` from the [published example evidence](replay/qnx-road-scope-receipts.json). Verify again and confirm that the supplied key matches it. Change any hexadecimal digit and verify to see the key comparison fail before the verifier displays a finding. For a real work order, confirm the full fingerprint with the issuer through a trusted channel and load the shop's independently saved request. The printout identifies which request was checked.

## 1. Compile and run

Install QNX SDP 8.0, QEMU for x86-64 and 64-bit Python 3.10 or later. Extract the source to a short path such as `%USERPROFILE%\rr` to avoid errors while Python creates the virtual environment. Open **Command Prompt** in the folder that contains `build-qnx.cmd`. The scripts load the default Windows SDK at `%USERPROFILE%\qnx800`. For an SDK installed elsewhere, run `call "C:\path\to\qnxsdp-env.bat"` with your SDK path in this prompt before building. [QNX SDP installation guide](https://www.qnx.com/developers/docs/8.0/com.qnx.doc.qnxsdp.quickstart/topic/install_host.html)

```bat
python -m venv .venv
call .venv\Scripts\activate.bat
python -m pip install -r requirements-live.txt
build-qnx.cmd
start-live.cmd --check
start-live.cmd --practice
```

Practice mode gives the walkthrough an empty shop register and a temporary driver key. Download any files you want to keep before closing the app. See [setup in the README](README.md#live-driver-and-shop-workflow) for loading the SDK and selecting a custom QEMU path.

If the Driver page reports a QNX image preparation failure, check the launch console and choose **Retry QNX preparation** after resolving the error. Once the new image is ready, start the review with the files already selected.

Open the printed shop and driver URLs. In the driver, save the public key under **Enroll your issuer key at the shop**. In the shop, load the public key, choose **At idle only**, create the request and download it. The request carries a random ID, a fixed recipe version and one operating condition. The shop register retains the request and its enrolled public key.

In the driver page, load that request, run **Trip A** and review the preview. Approve and choose **Download verification packet**. In the shop register, open the packet under **Find a request from a receipt or packet**. The register opens the matching job and verifies it against the request and key on file. Choose **File verified receipt** and load the packet again to observe repeat handling. In the standalone verifier, try a freshly generated idle-only request against the same valid packet to see the request mismatch.

Run **Missing samples** under the same request, approve it and open the returned packet in the shop. **Two verified receipts** compares the filed threshold observation with the returned insufficient-evidence finding. Open the first packet again to verify the work order still holds the original answer. Load both packets in the offline verifier with the enrolled key. Both signatures verify, and the verifier flags the shared request ID. Open **Find the filed receipt** and paste the **Receipt SHA-256** line from the shop's printed work order. The verifier marks the original attachment.

Choose **View work-order findings** to open a print view directly from the filed request. The idle-only printout gives the finding, test rule, input source, filing time and full receipt request ID.

From this filed request choose **Create recheck request**, download it and use **Hot while moving** as the second fixture in the driver view. The original idle test observed a crossing and the recheck reports **Threshold not observed**. File the recheck and open **View work-order findings** to compare the two receipts under the same idle rule. Their request IDs and receipt digests appear separately on the printout.

A recheck always asks for the original request's conditions. If a work order starts with both idle and moving and a moving-only follow-up completes coverage, the next recheck again asks for both. The report keeps the separate original receipts as the prior evidence for their respective conditions.

Create a new idle-only request and run **Missing samples** in the driver view. The approved receipt reports insufficient evidence. File it and choose **Create follow-up request**. Open **View work-order findings** to check the outstanding scope. Choose **Open pending request** and download that request. Run **Trip A** with it, approve its answer, and file it. Reopen the work order to see the resolved finding and open its source receipt. The original request retains its signed insufficient-evidence result.

Download a **verification packet** from a filed request. Open the standalone verifier offline and load the packet with the issuer key you enrolled separately. The verifier checks the original request and signature, and the work-order printout includes the issuer fingerprint. Repeat with a different issuer key to see verification fail.

In the work-order view, choose **Download verification files**. Extract the ZIP, select both packet files together and choose **Verify packets** in the offline verifier. The earlier packet still shows insufficient evidence and the follow-up carries the later finding. Paste each digest from the printed work order into **Find the filed receipt** and compare the matching request IDs.

Use this practice review to simulate filing the wrong recording. In **View work-order findings**, open **Wrong recording filed?** and choose **Withdraw and issue replacement**. Download the new request and check that its ID changed and its rule and scope stayed the same. Try to return the original packet to the register. The shop reports that its request was withdrawn. Open **View work-order findings** on the replacement and choose **Open the withdrawn review** to recover the original signed packet for audit. Complete the replacement with a fresh driver review and confirm its verification ZIP contains only packets filed under the replacement.

Download a **Register backup** from the shop intake page. Start a separate session with `start-live.cmd --ephemeral-issuer --shop-register "C:\path\practice-backup-copy.sqlite3"` pointing at a copy of that file. Reopen the work order and follow its source receipt links. The register verifies prior receipts using the public keys saved with those requests, even with a different local driver key.

## 2. Follow the QNX boundary

Read [policy.conf](policy.conf) and find the two native channel grants. The supervisor can connect to the vault. The export process can connect to the supervisor. The vault also checks the supervisor's process ID on every message. [QNX security policy language](https://www.qnx.com/developers/docs/8.0/com.qnx.doc.security.system/topic/manual/secpol_language.html)

In [probe.c](probe.c), follow the scoped review:

1. The vault reads and validates the allowlisted scope and computes one preview from the local CSV.
2. A signing call before approval receives `EACCES`. The vault reads the driver's decision over its serial input and signs the exact preview after approval.
3. The vault serves the approved envelope once. The unprivileged exporter checks that opening the raw channel, CSV and vault memory all fail before requesting the bounded envelope.

The native guest uses `ConnectAttach`, `MsgSend`, `MsgReceive` and `MsgReply`. The browser and QEMU harness exchange the preview and decision over the guest's serial port. The guest has no network interface.

### Remove one channel grant

After building, run the native policy exercise from the same Command Prompt. The launcher finds QEMU the same way it does in practice mode. If needed, append `--qemu "C:\path to\qemu-system-x86_64.exe"`.

```bat
start-live.cmd --policy-lab
```

The script compiles two policies in a temporary directory, runs three QNX guests with the same app binary and prints a JSON report after all trials pass. Each trial uses the same idle-only request, recording and temporary issuer. The restricted policy removes this line:

```text
allow receipt_export_t receipt_owner_t:channel connect;
```

| Policy | Driver decision | Expected guest result |
| --- | --- | --- |
| Export grant removed | Approve | QNX denies the exporter's channel connection after the preview. The trace contains `RR_FAIL connect to receipt channel errno=1` and no receipt. |
| Standard | Decline | The consent gate withholds the receipt. |
| Standard | Approve | The script verifies the signed receipt against the exact preview. The exporter is denied access to the raw channel, file, job disk and vault memory. |

For the remaining command-line exercises that call Python directly, load your SDK in the current prompt first. With the default installation, run `call "%USERPROFILE%\qnx800\qnxsdp-env.bat"`. In those exercises, pass your own QEMU executable path if it differs from the example.

To observe the denial in the browser, use a separate project copy. Remove the line from its `policy.conf`, rebuild with `build-qnx.cmd` and start a fresh app instance. Load the idle-only request and approve **Trip A**. The preview appears and export fails. Restore the grant and rebuild to run the successful control. [Recorded QNX trials](replay/qnx-policy-lab-proof.json)

## 3. Change a withheld finding

Use the **same idle-only request** to approve **Trip C**. It retains the idle threshold crossing and adds a crossing while moving. Compare the full signed files from A and C. They should be byte-identical. Now create a **While moving only** request for Trip C. The result should include the driving observation.

### Compare the published road pair

The source includes both normalized drives from the [KIT Automotive OBD-II Dataset](https://publikationen.bibliothek.kit.edu/1000085073). After building, run the native check from Command Prompt. The launcher checks the input hashes, boots four QNX reviews and verifies each newly signed receipt against a temporary issuer.

```bat
start-live.cmd --road-lab
```

In the browser, use **July 26 · Full drive** and **July 27 · Full drive** from the sample menu. Load one idle-only shop request at 95 °C, approve each review and compare the saved packets. Both say **Threshold observed** and the packets match byte for byte. Create a new moving-only request at the same threshold and repeat. July 26 shows **Threshold observed** and July 27 shows **Insufficient evidence**. Both files start before all three signals are available. QNX preserves a fully observed crossing even when coverage is incomplete. [Paired results and input hashes](replay/qnx-road-scope-proof.json)

Open the downloaded HTML in a current Chromium browser. **Check idle receipts** and **Check moving receipts** verify the signatures, request bindings and signed published-road input type. After either check, open **Download proof files** to save the two verification packets and example key. Load those files back into the verifier to check each signature and receipt hash independently. [Download the offline verifier](https://github.com/josepha-mayo/repair-receipt-qnx/releases/latest/download/verify-receipt.html) · [Signed QNX evidence](replay/qnx-road-scope-receipts.json)

### Try an upload and follow-up

To exercise the uploaded-CSV path, choose `fixtures\kit-july-26.csv` and `fixtures\kit-july-27.csv` with **Import an OBD-II recording**. The importer also accepts the original `2017-07-26_Seat_Leon_RT_S_Stau.csv` and `2017-07-27_Seat_Leon_KA_KA_2_Normal.csv` from KIT. Both forms reproduce the findings with an uploaded-CSV label. Run `node --test verify_obd_import.cjs` to check opening and closing gaps, a clean midnight rollover and a short clock reversal across midnight.

You can also select an original metric Torque Pro CSV with English dated **Device Time**, engine RPM, OBD speed and coolant temperature. The browser projects just those four columns and uses elapsed milliseconds. Before importing, keep the original export so the date and full clock are available.

When a different request reuses an earlier upload in the same driver session, the consent preview identifies the match. This exercise deliberately reuses the published recordings. In a follow-up that calls for a fresh capture, decline the reused preview and select the new recording.

Approve a July 27 receipt for **At idle only** at **95 °C**, then review a different recording and decline. Create a **While moving only** request at **98 °C** and select the July 27 CSV again, with a different filename if you like. The preview shows the previous 95 °C idle rule along with the current moving rule. Approve and verify the new packet. Its signed claim covers only the 98 °C moving request. [Repeat-consent checks](replay/qnx-recording-reuse-proof.json)

For a work-order trial, request both conditions at 95 °C. Upload July 27, approve, file and open **View work-order findings**. **Where to start** points to idle and flags incomplete moving coverage. Choose **Request moving-only follow-up** in that report and download the new request. Load it on the driver side, upload July 26 and file the returned receipt. Both conditions now have a threshold observation. The detailed findings show the two separate receipts. Use the recordings as example data for this exercise.

### Request a startup window

For the same July 27 CSV, create a separate request for both conditions at 95 °C. Under **Recording window**, choose **Allow 1 second for startup**. The driver preview reports that QNX excluded the first 0.21 s. It shows **Threshold observed** at idle and **Threshold not observed** while moving. The scope of that moving finding is the reviewed window. File it and open **View work-order findings**. Its summary points you to idle first and says no moving crossing met the rule in the reviewed data. Verify the packet offline with the original request and trusted issuer key. Change the request recipe to the entire-recording rule to see verification reject the mismatch.

The allowance covers incomplete rows only before the first complete sample, and only when that sample arrives within 1 second. Any later gap still affects coverage. Follow-ups and rechecks inherit the selected rule.

For a recorded gap beyond the allowance, import `2017-07-11_Seat_Leon_KA_KA_Stau.csv` from the [KIT archive](https://publikationen.bibliothek.kit.edu/1000085073) with a 105 °C request for both conditions and the startup allowance enabled. Under **Recording guidance**, the first break is near 00:08:34 into the recording. Approve the review and verify that the shop packet carries both insufficient-evidence findings and the test rule. The relative gap location appears only in the driver's preview. [Coverage detail check](replay/qnx-coverage-detail-proof.json)

The [native duration controls](replay/qnx-duration-proof.json) also compare two recordings under one idle request and issuer. Their private gap locations are 1 s and 1.5 s. QNX issues byte-identical insufficient-evidence receipts.

Open the offline verifier and choose **Compare startup rules** to verify both signatures and see their moving findings. Open **Download proof files** to save the two packets and example public key. The release also bundles those files in `qnx-startup-window-packets.zip` for batch verification. [Release downloads](https://github.com/josepha-mayo/repair-receipt-qnx/releases/latest)

```bat
python verify_startup_window.py --qemu "C:\QNX\qemu\qemu-system-x86_64.exe"
```

The native test uses the same request and issuer with three different opening intervals and checks that all three signed receipts are byte-identical. It checks that the native log redacts the private timing.

### Measure what the shop receives

With the Python dependencies installed and Node.js 24 available, run the measurement tool on both original CSVs. It regenerates the normalized inputs using the browser's parser and verifies the archived idle signature before counting the bytes of the verification packet. This check runs on the host.

```bat
python measure_road_disclosure.py "path\to\2017-07-26_Seat_Leon_RT_S_Stau.csv" "path\to\2017-07-27_Seat_Leon_KA_KA_2_Normal.csv"
```

The complete attachment is **667 bytes** for either recording in this idle-only test. To verify the count from the browser, save both packets using **Download proof files** after checking the idle receipts. The issuing key is shared separately at enrollment. [Measured file sizes and claim fields](replay/qnx-road-disclosure.json)

### Vary the test threshold

From the QNX SDK prompt, run the sweep with the bundled normalized drives.

```bat
python verify_requests.py --qemu C:\QNX\qemu\qemu-system-x86_64.exe --road-sweep fixtures\kit-july-26.csv fixtures\kit-july-27.csv
```

The harness verifies four QNX-signed receipts per whole-degree threshold. Each scope and threshold uses one request and issuer for both drives. The pairs below list July 26 first.

| Test threshold | At idle | While moving |
| --- | --- | --- |
| 90–94 °C | Both observed | Both observed |
| 95 °C | Both observed | Observed / Insufficient evidence |
| 96–97 °C | Observed / Insufficient evidence | Observed / Insufficient evidence |
| 98–100 °C | Both insufficient | Observed / Insufficient evidence |
| 101–105 °C | Both insufficient | Both insufficient |

Equal findings within a scope produced byte-identical receipts. At 96–97 °C the requested idle findings differed and the receipts reflected it. These thresholds describe this test on the two published recordings. [Full QNX sweep](replay/qnx-road-threshold-sweep.json)

### Measure archive-wide answer coverage

Download the original KIT ZIP, then run this from the QNX SDK prompt with Node.js 24 available. The harness uses the browser's CSV normalizer and verifies 162 newly signed QNX receipts. It asks for both conditions on all 81 recordings at 95 °C and at the 105 °C default. [KIT archive record](https://publikationen.bibliothek.kit.edu/1000085073)

```bat
python verify_road_corpus.py "path\to\OBD-II-Dataset.zip" --qemu "C:\QNX\qemu\qemu-system-x86_64.exe" --proof road-coverage.json
```

Add `--recipe coolant-startup-window/v3` to repeat the same run with the startup allowance on the same normalized input bytes. The report counts a condition as answerable when the signed result is **Observed** or **Not observed**.

| Test threshold | Recording window | Both conditions answerable | One answerable | Neither answerable |
| --- | --- | ---: | ---: | ---: |
| 95 °C | Entire recording | 8 | 14 | 59 |
| 95 °C | Startup allowance | 66 | 2 | 13 |
| 105 °C | Entire recording | 0 | 0 | 81 |
| 105 °C | Startup allowance | 65 | 0 | 16 |

The 16 recordings with later gaps returned the same findings under both rules at each threshold. These results measure evidence coverage in this archive. [Entire-recording results](replay/qnx-road-corpus-proof.json) · [Startup allowance results](replay/qnx-road-startup-window-proof.json)

### Run the native scope controls

Run the included demo controls without a browser from Windows:

```bat
start-live.cmd --self-test
```

The self-test verifies four signatures, identical signed idle receipts and different moving receipts under a common request for each condition. It checks that QNX explains gaps to the driver and the diagnostic log redacts that guidance. Declining must produce no receipt. One additional boot repeats the approved idle review under the policy from section 2 with the export grant removed. QNX must deny the connection after the preview. For the individual receipt SHA-256 digests, run `python verify_requests.py --qemu C:\QNX\qemu\qemu-system-x86_64.exe` from the SDK prompt.

Run `python verify_consent.py` on the host to check the five-minute boundary. It exercises approval immediately before, at and after expiry. It also checks that the pending preview and coverage guidance drop out of the driver's response at expiry.

Run `python verify_requests.py --qemu C:\QNX\qemu\qemu-system-x86_64.exe --scope-matrix` to check both request scopes and all three result types. Each group of three recordings changes the unrequested samples. The longest variant also changes cadence, elapsed time, recording length and CSV line endings. QNX produces identical signed receipts within each group, and the resulting verification packets are byte-identical. A request for both conditions shows the moving result change. For each scope, the driver sees distinct guidance for a gap, a short window, or both. Each reason yields the same signed insufficient-evidence result. The suite checks that diagnostic logs retain redacted markers and that QNX rejects a malformed out-of-scope row before preview. [Native scope matrix](replay/qnx-scope-matrix-proof.json)

Run `python verify_shop_register.py` to test the shop side with independent test keys. It checks the pinned issuer, races two valid answers to the same request, and reopens the database to check the exact stored receipt. The same command verifies the four archived road receipts and their matching idle digest.

## 4. Capture through a QNX serial device

Repeat the live workflow with **Simulated OBD-II adapter · Live QNX capture**. Watch the receipt identify the simulated source after approval. The host runs an adapter simulator. QNX opens its UART, sends a fixed set of Mode 01 read requests, parses each response and evaluates the capture in its vault.

Run `python verify_obd_bench.py --qemu C:\QNX\qemu\qemu-system-x86_64.exe`. The checks use the same prepared guest path as the app.

| Simulated adapter case | Expected result |
| --- | --- |
| Complete capture | Idle threshold observed and moving threshold not observed |
| Missing and ambiguous frames | Insufficient evidence for both conditions |
| The third sample in the idle window arrives from CAN address `7E9` | QNX drops the sample and resumes polling. Both findings are insufficient. |
| Missing responder header, wrong ISO-TP length or malformed frame padding | QNX drops the sample and resumes polling. Both findings are insufficient. |
| Vehicle stops between the two speed reads for one sample | QNX drops the ambiguous sample and reports insufficient evidence for both conditions |
| Prompt arrives after the reply deadline | Capture ends before another request. Both findings are insufficient. |
| Four delayed prompts complete within the shared sample budget | QNX accepts the delayed idle sample. The receipt observes the idle crossing. |
| The same readings complete beyond the shared sample budget, with every reply individually under 350 ms | QNX drops the delayed sample and stops polling. The receipt reports insufficient evidence for both conditions. |
| Link drops partway through a speed response | QNX retains the completed idle crossing. Moving coverage is insufficient. |
| Adapter setup fails | QNX stops before preview, without producing a receipt. |

In [obd_capture.c](obd_capture.c), follow `initialize` and `read_pid` to see the adapter setup and the independent response check. The ID is the responder field reported by the adapter. The exporter tests that the UART and capture file are inaccessible. [ELM327 datasheet](https://www.elmelectronics.com/wp-content/uploads/2016/07/ELM327DS.pdf) · [Native bench traces](replay/qnx-obd-proof.txt)

## 5. Check elapsed time before accepting a finding

Run `python verify_duration.py --qemu C:\QNX\qemu\qemu-system-x86_64.exe`. Compare the same three hot samples packed into six milliseconds under the archived and current rules. The archived sample-count rule observes a threshold crossing. The current rule needs the samples to span two seconds in one operating condition. Its boundary tests compare 1,999 ms with 2,000 ms, and its coverage controls test shifts between idle and moving and missing recording time.

Check the leading and trailing gap controls in the same run. A gap of two seconds at either edge permits a negative finding with enough continuous coverage. At 2,001 ms the result becomes **Insufficient evidence**. A fully observed hot run still supports a positive finding before a later gap. The engine-stop control checks that samples across a stopped engine cannot be combined into one hot run.

The shop saves the selected rule with the request. The signed claim includes that rule, and the offline verifier and filing register check it against the request. `verify_shop_register.py` opens an earlier database and checks that the exact previously filed receipt survives the schema upgrade.

Create two idle-only requests for **Trip A**, one with a test threshold of **106 °C** and the other with **108 °C**. Run each in QNX. The fixture crosses 106 °C for the required duration. At 108 °C, its finding is **Threshold not observed**. Both receipts carry the selected threshold. Change one threshold in the request JSON, then try that request with the original signed receipt in the offline verifier to see validation fail.

In the driver view, remove the shop request and run **Trip A**. The vault uses the same sustained rule and previews idle and moving before approval. Approve and open the receipt in the offline verifier with the enrolled key. The verifier labels it **Driver-started review**. Repeat and decline to check that QNX withholds the signed file.

## 6. Reuse the QNX image between reviews

Run `python verify_prepared_guest.py --qemu C:\QNX\qemu\qemu-system-x86_64.exe` from the QNX SDK prompt. The harness measures the time from review start to the native preview with a full image build and a prepared image. The same recording and request yield identical signed bytes despite fresh staging keys and ciphertext. QNX denies the exporter's attempt to open the raw job disk. The vault discards recordings with an altered authentication tag or encrypted source marker before showing a preview. The harness checks the staged files for the original data and keys, then checks that the shared image's bytes stay unchanged.

The live template sets five image-builder options in `run_qnx.py`. In the cold-start comparison, the baseline used the SDK defaults and the compact profile used those options. Each of the six trials built a fresh template and booted the same guest executable with the July 27 recording, the same 95 °C request for both conditions and the same temporary issuer. The base disk sizes and time to first preview are recorded for every trial. [Cold-start comparison](replay/qnx-compact-template-proof.json)

The prepared-guest check also scans the job files for the exact preview, signed response and issuer key. The diagnostic log should contain redacted event markers while the signature and receipt still verify in memory. A separate interrupted-review test exercises the same boundary before driver approval. [Interrupted-review evidence](replay/qnx-private-staging-proof.json)

Run `python verify_parser_perf.py --qemu C:\QNX\qemu\qemu-system-x86_64.exe` to compare the time spent evaluating a 4 MiB recording inside QNX with the time from the host request to preview. The harness collects the numeric evaluation time directly from the review callback. Saved diagnostic logs retain a redacted timing marker. The harness reports a receipt hash and checks a normal file with CRLF line endings and an unterminated last row. It also checks that QNX refuses embedded NUL bytes and overlong rows before approval. [Recorded comparison](replay/qnx-parser-performance-proof.json)

Use the bundled normalized drives to reproduce the latency distribution.

```bat
python verify_parser_perf.py --qemu C:\QNX\qemu\qemu-system-x86_64.exe --road-pair fixtures\kit-july-26.csv fixtures\kit-july-27.csv
```

The harness interleaves 20 runs per input, including a synthetic recording at the 4 MiB limit. It uses one prepared template and a fresh guest for each run, and verifies every receipt. Host timing includes encrypted staging and guest boot. Native timing starts after authentication. The report shows every timing, the median, the nearest-rank 95th percentile and the maximum. Browser import and UI polling are outside the measured interval. [Preview latency distributions](replay/qnx-preview-latency.json)

## 7. Run the driver and shop separately

The combined practice session is convenient for one browser. The two launch modes below also let you test the handoff in separate processes or on separate PCs. Both servers listen on their own loopback address. The files you exchange are the issuer public key, the shop request and the verification packet.

On the workshop PC, use an environment with 64-bit Python 3.10 or later. Install the Python dependencies and start the shop with a fresh test register:

```text
python -m pip install -r requirements-live.txt
python live.py --shop-only --shop-register work/separate-shop.sqlite3 --open
```

The workshop gets a shop URL and its register. The QNX SDK, QEMU and a signing key are required on the driver side. From the Windows QNX SDK prompt, build and start that side with a temporary key for this test:

```bat
build-qnx.cmd
start-live.cmd --driver-only --ephemeral-issuer --open
```

1. Download the driver’s public key and enroll it at the shop after confirming its fingerprint. Create a request for both conditions at 95 °C and download it.
2. Open the request in the driver page and choose **July 27 · Full drive**. Approve the QNX finding and download the verification packet. The shop imports and files it for the same request.
3. The idle receipt shows an observation and the moving finding shows insufficient evidence. Create a moving-only follow-up and take it back to the driver. Run **Hot while moving** as the control capture, approve it and file its signed packet. Restart the shop with the same register to check the original and follow-up receipts.

Run `python verify_shop_server.py` to check the shop-only startup and verify an archived QNX receipt with an SDK-free executable search path. The live walkthrough was tested with two independent local processes on one Windows PC. [Recorded two-instance results](replay/qnx-split-role-proof.json)

### Check a saved register

The same `python verify_shop_server.py` command tests three kinds of damage on a backup copy. It alters a signed finding, supplies malformed receipt JSON, and substitutes an otherwise valid receipt issued for a different request. The shop flags the affected row, withholds its finding and export, and still opens other verified receipts. This check uses the enrolled issuer key from the register. [Browser recovery check](replay/qnx-backup-integrity-proof.json)

## Trust model

The shop supplies a previously trusted issuer key and retains its original request. The Windows host provides local issuer enrollment, with the persistent seed protected by DPAPI. The isolated QNX guest receives its signing key in vault memory for the review. The local register tracks filed requests and preserves the first accepted signed file. Production vehicle capture and hardware-backed issuer provisioning remain separate integration tasks.
