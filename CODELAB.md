# QNX codelab · Release one diagnostic finding by consent

Build a QNX 8.0 guest that can return a signed coolant observation from a local recording. You will test which processes can reach the recording, when the vault will issue, and whether changing a withheld finding changes the exported file.

## 1. Compile and run

Use a Windows command prompt with QNX SDP 8.0, QEMU for x86-64 and 64-bit Python 3.10 or later. From this directory:

```bat
python -m pip install -r requirements-live.txt
build-qnx.cmd
start-live.cmd --check
start-live.cmd --practice
```

Practice mode gives the walkthrough an empty shop register and a temporary driver key. Download any files you want to keep before closing the app. See [setup in the README](README.md#live-driver-and-shop-workflow) for loading the SDK and selecting a custom QEMU path.

Open the printed shop and driver URLs. In the driver, save the public key under **Enroll your issuer key at the shop**. In the shop, load the public key, choose **At idle only**, create the request and download it. The request carries a random ID, a fixed recipe version and one operating condition. The shop register retains the request and its enrolled public key.

In the driver page, load that request, run **Trip A** and review the preview. Approve and choose **Download verification packet**. In the shop register, open the packet under **Find a request from a receipt or packet**. The register opens the matching job and verifies it against the request and key on file. Choose **File verified receipt** and load the packet again to observe repeat handling. In the standalone verifier, try a freshly generated idle-only request against the same valid packet to see the request mismatch.

Run **Missing samples** under the same request, approve it and open the returned packet in the shop. **Two verified receipts** compares the filed threshold observation with the returned insufficient-evidence finding. Open the first packet again to verify the work order still holds the original answer. Load both packets in the offline verifier with the enrolled key. Both signatures verify, and the verifier flags the shared request ID. Use the filed work order's receipt digest to identify the filed answer.

Choose **View work-order findings** to open a print view directly from the filed request. The idle-only printout gives the finding, test rule, input source, filing time and full receipt request ID.

From this filed request choose **Create recheck request**, download it and use **Hot while moving** as the second fixture in the driver view. The original idle test observed a crossing and the recheck reports **Threshold not observed**. File the recheck and open **View work-order findings** to compare the two receipts under the same idle rule. Their request IDs and receipt digests appear separately on the printout.

A recheck always asks for the original request's conditions. If a work order starts with both idle and moving and a moving-only follow-up completes coverage, the next recheck again asks for both. The report keeps the separate original receipts as the prior evidence for their respective conditions.

Create a new idle-only request and run **Missing samples** in the driver view. The approved receipt reports insufficient evidence. File it and choose **Create follow-up request**. Open **View work-order findings** to see the outstanding recording. Run **Trip A** with the new request, approve its answer, and file it. Reopen the work order to see the resolved finding and open its source receipt. The original request retains its signed insufficient-evidence result.

Download a **verification packet** from a filed request. Open the standalone verifier offline and load the packet with the issuer key you enrolled separately. The verifier checks the original request and signature, and the work-order printout includes the issuer fingerprint. Repeat with a different issuer key to see verification fail.

In the work-order view, choose **Download verification files**. Extract the ZIP, select both packet files together and choose **Verify packets** in the offline verifier. The earlier packet still shows insufficient evidence and the follow-up carries the later finding. Match their full request IDs and receipt digests to the printed work order.

Download a **Register backup** from the shop intake page. Start a separate session with `start-live.cmd --ephemeral-issuer --shop-register "C:\path\practice-backup-copy.sqlite3"` pointing at a copy of that file. Reopen the work order and follow its source receipt links. The register verifies prior receipts using the public keys saved with those requests, even with a different local driver key.

## 2. Follow the QNX boundary

Read [policy.conf](policy.conf) and find the two native channel grants. The supervisor can connect to the vault. The export process can connect to the supervisor. The vault also checks the supervisor's process ID on every message. [QNX security policy language](https://www.qnx.com/developers/docs/8.0/com.qnx.doc.security.system/topic/manual/secpol_language.html)

In [probe.c](probe.c), follow the scoped review:

1. The vault reads and validates the allowlisted scope and computes one preview from the local CSV.
2. A signing call before approval receives `EACCES`. The vault reads the driver's decision over its serial input and signs the exact preview after approval.
3. The vault serves the approved envelope once. The unprivileged exporter checks that opening the raw channel, CSV and vault memory all fail before requesting the bounded envelope.

The native guest uses `ConnectAttach`, `MsgSend`, `MsgReceive` and `MsgReply`. The browser and QEMU harness exchange the preview and decision over the guest's serial port. The guest has no network interface.

### Remove one channel grant

After building the app, run the check from a QNX SDP 8.0 command prompt. Use the path to your QEMU executable.

```bat
python verify_policy.py --qemu C:\QNX\qemu\qemu-system-x86_64.exe
```

The script compiles two policies in a temporary directory and boots the same app executable with each one. Each run uses the same idle-only request, recording and issuer. The restricted policy removes exactly this line:

```text
allow receipt_export_t receipt_owner_t:channel connect;
```

| Policy | Driver decision | Expected guest result |
| --- | --- | --- |
| Export grant removed | Approve | QNX denies the exporter's channel connection after the preview. The trace contains `RR_FAIL connect to receipt channel errno=1` and no receipt. |
| Standard | Decline | The consent gate withholds the receipt. |
| Standard | Approve | The script verifies the signed receipt against the exact preview. The exporter is denied access to the raw channel, file, job disk and vault memory. |

To observe the denial in the browser, use a separate project copy. Remove the line from its `policy.conf`, rebuild with `build-qnx.cmd` and start a fresh app instance. Load the idle-only request and approve **Trip A**. The preview appears and export fails. Restore the grant and rebuild to run the successful control. [Recorded QNX trials](replay/qnx-policy-lab-proof.json)

## 3. Change a withheld finding

Use the **same idle-only request** to approve **Trip C**. It retains the idle threshold crossing and adds a crossing while moving. Compare the full signed files from A and C. They should be byte-identical. Now create a **While moving only** request for Trip C. The result should include the driving observation.

Repeat the comparison with two published recordings from the [KIT Automotive OBD-II Dataset](https://publikationen.bibliothek.kit.edu/1000085073). Import `2017-07-26_Seat_Leon_RT_S_Stau.csv` and `2017-07-27_Seat_Leon_KA_KA_2_Normal.csv` directly in the driver page. Use the same idle-only request at a test threshold of 95 °C and the same issuer. Approve each review and compare the downloaded files. Both say **Threshold observed** and the signed files are byte-identical. Run both recordings again with a new moving-only request at the same test threshold. July 26 shows **Threshold observed**, and July 27 shows **Insufficient evidence**. Both files start before all three signals are available. QNX preserves a fully observed crossing even when coverage is incomplete. [Paired real-recording results](replay/qnx-road-scope-proof.json)

Open the downloaded HTML in a current Chromium browser. **Check idle receipts** and **Check moving receipts** verify the signatures, request bindings and signed published-road input type. After either check, open **Download proof files** to save the two verification packets and example key. Load those files back into the verifier to check each signature and receipt hash independently. [Download the offline verifier](https://github.com/josepha-mayo/repair-receipt-qnx/releases/latest/download/verify-receipt.html) · [Signed QNX evidence](replay/qnx-road-scope-receipts.json)

The archived run uses the normalized input hashes listed in the [paired-drive proof](replay/qnx-road-scope-proof.json). Importing the raw files through the driver page reproduces the findings and the equality comparison with an uploaded-CSV input label. To check that import preserves missing samples at either end of a recording, run `node --test verify_obd_import.cjs`.

For a work-order trial, create a request for both conditions at 95 °C and file the July 27 result. The shop sees the observed idle finding and the insufficient moving result together. **Create follow-up request** asks only about moving and keeps the original signed receipt in the work order.

### Measure what the shop receives

With the Python dependencies installed and Node.js 24 available, run the measurement tool on both original CSVs. It regenerates the normalized inputs using the browser's parser and verifies the archived idle signature before counting the bytes of the verification packet. This check runs on the host.

```bat
python measure_road_disclosure.py "path\to\2017-07-26_Seat_Leon_RT_S_Stau.csv" "path\to\2017-07-27_Seat_Leon_KA_KA_2_Normal.csv"
```

The complete attachment is **667 bytes** for either recording in this idle-only test. To verify the count from the browser, save both packets using **Download proof files** after checking the idle receipts. The issuing key is shared separately at enrollment. [Measured file sizes and claim fields](replay/qnx-road-disclosure.json)

### Vary the test threshold

Use Node.js 24 and the same two raw CSVs. The command-line normalizer uses the driver page's parser. From the QNX SDK prompt, run these commands from the project root:

```bat
node normalize-obd.cjs "path\to\2017-07-26_Seat_Leon_RT_S_Stau.csv" first.normalized
node normalize-obd.cjs "path\to\2017-07-27_Seat_Leon_KA_KA_2_Normal.csv" second.normalized
python verify_requests.py --qemu C:\QNX\qemu\qemu-system-x86_64.exe --road-sweep first.normalized second.normalized
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

### Run the native scope controls

Run the included demo controls without a browser from Windows:

```bat
start-live.cmd --self-test
```

The self-test verifies four signatures, identical signed idle receipts and different moving receipts under a common request for each condition. It checks that QNX explains gaps to the driver and the diagnostic log redacts that guidance. Declining must produce no receipt. One additional boot repeats the approved idle review under the policy from section 2 with the export grant removed. QNX must deny the connection after the preview. For the individual receipt SHA-256 digests, run `python verify_requests.py --qemu C:\QNX\qemu\qemu-system-x86_64.exe` from the SDK prompt.

Run `python verify_consent.py` on the host to check the five-minute boundary. It exercises approval immediately before, at and after expiry. It also checks that the pending preview and coverage guidance drop out of the driver's response at expiry.

Run `python verify_requests.py --qemu C:\QNX\qemu\qemu-system-x86_64.exe --scope-matrix` to check both request scopes and all three result types. Each pair changes the temperature and RPM outside the requested condition. QNX produces the same signed bytes within each pair. A request for both conditions shows the moving result change. The suite also checks that QNX withholds a negative answer after a coverage gap and rejects a malformed out-of-scope row before preview. [Native scope matrix](replay/qnx-scope-matrix-proof.json)

Run `python verify_shop_register.py` to test the shop side with independent test keys. It checks the pinned issuer, races two valid answers to the same request, and reopens the database to check the exact stored receipt. The same command verifies the four archived road receipts and their matching idle digest.

## 4. Capture through a QNX serial device

Repeat the live workflow with **Simulated OBD-II adapter · Live QNX capture**. Watch the receipt identify the simulated source after approval. The host runs an adapter simulator. QNX opens its UART, sends a fixed set of Mode 01 read requests, parses each response and evaluates the capture in its vault.

Run `python verify_obd_bench.py --qemu C:\QNX\qemu\qemu-system-x86_64.exe`. The checks use the same prepared guest path as the app.

| Simulated adapter case | Expected result |
| --- | --- |
| Complete capture | Idle threshold observed and moving threshold not observed |
| Missing and ambiguous frames | Insufficient evidence for both conditions |
| Vehicle stops between the two speed reads for one sample | QNX drops the ambiguous sample and reports insufficient evidence for both conditions |
| Prompt arrives after the reply deadline | Capture ends before another request. Both findings are insufficient. |
| Four delayed prompts complete within the shared sample budget | QNX accepts the third hot idle sample. The receipt observes the idle crossing. |
| The same readings complete beyond the shared sample budget, with every reply individually under 350 ms | QNX drops the third sample and stops polling. The receipt reports insufficient evidence for both conditions. |
| Link drops partway through a speed response | QNX retains the completed idle crossing. Moving coverage is insufficient. |
| Adapter setup fails | QNX stops before preview, without producing a receipt. |

The exporter tests that the UART and capture file are inaccessible. [Native bench traces](replay/qnx-obd-proof.txt)

## 5. Check elapsed time before accepting a finding

Run `python verify_duration.py --qemu C:\QNX\qemu\qemu-system-x86_64.exe`. Compare the same three hot samples packed into six milliseconds under the archived and current rules. The archived sample-count rule observes a threshold crossing. The current rule needs the samples to span two seconds in one operating condition. Its boundary tests compare 1,999 ms with 2,000 ms, and its coverage controls test shifts between idle and moving and missing recording time.

Check the leading and trailing gap controls in the same run. A gap of two seconds at either edge permits a negative finding with enough continuous coverage. At 2,001 ms the result becomes **Insufficient evidence**. A fully observed hot run still supports a positive finding before a later gap. The engine-stop control checks that samples across a stopped engine cannot be combined into one hot run.

The shop saves the selected rule with the request. The signed claim includes that rule, and the offline verifier and filing register check it against the request. `verify_shop_register.py` opens an earlier database and checks that the exact previously filed receipt survives the schema upgrade.

Create two idle-only requests for **Trip A**, one with a test threshold of **106 °C** and the other with **108 °C**. Run each in QNX. The fixture crosses 106 °C for the required duration. At 108 °C, its finding is **Threshold not observed**. Both receipts carry the selected threshold. Change one threshold in the request JSON, then try that request with the original signed receipt in the offline verifier to see validation fail.

In the driver view, remove the shop request and run **Trip A**. The vault uses the same sustained rule and previews idle and moving before approval. Approve and open the receipt in the offline verifier with the enrolled key. The verifier labels it **Driver-started review**. Repeat and decline to check that QNX withholds the signed file.

## 6. Reuse the QNX image between reviews

Run `python verify_prepared_guest.py --qemu C:\QNX\qemu\qemu-system-x86_64.exe` from the QNX SDK prompt. The harness measures the time from review start to the native preview with a full image build and a prepared image. The same recording and request yield identical signed bytes despite fresh staging keys and ciphertext. QNX denies the exporter's attempt to open the raw job disk. The vault discards recordings with an altered authentication tag or encrypted source marker before showing a preview. The harness checks the staged files for the original data and keys, then checks that the shared image's bytes stay unchanged.

The prepared-guest check also scans the job files for the exact preview, signed response and issuer key. The diagnostic log should contain redacted event markers while the signature and receipt still verify in memory. A separate interrupted-review test exercises the same boundary before driver approval. [Interrupted-review evidence](replay/qnx-private-staging-proof.json)

Run `python verify_parser_perf.py --qemu C:\QNX\qemu\qemu-system-x86_64.exe` to compare the time spent evaluating a 4 MiB recording inside QNX with the time from the host request to preview. The harness reports a receipt hash and checks a normal file with CRLF line endings and an unterminated last row. It also checks that QNX refuses embedded NUL bytes and overlong rows before approval. [Recorded comparison](replay/qnx-parser-performance-proof.json)

For a distribution, reuse the two normalized files from [the threshold sweep](#vary-the-test-threshold).

```bat
python verify_parser_perf.py --qemu C:\QNX\qemu\qemu-system-x86_64.exe --road-pair first.normalized second.normalized
```

The harness interleaves 20 runs per input, including a synthetic recording at the 4 MiB limit. It uses one prepared template and a fresh guest for each run, and verifies every receipt. Host timing includes encrypted staging and guest boot. Native timing starts after authentication. The report shows every timing, the median, the nearest-rank 95th percentile and the maximum. Browser import and UI polling are outside the measured interval. [Preview latency distributions](replay/qnx-preview-latency.json)

## Trust model

The shop supplies a previously trusted issuer key and retains its original request. The Windows host provides local issuer enrollment, with the persistent seed protected by DPAPI. The isolated QNX guest receives its signing key in vault memory for the review. The local register tracks filed requests and preserves the first accepted signed file. Production vehicle capture and hardware-backed issuer provisioning remain separate integration tasks.
