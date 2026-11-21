# Repair Receipt native QNX policy lab

All three trials used the same application binary, sample recording, request and temporary issuer.

Application SHA-256 `4612015840818afc509ae3b30c41db37feabc421b3bd8195e2bdade2cc6e2c5a`

## Policy change

```diff
--- standard
+++ restricted
@@ -18 +17,0 @@
-allow receipt_export_t receipt_owner_t:channel connect;
```

## Export grant removed · driver approves

```text
RR_PLATFORM QNX 8.0.0
RR_LIVE_RAW_WITHHELD
RR_SIGN_WITHHELD approval_required
RR_RECORDING_AUTHENTICATED
RR_PREVIEW [private preview]
RR_PLAINTEXT_BOUNDARY no_staged_file
RR_JOB_DISK_BOUNDARY raw_device_denied
RR_KEY_BOUNDARY vault_memory_denied
RR_FAIL connect to receipt channel errno=1
```

## Standard policy · driver declines

```text
RR_PLATFORM QNX 8.0.0
RR_LIVE_RAW_WITHHELD
RR_SIGN_WITHHELD approval_required
RR_RECORDING_AUTHENTICATED
RR_PREVIEW [private preview]
RR_PLAINTEXT_BOUNDARY no_staged_file
RR_JOB_DISK_BOUNDARY raw_device_denied
RR_KEY_BOUNDARY vault_memory_denied
RR_UNAPPROVED refused
RR_BOUNDARY raw_channel_denied raw_file_denied
RR_SIGN_WITHHELD review_complete
RR_DONE
RR_EXIT=0
```

## Standard policy · driver approves

```text
RR_PLATFORM QNX 8.0.0
RR_LIVE_RAW_WITHHELD
RR_SIGN_WITHHELD approval_required
RR_RECORDING_AUTHENTICATED
RR_PREVIEW [private preview]
RR_PLAINTEXT_BOUNDARY no_staged_file
RR_JOB_DISK_BOUNDARY raw_device_denied
RR_KEY_BOUNDARY vault_memory_denied
RR_RECEIPT import [signed receipt]
RR_BOUNDARY raw_channel_denied raw_file_denied
RR_SIGN_WITHHELD review_complete
RR_DONE
RR_EXIT=0
```
