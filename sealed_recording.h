#ifndef REPAIR_RECEIPT_SEALED_RECORDING_H
#define REPAIR_RECEIPT_SEALED_RECORDING_H

#include "issuer.h"

/* Authenticate the entire recording before exposing it to the evaluator. */
FILE *open_sealed_recording(const char *path, const unsigned char key[SECRET_BYTES]);

#endif
