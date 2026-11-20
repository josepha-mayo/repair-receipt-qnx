#ifndef REPAIR_RECEIPT_OBD_CAPTURE_H
#define REPAIR_RECEIPT_OBD_CAPTURE_H

#include <stdio.h>

struct capture_quality {
    unsigned samples;
    unsigned missed;
    unsigned context_changes;
};

/* Capture Mode 01 coolant, engine RPM and speed using one ELM327 serial device. */
int capture_obd(const char *device, FILE *destination, unsigned duration_ms,
                struct capture_quality *quality);

#endif
