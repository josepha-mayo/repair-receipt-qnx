#ifndef REPAIR_RECEIPT_H
#define REPAIR_RECEIPT_H

#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>

enum { RECEIPT_CAPACITY = 224, REQUEST_ID_BYTES = 16 };
enum { DEFAULT_THRESHOLD_C = 105, MIN_TEMPERATURE_C = -40, MAX_TEMPERATURE_C = 200 };

enum receipt_scope { SCOPE_IDLE = 1, SCOPE_MOVING = 2, SCOPE_BOTH = 3 };
enum receipt_recipe { RECIPE_SAMPLE_COUNT = 1, RECIPE_SUSTAINED = 2, RECIPE_STARTUP_WINDOW = 4 };
enum request_encoding { REQUEST_CONFIGURED = 3, REQUEST_STARTUP_CONFIGURED = 5 };
enum coverage_limit { COVERAGE_GAP = 1, COVERAGE_SHORT_RUN = 2 };
enum recording_source {
    SOURCE_UNSPECIFIED = 0, SOURCE_IMPORTED = 1, SOURCE_DEMO = 2, SOURCE_PUBLISHED = 3, SOURCE_BENCH
};

struct shop_request {
    enum receipt_scope scope;
    enum receipt_recipe recipe;
    int threshold_c;
    bool custom_threshold;
    char id[2 * REQUEST_ID_BYTES + 1];
};

struct receipt_coverage {
    unsigned idle;
    unsigned moving;
    int startup_excluded_ms;
};

/* Decode a local recording and emit only the findings requested by the shop. */
int evaluate_recording(FILE *input, const struct shop_request *request, enum recording_source source,
                       char receipt[RECEIPT_CAPACITY], struct receipt_coverage *coverage);
int evaluate_driver_recording(FILE *input, enum recording_source source, char receipt[RECEIPT_CAPACITY],
                              struct receipt_coverage *coverage);
int evaluate_bench_capture(FILE *input, const struct shop_request *request, unsigned missing,
                           char receipt[RECEIPT_CAPACITY], struct receipt_coverage *coverage);

#endif
