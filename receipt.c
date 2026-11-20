#include "receipt.h"

#include <errno.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

enum { IDLE, MOVING, CONTEXTS };

enum {
    MIN_SAMPLES = 3,
    MAX_GAP_MS = 2000,
    SUSTAINED_MS = 2000,
    MAX_DURATION_MS = 86400000,
};

struct findings {
    unsigned samples;
    unsigned hot_run;
    unsigned context_run;
    long hot_since;
    long context_since;
    bool adequate;
    bool observed;
};

static bool parse_columns(char *line, long *values, size_t count)
{
    for (size_t i = 0; i < count; ++i) {
        char *end;
        errno = 0;
        values[i] = strtol(line, &end, 10);
        if (errno || end == line) {
            return false;
        }
        if (i + 1 < count) {
            if (*end != ',') {
                return false;
            }
            line = end + 1;
        } else {
            return strcmp(end, "\n") == 0 || strcmp(end, "\r\n") == 0 ||
                   *end == '\0';
        }
    }
    return false;
}

static bool parse_sample(char *line, long values[4], bool *missing)
{
    char *separator = strchr(line, ',');
    *missing = separator && (strcmp(separator, ",,,\n") == 0 ||
                             strcmp(separator, ",,,\r\n") == 0 || strcmp(separator, ",,,") == 0);
    if (*missing) {
        *separator = '\0';
    }
    return parse_columns(line, values, *missing ? 1 : 4);
}

static const char *finding(const struct findings *summary, bool complete, bool sustained)
{
    if (summary->observed) {
        return "observed";
    }
    if (complete && (sustained ? summary->adequate : summary->samples >= MIN_SAMPLES)) {
        return "not_observed";
    }
    return "insufficient_evidence";
}

static void observe(struct findings *summary, long timestamp, long temperature, int threshold,
                    bool interrupted, bool sustained)
{
    ++summary->samples;
    if (interrupted) {
        summary->context_since = timestamp;
        summary->context_run = 0;
        summary->hot_run = 0;
    }
    if (++summary->context_run >= MIN_SAMPLES && timestamp - summary->context_since >= SUSTAINED_MS) {
        summary->adequate = true;
    }
    if (temperature < threshold) {
        summary->hot_run = 0;
        return;
    }
    if (summary->hot_run == 0) {
        summary->hot_since = timestamp;
    }
    if (++summary->hot_run >= MIN_SAMPLES && (!sustained || timestamp - summary->hot_since >= SUSTAINED_MS)) {
        summary->observed = true;
    }
}

struct recording_reader {
    FILE *input;
    unsigned char block[8192];
    size_t offset;
    size_t available;
};

/* An input line must fit in its entirety. Reject embedded NUL bytes. */
static int read_line(struct recording_reader *reader, char *line, size_t capacity)
{
    size_t length = 0;
    for (;;) {
        if (reader->offset == reader->available) {
            reader->offset = 0;
            reader->available = fread(reader->block, 1, sizeof(reader->block), reader->input);
            if (ferror(reader->input)) {
                return -1;
            }
            if (!reader->available) {
                break;
            }
        }
        const unsigned char *start = reader->block + reader->offset;
        const size_t remaining = reader->available - reader->offset;
        const size_t space = capacity - 1 - length;
        const size_t limit = remaining < space ? remaining : space;
        const unsigned char *newline = memchr(start, '\n', limit);
        const size_t copied = newline ? (size_t)(newline - start) + 1 : limit;
        if ((!newline && remaining > space) || memchr(start, '\0', copied)) {
            return -1;
        }
        memcpy(line + length, start, copied);
        length += copied;
        reader->offset += copied;
        if (newline) {
            break;
        }
    }
    line[length] = '\0';
    return length > 0;
}

static int format_receipt(char receipt[RECEIPT_CAPACITY], const struct shop_request *request,
                          const struct findings summaries[CONTEXTS], bool complete,
                          enum recording_source source, bool sustained)
{
    const enum receipt_scope scope = request ? request->scope : SCOPE_BOTH;
    const char *idle = scope & SCOPE_IDLE ? finding(&summaries[IDLE], complete, sustained) : NULL;
    const char *moving = scope & SCOPE_MOVING ? finding(&summaries[MOVING], complete, sustained) : NULL;
    const char *recipe = sustained ? "coolant-duration-demo/v2" : "coolant-context-demo/v1";
    static const char *const sources[] = {
        [SOURCE_UNSPECIFIED] = "",
        [SOURCE_IMPORTED] = ",\"source\":\"uploaded-csv/v1\"",
        [SOURCE_DEMO] = ",\"source\":\"demo-fixture/v1\"",
        [SOURCE_PUBLISHED] = ",\"source\":\"published-road/v1\"",
        [SOURCE_BENCH] = ",\"source\":\"obd-bench/v1\"",
    };
    char threshold[32] = "";
    if (request && request->custom_threshold) {
        snprintf(threshold, sizeof(threshold), ",\"thresholdC\":%d", request->threshold_c);
    }
    char prefix[96];
    const int base_size = snprintf(prefix, sizeof(prefix), "{\"recipe\":\"%s\"%s%s", recipe, threshold, sources[source]);
    if (base_size < 0 || (size_t)base_size >= sizeof(prefix)) {
        return -1;
    }
    int size;
    if (!request) {
        size = snprintf(receipt, RECEIPT_CAPACITY, "%s,\"idle\":\"%s\",\"moving\":\"%s\"}",
                        prefix, idle, moving);
    } else if (request->scope == SCOPE_IDLE) {
        size = snprintf(receipt, RECEIPT_CAPACITY, "%s,\"request\":\"%s\",\"scope\":\"idle\",\"idle\":\"%s\"}",
                        prefix, request->id, idle);
    } else if (request->scope == SCOPE_MOVING) {
        size = snprintf(receipt, RECEIPT_CAPACITY, "%s,\"request\":\"%s\",\"scope\":\"moving\",\"moving\":\"%s\"}",
                        prefix, request->id, moving);
    } else if (request->scope == SCOPE_BOTH) {
        size = snprintf(receipt, RECEIPT_CAPACITY,
                        "%s,\"request\":\"%s\",\"scope\":\"both\",\"idle\":\"%s\",\"moving\":\"%s\"}",
                        prefix, request->id, idle, moving);
    } else {
        return -1;
    }
    return size >= 0 && size < RECEIPT_CAPACITY ? 0 : -1;
}

static int evaluate(FILE *input, const struct shop_request *request, enum receipt_recipe recipe,
                    enum recording_source source, unsigned missing,
                    char receipt[RECEIPT_CAPACITY])
{
    struct recording_reader reader = {.input = input};
    char line[256];
    long duration;
    if (read_line(&reader, line, sizeof(line)) != 1 ||
        !parse_columns(line, &duration, 1) || duration < 1 || duration > MAX_DURATION_MS) {
        return -1;
    }
    struct findings summaries[CONTEXTS] = {0};
    long previous = -1;
    int previous_context = -1;
    bool complete = missing == 0;
    const bool sustained = recipe == RECIPE_SUSTAINED;
    const int threshold = request ? request->threshold_c : DEFAULT_THRESHOLD_C;
    const enum receipt_scope scope = request ? request->scope : SCOPE_BOTH;
    const bool requested[CONTEXTS] = {scope & SCOPE_IDLE, scope & SCOPE_MOVING};
    int line_status;
    while ((line_status = read_line(&reader, line, sizeof(line))) == 1) {
        long columns[4] = {0};
        bool missing_sample;
        if (!parse_sample(line, columns, &missing_sample)) {
            return -1;
        }
        const long time_ms = columns[0], rpm = columns[1], speed_kmh = columns[2];
        const long temperature_c = columns[3];
        if (time_ms <= previous || time_ms > duration || rpm < 0 || rpm > 14000 ||
            speed_kmh < 0 || speed_kmh > 400 || temperature_c < MIN_TEMPERATURE_C || temperature_c > MAX_TEMPERATURE_C) {
            return -1;
        }
        const bool gap = previous < 0 ? time_ms > MAX_GAP_MS : time_ms - previous > MAX_GAP_MS;
        complete = complete && !gap && !missing_sample;
        int context = speed_kmh > 0 ? MOVING : IDLE;
        if (rpm == 0) {
            context = -1;
        } else if (requested[context]) {
            observe(&summaries[context], time_ms, temperature_c, threshold, gap || context != previous_context, sustained);
        }
        previous = time_ms;
        previous_context = context;
    }
    if (line_status < 0) {
        return -1;
    }
    complete = complete && previous >= 0 && duration - previous <= MAX_GAP_MS;
    return format_receipt(receipt, request, summaries, complete, source, sustained);
}

int evaluate_recording(FILE *input, const struct shop_request *request, enum recording_source source,
                       char receipt[RECEIPT_CAPACITY])
{
    return evaluate(input, request, request ? request->recipe : RECIPE_SAMPLE_COUNT, source, 0, receipt);
}

int evaluate_driver_recording(FILE *input, enum recording_source source, char receipt[RECEIPT_CAPACITY])
{
    return evaluate(input, NULL, RECIPE_SUSTAINED, source, 0, receipt);
}

int evaluate_bench_capture(FILE *input, const struct shop_request *request, unsigned missing,
                           char receipt[RECEIPT_CAPACITY])
{
    return evaluate(input, request, request->recipe, SOURCE_BENCH, missing, receipt);
}
