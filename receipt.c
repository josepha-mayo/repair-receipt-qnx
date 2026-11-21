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
    STARTUP_WINDOW_MS = 1000,
    MAX_DURATION_MS = 86400000,
};

struct findings {
    unsigned samples;
    unsigned hot_run;
    unsigned context_run;
    long hot_since;
    long context_since;
    int eligible_span_ms;
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

static unsigned coverage_limits(const struct findings *summary, bool complete, bool sustained)
{
    if (summary->observed) {
        return 0;
    }
    const bool adequate = sustained ? summary->eligible_span_ms >= SUSTAINED_MS : summary->samples >= MIN_SAMPLES;
    return (complete ? 0 : COVERAGE_GAP) | (adequate ? 0 : COVERAGE_SHORT_RUN);
}

static const char *finding(const struct findings *summary, unsigned limits)
{
    if (summary->observed) {
        return "observed";
    }
    return limits ? "insufficient_evidence" : "not_observed";
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
    const int span_ms = (int)(timestamp - summary->context_since);
    if (++summary->context_run >= MIN_SAMPLES && span_ms > summary->eligible_span_ms) {
        summary->eligible_span_ms = span_ms;
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
                          const struct findings summaries[CONTEXTS], struct receipt_coverage coverage,
                          enum recording_source source, enum receipt_recipe recipe)
{
    const enum receipt_scope scope = request ? request->scope : SCOPE_BOTH;
    const char *idle = scope & SCOPE_IDLE ? finding(&summaries[IDLE], coverage.idle) : NULL;
    const char *moving = scope & SCOPE_MOVING ? finding(&summaries[MOVING], coverage.moving) : NULL;
    const char *recipe_name = recipe == RECIPE_SAMPLE_COUNT ? "coolant-context-demo/v1" :
                              recipe == RECIPE_STARTUP_WINDOW ? "coolant-startup-window/v3" :
                              "coolant-duration-demo/v2";
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
    const int base_size = snprintf(prefix, sizeof(prefix), "{\"recipe\":\"%s\"%s%s",
                                   recipe_name, threshold, sources[source]);
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
                    char receipt[RECEIPT_CAPACITY], struct receipt_coverage *coverage)
{
    struct recording_reader reader = {.input = input};
    char line[256];
    long duration;
    if (read_line(&reader, line, sizeof(line)) != 1 ||
        !parse_columns(line, &duration, 1) || duration < 1 || duration > MAX_DURATION_MS) {
        return -1;
    }
    struct findings summaries[CONTEXTS] = {
        [IDLE] = {.eligible_span_ms = -1}, [MOVING] = {.eligible_span_ms = -1},
    };
    long previous = -1;
    int previous_context = -1;
    bool complete = missing == 0;
    const bool sustained = recipe != RECIPE_SAMPLE_COUNT;
    bool opening = recipe == RECIPE_STARTUP_WINDOW;
    int startup_excluded_ms = 0;
    int first_gap_ms = -1;
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
        if (opening) {
            if (missing_sample && time_ms <= STARTUP_WINDOW_MS) {
                previous = time_ms;
                continue;
            }
            // Initial missing rows still affect coverage if the first complete sample arrives after the limit.
            if (previous >= 0) {
                if (time_ms <= STARTUP_WINDOW_MS) {
                    startup_excluded_ms = (int)time_ms;
                } else {
                    complete = false;
                    first_gap_ms = 0;
                }
            }
            opening = false;
        }
        const bool gap = previous < 0 ? time_ms > MAX_GAP_MS : time_ms - previous > MAX_GAP_MS;
        if (first_gap_ms < 0 && (gap || missing_sample)) {
            first_gap_ms = gap ? (int)(previous < 0 ? 0 : previous) : (int)time_ms;
        }
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
    const bool trailing_gap = previous >= 0 && duration - previous > MAX_GAP_MS;
    if (first_gap_ms < 0 && (opening || trailing_gap)) {
        first_gap_ms = opening ? 0 : (int)previous;
    }
    complete = complete && !opening && previous >= 0 && !trailing_gap;
    struct receipt_coverage limits = {
        .idle = requested[IDLE] ? coverage_limits(&summaries[IDLE], complete, sustained) : 0,
        .moving = requested[MOVING] ? coverage_limits(&summaries[MOVING], complete, sustained) : 0,
        .startup_excluded_ms = recipe == RECIPE_STARTUP_WINDOW ? startup_excluded_ms : -1,
    };
    limits.first_gap_ms = (limits.idle | limits.moving) & COVERAGE_GAP ? first_gap_ms : -1;
    /* -2 omits the span. -1 means no run qualified for a measured span. */
    limits.idle_span_ms = sustained && (limits.idle & COVERAGE_SHORT_RUN) ? summaries[IDLE].eligible_span_ms : -2;
    limits.moving_span_ms = sustained && (limits.moving & COVERAGE_SHORT_RUN) ? summaries[MOVING].eligible_span_ms : -2;
    if (coverage) {
        *coverage = limits;
    }
    return format_receipt(receipt, request, summaries, limits, source, recipe);
}

int evaluate_recording(FILE *input, const struct shop_request *request, enum recording_source source,
                       char receipt[RECEIPT_CAPACITY], struct receipt_coverage *coverage)
{
    return evaluate(input, request, request ? request->recipe : RECIPE_SAMPLE_COUNT, source, 0, receipt, coverage);
}

int evaluate_driver_recording(FILE *input, enum recording_source source, char receipt[RECEIPT_CAPACITY],
                              struct receipt_coverage *coverage)
{
    return evaluate(input, NULL, RECIPE_SUSTAINED, source, 0, receipt, coverage);
}

int evaluate_bench_capture(FILE *input, const struct shop_request *request, unsigned missing,
                           char receipt[RECEIPT_CAPACITY], struct receipt_coverage *coverage)
{
    if (request->recipe == RECIPE_STARTUP_WINDOW) {
        return -1;
    }
    return evaluate(input, request, request->recipe, SOURCE_BENCH, missing, receipt, coverage);
}
