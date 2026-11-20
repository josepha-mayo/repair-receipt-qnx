#include "obd_capture.h"

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdint.h>
#include <string.h>
#include <termios.h>
#include <time.h>
#include <unistd.h>

enum { FRAME_CAPACITY = 128, CADENCE_MS = 1250, SAMPLE_BUDGET_MS = 350, SETUP_BUDGET_MS = 1500 };

static int64_t now_ms(void)
{
    struct timespec clock;
    if (clock_gettime(CLOCK_MONOTONIC, &clock) == -1) {
        return -1;
    }
    return (int64_t)clock.tv_sec * 1000 + clock.tv_nsec / 1000000;
}

static int ready(int fd, short event, int64_t deadline)
{
    struct pollfd channel = {.fd = fd, .events = event};
    for (;;) {
        const int64_t now = now_ms();
        if (now < 0 || now >= deadline) {
            return 0;
        }
        const int result = poll(&channel, 1, (int)(deadline - now));
        if (result < 0 && errno == EINTR) {
            continue;
        }
        return result > 0 && (channel.revents & event);
    }
}

static int exchange(int fd, const char *command, char response[FRAME_CAPACITY], int64_t deadline)
{
    char request[16];
    const int length = snprintf(request, sizeof(request), "%s\r", command);
    if (length <= 0 || (size_t)length >= sizeof(request)) {
        return -1;
    }
    for (int offset = 0; offset < length;) {
        if (!ready(fd, POLLOUT, deadline)) {
            return -1;
        }
        const ssize_t count = write(fd, request + offset, (size_t)(length - offset));
        if (count < 0 && (errno == EINTR || errno == EAGAIN)) {
            continue;
        }
        if (count <= 0) {
            return -1;
        }
        offset += (int)count;
    }
    for (size_t offset = 0; offset < FRAME_CAPACITY;) {
        if (!ready(fd, POLLIN, deadline)) {
            return -1;
        }
        char byte;
        const ssize_t count = read(fd, &byte, 1);
        if (count < 0 && (errno == EINTR || errno == EAGAIN)) {
            continue;
        }
        if (count != 1 || byte == '\0') {
            return -1;
        }
        if (byte == '>') {
            const int64_t completed = now_ms();
            if (completed < 0 || completed >= deadline) {
                return -1;
            }
            response[offset] = '\0';
            return 0;
        }
        response[offset++] = byte;
    }
    return -1;
}

/* Accept one response line per request. An adapter may echo the command. */
static int single_line(const char *response, const char *command, char line[FRAME_CAPACITY])
{
    int selected = 0;
    while (*response) {
        char compact[FRAME_CAPACITY];
        size_t size = 0;
        while (*response && *response != '\n' && *response != '\r') {
            const unsigned char byte = (unsigned char)*response++;
            if (byte != ' ' && byte != '\t') {
                compact[size++] = (char)toupper(byte);
            }
        }
        if (*response) {
            ++response;
        }
        compact[size] = '\0';
        if (size && strcmp(compact, command) != 0) {
            if (selected) {
                return 0;
            }
            memcpy(line, compact, size + 1);
            selected = 1;
        }
    }
    return selected;
}

static int hex(char digit)
{
    if (digit >= '0' && digit <= '9') {
        return digit - '0';
    }
    if (digit >= 'A' && digit <= 'F') {
        return digit - 'A' + 10;
    }
    return -1;
}

/* Return -1 for transport loss, 0 for an unusable reply, and 1 for a reading. */
static int read_pid(int fd, const char *request, int octets, int *value, int64_t deadline)
{
    char response[FRAME_CAPACITY], line[FRAME_CAPACITY];
    if (exchange(fd, request, response, deadline) != 0) {
        return -1;
    }
    if (!single_line(response, request, line) || strlen(line) != (size_t)(4 + octets * 2) ||
        line[0] != '4' || line[1] != '1' || memcmp(line + 2, request + 2, 2) != 0) {
        return 0;
    }
    *value = 0;
    for (int index = 0; index < octets * 2; ++index) {
        const int digit = hex(line[index + 4]);
        if (digit < 0) {
            return 0;
        }
        *value = *value * 16 + digit;
    }
    return 1;
}

static int initialize(int fd, const struct termios *original)
{
    struct termios serial = *original;
    serial.c_iflag = 0;
    serial.c_oflag = 0;
    serial.c_lflag = 0;
    serial.c_cflag = CLOCAL | CREAD | CS8;
    serial.c_cc[VMIN] = 1;
    serial.c_cc[VTIME] = 0;
    if (cfsetspeed(&serial, B38400) != 0 || tcsetattr(fd, TCSAFLUSH, &serial) != 0) {
        return -1;
    }
    /* Fixed ISO 15765-4 CAN profile for one engine ECU. Adapter settings are volatile. */
    static const char *const setup[] = {"ATE0", "ATL0", "ATS0", "ATH0", "ATCAF1", "ATM0",
                                       "ATTP6", "ATSH7E0", "ATCRA7E8"};
    for (size_t index = 0; index < sizeof(setup) / sizeof(*setup); ++index) {
        char response[FRAME_CAPACITY], line[FRAME_CAPACITY];
        if (exchange(fd, setup[index], response, now_ms() + SETUP_BUDGET_MS) != 0 ||
            !single_line(response, setup[index], line) || strcmp(line, "OK") != 0) {
            return -1;
        }
    }
    return 0;
}

static int wait_until(int64_t instant)
{
    const struct timespec target = {.tv_sec = instant / 1000, .tv_nsec = (instant % 1000) * 1000000};
    int result;
    do {
        result = clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME, &target, NULL);
    } while (result == EINTR);
    return result;
}

static int collect(int fd, FILE *destination, unsigned duration_ms, struct capture_quality *quality)
{
    const int64_t start = now_ms();
    if (start < 0 || fprintf(destination, "%u\n", duration_ms) < 0) {
        return -1;
    }
    for (unsigned tick = 0; tick + SAMPLE_BUDGET_MS <= duration_ms; tick += CADENCE_MS) {
        const int64_t scheduled = start + tick;
        if (wait_until(scheduled) != 0) {
            return -1;
        }
        const int64_t actual = now_ms();
        if (actual < start) {
            return -1;
        }
        const int64_t deadline = scheduled + SAMPLE_BUDGET_MS;
        if (actual >= deadline) {
            ++quality->missed;
            continue;
        }
        int speed_before, temperature, rpm, speed_after;
        const int opening_status = read_pid(fd, "010D", 1, &speed_before, deadline);
        const int coolant_status = opening_status > 0 ? read_pid(fd, "0105", 1, &temperature, deadline) : opening_status;
        const int rpm_status = coolant_status > 0 ? read_pid(fd, "010C", 2, &rpm, deadline) : coolant_status;
        const int speed_status = rpm_status > 0 ? read_pid(fd, "010D", 1, &speed_after, deadline) : rpm_status;
        if (speed_status < 0) {
            ++quality->missed;
            return fflush(destination) == 0 ? 0 : -1; /* Pending replies make the link unusable. */
        }
        if (!speed_status || temperature > 240 || rpm / 4 > 14000) {
            ++quality->missed;
            continue;
        }
        if ((speed_before == 0) != (speed_after == 0)) {
            ++quality->missed;
            ++quality->context_changes;
            continue;
        }
        if (fprintf(destination, "%lld,%d,%d,%d\n", (long long)(actual - start),
                    rpm / 4, speed_after, temperature - 40) < 0) {
            return -1;
        }
        ++quality->samples;
    }
    return wait_until(start + duration_ms) == 0 && fflush(destination) == 0 ? 0 : -1;
}

int capture_obd(const char *device, FILE *destination, unsigned duration_ms,
                struct capture_quality *quality)
{
    if (duration_ms < 3000 || duration_ms > 300000) {
        return -1;
    }
    *quality = (struct capture_quality){0};
    const int fd = open(device, O_RDWR | O_NOCTTY | O_NONBLOCK);
    if (fd < 0) {
        return -1;
    }
    int result = -1;
    struct termios original;
    if (tcgetattr(fd, &original) == 0) {
        if (initialize(fd, &original) == 0) {
            result = collect(fd, destination, duration_ms, quality);
        }
        tcsetattr(fd, TCSANOW, &original);
    }
    close(fd);
    return result;
}
