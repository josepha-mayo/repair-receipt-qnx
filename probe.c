#include "issuer.h"
#include "obd_capture.h"
#include "sealed_recording.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <secpol/secpol.h>
#include <spawn.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/neutrino.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <termios.h>
#include <time.h>
#include <unistd.h>

enum { FIXTURE_CASES = 6, IMPORT_CASE = FIXTURE_CASES, EXPORT_ID = 2100 };
static const char *const cases[] = {"trip-a", "trip-b", "moving", "gap", "kit-obd", "scope-control", "import"};
static const char *const inputs[] = {
    "/system/receipt-private/trip-a.csv", "/system/receipt-private/trip-b.csv",
    "/system/receipt-private/moving.csv", "/system/receipt-private/gap.csv",
    "/system/receipt-private/kit-obd.csv", "/system/receipt-private/scope-control.csv",
    "/system/receipt-private/import.csv",
};

enum command { READ_RAW, EVALUATE, STOP_VAULT, GET_RECEIPT, SIGN_RECEIPT, REVIEW_SIGNED };
enum vault_mode { VAULT_FIXTURES, VAULT_IMPORT, VAULT_SIGNED, VAULT_REQUEST, VAULT_OBD_BENCH };
static const char bench_recording[] = "/dev/shmem/rr-obd-capture.csv";
static const char sealed_recording[] = "/system/receipt-private/import.aesgcm";

struct request {
    enum command command;
    unsigned case_id;
};

static void check(int condition, const char *message)
{
    if (!condition) {
        fprintf(stderr, "RR_FAIL %s errno=%d\n", message, errno);
        exit(EXIT_FAILURE);
    }
}

static void timeout(unsigned flags)
{
    const uint64_t budget = 3000000000ULL;
    check(TimerTimeout(CLOCK_MONOTONIC, flags, NULL, &budget, NULL) != -1, "arm IPC timeout");
}

static int request(int coid, enum command command, unsigned case_id, char body[ENVELOPE_CAPACITY])
{
    const struct request req = {command, case_id};
    if (command == REVIEW_SIGNED) {
        const uint64_t decision_budget = 330000000000ULL;
        check(TimerTimeout(CLOCK_MONOTONIC, _NTO_TIMEOUT_SEND | _NTO_TIMEOUT_REPLY, NULL,
                           &decision_budget, NULL) != -1, "arm review deadline");
    } else {
        timeout(_NTO_TIMEOUT_SEND | _NTO_TIMEOUT_REPLY);
    }
    return MsgSend(coid, &req, sizeof(req), body, ENVELOPE_CAPACITY);
}

static int receive(int channel, pid_t permitted_pid, struct request *request, int bounded)
{
    for (;;) {
        struct _msg_info info;
        union {
            struct request request;
            struct _pulse pulse;
        } message;
        if (bounded) {
            timeout(_NTO_TIMEOUT_RECEIVE);
        }
        int rcvid = MsgReceive(channel, &message, sizeof(message), &info);
        check(rcvid != -1, "receive native request");
        if (rcvid > 0) {
            if (info.pid != permitted_pid) {
                MsgError(rcvid, EACCES);
                continue;
            }
            if (info.srcmsglen != sizeof(message.request)) {
                MsgError(rcvid, EINVAL);
                continue;
            }
            *request = message.request;
            return rcvid;
        }
    }
}

static int number(const char *text)
{
    char *end;
    errno = 0;
    long value = strtol(text, &end, 10);
    check(!errno && *text && !*end && value >= 0 && value <= INT_MAX, "valid role argument");
    return (int)value;
}

static void read_shop_request(struct shop_request *request)
{
    FILE *file = fopen("/system/receipt-private/request.bin", "rb");
    check(file != NULL, "open shop request");
    const int scope = fgetc(file);
    check(scope == SCOPE_IDLE || scope == SCOPE_MOVING || scope == SCOPE_BOTH,
          "allowlisted request scope");
    request->scope = (enum receipt_scope)scope;
    unsigned char id[REQUEST_ID_BYTES];
    check(fread(id, 1, sizeof(id), file) == sizeof(id), "read request ID");
    const int version = fgetc(file);
    const bool startup_window = version == RECIPE_STARTUP_WINDOW || version == REQUEST_STARTUP_CONFIGURED;
    request->custom_threshold = version == REQUEST_CONFIGURED || version == REQUEST_STARTUP_CONFIGURED;
    request->threshold_c = DEFAULT_THRESHOLD_C;
    if (request->custom_threshold) {
        const int encoded = fgetc(file);
        check(encoded >= 0 && encoded <= MAX_TEMPERATURE_C - MIN_TEMPERATURE_C, "read configured threshold");
        request->threshold_c = MIN_TEMPERATURE_C + encoded;
    }
    check((version == EOF || version == RECIPE_SUSTAINED || startup_window || request->custom_threshold) &&
          (version == EOF || fgetc(file) == EOF) && !ferror(file), "read allowlisted recipe");
    request->recipe = version == EOF ? RECIPE_SAMPLE_COUNT : startup_window ? RECIPE_STARTUP_WINDOW : RECIPE_SUSTAINED;
    fclose(file);
    for (size_t i = 0; i < sizeof(id); ++i) {
        snprintf(request->id + i * 2, 3, "%02x", (unsigned)id[i]);
    }
}

static int consent(const char *receipt, const char *issuer, const struct receipt_coverage *coverage);
static EVP_PKEY *provision_issuer(unsigned char *recording_key);

static FILE *capture_bench(struct capture_quality *quality)
{
    const int fd = open(bench_recording, O_CREAT | O_EXCL | O_RDWR, 0600);
    if (fd < 0) {
        return NULL;
    }
    FILE *output = fdopen(fd, "w+");
    if (!output) {
        close(fd);
        unlink(bench_recording);
        return NULL;
    }
    puts("RR_CAPTURE_BEGIN obd_bench");
    fflush(stdout);
    if (capture_obd("/dev/ser3", output, 9000, quality) != 0 ||
        fseek(output, 0, SEEK_SET) != 0) {
        fclose(output);
        unlink(bench_recording);
        return NULL;
    }
    if (quality->context_changes) {
        printf("RR_CAPTURE_CONTEXT_CHANGED %u\n", quality->context_changes);
    }
    printf("RR_CAPTURE_COMPLETE %u %u\n", quality->samples, quality->missed);
    return output;
}

static enum recording_source read_recording_source(FILE *recording)
{
    const int marker = fgetc(recording);
    switch (marker) {
    case SOURCE_IMPORTED:
    case SOURCE_DEMO:
    case SOURCE_PUBLISHED:
        return (enum recording_source)marker;
    default:
        if (marker != EOF) {
            check(ungetc(marker, recording) != EOF, "restore first CSV byte");
        }
        return SOURCE_UNSPECIFIED;
    }
}

static void review_signed(int rcvid, const struct request *message, const struct shop_request *scope,
                          EVP_PKEY *key, unsigned char recording_key[SECRET_BYTES], int *review_started,
                          char approved[ENVELOPE_CAPACITY], int bench)
{
    if (message->case_id != IMPORT_CASE) {
        MsgError(rcvid, EACCES);
        return;
    }
    if (message->command == SIGN_RECEIPT && approved[0] != '\0') {
        check(MsgReply(rcvid, 0, approved, ENVELOPE_CAPACITY) == 0, "return consent-bound receipt");
        memset(approved, 0, ENVELOPE_CAPACITY);
        return;
    }
    if (message->command != REVIEW_SIGNED || *review_started) {
        MsgError(rcvid, EACCES);
        return;
    }
    *review_started = 1;
    struct capture_quality quality;
    FILE *recording = bench ? capture_bench(&quality) : open_sealed_recording(sealed_recording, recording_key);
    OPENSSL_cleanse(recording_key, SECRET_BYTES);
    if (!recording) {
        MsgError(rcvid, bench ? ENODEV : EBADMSG);
        return;
    }
    if (!bench) {
        puts("RR_RECORDING_AUTHENTICATED");
    }
    char claim[RECEIPT_CAPACITY], issuer[KEY_HEX_CAPACITY];
    struct timespec started, finished;
    const int timed = clock_gettime(CLOCK_MONOTONIC, &started) == 0;
    const enum recording_source source = bench ? SOURCE_BENCH : read_recording_source(recording);
    struct receipt_coverage coverage;
    const int parsed = bench ? evaluate_bench_capture(recording, scope, quality.missed, claim, &coverage)
                             : scope ? evaluate_recording(recording, scope, source, claim, &coverage)
                                     : evaluate_driver_recording(recording, source, claim, &coverage);
    if (timed && clock_gettime(CLOCK_MONOTONIC, &finished) == 0) {
        const long long elapsed = (finished.tv_sec - started.tv_sec) * 1000000LL +
                                  (finished.tv_nsec - started.tv_nsec) / 1000;
        printf("RR_EVALUATION_US %lld\n", elapsed);
    }
    fclose(recording);
    if (parsed != 0) {
        MsgError(rcvid, EINVAL);
        return;
    }
    check(issuer_public_key(key, issuer), "load live issuer key");
    const int allowed = consent(claim, issuer, &coverage);
    if (allowed) {
        const int version = bench ? 3 : source == SOURCE_UNSPECIFIED ? (scope ? 2 : 4) : (scope ? 5 : 6);
        check(issuer_envelope(key, claim, version, approved), "sign the exact approved claim");
    }
    check(MsgReply(rcvid, allowed, NULL, 0) == 0, "return the consent decision");
}

static void vault(const char *ready_path, enum vault_mode mode)
{
    struct shop_request request;
    const int scoped = mode == VAULT_REQUEST || mode == VAULT_OBD_BENCH;
    if (scoped) {
        read_shop_request(&request);
    }
    const int signed_mode = scoped || mode == VAULT_SIGNED;
    unsigned char recording_key[SECRET_BYTES] = {0};
    EVP_PKEY *key = signed_mode ? provision_issuer(mode == VAULT_OBD_BENCH ? NULL : recording_key) : NULL;
    const pid_t owner = getppid();
    int channel = ChannelCreate(0);
    check(channel >= 0, "create protected raw channel");
    FILE *ready = fopen(ready_path, "wx");
    check(ready != NULL, "write vault address");
    check(fprintf(ready, "%d\n", channel) > 0 && fclose(ready) == 0, "publish vault address");

    int review_started = 0;
    char approved[ENVELOPE_CAPACITY] = {0};
    for (;;) {
        struct request req;
        int rcvid = receive(channel, owner, &req, 0);
        if (req.command == STOP_VAULT) {
            OPENSSL_cleanse(recording_key, sizeof(recording_key));
            EVP_PKEY_free(key);
            if (mode == VAULT_OBD_BENCH) {
                unlink(bench_recording);
            }
            MsgReply(rcvid, 0, NULL, 0);
            return;
        }
        if (signed_mode) {
            review_signed(rcvid, &req, scoped ? &request : NULL, key, recording_key, &review_started, approved,
                          mode == VAULT_OBD_BENCH);
            continue;
        }
        if ((mode != VAULT_FIXTURES && (req.case_id != IMPORT_CASE || req.command == READ_RAW)) ||
            (mode == VAULT_FIXTURES && req.case_id >= FIXTURE_CASES)) {
            MsgError(rcvid, EACCES);
            continue;
        }
        char body[ENVELOPE_CAPACITY] = {0};
        FILE *recording = fopen(inputs[req.case_id], "r");
        check(recording != NULL, "open private recording");
        int valid = 0;
        if (req.command == READ_RAW) {
            valid = fgets(body, RECEIPT_CAPACITY, recording) != NULL &&
                    fgets(body, RECEIPT_CAPACITY, recording) != NULL;
        } else if (req.command == EVALUATE) {
            valid = evaluate_recording(recording, NULL, SOURCE_UNSPECIFIED, body, NULL) == 0;
        }
        fclose(recording);
        if (!valid) {
            MsgError(rcvid, EINVAL);
            continue;
        }
        check(MsgReply(rcvid, 0, body, sizeof(body)) == 0, "reply inside vault");
    }
}

static void exporter(int vault_pid, int vault_channel, int publisher_pid, int publisher_channel,
                     unsigned case_id, int approved, int signed_review, int bench)
{
    check(getuid() == EXPORT_ID && geteuid() == EXPORT_ID &&
          getgid() == EXPORT_ID && getegid() == EXPORT_ID, "verify unprivileged exporter credentials");
    int raw = ConnectAttach(0, vault_pid, vault_channel, _NTO_SIDE_CHANNEL, 0);
    check(raw == -1 && (errno == EPERM || errno == EACCES), "kernel must deny raw channel attach");
    const char *protected_path = bench ? bench_recording : signed_review ? sealed_recording : inputs[case_id];
    FILE *raw_file = fopen(protected_path, "r");
    check(raw_file == NULL && (errno == EPERM || errno == EACCES), "raw file must be unreadable");
    if (signed_review && !bench) {
        check(open(inputs[case_id], O_RDONLY) == -1 && errno == ENOENT, "no plaintext recording file in the guest");
        puts("RR_PLAINTEXT_BOUNDARY no_staged_file");
    }
    if (access("/system/receipt-private/job-disk", F_OK) == 0) {
        const int disk = open("/dev/hd1", O_RDONLY | O_NONBLOCK);
        check(disk == -1 && (errno == EACCES || errno == EPERM), "raw job disk must be inaccessible to the exporter");
        puts("RR_JOB_DISK_BOUNDARY raw_device_denied");
    }
    if (bench) {
        const int device = open("/dev/ser3", O_RDONLY | O_NOCTTY | O_NONBLOCK);
        check(device == -1 && (errno == EACCES || errno == EPERM), "adapter must be inaccessible to the exporter");
        puts("RR_CAPTURE_ACCESS adapter_denied");
    }
    if (signed_review) {
        char address[64];
        snprintf(address, sizeof(address), "/proc/%d/as", vault_pid);
        FILE *memory = fopen(address, "rb");
        check(memory == NULL && (errno == EPERM || errno == EACCES), "vault memory must be unreadable");
        puts("RR_KEY_BOUNDARY vault_memory_denied");
    }

    int receipt = ConnectAttach(0, publisher_pid, publisher_channel, _NTO_SIDE_CHANNEL, 0);
    check(receipt >= 0, "connect to receipt channel");
    char body[ENVELOPE_CAPACITY];
    int result = request(receipt, GET_RECEIPT, case_id, body);
    if (approved) {
        check(result == 0 && memchr(body, '\0', sizeof(body)) != NULL, "get approved receipt");
        printf("RR_RECEIPT %s %s\n", cases[case_id], body);
    } else {
        check(result == -1 && errno == EACCES, "refuse unapproved receipt");
        puts("RR_UNAPPROVED refused");
    }
    ConnectDetach(receipt);
    puts("RR_BOUNDARY raw_channel_denied raw_file_denied");
}

static pid_t start_role(const char *type, char *const arguments[], int unprivileged, int consent_input)
{
    posix_spawnattr_t attr;
    check(posix_spawnattr_init(&attr) == 0, "init role attributes");
    check(secpol_posix_spawnattr_settypeid(NULL, &attr, type, SECPOL_TYPE_NAME) == 0,
          "set QNX policy type");
    if (unprivileged) {
        uint32_t flags;
        check(posix_spawnattr_getxflags(&attr, &flags) == 0, "read spawn flags");
        check(posix_spawnattr_setcred(&attr, EXPORT_ID, EXPORT_ID) == 0, "set exporter credentials");
        check(posix_spawnattr_setxflags(&attr, flags | POSIX_SPAWN_SETCRED) == 0,
              "apply credentials before execution");
    }
    posix_spawn_file_actions_t files;
    check(posix_spawn_file_actions_init(&files) == 0, "init allowed child descriptors");
    if (!consent_input) {
        check(posix_spawn_file_actions_addclose(&files, STDIN_FILENO) == 0, "withhold consent input");
    }
    pid_t pid;
    const int result = posix_spawn(&pid, arguments[0], &files, &attr, arguments, NULL);
    posix_spawn_file_actions_destroy(&files);
    posix_spawnattr_destroy(&attr);
    if (result != 0) {
        errno = result;
        check(0, "spawn isolated role");
    }
    return pid;
}

static void join(pid_t pid)
{
    int status;
    check(waitpid(pid, &status, 0) == pid && WIFEXITED(status) && WEXITSTATUS(status) == 0,
          "role exited successfully");
}

static void serial_read_mode(struct termios *original)
{
    check(tcgetattr(STDIN_FILENO, original) == 0, "read private serial settings");
    struct termios input = *original;
    input.c_lflag &= ~(ICANON | ECHO | ECHONL);
    input.c_cc[VMIN] = 1;
    input.c_cc[VTIME] = 0;
    check(tcsetattr(STDIN_FILENO, TCSANOW, &input) == 0, "configure private serial input");
}

static int serial_read_line(char *line, size_t capacity)
{
    for (size_t length = 0; length < capacity; ++length) {
        char byte;
        ssize_t count;
        do {
            count = read(STDIN_FILENO, &byte, 1);
        } while (count == -1 && errno == EINTR);
        if (count != 1 || byte == '\0') {
            return -1;
        }
        if (byte == '\r' || byte == '\n') {
            line[length] = '\0';
            return (int)length;
        }
        line[length] = byte;
    }
    return -1;
}

static EVP_PKEY *provision_issuer(unsigned char *recording_key)
{
    char token[KEY_HEX_CAPACITY] = {0};
    FILE *credentials = fopen("/system/receipt-private/boot-token", "rb");
    check(credentials != NULL, "open one-time boot token");
    check(fread(token, 1, sizeof(token) - 1, credentials) == sizeof(token) - 1 &&
          fgetc(credentials) == EOF && !ferror(credentials), "read one-time boot token");
    fclose(credentials);

    struct termios original;
    serial_read_mode(&original);
    printf("RR_ISSUER_SETUP %s\n", token);
    fflush(stdout);
    char input[KEY_HEX_CAPACITY] = {0};
    const int length = serial_read_line(input, sizeof(input));
    EVP_PKEY *key = length == KEY_HEX_CAPACITY - 1 ? issuer_from_hex(input) : NULL;
    OPENSSL_cleanse(input, sizeof(input));
    int recording_key_loaded = 1;
    if (key && recording_key) {
        recording_key_loaded = serial_read_line(input, sizeof(input)) == KEY_HEX_CAPACITY - 1 &&
                               secret_from_hex(input, recording_key);
        OPENSSL_cleanse(input, sizeof(input));
    }
    check(tcsetattr(STDIN_FILENO, TCSANOW, &original) == 0, "restore private serial settings");
    check(key != NULL, "provision issuer in vault memory");
    check(recording_key_loaded, "provision sealed recording key in vault memory");
    return key;
}

static int consent(const char *receipt, const char *issuer, const struct receipt_coverage *coverage)
{
    struct termios original;
    serial_read_mode(&original);
    if (issuer) {
        printf("RR_ISSUER %s\n", issuer);
    }
    if (coverage && (coverage->idle || coverage->moving)) {
        printf("RR_COVERAGE %u %u\n", coverage->idle, coverage->moving);
    }
    if (coverage && coverage->startup_excluded_ms >= 0) {
        printf("RR_STARTUP_WINDOW %d\n", coverage->startup_excluded_ms);
    }
    printf("RR_PREVIEW %s\n", receipt);
    fflush(stdout);
    char decision[24];
    const int length = serial_read_line(decision, sizeof(decision));
    check(tcsetattr(STDIN_FILENO, TCSANOW, &original) == 0, "restore private serial settings");
    return length == 5 && memcmp(decision, "share", 5) == 0;
}

int main(int argc, char **argv)
{
    if (argc == 4 && strcmp(argv[1], "vault") == 0) {
        const int mode = number(argv[3]);
        check(mode <= VAULT_OBD_BENCH, "valid vault mode");
        vault(argv[2], (enum vault_mode)mode);
        return 0;
    }
    if (argc == 10 && strcmp(argv[1], "export") == 0) {
        unsigned i = (unsigned)number(argv[6]);
        check(i < sizeof(cases) / sizeof(*cases), "valid case");
        exporter(number(argv[2]), number(argv[3]), number(argv[4]), number(argv[5]),
                 i, number(argv[7]), number(argv[8]), number(argv[9]));
        return 0;
    }
    const int bench = argc == 2 && strcmp(argv[1], "--review-obd-bench") == 0;
    const int request_bound = bench || (argc == 2 && strcmp(argv[1], "--review-request") == 0);
    const int signed_review = request_bound || (argc == 2 && strcmp(argv[1], "--review-signed") == 0);
    const int review = signed_review || (argc == 2 && strcmp(argv[1], "--review-import") == 0);
    check(review || (argc == 2 && strcmp(argv[1], "--approved-fixture-run") == 0),
          "select live review or the approved fixture run");
    setvbuf(stdout, NULL, _IOLBF, 0);
    struct utsname platform;
    check(uname(&platform) == 0, "identify guest");
    printf("RR_PLATFORM %s %s\n", platform.sysname, platform.release);

    char handoff[] = "/data/rr-XXXXXX";
    check(mkdtemp(handoff) != NULL, "create private runtime directory");
    char ready_path[96];
    snprintf(ready_path, sizeof(ready_path), "%s/ready", handoff);
    char vault_mode_arg[12];
    snprintf(vault_mode_arg, sizeof(vault_mode_arg), "%d",
             bench ? VAULT_OBD_BENCH : request_bound ? VAULT_REQUEST : signed_review ? VAULT_SIGNED :
             review ? VAULT_IMPORT : VAULT_FIXTURES);
    char *vault_args[] = {argv[0], "vault", ready_path, vault_mode_arg, NULL};
    const pid_t pid = start_role("receipt_vault_t", vault_args, 0, signed_review);
    FILE *address = NULL;
    int raw_channel = -1;
    const int attempts = signed_review ? 800 : 100;
    for (int attempt = 0; attempt < attempts; ++attempt) {
        address = fopen(ready_path, "r");
        if (address != NULL) {
            int found = fscanf(address, "%d", &raw_channel);
            fclose(address);
            if (found == 1) {
                break;
            }
        }
        struct timespec pause = {.tv_nsec = 10000000};
        nanosleep(&pause, NULL);
    }
    check(raw_channel != -1, "resolve vault address");
    unlink(ready_path);
    rmdir(handoff);
    const int raw = ConnectAttach(0, pid, raw_channel, _NTO_SIDE_CHANNEL, 0);
    check(raw >= 0, "authorized supervisor can attach");
    char body[ENVELOPE_CAPACITY];
    int share = 0;
    if (signed_review) {
        check(request(raw, READ_RAW, IMPORT_CASE, body) == -1 && errno == EACCES,
              "vault must withhold raw rows from the review process");
        puts("RR_LIVE_RAW_WITHHELD");
        check(request(raw, SIGN_RECEIPT, IMPORT_CASE, body) == -1 && errno == EACCES,
              "vault must withhold preapproval issuance");
        puts("RR_SIGN_WITHHELD approval_required");
        const int verdict = request(raw, REVIEW_SIGNED, IMPORT_CASE, body);
        if (verdict == -1 && (errno == EINVAL || errno == ENODEV || errno == EBADMSG)) {
            const int review_error = errno;
            request(raw, STOP_VAULT, 0, body);
            join(pid);
            puts(review_error == ENODEV ? "RR_INVALID adapter_unavailable" :
                 review_error == EBADMSG ? "RR_INVALID recording_authentication_failed" : "RR_INVALID recording_rejected");
            return EXIT_FAILURE;
        }
        check(verdict == 0 || verdict == 1, "vault completed signed review");
        share = verdict;
    } else if (review) {
        if (request(raw, EVALUATE, IMPORT_CASE, body) != 0) {
            request(raw, STOP_VAULT, 0, body);
            join(pid);
            puts("RR_INVALID recording_rejected");
            return EXIT_FAILURE;
        }
        share = consent(body, NULL, NULL);
    } else {
        check(request(raw, READ_RAW, 0, body) == 0 && strchr(body, ',') != NULL,
              "authorized supervisor can read an actual raw row");
        puts("RR_CONTROL authorized_raw_read");
    }

    const int downstream = ChannelCreate(0);
    check(downstream >= 0, "create receipt channel");
    char vpid[24], vchid[24], ppid[24], pchid[24], case_arg[24];
    snprintf(vpid, sizeof(vpid), "%d", pid);
    snprintf(vchid, sizeof(vchid), "%d", raw_channel);
    snprintf(ppid, sizeof(ppid), "%d", getpid());
    snprintf(pchid, sizeof(pchid), "%d", downstream);
    for (int run = review ? IMPORT_CASE : -1; run < (review ? IMPORT_CASE + 1 : FIXTURE_CASES); ++run) {
        const unsigned selected = run < 0 ? 0u : (unsigned)run;
        const int approved = review ? share : run >= 0;
        snprintf(case_arg, sizeof(case_arg), "%u", selected);
        char *args[] = {argv[0], "export", vpid, vchid, ppid, pchid, case_arg,
                        approved ? "1" : "0", signed_review ? "1" : "0", bench ? "1" : "0", NULL};
        pid_t child = start_role("receipt_export_t", args, 1, 0);
        struct request req;
        int rcvid = receive(downstream, child, &req, 1);
        if (!approved || req.command != GET_RECEIPT || req.case_id != selected) {
            check(MsgError(rcvid, EACCES) == 0, "return consent denial");
        } else {
            check(request(raw, signed_review ? SIGN_RECEIPT : EVALUATE, selected, body) == 0,
                  "compute approved recipe locally");
            check(MsgReply(rcvid, 0, body, sizeof(body)) == 0, "publish only the bounded receipt");
        }
        join(child);
    }
    if (signed_review) {
        check(request(raw, SIGN_RECEIPT, IMPORT_CASE, body) == -1 && errno == EACCES,
              "vault must withhold repeat issuance");
        puts("RR_SIGN_WITHHELD review_complete");
    }
    check(request(raw, STOP_VAULT, 0, body) == 0, "stop fixture vault");
    join(pid);
    ConnectDetach(raw);
    ChannelDestroy(downstream);
    puts("RR_DONE");
    return 0;
}
