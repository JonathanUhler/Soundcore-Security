/*
 * scprobe.c -- Goal 1 injection probe for the iOS Custom Dylib Monitor plan.
 *
 * This is the minimal decisive experiment from the plan's Problem Statement. It
 * is a passive, file backed, app signed dynamic library added to the Soundcore
 * bundle at re-sign time. It does nothing but announce that its constructor ran,
 * on a channel recoverable from a stock, non jailbroken device with no debugger
 * attached.
 *
 * If the re-signed app boots and this marker reaches the device log, then dyld
 * loaded a custom image into the process and the reinforcement SDK did not kill
 * the app for it. That result proves there is no load time library whitelist and
 * clears the one open question before the real reader dylib (Goal 2) is built.
 *
 * The library links only against libSystem. It uses os_log, which is delivered
 * to Apple's unified logging system and is readable with
 * `pymobiledevice3 syslog live` or `idevicesyslog`. No debugger, jailbreak, or
 * Frida agent is involved in the read, so nothing here mimics the footprint that
 * the SDK's memory and thread scans catch.
 */

#include <os/log.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <dlfcn.h>

/* A distinctive ASCII marker so the operator can grep the log stream. */
#define SCPROBE_MARKER "SCPROBE_HELLO_WORLD"

__attribute__((constructor))
static void scprobe_init(void) {
    /* Primary channel. Unified logging, recoverable over USB with
     * `pymobiledevice3 syslog live | grep SCPROBE_HELLO_WORLD`. A dedicated
     * subsystem makes the message easy to isolate, and OS_LOG_DEFAULT keeps a
     * copy at a level the syslog streamers always surface. */
    os_log_t log = os_log_create("com.soundcore.research", "probe");

    /* Resolve our own on disk path to confirm dyld mapped us as a file backed
     * image rather than the anonymous executable memory a Frida agent uses. */
    const char *self_path = "unknown";
    Dl_info info;
    if (dladdr((const void *)&scprobe_init, &info) != 0 && info.dli_fname != NULL) {
        self_path = info.dli_fname;
    }

    os_log(log, "%{public}s constructor ran in pid %d, image=%{public}s",
           SCPROBE_MARKER, getpid(), self_path);
    os_log(OS_LOG_DEFAULT, "%{public}s constructor ran (default log)", SCPROBE_MARKER);

    /* Secondary channel. Drop a marker file in the app sandbox tmp dir. This is
     * a fallback the operator can pull with house_arrest if the app exposes file
     * sharing. The write is best effort and its failure is harmless. */
    const char *tmp = getenv("TMPDIR");
    if (tmp != NULL) {
        char path[1024];
        int n = snprintf(path, sizeof(path), "%s/%s.txt", tmp, SCPROBE_MARKER);
        if (n > 0 && (size_t)n < sizeof(path)) {
            int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
            if (fd >= 0) {
                char line[256];
                int m = snprintf(line, sizeof(line),
                                 "%s constructor ran at %ld in pid %d\n",
                                 SCPROBE_MARKER, (long)time(NULL), getpid());
                if (m > 0) {
                    ssize_t w = write(fd, line, (size_t)m);
                    (void)w;
                }
                close(fd);
            }
        }
    }
}
