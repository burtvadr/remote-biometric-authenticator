/*
 * pam-test: drive a PAM service directly, without touching any real service's
 * configuration.
 *
 * The point is to load the module through libpam exactly as a login or sudo would,
 * so symbol resolution, entry-point naming, argument parsing and the result mapping
 * are all exercised for real. Nothing here modifies /etc/pam.d; it only reads a
 * service it is pointed at.
 *
 * Usage:
 *   pam-test <service> <user>
 *
 * Exit status:
 *   0  PAM_SUCCESS
 *   1  the stack returned a failure code (printed)
 *   2  usage or setup problem
 */

#define _GNU_SOURCE

#include <security/pam_appl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/*
 * A silent conversation. The device is the prompt, so the module must never ask the
 * terminal for anything. If some other stack entry does try to prompt, it receives
 * PAM_CONV_ERR and fails visibly rather than hanging the test.
 */
static int silent_conv(int n, const struct pam_message **msg,
                       struct pam_response **resp, void *data) {
    (void)n;
    (void)msg;
    (void)data;
    *resp = NULL;
    return PAM_CONV_ERR;
}

/* Only `conv` is portable; the remaining members vary by PAM implementation. */
static struct pam_conv conv = { .conv = silent_conv };

static const char *code_name(int code) {
    switch (code) {
    case PAM_SUCCESS: return "PAM_SUCCESS";
    case PAM_AUTH_ERR: return "PAM_AUTH_ERR";
    case PAM_CRED_INSUFFICIENT: return "PAM_CRED_INSUFFICIENT";
    case PAM_AUTHINFO_UNAVAIL: return "PAM_AUTHINFO_UNAVAIL";
    case PAM_PERM_DENIED: return "PAM_PERM_DENIED";
    case PAM_BUF_ERR: return "PAM_BUF_ERR";
    case PAM_ABORT: return "PAM_ABORT";
    case PAM_USER_UNKNOWN: return "PAM_USER_UNKNOWN";
    case PAM_MAXTRIES: return "PAM_MAXTRIES";
    default: return "PAM_OTHER";
    }
}

/*
 * Print the stack libpam will walk, from the same file libpam reads.
 *
 * This is not a substitute for observing the result, but it makes stack ordering
 * visible, which is the failure mode that locks users out: a module listed after a
 * `required` entry, or in the wrong phase, simply never gets a chance to succeed.
 */
static void print_stack(const char *service) {
    char path[512];
    snprintf(path, sizeof(path), "/etc/pam.d/%s", service);
    FILE *f = fopen(path, "r");
    if (!f) {
        printf("stack       : (%s not found)\n", path);
        return;
    }
    printf("stack       :\n");
    char line[512];
    while (fgets(line, sizeof(line), f)) {
        char *p = line;
        while (*p == ' ' || *p == '\t') p++;
        if (*p == '#' || *p == '\n' || *p == '\0') continue;
        char *nl = strchr(p, '\n');
        if (nl) *nl = '\0';
        printf("              %s\n", p);
    }
    fclose(f);
}

int main(int argc, char **argv) {
    if (argc < 3) {
        fprintf(stderr, "usage: %s <service> <user>\n", argv[0]);
        return 2;
    }
    const char *service = argv[1];
    const char *user = argv[2];

    pam_handle_t *pamh = NULL;
    int rc = pam_start(service, user, &conv, &pamh);
    if (rc != PAM_SUCCESS) {
        fprintf(stderr, "pam_start failed: %s\n", pam_strerror(pamh, rc));
        return 2;
    }

    printf("service     : %s\n", service);
    printf("user        : %s\n", user);
    print_stack(service);

    rc = pam_authenticate(pamh, 0);
    printf("authenticate: %s (%d)\n", code_name(rc), rc);

    /* pam_get_authtok() returns whether a token is now set, which shows whether the
     * stack fell through to another module. */
    const void *tok = NULL;
    int tokrc = pam_get_item(pamh, PAM_AUTHTOK, &tok);
    printf("authtok rc  : %s%s\n", code_name(tokrc),
           tok ? " (a credential was established)" : "");

    pam_end(pamh, rc);
    return rc == PAM_SUCCESS ? 0 : 1;
}