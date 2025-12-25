#include <hyprauth/hyprauth.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <sys/poll.h>

void handle_prompt(hyprauth_provider_t provider, const char* promptText, void* userData) {
    printf("Prompt text: %s\n", promptText);
}

void handle_fail(hyprauth_provider_t provider, const char* failText, void* userData) {
    printf("Fail text: %s\n", failText);
}

void handle_success(hyprauth_provider_t provider, void* userData) {
    printf("Success!\n");
    *(bool*)userData = true;
}

static hyprauth_callbacks auth_callbacks = {
    .hyprauth_cb_prompt  = handle_prompt,
    .hyprauth_cb_fail    = handle_fail,
    .hyprauth_cb_success = handle_success,
};

int main() {
    hyprauth_authenticator_t auth_handle = hyprauth_create("");

    hyprauth_provider_t      pam_provider    = hyprauth_add_pam_provider(auth_handle, (hyprauth_pam_options){"su", true});
    hyprauth_provider_t      fprint_provider = hyprauth_add_fprint_provider(auth_handle, (hyprauth_fprint_options){NULL, 3});

    bool                     success = false;
    hyprauth_set_callbacks(auth_handle, auth_callbacks, (void*)&success);

    hyprauth_start(auth_handle);

    int    pam_fd    = hyprauth_provider_loop_fd(auth_handle, pam_provider);
    int    fprint_fd = hyprauth_provider_loop_fd(auth_handle, fprint_provider);

    char*  line = NULL;
    size_t size = 0;
    while (!success) {
        struct pollfd pfds[3] = {
            {.fd = STDIN_FILENO, .events = POLLIN, .revents = 0}, {.fd = pam_fd, .events = POLLIN, .revents = 0}, {.fd = fprint_fd, .events = POLLIN, .revents = 0}};
        if (poll(pfds, (fprint_fd > 0) ? 3 : 2, -1) < 1)
            continue;

        if (pfds[0].revents & POLLIN) {
            ssize_t nread = getline(&line, &size, stdin); // no good when not line buffered
            if (!line || nread <= 0)
                continue;

            line[nread - 1] = 0;
            if (strcmp(line, "exit") == 0) { // test async terminate
                hyprauth_terminate(auth_handle);
                break;
            }

            hyprauth_submit_input(auth_handle, line);
            free(line);
            line = NULL;
        }

        bool good = true;
        if (pfds[1].revents & POLLIN)
            good &= hyprauth_provider_dispatch(auth_handle, pam_provider);

        if (fprint_fd > 0 && pfds[2].revents & POLLIN)
            good &= hyprauth_provider_dispatch(auth_handle, fprint_provider);

        if (!good)
            break;
    }

    hyprauth_terminate(auth_handle);
}
