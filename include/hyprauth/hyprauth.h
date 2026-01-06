#pragma once

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef void*            hyprauth_authenticator_t;
typedef uint64_t         hyprauth_provider_t;
typedef int8_t           hyprauth_provider_enum_t;

hyprauth_authenticator_t hyprauth_create(const char* user_name, bool allow_coredump);
void                     hyprauth_destroy(hyprauth_authenticator_t auth);

typedef struct {
    const char* pam_module;
    bool        extend_user_creds;
} hyprauth_pam_options;

typedef struct {
    const char* ready_prompt;
    size_t      num_tries;
} hyprauth_fprint_options;

hyprauth_provider_t hyprauth_add_pam_provider(hyprauth_authenticator_t auth, hyprauth_pam_options opts);
hyprauth_provider_t hyprauth_add_fprint_provider(hyprauth_authenticator_t auth, hyprauth_fprint_options opts);

int                 hyprauth_provider_loop_fd(hyprauth_authenticator_t auth, hyprauth_provider_t provider);
bool                hyprauth_provider_dispatch(hyprauth_authenticator_t auth, hyprauth_provider_t provider);

void                hyprauth_start(hyprauth_authenticator_t auth);
void                hyprauth_terminate(hyprauth_authenticator_t auth);
void                hyprauth_submit_input(hyprauth_authenticator_t auth, const char* input);

typedef struct {
    void (*hyprauth_cb_prompt)(hyprauth_provider_enum_t provider, const char* promptText, void* data);
    void (*hyprauth_cb_fail)(hyprauth_provider_enum_t provider, const char* failText, void* data);
    void (*hyprauth_cb_busy)(hyprauth_provider_enum_t provider, bool busy, void* data);
    void (*hyprauth_cb_success)(hyprauth_provider_enum_t provider, void* data);
} hyprauth_callbacks;

void hyprauth_set_callbacks(hyprauth_authenticator_t auth, hyprauth_callbacks cbs, void* userData);

#ifdef __cplusplus
}
#endif
