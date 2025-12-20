#include <hyprauth/hyprauth.h>
#include <hyprauth/hyprauth.hpp>

#include "./core/Authenticator.hpp"

#include <cstring>
#include <string_view>

using namespace Hyprauth;
using namespace Hyprutils::Memory;

hyprauth_authenticator_t hyprauth_create(const char* user_name) {
    IAuthenticator::SAuthenticatorCreationData data;
    data.userName = user_name;

    auto authenticator = IAuthenticator::create(data);
    if (!authenticator)
        return nullptr;

    return g_auth.get();
}

void hyprauth_destroy(hyprauth_authenticator_t auth) {
    if (g_auth.get() != auth)
        return;

    g_auth.reset();
}

hyprauth_provider_t hyprauth_add_pam_provider(hyprauth_authenticator_t auth, hyprauth_pam_options opts) {
    if (g_auth.get() != auth)
        return 0;

    IAuthProvider::SPamCreationData data;
    data.module = (opts.pam_module) ? opts.pam_module : "";
    data.extendUserCreds = opts.extend_user_creds;

    auto pam    = IAuthProvider::createPamProvider(data);
    if (!pam)
        return 0;

    g_auth->addProvider(pam);
    return pam->m_tok;
};

hyprauth_provider_t hyprauth_add_fprint_provider(hyprauth_authenticator_t auth, hyprauth_fprint_options opts) {
    if (g_auth.get() != auth)
        return 0;

    IAuthProvider::SFprintCreationData data;
    data.readyPrompt = (opts.ready_prompt) ? opts.ready_prompt : "";
    data.numTries = opts.num_tries;

    auto fprint   = IAuthProvider::createFprintProvider(data);
    if (!fprint)
        return 0;

    g_auth->addProvider(fprint);
    return fprint->m_tok;
};

int hyprauth_provider_loop_fd(hyprauth_authenticator_t auth, hyprauth_provider_t provider) {
    auto providerImpl = g_auth->getProvider(provider);
    if (!provider)
        return -1;

    return providerImpl->getLoopFd();
}

bool hyprauth_provider_dispatch(hyprauth_authenticator_t auth, hyprauth_provider_t provider) {
    auto providerImpl = g_auth->getProvider(provider);
    if (!provider)
        return false;

    return providerImpl->dispatchEvents();
}

void hyprauth_start(hyprauth_authenticator_t auth) {
    if (g_auth.get() != auth)
        return;

    g_auth->start();
}

void hyprauth_terminate(hyprauth_authenticator_t auth) {
    if (g_auth.get() != auth)
        return;

    g_auth->terminate();
}

void hyprauth_submit_input(hyprauth_authenticator_t auth, const char* input) {
    if (g_auth.get() != auth)
        return;

    const size_t INPUT_SIZE = strlen(input);
    g_auth->submitInput(std::string_view{input, INPUT_SIZE});
}

void hyprauth_set_callbacks(hyprauth_authenticator_t auth, hyprauth_callbacks cbs, void* userData) {
    if (g_auth.get() != auth)
        return;

    g_auth->m_events.prompt.listenStatic([userData, fun = cbs.hyprauth_cb_prompt](IAuthenticator::SAuthPromptData data) { fun(data.tok, data.promptText.c_str(), userData); });
    g_auth->m_events.fail.listenStatic([userData, fun = cbs.hyprauth_cb_fail](IAuthenticator::SAuthFailData data) { fun(data.tok, data.failText.c_str(), userData); });
    g_auth->m_events.success.listenStatic([userData, fun = cbs.hyprauth_cb_success](AuthProviderToken tok) { fun(tok, userData); });
}
