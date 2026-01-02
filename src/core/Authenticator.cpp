#include <cstdint>
#include "Authenticator.hpp"

#include "./pam/Pam.hpp"
#include "./fprint/FprintDbus.hpp"

#include "../helpers/Memory.hpp"

#include <pwd.h>
#include <errno.h>
#include <algorithm>
#include <fstream>
#include <sys/resource.h>

using namespace Hyprauth;
using namespace Hyprutils::CLI;

/*
    AuthProviderToken's are used to identify an authentication provider.
    A token must be used to submit providerSuccess and providerFail.
    AuthProviderTokens should be randomly generated with `getAuthProviderToken`.
    Their randomization does not mean they necessarily provide a meaningful security barrier.
    Rather, they exist to make the authenticator harder to exploit when having some contstrained control. Just in case.
    For example in case somehow the socket fd for pam was accessible by an adverserial application,
    they would need to know this randomized AuthProviderToken to trigger `CAuthenticator.m_authEvents.success`.
*/
static AuthProviderToken getAuthProviderToken() {
    std::ifstream     rnd("/dev/urandom", std::ios::in | std::ios::binary);
    AuthProviderToken res;
    rnd.read(rc<char*>(&res), sizeof(res));
    return res;
}

SP<IAuthenticator> IAuthenticator::create(const SAuthenticatorCreationData& data) {
    g_auth = makeShared<CAuthenticator>(data);

#ifndef HYPRAUTH_DEBUG
    if (g_auth && !data.allowCoredump) {
        const struct rlimit LIM{.rlim_cur = 0, .rlim_max = 0};
        if (setrlimit(RLIMIT_CORE, &LIM))
            g_auth->log(LOG_WARN, "Failed set RLIMIT_CORE to 0 (to disable coredumps): {}", strerror(errno));
    }
#endif

    return g_auth;
};

SP<IAuthProvider> Hyprauth::createPamProvider(const SPamCreationData& data) {
    auto pam = makeShared<CPam>(data);

    return pam;
};

SP<IAuthProvider> Hyprauth::createFprintProvider(const SFprintCreationData& data) {
    auto fprint = makeShared<CFprintDbus>(data);

    return fprint;
};

CAuthenticator::CAuthenticator(const SAuthenticatorCreationData& data) : m_data(data) {
    if (data.pLogConnection) {
        m_logger = data.pLogConnection;
        m_logger->setName("hyprauth");
        TRACE(m_logger->setLogLevel(LOG_TRACE));
    }
}

void CAuthenticator::addProvider(SP<IAuthProvider> impl) {
    if (m_running || !impl || impl->m_kind == HYPRAUTH_PROVIDER_INVALID)
        return;

    impl->m_tok = getAuthProviderToken();
    m_impls.emplace_back(std::move(impl));
}

void CAuthenticator::start() {
    for (const auto& i : m_impls) {
        i->start();
    }

    m_running = true;
}

void CAuthenticator::submitInput(const std::string_view input) {
    for (const auto& i : m_impls) {
        if (i->m_sendInput)
            i->handleInput(input);
    }
}

WP<IAuthProvider> CAuthenticator::getProvider(AuthProviderToken tok) {
    for (const auto& i : m_impls) {
        if (i->m_tok == tok)
            return i;
    }

    return WP<IAuthProvider>{};
}

void CAuthenticator::terminate() {
    for (const auto& i : m_impls) {
        i->terminate();
    }
}

void CAuthenticator::providerPrompt(AuthProviderToken tok, const std::string& promptText) {
    std::lock_guard<std::mutex> lg(m_implEventMutex);

    auto provider = getProvider(tok);
    if (!provider)
        return;

    log(LOG_TRACE, "Prompt {}", promptText);

    m_events.prompt.emit(SAuthPromptData{.from = provider->m_kind, .promptText = promptText});
}

void CAuthenticator::providerFail(AuthProviderToken tok, const std::string& failText) {
    std::lock_guard<std::mutex> lg(m_implEventMutex);

    auto provider = getProvider(tok);
    if (!provider)
        return;

    log(LOG_TRACE, "Authentication fail text: {}", failText);

    m_events.fail.emit(SAuthFailData{.from = provider->m_kind, .failText = failText});
}

void CAuthenticator::providerSuccess(AuthProviderToken tok) {
    std::lock_guard<std::mutex> lg(m_implEventMutex);

    auto provider = getProvider(tok);
    if (!provider)
        return;

    log(LOG_TRACE, "Authentication successful!");

    m_events.success.emit(provider->m_kind);
}

const std::string& CAuthenticator::getUserName() {
    if (!m_data.userName.empty())
        return m_data.userName;

    const auto PWUID = getpwuid(getuid());
    if (!PWUID) {
        log(LOG_ERR, "Failed to get username (getpwuid). This may break authentication providers.");
        return m_data.userName;
    }

    m_data.userName = PWUID->pw_name;
    return m_data.userName;
}
