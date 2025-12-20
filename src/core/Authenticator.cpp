#include <cstdint>
#include "Authenticator.hpp"

#include "./pam/Pam.hpp"
#include "./fprint/FprintDbus.hpp"

#include "../helpers/Memory.hpp"

#include <pwd.h>
#include <algorithm>
#include <fstream>

using namespace Hyprauth;
using namespace Hyprutils::CLI;

IAuthenticator::SAuthenticatorCreationData::SAuthenticatorCreationData() = default;
IAuthProvider::SPamCreationData::SPamCreationData()                      = default;
IAuthProvider::SFprintCreationData::SFprintCreationData()                = default;

AuthProviderToken Hyprauth::getAuthProviderToken() {
    std::ifstream     rnd("/dev/urandom", std::ios::in | std::ios::binary);
    AuthProviderToken res;
    rnd.read(rc<char*>(&res), sizeof(res));
    return res;
}

SP<IAuthenticator> IAuthenticator::create(const IAuthenticator::SAuthenticatorCreationData& data) {
    g_auth = makeShared<CAuthenticator>(data);

    return g_auth;
};

SP<IAuthProvider> IAuthProvider::createPamProvider(const IAuthProvider::SPamCreationData& data) {
    auto pam = makeShared<CPam>(getAuthProviderToken(), data);

    return pam;
};

SP<IAuthProvider> IAuthProvider::createFprintProvider(const IAuthProvider::SFprintCreationData& data) {
    auto fprint = makeShared<CFprintDbus>(getAuthProviderToken(), data);

    return fprint;
};

CAuthenticator::CAuthenticator(const IAuthenticator::SAuthenticatorCreationData& data) : m_data(data) {
    if (data.pLogConnection) {
        m_logger = data.pLogConnection;
        m_logger->setName("hyprauth");
    }
}

void CAuthenticator::addProvider(SP<IAuthProvider> impl) {
    if (m_running || !impl || impl->m_tok == 0)
        return;

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

    if (!getProvider(tok))
        return;

    log(LOG_TRACE, "Prompt {}", promptText);

    m_events.prompt.emit(SAuthPromptData{.tok = tok, .promptText = promptText});
}

void CAuthenticator::providerFail(AuthProviderToken tok, const std::string& failText) {
    std::lock_guard<std::mutex> lg(m_implEventMutex);

    if (!getProvider(tok))
        return;

    log(LOG_TRACE, "Authentication fail {}", failText);

    m_events.fail.emit(SAuthFailData{.tok = tok, .failText = failText});
}

void CAuthenticator::providerSuccess(AuthProviderToken tok) {
    std::lock_guard<std::mutex> lg(m_implEventMutex);

    if (!getProvider(tok))
        return;

    log(LOG_TRACE, "Authentication successful!");

    m_events.success.emit(tok);
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
