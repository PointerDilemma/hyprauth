#include "FprintDbus.hpp"
#include "../Authenticator.hpp"

#include <memory>
#include <unistd.h>
#include <pwd.h>

#include <cstring>

using namespace Hyprauth;
using namespace Hyprutils::CLI;

static const auto FPRINT              = sdbus::ServiceName{"net.reactivated.Fprint"};
static const auto DEVICE              = sdbus::ServiceName{"net.reactivated.Fprint.Device"};
static const auto MANAGER             = sdbus::ServiceName{"net.reactivated.Fprint.Manager"};
static const auto LOG_DEBUGIN_MANAGER = sdbus::ServiceName{"org.freedesktop.login1.Manager"};

enum MatchResult {
    MATCH_INVALID = 0,
    MATCH_NO_MATCH,
    MATCH_MATCHED,
    MATCH_RETRY,
    MATCH_SWIPE_TOO_SHORT,
    MATCH_FINGER_NOT_CENTERED,
    MATCH_REMOVE_AND_RETRY,
    MATCH_DISCONNECTED,
    MATCH_UNKNOWN_ERROR,
};

static std::map<std::string, MatchResult> s_mapStringToTestType = {{"verify-no-match", MATCH_NO_MATCH},
                                                                   {"verify-match", MATCH_MATCHED},
                                                                   {"verify-retry-scan", MATCH_RETRY},
                                                                   {"verify-swipe-too-short", MATCH_SWIPE_TOO_SHORT},
                                                                   {"verify-finger-not-centered", MATCH_FINGER_NOT_CENTERED},
                                                                   {"verify-remove-and-retry", MATCH_REMOVE_AND_RETRY},
                                                                   {"verify-disconnected", MATCH_DISCONNECTED},
                                                                   {"verify-unknown-error", MATCH_UNKNOWN_ERROR}};

CFprintDbus::CFprintDbus(AuthProviderToken tok, IAuthProvider::SFprintCreationData data) : IAuthProvider(tok, false), m_tok(tok), m_data(data) {
    ;
}

void CFprintDbus::start() {
    try {
        m_dbusState.connection = sdbus::createSystemBusConnection();
        m_dbusState.login      = sdbus::createProxy(*m_dbusState.connection, sdbus::ServiceName{"org.freedesktop.login1"}, sdbus::ObjectPath{"/org/freedesktop/login1"});
    } catch (sdbus::Error& e) {
        g_auth->log(LOG_ERR, "(FP) Failed to setup dbus ({})", e.what());
        m_dbusState.connection.reset();
        return;
    }

    m_dbusState.login->getPropertyAsync("PreparingForSleep")
        .onInterface(LOG_DEBUGIN_MANAGER)
        .uponReplyInvoke([this](std::optional<sdbus::Error> e, sdbus::Variant preparingForSleep) {
            if (e) {
                g_auth->log(LOG_WARN, "(FP) Failed getting value for PreparingForSleep: {}", e->what());
                return;
            }
            m_dbusState.sleeping = preparingForSleep.get<bool>();
            // When entering sleep, the wake signal will trigger startVerify().
            if (m_dbusState.sleeping)
                return;

            startVerify();
        });
    m_dbusState.login->uponSignal("PrepareForSleep").onInterface(LOG_DEBUGIN_MANAGER).call([this](bool start) {
        g_auth->log(LOG_DEBUG, "(FP) PrepareForSleep (start: {})", start);
        m_dbusState.sleeping = start;
        if (!m_dbusState.sleeping && !m_dbusState.verifying)
            startVerify();
    });
}

void CFprintDbus::handleInput(const std::string_view input) {
    ;
}

bool CFprintDbus::dispatchEvents() {
    if (!m_dbusState.connection) {
        g_auth->log(LOG_ERR, "(FP) Dispatch events without a connection!");
        return false;
    }

    size_t iter = 0;
    while (m_dbusState.connection->processPendingEvent() && ++iter < 0x100)
        ;
    return true;
}

int CFprintDbus::getLoopFd() {
    if (!m_dbusState.connection)
        return -1;

    return m_dbusState.connection->getEventLoopPollData().fd;
}

void CFprintDbus::terminate() {
    releaseDevice();
}

std::shared_ptr<sdbus::IConnection> CFprintDbus::getConnection() {
    return m_dbusState.connection;
}

bool CFprintDbus::createDeviceProxy() {
    auto              proxy = sdbus::createProxy(*m_dbusState.connection, FPRINT, sdbus::ObjectPath{"/net/reactivated/Fprint/Manager"});

    sdbus::ObjectPath path;
    try {
        proxy->callMethod("GetDefaultDevice").onInterface(MANAGER).storeResultsTo(path);
    } catch (sdbus::Error& e) {
        g_auth->log(LOG_WARN, "(FP) Couldn't connect to Fprint service ({})", e.what());
        return false;
    }
    g_auth->log(LOG_DEBUG, "(FP) Using device path {}", path.c_str());
    m_dbusState.device = sdbus::createProxy(*m_dbusState.connection, FPRINT, path);

    m_dbusState.device->uponSignal("VerifyFingerSelected").onInterface(DEVICE).call([](const std::string& finger) {
        g_auth->log(LOG_DEBUG, "(FP) Finger(s) selected: {}", finger);
    });
    m_dbusState.device->uponSignal("VerifyStatus").onInterface(DEVICE).call([this](const std::string& result, const bool done) { handleVerifyStatus(result, done); });

    m_dbusState.device->uponSignal("PropertiesChanged")
        .onInterface("org.freedesktop.DBus.Properties")
        .call([this](const std::string& interface, const std::map<std::string, sdbus::Variant>& properties) {
            if (interface != DEVICE || !m_dbusState.deviceClaimed)
                return;

            try {
                const bool PRESENT = properties.at("finger-present").get<bool>();
                g_auth->log(LOG_TRACE, "(FP) Finger present on the sensor: {}", PRESENT);

                // This property change could be useful in the future. Right now we don't do anything with it
            } catch (std::out_of_range& e) {}
        });

    return true;
}

void CFprintDbus::handleVerifyStatus(const std::string& result, bool done) {
    g_auth->log(LOG_TRACE, "(FP) Handling status {} (done: {})", result, done);

    if (m_dbusState.sleeping) {
        stopVerify();
        g_auth->log(LOG_WARN, "(FP) Device suspended");
        return;
    }

    if (done)
        stopVerify();

    const auto RESULT = s_mapStringToTestType[result];
    switch (RESULT) {
        case MATCH_INVALID: g_auth->log(LOG_WARN, "(FP) unknown status: {}", result); break;
        case MATCH_NO_MATCH: g_auth->providerFail(m_tok, "Fingerprint did not match"); break;
        case MATCH_UNKNOWN_ERROR: g_auth->providerFail(m_tok, "Fingerprint auth disabled (unknown error)"); break;
        case MATCH_MATCHED:
            if (m_numTry <= m_data.numTries)
                g_auth->providerSuccess(m_tok);
            break;
        case MATCH_RETRY: g_auth->providerPrompt(m_tok, "Please retry fingerprint scan"); break;
        case MATCH_SWIPE_TOO_SHORT: g_auth->providerPrompt(m_tok, "Swipe too short - try again"); break;
        case MATCH_FINGER_NOT_CENTERED: g_auth->providerPrompt(m_tok, "Finger not centered - try again"); break;
        case MATCH_REMOVE_AND_RETRY: g_auth->providerPrompt(m_tok, "Remove your finger and try again"); break;
        case MATCH_DISCONNECTED: g_auth->providerPrompt(m_tok, "Fingerprint device disconnected"); break;
    }

    if (done && RESULT != MATCH_MATCHED)
        startVerify();
}

void CFprintDbus::claimDevice() {
    const auto USERNAME = g_auth->getUserName();
    m_dbusState.device->callMethodAsync("Claim").onInterface(DEVICE).withArguments(USERNAME).uponReplyInvoke([this](std::optional<sdbus::Error> e) {
        if (e)
            g_auth->log(LOG_WARN, "(FP) could not claim device, {}", e->what());
        else {
            g_auth->log(LOG_DEBUG, "(FP) claimed device");
            m_dbusState.deviceClaimed = true;
            startVerify();
        }
    });
}

void CFprintDbus::startVerify() {
    if (m_numTry >= m_data.numTries) {
        g_auth->log(LOG_WARN, "(FP) fingerprint disabled after {} tries", m_numTry);
        return;
    }

    if (!m_dbusState.device) {
        if (!createDeviceProxy())
            return;

        claimDevice();
        return;
    }
    const auto FINGER = "any"; // Any finger.
    m_dbusState.device->callMethodAsync("VerifyStart").onInterface(DEVICE).withArguments(FINGER).uponReplyInvoke([this](std::optional<sdbus::Error> e) {
        if (e) {
            g_auth->log(LOG_WARN, "(FP) could not start verifying, {}", e->what());
            g_auth->providerFail(m_tok, "Fingerprint auth disabled (failed to restart)");
            return;
        }

        m_numTry++;
        m_dbusState.verifying = true;
        g_auth->providerPrompt(m_tok, m_data.readyPrompt);
    });
}

void CFprintDbus::stopVerify() {
    if (!m_dbusState.device || !m_dbusState.verifying)
        return;
    try {
        m_dbusState.device->callMethod("VerifyStop").onInterface(DEVICE);
    } catch (sdbus::Error& e) {
        g_auth->log(LOG_WARN, "(FP) could not stop verifying, {}", e.what());
        return;
    }
    g_auth->log(LOG_DEBUG, "(FP) stopped verification");
}

void CFprintDbus::releaseDevice() {
    if (!m_dbusState.device || !m_dbusState.deviceClaimed)
        return;
    try {
        m_dbusState.device->callMethod("Release").onInterface(DEVICE);
    } catch (sdbus::Error& e) {
        g_auth->log(LOG_WARN, "(FP) could not release device, {}", e.what());
        return;
    }
    m_dbusState.deviceClaimed = false;
    g_auth->log(LOG_DEBUG, "(FP) released device");
}
