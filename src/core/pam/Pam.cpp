#include "Pam.hpp"
#include "PamClient.hpp"

#include "../Authenticator.hpp"
#include "../../helpers/Memory.hpp"
#include "../../helpers/SendRecv.hpp"
#include "../../Macros.hpp"

#include <hyprwire/hyprwire.hpp>
#include <hyprutils/os/Process.hpp>

#include <filesystem>
#include <cerrno>
#include <csignal>
#include <cstring>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/poll.h>
#include <sys/wait.h>
#include <cstring>
#include <print>

using namespace Hyprauth;
using namespace Hyprutils::CLI;
using namespace Hyprutils::OS;

CPam::CPam(SPamCreationData data) : IAuthProvider(HYPRAUTH_PROVIDER_PAM, true), m_data(data) {
    if (!std::filesystem::exists(std::filesystem::path("/etc/pam.d/") / m_data.module)) {
        g_auth->log(LOG_WARN, R"((PAM S) Module "/etc/pam.d/{}" does not exist! Falling back to "/etc/pam.d/su")", m_data.module);
        m_data.module = "su";
    }

    m_wire.spec = makeShared<CHyprauthPamV1Impl>(HYPRAUTH_PAM_PROTOCOL_VERSION, [this](SP<Hyprwire::IObject> obj) {
        m_wire.manager = makeUnique<CPamConversationManagerV1Object>(std::move(obj));

        m_wire.manager->setMakeConversation([this](uint32_t seq) {
            g_auth->log(LOG_TRACE, "(PAM S) Client is here to conversate!");
            m_wire.conversation =
                makeUnique<CPamConversationV1Object>(m_wire.sock->createObject(m_wire.manager->getObject()->client(), m_wire.manager->getObject(), "pam_conversation_v1", seq));

            m_wire.conversation->setPamPrompt([this](const char* msg) {
                g_auth->log(LOG_TRACE, "(PAM S) prompt: {}", msg);
                setBusy(false);
                g_auth->providerPrompt(m_id, msg);
            });
            m_wire.conversation->setPamTextInfo([](const char* msg) { g_auth->log(LOG_DEBUG, "(PAM S) text info: {}", msg); });
            m_wire.conversation->setPamErrorMsg([this](const char* msg) {
                g_auth->log(LOG_ERR, "(PAM S) error: {}", msg);
                // Targets this log from pam_faillock: https://github.com/linux-pam/linux-pam/blob/fa3295e079dbbc241906f29bde5fb71bc4172771/modules/pam_faillock/pam_faillock.c#L417
                if (const auto MSG = std::string_view(msg); MSG.contains("left to unlock"))
                    m_failTextOverride = MSG;
            });
            m_wire.conversation->setFail([this](uint32_t id_lower, uint32_t id_upper, const char* msg) {
                g_auth->log(LOG_TRACE, "(PAM S) Recieved failure");
                setBusy(false);
                const auto ID = PROVIDER_ID(id_lower, id_upper);
                if (!m_failTextOverride.empty()) {
                    g_auth->providerFail(ID, m_failTextOverride);
                    m_failTextOverride.clear();
                } else
                    g_auth->providerFail(ID, msg);

                m_wire.conversation->sendStart();
            });
            m_wire.conversation->setSuccess([this](uint32_t id_lower, uint32_t id_upper) {
                g_auth->log(LOG_TRACE, "(PAM S) Recieved success");
                setBusy(false);
                g_auth->providerSuccess(PROVIDER_ID(id_lower, id_upper));

                m_wire.manager->sendDestroy();
            });

            m_wire.conversation->setOnDestroy([this]() {
                g_auth->log(LOG_TRACE, "(PAM S) Conversation destroyed");

                m_wire.conversation.reset();
            });

            m_wire.conversation->sendStart();
        });

        m_wire.manager->setOnDestroy([this]() {
            g_auth->log(LOG_DEBUG, "(PAM S) Manager destroyed");
            m_inputPipe.reset();
            m_wire.manager.reset();
        });

        // First thing when client is ready -> send the channel fd!
        int responseFds[2];
        RASSERT(!pipe(responseFds), "Couldn't create pam response channel pipes :(");
        m_inputPipe = CFileDescriptor(responseFds[1]);
        m_wire.manager->sendResponseChannel(responseFds[0]);
        close(responseFds[0]);
    });
}

CPam::~CPam() {
    ;
}

void CPam::start() {
    int sockFds[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sockFds)) {
        g_auth->log(LOG_ERR, "(PAM S) Error calling socketpair: {}", strerror(errno));
        return;
    }

    m_chldPid = fork();
    if (m_chldPid < 0) {
        close(sockFds[0]);
        close(sockFds[1]);
        g_auth->log(LOG_CRIT, "(PAM S) Failed to fork: {}", strerror(errno));
    } else if (m_chldPid == 0) {
        // CHILD (Pam client)
        close(sockFds[0]);

        // Block all blockable signals
        sigset_t set;
        sigfillset(&set);
        sigprocmask(SIG_BLOCK, &set, NULL);

        auto client = makeUnique<CPamClient>(sockFds[1], m_id, m_data);

        g_auth->log(LOG_TRACE, "(PAM C) Client entering eventloop!");
        while (client->m_wire.sock->dispatchEvents(true))
            ;

        _exit(1);
    } else {
        // PARENT (Authenticator)
        close(sockFds[1]);
        m_wire.sockFd = sockFds[0];
        m_wire.sock   = Hyprwire::IServerSocket::open();
        m_wire.sock->addImplementation(m_wire.spec);

        RASSERT(m_wire.sock->addClient(sockFds[0]) != nullptr, "Failed to add client fd");

        while (!m_inputPipe.isValid())
            m_wire.sock->dispatchEvents(true);

        g_auth->log(LOG_TRACE, "(PAM S) Init done!");
    }
}

void CPam::handleInput(const std::string_view input) {
    if (!m_inputPipe.isValid())
        return;

    if (!sendView(m_inputPipe.get(), input))
        g_auth->log(LOG_ERR, "(PAM S) Failed to send input to the pam client!");

    setBusy(true);
}

int CPam::getLoopFd() {
    if (m_wire.sock)
        return m_wire.sock->extractLoopFD();

    return -2;
}

bool CPam::dispatchEvents() {
    if (m_wire.sock)
        return m_wire.sock->dispatchEvents(false);

    return false;
}

void CPam::terminate() {
    if (m_wire.manager)
        m_wire.manager->sendDestroy();

    if (m_inputPipe.isValid())
        sendView(m_inputPipe.get(), std::string_view{"", 0});

    if (m_wire.sock) {
        m_wire.sock->removeClient(m_wire.sockFd);
        m_wire.sock.reset();
    }

    if (m_chldPid > 0) {
        int status = 0;
        waitpid(m_chldPid, &status, 0);
        if (status != 0)
            g_auth->log(LOG_ERR, "(PAM S) Client unexpected client status: {}", status);

        m_chldPid = 0;
    }
}

void CPam::setBusy(bool busy) {
    if (m_busy == busy)
        return;

    m_busy = busy;
    g_auth->providerBusy(m_id, busy);
}
