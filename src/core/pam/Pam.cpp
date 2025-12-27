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

CPam::CPam(AuthProviderToken tok, IAuthProvider::SPamCreationData data) : IAuthProvider(tok, true), m_data(data) {
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
                g_auth->providerPrompt(m_tok, msg);
            });
            m_wire.conversation->setPamTextInfo([](const char* msg) { g_auth->log(LOG_DEBUG, "(PAM S) text info: {}", msg); });
            m_wire.conversation->setPamErrorMsg([this](const char* msg) {
                g_auth->log(LOG_ERR, "(PAM S) error: {}", msg);
                // Targets this log from pam_faillock: https://github.com/linux-pam/linux-pam/blob/fa3295e079dbbc241906f29bde5fb71bc4172771/modules/pam_faillock/pam_faillock.c#L417
                if (const auto MSG = std::string_view(msg); MSG.contains("left to unlock"))
                    m_failTextOverride = MSG;
            });
            m_wire.conversation->setFail([this](const char* token_bytes, const char* msg) {
                g_auth->log(LOG_TRACE, "(PAM S) Recieved failure");
                AuthProviderToken tok = *rc<const AuthProviderToken*>(token_bytes);
                if (!m_failTextOverride.empty()) {
                    g_auth->providerFail(tok, m_failTextOverride);
                    m_failTextOverride.clear();
                } else
                    g_auth->providerFail(tok, msg);

                m_wire.conversation->sendStart();
            });
            m_wire.conversation->setSuccess([this](const char* token_bytes) {
                g_auth->log(LOG_TRACE, "(PAM S) Recieved success");
                AuthProviderToken tok = *rc<const AuthProviderToken*>(token_bytes);
                g_auth->providerSuccess(tok);

                m_wire.manager->sendDestroy();
            });

            m_wire.conversation->setOnDestroy([this]() {
                g_auth->log(LOG_TRACE, "(PAM S) Conversation destroyed");

                m_wire.conversation.reset();
            });

            m_wire.sock->dispatchEvents(false);
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
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sockFds))
        return;

    m_chldPid = fork();
    if (m_chldPid < 0) {
        close(sockFds[0]);
        close(sockFds[1]);
        g_auth->log(LOG_CRIT, "(PAM S) Failed to fork: {}", strerror(errno));
    } else if (m_chldPid == 0) {
        // CHILD (Pam client)
        close(sockFds[0]);
        auto client = makeUnique<CPamClient>(sockFds[1], m_tok, m_data);

        g_auth->log(LOG_TRACE, "(PAM C) Client entering eventloop!");
        while (client->m_wire.sock->dispatchEvents(true))
            ;

        exit(1); // This is an error. We exit directly within the destoy event.
    } else {
        // PARENT (Authenticator)
        close(sockFds[1]);
        m_wire.sockFd = sockFds[0];
        m_wire.sock   = Hyprwire::IServerSocket::open();
        m_wire.sock->addImplementation(m_wire.spec);

        pollfd pfd = {.fd = sockFds[0], .events = POLLIN, .revents = 0};
        RASSERT(poll(&pfd, 1, 1000) > 0 && (pfd.revents & POLLIN), "Failed to wait for client hello");
        RASSERT(m_wire.sock->addClient(sockFds[0]) != nullptr, "Failed to add client fd");

        g_auth->log(LOG_TRACE, "(PAM S) Init done!");
    }
}

void CPam::handleInput(const std::string_view input) {
    if (!m_inputPipe.isValid())
        return;

    if (!sendView(m_inputPipe.get(), input))
        g_auth->log(LOG_ERR, "(PAM S) Failed to send input to the pam client!");
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

    dispatchEvents();

    if (m_chldPid > 0) {
        int status = 0;
        waitpid(m_chldPid, &status, 0);
        if (status != 0)
            g_auth->log(LOG_ERR, "(PAM S) Client unexpected client status: {}", status);

        m_chldPid = 0;
    }

    m_wire.sock.reset();
}
