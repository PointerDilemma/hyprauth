#include "PamClient.hpp"
#include "../Authenticator.hpp"
#include "../../helpers/SendRecv.hpp"

#include <security/pam_appl.h>
#if __has_include(<security/pam_misc.h>)
#include <security/pam_misc.h>
#endif

using namespace Hyprauth;
using namespace Hyprutils::CLI;
using namespace Hyprutils::OS;

CPamClient::CPamClient(int sockFd, AuthProviderToken tok, const SPamCreationData& data) : m_tok(tok), m_data(data) {
    m_wire.spec = makeShared<CCHyprauthPamV1Impl>(HYPRAUTH_PAM_PROTOCOL_VERSION);
    m_wire.sock = Hyprwire::IClientSocket::open(sockFd);
    if (!m_wire.sock) {
        g_auth->log(LOG_ERR, "(PAM C) Error attempting to open the pam client socket!");
        exit(1);
    }

    m_wire.sock->addImplementation(m_wire.spec);
    if (!m_wire.sock->waitForHandshake()) {
        g_auth->log(LOG_ERR, "(PAM C) Error waiting for conversation handshake!");
        exit(1);
    }

    const auto SPEC = m_wire.sock->getSpec(m_wire.spec->protocol()->specName());
    RASSERT(SPEC, "(PAM C) Internal protocol error (unsupported version?)")

    m_wire.manager = makeUnique<CCPamConversationManagerV1Object>(m_wire.sock->bindProtocol(m_wire.spec->protocol(), HYPRAUTH_PAM_PROTOCOL_VERSION));
    m_wire.manager->setDestroy([this]() {
        g_auth->log(LOG_TRACE, "(PAM C) Server send destroy! Will exit.");
        exit(0);
    });

    m_wire.manager->setResponseChannel([this](int fd) {
        g_auth->log(LOG_TRACE, "(PAM C) Got responsePipeFd {}", fd);
        m_responsePipe = CFileDescriptor(fd);

        m_wire.conversation = makeUnique<CCPamConversationV1Object>(m_wire.manager->sendMakeConversation());
        m_wire.conversation->setStart([this]() { auth(); });
    });
}

int conv(int num_msg, const struct pam_message** msg, struct pam_response** resp, void* appdata_ptr) {
    const auto           CLIENT   = (CPamClient*)appdata_ptr;
    struct pam_response* pamReply = (struct pam_response*)calloc(num_msg, sizeof(struct pam_response));

    std::string          prompt   = "";
    std::string          response = "";

    for (int i = 0; i < num_msg; ++i) {
        switch (msg[i]->msg_style) {
            case PAM_PROMPT_ECHO_OFF:
            case PAM_PROMPT_ECHO_ON: {
                const auto PROMPT        = std::string(msg[i]->msg);
                const auto PROMPTCHANGED = PROMPT != prompt;

                // Some pam configurations ask for the password twice for whatever reason (Fedora su for example)
                // When the prompt is the same as the last one, I guess our answer can be the same.
                if (PROMPTCHANGED) {
                    prompt = PROMPT;
                    CLIENT->m_wire.conversation->sendPamPrompt(PROMPT.data());
                    CLIENT->m_wire.sock->roundtrip();
                    g_auth->log(LOG_TRACE, "(PAM C) waiting for password!");

                    if (!recvView(CLIENT->m_responsePipe.get(), response))
                        g_auth->log(LOG_ERR, "(PAM C) failed to recieve password input!");

                    CLIENT->m_wire.sock->dispatchEvents(false);
                }

                pamReply[i].resp = strdup(response.c_str());
            } break;
            case PAM_ERROR_MSG: CLIENT->m_wire.conversation->sendPamErrorMsg(msg[i]->msg); break;
            case PAM_TEXT_INFO: CLIENT->m_wire.conversation->sendPamTextInfo(msg[i]->msg); break;
        }
    }

    *resp = pamReply;
    return PAM_SUCCESS;
}

void CPamClient::auth() {
    const auto     USERNAME = g_auth->getUserName();

    const pam_conv localConv            = {.conv = conv, .appdata_ptr = this};
    pam_handle_t*  handle               = nullptr;
    char           tokenBytes[9]        = {0};
    *rc<AuthProviderToken*>(tokenBytes) = m_tok;

    int ret = PAM_SUCCESS;
    ret     = pam_start(m_data.module.c_str(), USERNAME.c_str(), &localConv, &handle);

    if (ret != PAM_SUCCESS) {
        m_wire.conversation->sendFail(tokenBytes, std::format("pam_start failed for module {}", m_data.module).c_str());
        return;
    }

    ret                = pam_authenticate(handle, 0);
    const char* PAMERR = pam_strerror(handle, ret);

    if (ret == PAM_SUCCESS && m_data.extendUserCreds) {
        ret = pam_setcred(handle, PAM_REFRESH_CRED);
        if (ret != PAM_SUCCESS)
            g_auth->log(LOG_WARN, "Failed to extend user credentials: {}", pam_strerror(handle, ret));
    }

    pam_end(handle, ret);
    handle = nullptr;

    if (ret != PAM_SUCCESS)
        m_wire.conversation->sendFail(tokenBytes, (ret != PAM_AUTH_ERR && PAMERR) ? PAMERR : "Authentication failed");
    else
        m_wire.conversation->sendSuccess(tokenBytes);
}
