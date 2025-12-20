#include "PamClient.hpp"
#include "../Authenticator.hpp"

#include <hyprauth/core/SecretBuffer.hpp>

#include <security/pam_appl.h>
#if __has_include(<security/pam_misc.h>)
#include <security/pam_misc.h>
#endif

using namespace Hyprauth;
using namespace Hyprutils::CLI;
using namespace Hyprutils::OS;

CPamClient::CPamClient(int sockFd, AuthProviderToken tok, const IAuthProvider::SPamCreationData& data) :
    m_tok(tok), m_data(data), m_responseData(HYPRAUTH_SECRETBUFFER_DEFAULT_SIZE) {
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

    m_wire.com = makeUnique<CCPamConversationV1Object>(m_wire.sock->bindProtocol(m_wire.spec->protocol(), HYPRAUTH_PAM_PROTOCOL_VERSION));
    m_wire.com->setStart([this]() {
        if (m_conversationActive) {
            m_wire.com->getObject()->error(HYPRAUTH_PAM_V1_INTERNAL_ERROR_CLIENT, "Already started");
            return;
        }

        auth();
    });
    m_wire.com->setFinished([this]() {
        g_auth->log(LOG_TRACE, "(PAM C) recieved finished! Will exit.");
        m_exit = true;
        m_wire.com.reset();
        // I didn't find a fast way to exit the pam conversation.
        // Returning from the conversation with PAM_CONV_ERR seems to employ a fail delay.
        exit(0);
    });
    m_wire.com->setPamResponseChannel([this](int fd) {
        g_auth->log(LOG_TRACE, "(PAM C) Got responsePipeFd {}", fd);
        m_responsePipe = CFileDescriptor(fd);
    });

    m_wire.com->sendClientReady();
    m_wire.sock->roundtrip();

    RASSERT(m_responsePipe.isValid(), "(PAM C) No response channel pipe after roundtrip?");
}

int conv(int num_msg, const struct pam_message** msg, struct pam_response** resp, void* appdata_ptr) {
    const auto           CLIENT   = (CPamClient*)appdata_ptr;
    struct pam_response* pamReply = (struct pam_response*)calloc(num_msg, sizeof(struct pam_response));

    std::string          prompt = "";

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
                    CLIENT->m_wire.com->sendPamPrompt(PROMPT.data());
                    CLIENT->m_wire.sock->roundtrip();
                    g_auth->log(LOG_TRACE, "(PAM C) waiting for password!");
                    if (!recvSecretBuffer(CLIENT->m_responsePipe.get(), CLIENT->m_responseData))
                        g_auth->log(LOG_ERR, "(PAM C) failed to recieve password input!");

                    CLIENT->m_wire.sock->dispatchEvents(false);
                }

                pamReply[i].resp = strdup(CLIENT->m_responseData.c_str());
            } break;
            case PAM_ERROR_MSG: CLIENT->m_wire.com->sendPamErrorMsg(msg[i]->msg); break;
            case PAM_TEXT_INFO: CLIENT->m_wire.com->sendPamTextInfo(msg[i]->msg); break;
        }
    }

    *resp = pamReply;
    return PAM_SUCCESS;
}

void CPamClient::auth() {
    m_conversationActive    = true;
    const auto     USERNAME = g_auth->getUserName();

    const pam_conv localConv            = {.conv = conv, .appdata_ptr = this};
    pam_handle_t*  handle               = nullptr;
    char           tokenBytes[9]        = {0};
    *rc<AuthProviderToken*>(tokenBytes) = m_tok;

    int ret = PAM_SUCCESS;
    ret     = pam_start(m_data.module.c_str(), USERNAME.c_str(), &localConv, &handle);

    if (ret != PAM_SUCCESS) {
        m_wire.com->sendFail(tokenBytes, std::format("pam_start failed for module {}", m_data.module).c_str());
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
        m_wire.com->sendFail(tokenBytes, (ret != PAM_AUTH_ERR && PAMERR) ? PAMERR : "Authentication failed");
    else {
        m_wire.com->sendSuccess(tokenBytes);
    }

    m_conversationActive = false;
}
