#pragma once

#include <hyprauth/hyprauth.hpp>
#include <hyprauth/core/SecretBuffer.hpp>

#include <hyprutils/memory/SharedPtr.hpp>
#include <hyprutils/memory/UniquePtr.hpp>
#include <hyprutils/os/FileDescriptor.hpp>

#include "generated/hyprauth_pam_v1-client.hpp"

namespace Hyprauth {
    constexpr const uint32_t HYPRAUTH_PAM_PROTOCOL_VERSION = 1;

    class CPamClient {
      public:
        ~CPamClient() = default;
        CPamClient(int sockFd, AuthProviderToken tok, const IAuthProvider::SPamCreationData& data);

        struct {
            Hyprutils::Memory::CSharedPointer<CCHyprauthPamV1Impl>              spec;
            Hyprutils::Memory::CSharedPointer<Hyprwire::IClientSocket>          sock;
            Hyprutils::Memory::CUniquePointer<CCPamConversationManagerV1Object> manager;
            Hyprutils::Memory::CUniquePointer<CCPamConversationV1Object>        conversation;
        } m_wire;

        AuthProviderToken               m_tok;
        IAuthProvider::SPamCreationData m_data;

        Hyprutils::OS::CFileDescriptor  m_responsePipe;
        CSecretBuffer                   m_responseData;

        void                            start();
        void                            auth();
    };
}
