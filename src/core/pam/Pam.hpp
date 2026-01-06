#pragma once

#include <hyprauth/hyprauth.hpp>
#include <hyprwire/hyprwire.hpp>

#include <optional>
#include <string>
#include <mutex>
#include <condition_variable>
#include <functional>
#include <thread>

#include <hyprutils/memory/WeakPtr.hpp>
#include <hyprutils/memory/UniquePtr.hpp>
#include <hyprutils/os/FileDescriptor.hpp>

#include "generated/hyprauth_pam_v1-server.hpp"

namespace Hyprauth {
    class CPam : public IAuthProvider {
      public:
        CPam(SPamCreationData data);

        virtual ~CPam();
        virtual void                    start();
        virtual void                    handleInput(const std::string_view input);
        virtual bool                    dispatchEvents();
        virtual int                     getLoopFd();
        virtual void                    terminate();

        SPamCreationData m_data;

      private:
        void setBusy(bool busy);

        struct {
            Hyprutils::Memory::CSharedPointer<CHyprauthPamV1Impl>              spec;
            Hyprutils::Memory::CSharedPointer<Hyprwire::IServerSocket>         sock;
            Hyprutils::Memory::CUniquePointer<CPamConversationManagerV1Object> manager;
            Hyprutils::Memory::CUniquePointer<CPamConversationV1Object>        conversation;
            int                                                                sockFd = -1; // we keep this just to remove the client later
        } m_wire;

        Hyprutils::OS::CFileDescriptor m_inputPipe;
        std::string                    m_failTextOverride = "";

        bool                           m_busy = false;
        pid_t                          m_chldPid = -1;
    };
}
