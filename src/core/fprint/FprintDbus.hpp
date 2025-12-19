#pragma once

#include <hyprauth/hyprauth.hpp>

#include <sdbus-c++/sdbus-c++.h>
#include <optional>
#include <string>

namespace Hyprauth {
    class CFprintDbus : public IAuthProvider {
      public:
        CFprintDbus(AuthProviderToken tok, IAuthProvider::SFprintCreationData data);

        virtual ~CFprintDbus() = default;
        virtual void                        start();
        virtual void                        handleInput(const std::string_view input);
        virtual bool                        dispatchEvents();
        virtual int                         getLoopFd();
        virtual void                        terminate();

        std::shared_ptr<sdbus::IConnection> getConnection();

      private:
        AuthProviderToken                  m_tok;
        IAuthProvider::SFprintCreationData m_data;

        struct SDBUSState {
            std::shared_ptr<sdbus::IConnection> connection;
            std::unique_ptr<sdbus::IProxy>      login;
            std::unique_ptr<sdbus::IProxy>      device;

            bool                                verifying     = false;
            bool                                deviceClaimed = false;
            bool                                sleeping      = false;
        } m_dbusState;

        size_t m_numTry = 0;

        void   handleVerifyStatus(const std::string& result, const bool done);

        bool   createDeviceProxy();
        void   claimDevice();
        void   startVerify();
        void   stopVerify();
        void   releaseDevice();
    };
}
