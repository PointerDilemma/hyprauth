#pragma once

#include <cstddef>
#include <string>

#include <hyprutils/memory/SharedPtr.hpp>

namespace Hyprauth {
    enum eAuthProvider: int8_t {
        HYPRAUTH_PROVIDER_INVALID = -1,
        HYPRAUTH_PROVIDER_PAM,
        HYPRAUTH_PROVIDER_FPRINT,
    };

    using AuthProviderToken = uint64_t;

    class IAuthProvider {
      public:
        IAuthProvider(eAuthProvider kind, bool sendInput = false) : m_kind(kind), m_sendInput(sendInput) {};

        virtual ~IAuthProvider() = default;

        /*
            Start and terminate is called by the authenticator.
        */
        virtual void start()     = 0;
        virtual void terminate() = 0;

        /*
            Submit input to the implementation.
            An implementation must not block the current thread with this call.
        */
        virtual void handleInput(const std::string_view input) = 0;

        /*
            Synchronously dispatch auth provider events. Usually called when the loop fd has active events.
            May return false in case of a failure.
        */
        virtual bool dispatchEvents() = 0;

        /*
           Use this function to integrate the provider into an eventloop.
           FD is owned by the provider. Don't close it.
           In case something failed or this function is called before init (called via IAuthenticator::start),
           it may return -1;
        */
        virtual int       getLoopFd() = 0;

        eAuthProvider     m_kind = HYPRAUTH_PROVIDER_INVALID;
        AuthProviderToken m_tok       = 0; // set by CAuthenticator::addProvider
        bool              m_sendInput = false;
    };

    /*
        BUILT-IN PROVIDERS
    */
    struct SPamCreationData {
        SPamCreationData() = default;

        /* Name of pam module in /etc/pam.d/<moduleName>. */
        std::string module = "";

        /*
           When enabled, call pam_setcred with PAM_REFRESH_CRED after successful authentication.
           This will extend the lifetime of existing credentials for the user's session.
        */
        bool extendUserCreds = false;
    };

    /*
        Create pam authentication provider.
    */
    Hyprutils::Memory::CSharedPointer<IAuthProvider> createPamProvider(const SPamCreationData& data);

    struct SFprintCreationData {
        SFprintCreationData() = default;

        /*
           Number of unmatched fingerprint checks before the provider refuses to accept further scans.
           What number makes sense here depends a bit on your sensor.
           Lot's of touch drivers (mostly unoffical libfprint) scan and fail rapidly because they are implemented poorly.
           Those may need a higher limit here.
        */
        size_t numTries = 3;

        /* Prompt message used when the device is ready */
        std::string readyPrompt = "(Scan fingerprint to unlock)";
    };

    /*
        Create fprint authentication provider. (Uses the dbus API from fprintd)
    */
    Hyprutils::Memory::CSharedPointer<IAuthProvider> createFprintProvider(const SFprintCreationData& data);
}
