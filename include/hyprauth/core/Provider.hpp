#pragma once

#include <cstddef>
#include <string>

#include <hyprutils/memory/SharedPtr.hpp>

namespace Hyprauth {
    /*
        AuthProviderToken's are used to identify an authentication provider.
        A token must be used to submit providerSuccess and providerFail.
        AuthProviderTokens should be randomly generated with `getProviderAuthProviderToken`.
        Their randomization does not mean they necessarily provide a meaningful security barrier.
        Rather, they exist to make the authenticator harder to exploit when having some contstrained control. Just in case.
        For example in case somehow the socket fd for pam was accessible by an adverserial application,
        they would need to know this randomized AuthProviderToken to trigger `CAuthenticator.m_authEvents.success`.
    */
    using AuthProviderToken = uint64_t;
    AuthProviderToken getAuthProviderToken();

    class IAuthProvider {
      public:
        IAuthProvider(AuthProviderToken tok, bool sendInput = false) : m_tok(tok), m_sendInput(sendInput) {};

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

        AuthProviderToken m_tok       = 0;
        bool              m_sendInput = false;

        /*
            BUILT-IN PROVIDERS
        */
        struct SPamCreationData {
            explicit SPamCreationData();

            /* Name of pam module in /etc/pam.d/<moduleName>. */
            std::string module = "";
        };

        /*
            Create pam authentication provider.
        */
        static Hyprutils::Memory::CSharedPointer<IAuthProvider> createPamProvider(const SPamCreationData& data);

        struct SFprintCreationData {
            explicit SFprintCreationData();

            /*
               Number of unmatched fingerprint checks before the provider refuses to accept further scans
               What number makes sense here depends a bit on your sensor.
               Most touch sensors either have bad and unoffical libfprint or support.
               Some of those drivers scan and fail rapidly and because of that they may need a higher number.
            */
            size_t numTries = 3;

            /* Prompt message used when the device is ready */
            std::string readyPrompt = "(Scan fingerprint to unlock)";
        };

        /*
            Create fprint authentication provider. (Uses the dbus API from fprintd)
        */
        static Hyprutils::Memory::CSharedPointer<IAuthProvider> createFprintProvider(const SFprintCreationData& data);
    };
}
