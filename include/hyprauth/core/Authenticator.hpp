#pragma once

#include "Provider.hpp"

#include <string>

#include <hyprutils/memory/UniquePtr.hpp>
#include <hyprutils/memory/WeakPtr.hpp>
#include <hyprutils/signal/Signal.hpp>
#include <hyprutils/cli/Logger.hpp>

namespace Hyprauth {
    struct SAuthenticatorCreationData {
        Hyprutils::Memory::CSharedPointer<Hyprutils::CLI::CLoggerConnection> pLogConnection;

        /* Empty means currently active uid. */
        std::string userName = "";

        /*
            When hyprauth is built in release mode, it uses setrlimit to disable coredumps.
            Use this flag to disable this precaution.
        */
        bool allowCoredump = false;
    };

    class IAuthenticator {
      public:
        virtual ~IAuthenticator() = default;
        IAuthenticator()          = default;

        /*
            Create an authenticator.
            There can only be one authenticator per process: In case of another create(),
            it will fail.
        */
        static Hyprutils::Memory::CSharedPointer<IAuthenticator> create(const SAuthenticatorCreationData& data);

        /*
            Hyprauth supports running multiple authentication providers in parallel.
            All providers need to be added before start().
            Adding more than one provider with the same eAuthProvider (IAuthProvider::m_kind) is not supported.
        */
        virtual void addProvider(Hyprutils::Memory::CSharedPointer<IAuthProvider> impl) = 0;

        /*
            Start and terminate all providers that were added.
        */
        virtual void start()     = 0;
        virtual void terminate() = 0;

        /*
            Submit input. It's encouraged to use CPasswordBuffer for the input.
        */
        virtual void submitInput(const std::string_view input) = 0;

        struct SAuthPromptData {
            eAuthProvider     from;
            std::string       promptText;
        };

        struct SAuthFailData {
            eAuthProvider     from;
            std::string       failText;
        };

        struct SBusyData {
            eAuthProvider     from;
            bool              busy = false;
        };

        struct {
            /*
                Informs the library user about provider prompt texts.
            */
            Hyprutils::Signal::CSignalT<SAuthPromptData> prompt;

            /*
                Notification for a failed authentication attempt.
            */
            Hyprutils::Signal::CSignalT<SAuthFailData> fail;

            /*
                Indicates whether an authentication provider is busy.
                TODO: Add fprint busy events
            */
            Hyprutils::Signal::CSignalT<SBusyData> busy;

            /*
                The provided authentication provider authenticated successfully.
            */
            Hyprutils::Signal::CSignalT<eAuthProvider> success;
        } m_events;
    };
}
