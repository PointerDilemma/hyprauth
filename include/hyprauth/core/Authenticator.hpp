#pragma once

#include "Provider.hpp"

#include <string>

#include <hyprutils/memory/UniquePtr.hpp>
#include <hyprutils/memory/WeakPtr.hpp>
#include <hyprutils/signal/Signal.hpp>
#include <hyprutils/cli/Logger.hpp>

namespace Hyprauth {
    class IAuthenticator {
      public:
        virtual ~IAuthenticator() = default;
        IAuthenticator()          = default;

        struct SAuthenticatorCreationData {
            explicit SAuthenticatorCreationData();

            Hyprutils::Memory::CSharedPointer<Hyprutils::CLI::CLoggerConnection> pLogConnection;

            /* Empty means currently active uid. */
            std::string userName = "";
        };

        /*
            Create an authenticator.
            There can only be one authenticator per process: In case of another create(),
            it will fail.
        */
        static Hyprutils::Memory::CSharedPointer<IAuthenticator> create(const SAuthenticatorCreationData& data);

        /*
            Hyprauth supports running multiple authentication providers in parallel.
            All providers need to be added before start().
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
            AuthProviderToken tok;
            std::string       promptText;
        };

        struct SAuthFailData {
            AuthProviderToken tok;
            std::string       failText;
        };

        struct {
            /*
                One of the authentication providers sends a prompt text.
                The token identifies which one.
            */
            Hyprutils::Signal::CSignalT<SAuthPromptData> prompt;

            /*
                One of the authentication providers had an authentication failure.
            */
            Hyprutils::Signal::CSignalT<SAuthFailData> fail;

            /*
                One of the authentication providers authenticated successfully.
            */
            Hyprutils::Signal::CSignalT<AuthProviderToken> success;

        } m_events;
    };
}
