#pragma once

#include <hyprauth/hyprauth.hpp>
#include "../helpers/Memory.hpp"
#include "../Macros.hpp"

namespace Hyprauth {
    class CAuthenticator : public IAuthenticator {
      public:
        CAuthenticator(const SAuthenticatorCreationData& data);

        virtual void      addProvider(SP<IAuthProvider> impl);

        virtual void      start();
        virtual void      terminate();

        virtual void      submitInput(const std::string_view input);

        WP<IAuthProvider> getProvider(uint64_t id);

        // Provider events
        void               providerPrompt(uint64_t id, const std::string& promptText);
        void               providerFail(uint64_t id, const std::string& failText);
        void               providerBusy(uint64_t id, bool busy);
        void               providerSuccess(uint64_t id);

        const std::string& getUserName();

        template <typename... Args>
        inline constexpr void log(Hyprutils::CLI::eLogLevel level, std::format_string<Args...> fmt, Args&&... args) {
            if (m_logger)
                m_logger->log(level, fmt, std::forward<decltype(args)>(args)...);
            else {
                switch (level) {
                    case Hyprutils::CLI::LOG_DEBUG: std::cout << "[ha] debug: "; break;
                    case Hyprutils::CLI::LOG_WARN: std::cout << "[ha] warn: "; break;
                    case Hyprutils::CLI::LOG_ERR: std::cout << "[ha] err: "; break;
                    case Hyprutils::CLI::LOG_CRIT: std::cout << "[ha] critical: "; break;
                    case Hyprutils::CLI::LOG_TRACE: {
                        if (!Env::isTrace())
                            return;
                        std::cout << "[ha] trace: ";
                    } break;
                }
                std::cout << std::vformat(fmt.get(), std::make_format_args(args...)) << std::endl;
            }
        }

      private:
        SAuthenticatorCreationData            m_data;

        SP<Hyprutils::CLI::CLoggerConnection> m_logger;

        std::mutex                            m_implEventMutex;
        std::vector<SP<IAuthProvider>>        m_impls;

        bool                                  m_running = false;
    };

    inline Hyprutils::Memory::CSharedPointer<CAuthenticator> g_auth;
}
