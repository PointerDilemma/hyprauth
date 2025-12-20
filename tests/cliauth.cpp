#include <hyprauth/core/SecretBuffer.hpp>
#include <hyprauth/hyprauth.hpp>
#include <hyprutils/cli/Logger.hpp>
#include <print>
#include <iostream>
#include <sys/poll.h>
#include <unistd.h>
#include <termios.h>

using namespace Hyprutils::Memory;
using namespace Hyprutils::CLI;
using namespace Hyprauth;

#define SP CSharedPointer
#define WP CWeakPointer

void terminalEcho(bool enable = false) {
    termios tios;
    tcgetattr(STDIN_FILENO, &tios);

    if (enable)
        tios.c_lflag |= ECHO;
    else
        tios.c_lflag &= ~ECHO;

    tcsetattr(STDIN_FILENO, TCSANOW, &tios);
}

int main(int argc, char** argv, char** envp) {
    CSecretBuffer passBuf(0x1000);

    protectStdin();
    terminalEcho(false);

    Hyprutils::CLI::CLogger                    logger;

    IAuthenticator::SAuthenticatorCreationData data;
    data.pLogConnection                           = makeShared<CLoggerConnection>(logger);
    auto                            authenticator = IAuthenticator::create(data);

    IAuthProvider::SPamCreationData pamData;
    pamData.module          = "su";
    pamData.extendUserCreds = true;
    auto pam                = IAuthProvider::createPamProvider(pamData);

    auto fprint = IAuthProvider::createFprintProvider(IAuthProvider::SFprintCreationData{});

    authenticator->addProvider(pam);
    authenticator->addProvider(fprint);

    uint32_t fails   = 0;
    bool     success = false;

    authenticator->m_events.prompt.listenStatic([&logger, &authenticator](IAuthenticator::SAuthPromptData data) { //
        logger.log(LOG_DEBUG, "Prompt text: {}", data.promptText);
    });

    authenticator->m_events.fail.listenStatic([&fails, &logger, &authenticator](IAuthenticator::SAuthFailData data) { //
        logger.log(LOG_WARN, "Fail text: {}, total fails: {}", data.failText, ++fails);
    });

    authenticator->m_events.success.listenStatic([&logger, &authenticator, &success](AuthProviderToken tok) {
        logger.log(LOG_DEBUG, "Success!");
        success = true;
    });

    authenticator->start();
    logger.log(LOG_DEBUG, "Authentication started!");

    int         pamFd    = pam->getLoopFd();
    int         fprintFd = (fprint) ? fprint->getLoopFd() : -1;

    std::string line;
    while (!success) {
        pollfd pfds[3] = {{.fd = STDIN_FILENO, .events = POLLIN, .revents = 0}, {.fd = pamFd, .events = POLLIN, .revents = 0}, {.fd = fprintFd, .events = POLLIN, .revents = 0}};
        if (poll(pfds, (fprint) ? 3 : 2, -1) < 1)
            continue;

        if (pfds[0].revents & POLLIN) {
            std::getline(std::cin, line); // not good when input is not line buffered
            if (line == "exit") {         // test async terminate
                authenticator->terminate();
                break;
            }
            if (line == "ThisStringShouldOnlyInTheELF(RO)DataSectionOfTheCoredump")
                std::abort();

            passBuf.feed(line);
            line.clear();
            authenticator->submitInput(passBuf.view());
            passBuf.clear();
        }

        bool good = false;
        if (pfds[1].revents & POLLIN)
            good &= pam->dispatchEvents();

        if (fprint && pfds[2].revents & POLLIN)
            good &= fprint->dispatchEvents();

        if (good)
            break;
    }

    authenticator->terminate();

    terminalEcho(true);

    return 0;
}
