#include <hyprauth/core/SecretBuffer.hpp>
#include <sys/socket.h>
#include "../src/Macros.hpp"

#include <gtest/gtest.h>
#include <cerrno>
#include <cstring>

using namespace Hyprauth;

TEST(SECRETBUFFER, boundChecks) {
    CSecretBuffer buf(HYPRAUTH_SECRETBUFFER_DEFAULT_SIZE);
    EXPECT_EQ(buf.capacity(), HYPRAUTH_SECRETBUFFER_DEFAULT_SIZE);

    // doesn't fit
    EXPECT_EQ(buf.feed(std::string(HYPRAUTH_SECRETBUFFER_DEFAULT_SIZE, 'A')), false);
    EXPECT_EQ(buf.view(), std::string_view(""));

    // doesn't fit
    EXPECT_EQ(buf.voidFeed(HYPRAUTH_SECRETBUFFER_DEFAULT_SIZE), false);
    EXPECT_EQ(buf.view(), std::string_view(""));

    const auto FILL = std::string(HYPRAUTH_SECRETBUFFER_DEFAULT_SIZE - 1, 'A');
    EXPECT_EQ(buf.feed(FILL), true);
    EXPECT_EQ(buf.view(), FILL);
    EXPECT_EQ(buf.size(), FILL.size());

    // full
    EXPECT_EQ(buf.feed("B"), false);
    EXPECT_EQ(buf.view(), FILL);
    EXPECT_EQ(*(buf.c_str() + FILL.size()), '\x00');

    // full
    EXPECT_EQ(buf.voidFeed(1), false);
    EXPECT_EQ(buf.view(), FILL);
    EXPECT_EQ(*(buf.c_str() + FILL.size()), '\x00');
}

TEST(SECRETBUFFER, nullTermination) {
    CSecretBuffer buf(HYPRAUTH_SECRETBUFFER_DEFAULT_SIZE);
    EXPECT_EQ(*(buf.c_str()), '\x00');

    EXPECT_EQ(buf.feed("A"), true);
    EXPECT_EQ(*(buf.c_str() + 1), '\x00');
    EXPECT_EQ(buf.size(), 1);

    buf.clear();
    EXPECT_EQ(*(buf.c_str()), '\x00');
    EXPECT_EQ(buf.size(), 0);

    EXPECT_EQ(buf.feed("AA"), true);
    EXPECT_EQ(*(buf.c_str() + 2), '\x00');
    EXPECT_EQ(buf.size(), 2);

    EXPECT_EQ(buf.voidFeed(2), true);
    EXPECT_EQ(*(buf.c_str() + 4), '\x00');
    EXPECT_EQ(buf.size(), 4);
}

TEST(SECRETBUFFER, sendRecv) {
    int pipes[2];
    EXPECT_EQ(pipe(pipes), 0);

    CSecretBuffer buf(HYPRAUTH_SECRETBUFFER_DEFAULT_SIZE);
    CSecretBuffer recvBuf(HYPRAUTH_SECRETBUFFER_DEFAULT_SIZE);
    const auto    FILL = std::string(HYPRAUTH_SECRETBUFFER_DEFAULT_SIZE - 1, 'A');
    EXPECT_EQ(buf.feed(FILL), true);

    sendSecretBuffer(pipes[1], buf.view());
    recvSecretBuffer(pipes[0], recvBuf);

    EXPECT_EQ(buf.view(), FILL);
    EXPECT_EQ(buf.view(), recvBuf.view());
    EXPECT_EQ(*(recvBuf.c_str() + FILL.size()), '\x00');

    buf.clear();

    sendSecretBuffer(pipes[1], buf.view());
    recvSecretBuffer(pipes[0], recvBuf);

    EXPECT_EQ(buf.view(), std::string_view(""));
    EXPECT_EQ(buf.view(), recvBuf.view());
    EXPECT_EQ(*(recvBuf.c_str()), '\x00');

    EXPECT_EQ(buf.feed(std::string_view("A")), true);

    sendSecretBuffer(pipes[1], buf.view());
    recvSecretBuffer(pipes[0], recvBuf);

    EXPECT_EQ(buf.view(), std::string_view("A"));
    EXPECT_EQ(buf.view(), recvBuf.view());
    EXPECT_EQ(*(recvBuf.c_str() + 1), '\x00');

    EXPECT_EQ(buf.feed(std::string_view("BB")), true);

    sendSecretBuffer(pipes[1], buf.view());
    recvSecretBuffer(pipes[0], recvBuf);

    EXPECT_EQ(buf.view(), std::string_view("ABB"));
    EXPECT_EQ(buf.view(), recvBuf.view());
    EXPECT_EQ(*(recvBuf.c_str() + 3), '\x00');

    EXPECT_EQ(buf.feed(std::string_view("\n\x01\x02")), true);

    sendSecretBuffer(pipes[1], buf.view());
    recvSecretBuffer(pipes[0], recvBuf);

    EXPECT_EQ(buf.view(), std::string_view("ABB\n\x01\x02"));
    EXPECT_EQ(buf.view(), recvBuf.view());
    EXPECT_EQ(*(recvBuf.c_str() + 6), '\x00');
}
