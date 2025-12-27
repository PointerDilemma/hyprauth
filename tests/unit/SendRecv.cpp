#include "../src/helpers/SendRecv.hpp"

#include <gtest/gtest.h>
#include <cerrno>
#include <cstring>

using namespace Hyprauth;

TEST(HELPERS, sendRecv) {
    int pipes[2];
    EXPECT_EQ(pipe(pipes), 0);

    std::string ref{0x100, 'A'};
    std::string buf = "";

    sendView(pipes[1], ref);
    recvView(pipes[0], buf);

    EXPECT_EQ(ref, buf);

    ref.clear();

    sendView(pipes[1], ref);
    recvView(pipes[0], buf);

    EXPECT_EQ(ref, "");
    EXPECT_EQ(ref, buf);

    ref = "A";

    sendView(pipes[1], ref);
    recvView(pipes[0], buf);

    ref = "BB";

    sendView(pipes[1], ref);
    recvView(pipes[0], buf);

    EXPECT_EQ(ref, buf);

    ref = "\n\x01\x02";

    sendView(pipes[1], ref);
    recvView(pipes[0], buf);

    EXPECT_EQ(ref, buf);
}
