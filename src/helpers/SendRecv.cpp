#include "SendRecv.hpp"
#include "../Macros.hpp"

#include <cerrno>
#include <unistd.h>
#include <hyprutils/memory/Casts.hpp>

using namespace Hyprutils::Memory;

bool Hyprauth::sendView(int fd, const std::string_view sv) {
    const char*  DATA    = sv.data();
    const size_t SIZE    = sv.size();
    size_t       written = 0;

    while (true) {
        ssize_t delta = write(fd, rc<const char*>(&SIZE) + written, sizeof(SIZE) - written);
        if (delta < 0) {
            if (errno == EINTR)
                continue;
            return false;
        }

        written += delta;
        if (written == sizeof(SIZE))
            break;

        RASSERT(written < sizeof(SIZE), "PANIC! sendView has bad logic for sending the size");
    }

    written = 0;
    while (true) {
        ssize_t delta = write(fd, DATA + written, SIZE - written);
        if (delta < 0) {
            if (errno == EINTR)
                continue;
            return false;
        }

        written += delta;
        if (written == SIZE)
            break;

        RASSERT(written < SIZE, "PANIC! sendView has bad logic");
    }

    return true;
}

bool Hyprauth::recvView(int fd, std::string& buf) {
    buf.clear();

    size_t size     = 0;
    size_t consumed = 0;
    while (true) {
        ssize_t delta = read(fd, rc<char*>(&size) + consumed, sizeof(size) - consumed);
        if (delta < 0) {
            if (errno == EINTR)
                continue;
            return false;
        }

        consumed += delta;
        if (consumed == sizeof(size))
            break;

        RASSERT(consumed < sizeof(size), "PANIC! recvView has bad logic for reading the size");
    }

    consumed = 0;
    char immediate[0x100];
    while (true) {
        ssize_t delta = read(fd, immediate, std::min(size - consumed, sizeof(immediate)));
        if (delta < 0) {
            if (errno == EINTR)
                continue;
            return false;
        }

        consumed += delta;
        buf += std::string_view{immediate, delta};
        if (consumed == size)
            break;

        RASSERT(consumed < size, "PANIC! recvView has bad logic");
    }

    return true;
}
