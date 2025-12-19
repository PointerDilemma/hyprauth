#include <hyprauth/core/SecretBuffer.hpp>
#include <hyprutils/memory/Casts.hpp>

#include <sys/mman.h>

#include <cerrno>
#include <cstring>
#include <iostream>

#include "../Macros.hpp"

using namespace Hyprauth;
using namespace Hyprutils::Memory;

static char* mapSecretsBuffer(size_t capacity) {
    int flags = MAP_PRIVATE | MAP_ANONYMOUS;
#if defined(__OpenBSD__)
    flags |= MAP_CONCEAL;
#elif defined(__FreeBSD__) || defined(__DragonFly__)
    flags |= MAP_NOCORE;
#endif

    auto buffer = sc<char*>(mmap(0, capacity, PROT_READ | PROT_WRITE, flags, -1, 0));
    RASSERT(buffer && buffer != rc<void*>(-1), "Failed to map anonymous password buffer! Error: {}", strerror(errno));

    int ret = 0;
    for (int i = 0; i < 0x10; i++) {
        ret = mlock(buffer, capacity);
        if (ret == EAGAIN)
            continue;
        else
            break;
    }

    RASSERT(ret == 0, "Failed to mlock! Error: {}", strerror(errno));

#if not(defined(__FreeBSD__) || defined(__NetBSD__) || defined(__OpenBSD__) || defined(__DragonFly__))
    // Probably linux
    for (int i = 0; i < 0x10; i++) {
        ret = madvise(buffer, capacity, MADV_DONTDUMP | MADV_WIPEONFORK);
        if (ret == EAGAIN)
            continue;
        else
            break;
    }

    RASSERT(ret == 0, "Failed to madvise!");
#endif

    return buffer;
}

void Hyprauth::protectStdin() {
    const size_t SIZE = HYPRAUTH_SECRETBUFFER_DEFAULT_SIZE;

    if (auto buf = std::cin.rdbuf(); buf) {
        auto buffer = mapSecretsBuffer(SIZE);
        std::cin.rdbuf(buf->pubsetbuf(buffer, SIZE));
    }

    auto buffer = mapSecretsBuffer(SIZE);
    setbuffer(stdin, sc<char*>(buffer), SIZE);
}

CSecretBuffer::CSecretBuffer(size_t capacity) : m_capacity(capacity) {
    m_pool = mapSecretsBuffer(m_capacity);
}

CSecretBuffer::~CSecretBuffer() {
    munmap(m_pool, m_capacity);
    m_pool = nullptr;
}

std::string_view CSecretBuffer::view() const {
    return std::string_view(m_pool, m_size);
}

char* CSecretBuffer::c_str() const {
    return m_pool;
}

size_t CSecretBuffer::capacity() const {
    return m_capacity;
}

size_t CSecretBuffer::size() const {
    return m_size;
}

void CSecretBuffer::clear() {
    memset(m_pool, 0, m_size);
    m_size = 0;
}

bool CSecretBuffer::feed(std::string_view piece) {
    if (m_size + piece.size() + 1 > m_capacity)
        return false;

    memcpy(m_pool + m_size, piece.data(), piece.size());
    m_size += piece.size();
    *(m_pool + m_size) = '\x00';
    return true;
}

bool CSecretBuffer::voidFeed(size_t size) {
    if (m_size + size + 1 > m_capacity)
        return false;

    m_size += size;
    *(m_pool + m_size) = '\x00';
    return true;
}

bool Hyprauth::sendSecretBuffer(int fd, const std::string_view sv) {
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

        RASSERT(written < sizeof(SIZE), "PANIC! sendSecretBuffer has bad logic for sending the size");
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

        RASSERT(written < SIZE, "PANIC! sendSecretBuffer has bad logic");
    }

    return true;
}

bool Hyprauth::recvSecretBuffer(int fd, CSecretBuffer& buf) {
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

        RASSERT(consumed < sizeof(size), "PANIC! recvSecretBuffer has bad logic for reading the size");
    }

    if (size > buf.capacity())
        return false;

    consumed = 0;
    while (true) {
        ssize_t delta = read(fd, buf.c_str() + consumed, size - consumed);
        if (delta < 0) {
            if (errno == EINTR)
                continue;
            return false;
        }

        consumed += delta;
        buf.voidFeed(delta);
        if (consumed == size)
            break;

        RASSERT(consumed < size, "PANIC! recvSecretBuffer has bad logic");
    }

    return true;
}
