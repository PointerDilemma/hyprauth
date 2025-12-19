#pragma once

#include <cstddef>
#include <cstring>
#include <string_view>

namespace Hyprauth {
    constexpr const size_t HYPRAUTH_SECRETBUFFER_DEFAULT_SIZE = 0x1000;
    /*
        This can be used to make sure reading from stdin is not buffered on the heap,
        but in a buffer that is protected the same way that CSecretBuffer is. See below.

        Calling it will leak two pages of mmap'ed memory.
    */
    void protectStdin();

    /*
        Buffer for user secrets.

        This creates an anonymous memory mapping that is hopefully excluded from coredumps not swapped out.
        For coredump exclusion usually using the linux and bsd apis should be reliable.
        Though other projects that do this usually call it best-effort.

        It is still very much a good idea to check a coredump manually before uploading it to the internet.

        Use it for sensitive user input and avoid copying from the underlying buffer.
    */
    class CSecretBuffer {
      public:
        /*
           Capacity should be page-aligned.
        */
        CSecretBuffer(size_t capacity);
        ~CSecretBuffer();

        char*            c_str() const;
        std::string_view view() const;
        size_t           capacity() const;
        size_t           size() const;
        void             clear();

        /*
           Intended for feeding keysyms.
           Return false when piece doesn't fit.
        */
        bool feed(std::string_view piece);

        /*
           Increment size, add nullbyte without writing any data.
           Can be used when the buffer is written to used.
           Returns false when size doesn't fit.
        */
        bool voidFeed(size_t size);

      private:
        char*  m_pool     = nullptr;
        size_t m_capacity = 0;
        size_t m_size     = 0;
    };

    /*
        These are can be used to send CSecretBuffer over the wire.
        Message format: | m_size (size_t) | data (m_pool[0..m_size]) |
    */
    bool sendSecretBuffer(int fd, const std::string_view sv);
    bool recvSecretBuffer(int fd, CSecretBuffer&);
}
