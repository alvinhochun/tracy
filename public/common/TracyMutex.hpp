#ifndef __TRACYMUTEX_HPP__
#define __TRACYMUTEX_HPP__

#if defined _MSC_VER

#  include <shared_mutex>

namespace tracy
{
using TracyMutex = std::shared_mutex;
}

#elif defined __3DS__

#include <3ds.h>

namespace tracy
{
class TracyMutex
{
    LightLock m_lock{};

public:
    TracyMutex() noexcept
    {
        LightLock_Init(&m_lock);
    }

    ~TracyMutex() noexcept
    {
    }

    TracyMutex( const TracyMutex& ) = delete;
    TracyMutex( TracyMutex&& ) = delete;

    TracyMutex& operator=(const TracyMutex&) = delete;
    TracyMutex& operator=(TracyMutex&&) = delete;

    void lock() noexcept
    {
        LightLock_Lock(&m_lock);
    }

    [[nodiscard]] bool try_lock() noexcept
    {
        return !LightLock_TryLock(&m_lock);
    }

    void unlock() noexcept
    {
        LightLock_Unlock(&m_lock);
    }

};
}

#else

#include <mutex>

namespace tracy
{
using TracyMutex = std::mutex;
}

#endif

#endif
