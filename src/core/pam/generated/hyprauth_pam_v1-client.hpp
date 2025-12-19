// Generated with hyprwire-scanner 0.2.1. Made with vaxry's keyboard and ❤️.
// hyprauth_pam_v1

/*
 This protocol's authors' copyright notice is:


    Hyprauth contributors. #TODO:
  
*/

#pragma once

#include <functional>
#include "hyprauth_pam_v1-spec.hpp"

class CCPamConversationV1Object {
  public:
    CCPamConversationV1Object(Hyprutils::Memory::CSharedPointer<Hyprwire::IObject>&& object);
    ~CCPamConversationV1Object();

    Hyprutils::Memory::CSharedPointer<Hyprwire::IObject> getObject() {
        return m_object.lock();
    }

    void sendClientReady();

    void sendSuccess(const char* token_bytes);

    void sendFail(const char* token_bytes, const char* message);

    void sendPamPrompt(const char* message);

    void sendPamTextInfo(const char* message);

    void sendPamErrorMsg(const char* message);

    void setStart(std::function<void()>&& fn);

    void setFinished(std::function<void()>&& fn);

    void setPamResponseChannel(std::function<void(int)>&& fn);

  private:
    struct {
        std::function<void()>    start;
        std::function<void()>    finished;
        std::function<void(int)> pam_response_channel;
    } m_listeners;

    Hyprutils::Memory::CWeakPointer<Hyprwire::IObject> m_object;
};

class CCHyprauthPamV1Impl : public Hyprwire::IProtocolClientImplementation {
  public:
    CCHyprauthPamV1Impl(uint32_t version);
    virtual ~CCHyprauthPamV1Impl() = default;

    virtual Hyprutils::Memory::CSharedPointer<Hyprwire::IProtocolSpec>                            protocol();

    virtual std::vector<Hyprutils::Memory::CSharedPointer<Hyprwire::SClientObjectImplementation>> implementation();

  private:
    uint32_t m_version = 0;
};
