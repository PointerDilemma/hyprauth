// Generated with hyprwire-scanner 0.2.1. Made with vaxry's keyboard and ❤️.
// hyprauth_pam_v1

/*
 This protocol's authors' copyright notice is:


    Hyprauth contributors. #TODO:
  
*/

#pragma once

#include <functional>
#include "hyprauth_pam_v1-spec.hpp"

class CPamConversationV1Object {
  public:
    CPamConversationV1Object(Hyprutils::Memory::CSharedPointer<Hyprwire::IObject>&& object);
    ~CPamConversationV1Object();

    Hyprutils::Memory::CSharedPointer<Hyprwire::IObject> getObject() {
        return m_object.lock();
    }

    void setOnDestroy(std::function<void()>&& fn) {
        m_object->setOnDestroy(std::move(fn));
    }

    void error(uint32_t code, const std::string_view& sv) {
        m_object->error(code, sv);
    }

    void sendStart();

    void sendFinished();

    void sendPamResponseChannel(int messageFd);

    void setClientReady(std::function<void()>&& fn);

    void setSuccess(std::function<void(const char*)>&& fn);

    void setFail(std::function<void(const char*, const char*)>&& fn);

    void setPamPrompt(std::function<void(const char*)>&& fn);

    void setPamTextInfo(std::function<void(const char*)>&& fn);

    void setPamErrorMsg(std::function<void(const char*)>&& fn);

  private:
    struct {
        std::function<void()>                         client_ready;
        std::function<void(const char*)>              success;
        std::function<void(const char*, const char*)> fail;
        std::function<void(const char*)>              pam_prompt;
        std::function<void(const char*)>              pam_text_info;
        std::function<void(const char*)>              pam_error_msg;
    } m_listeners;

    Hyprutils::Memory::CWeakPointer<Hyprwire::IObject> m_object;
};

class CHyprauthPamV1Impl : public Hyprwire::IProtocolServerImplementation {
  public:
    CHyprauthPamV1Impl(uint32_t version, std::function<void(Hyprutils::Memory::CSharedPointer<Hyprwire::IObject>)>&& bindFn);
    virtual ~CHyprauthPamV1Impl() = default;

    virtual Hyprutils::Memory::CSharedPointer<Hyprwire::IProtocolSpec>                            protocol();

    virtual std::vector<Hyprutils::Memory::CSharedPointer<Hyprwire::SServerObjectImplementation>> implementation();

  private:
    uint32_t                                                                  m_version = 0;
    std::function<void(Hyprutils::Memory::CSharedPointer<Hyprwire::IObject>)> m_bindFn;
};
