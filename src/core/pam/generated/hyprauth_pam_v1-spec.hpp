// Generated with hyprwire-scanner 0.2.1. Made with vaxry's keyboard and ❤️.
// hyprauth_pam_v1

/*
 This protocol's authors' copyright notice is:


    Hyprauth contributors. #TODO:
  
*/

#pragma once

#include <hyprwire/core/types/MessageMagic.hpp>
#include <hyprwire/hyprwire.hpp>
#include <hyprutils/memory/WeakPtr.hpp>
#include <vector>

enum hyprauthPamV1InternalError : uint32_t {
    HYPRAUTH_PAM_V1_INTERNAL_ERROR_CLIENT = 0,
    HYPRAUTH_PAM_V1_INTERNAL_ERROR_SERVER = 1,
};

class CPamConversationV1Spec : public Hyprwire::IProtocolObjectSpec {
  public:
    CPamConversationV1Spec()          = default;
    virtual ~CPamConversationV1Spec() = default;

    virtual std::string objectName() {
        return "pam_conversation_v1";
    }

    std::vector<Hyprwire::SMethod>                m_c2s = {Hyprwire::SMethod{
                                                               .idx         = 0,
                                                               .params      = {},
                                                               .returnsType = "",
                                                               .since       = 0,
                                            },
                                                           Hyprwire::SMethod{
                                                               .idx         = 1,
                                                               .params      = {Hyprwire::HW_MESSAGE_MAGIC_TYPE_VARCHAR},
                                                               .returnsType = "",
                                                               .since       = 0,
                                            },
                                                           Hyprwire::SMethod{
                                                               .idx         = 2,
                                                               .params      = {Hyprwire::HW_MESSAGE_MAGIC_TYPE_VARCHAR, Hyprwire::HW_MESSAGE_MAGIC_TYPE_VARCHAR},
                                                               .returnsType = "",
                                                               .since       = 0,
                                            },
                                                           Hyprwire::SMethod{
                                                               .idx         = 3,
                                                               .params      = {Hyprwire::HW_MESSAGE_MAGIC_TYPE_VARCHAR},
                                                               .returnsType = "",
                                                               .since       = 0,
                                            },
                                                           Hyprwire::SMethod{
                                                               .idx         = 4,
                                                               .params      = {Hyprwire::HW_MESSAGE_MAGIC_TYPE_VARCHAR},
                                                               .returnsType = "",
                                                               .since       = 0,
                                            },
                                                           Hyprwire::SMethod{
                                                               .idx         = 5,
                                                               .params      = {Hyprwire::HW_MESSAGE_MAGIC_TYPE_VARCHAR},
                                                               .returnsType = "",
                                                               .since       = 0,
                                            }};

    virtual const std::vector<Hyprwire::SMethod>& c2s() {
        return m_c2s;
    }

    std::vector<Hyprwire::SMethod>                m_s2c = {Hyprwire::SMethod{
                                                               .idx    = 0,
                                                               .params = {},
                                                               .since  = 0,
                                            },
                                                           Hyprwire::SMethod{
                                                               .idx    = 1,
                                                               .params = {},
                                                               .since  = 0,
                                            },
                                                           Hyprwire::SMethod{
                                                               .idx    = 2,
                                                               .params = {Hyprwire::HW_MESSAGE_MAGIC_TYPE_FD},
                                                               .since  = 0,
                                            }};

    virtual const std::vector<Hyprwire::SMethod>& s2c() {
        return m_s2c;
    }
};

class CHyprauthPamV1ProtocolSpec : public Hyprwire::IProtocolSpec {
  public:
    CHyprauthPamV1ProtocolSpec()          = default;
    virtual ~CHyprauthPamV1ProtocolSpec() = default;

    virtual std::string specName() {
        return "hyprauth_pam_v1";
    }

    virtual uint32_t specVer() {
        return 1;
    }

    virtual std::vector<Hyprutils::Memory::CSharedPointer<Hyprwire::IProtocolObjectSpec>> objects() {
        return {Hyprutils::Memory::makeShared<CPamConversationV1Spec>()};
    }
};
