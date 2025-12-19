// Generated with hyprwire-scanner 0.2.1. Made with vaxry's keyboard and ❤️.
// hyprauth_pam_v1

/*
 This protocol's authors' copyright notice is:


    Hyprauth contributors. #TODO:
  
*/

#define private public
#include "hyprauth_pam_v1-client.hpp"
#undef private

using namespace Hyprutils::Memory;
#define SP CSharedPointer

static void pamConversationV1_method0(Hyprwire::IObject* r) {
    auto& fn = rc<CCPamConversationV1Object*>(r->getData())->m_listeners.start;
    if (fn)
        fn();
}

static void pamConversationV1_method1(Hyprwire::IObject* r) {
    auto& fn = rc<CCPamConversationV1Object*>(r->getData())->m_listeners.finished;
    if (fn)
        fn();
}

static void pamConversationV1_method2(Hyprwire::IObject* r, int messageFd) {
    auto& fn = rc<CCPamConversationV1Object*>(r->getData())->m_listeners.pam_response_channel;
    if (fn)
        fn(messageFd);
}

CCPamConversationV1Object::CCPamConversationV1Object(Hyprutils::Memory::CSharedPointer<Hyprwire::IObject>&& object) : m_object(std::move(object)) {
    m_object->setData(this);

    m_object->listen(0, rc<void*>(::pamConversationV1_method0));
    m_object->listen(1, rc<void*>(::pamConversationV1_method1));
    m_object->listen(2, rc<void*>(::pamConversationV1_method2));
}

CCPamConversationV1Object::~CCPamConversationV1Object() {
    ; // TODO: call destructor if present
}
void CCPamConversationV1Object::sendClientReady() {
    m_object->call(0);
}

void CCPamConversationV1Object::sendSuccess(const char* token_bytes) {
    m_object->call(1, token_bytes);
}

void CCPamConversationV1Object::sendFail(const char* token_bytes, const char* message) {
    m_object->call(2, token_bytes, message);
}

void CCPamConversationV1Object::sendPamPrompt(const char* message) {
    m_object->call(3, message);
}

void CCPamConversationV1Object::sendPamTextInfo(const char* message) {
    m_object->call(4, message);
}

void CCPamConversationV1Object::sendPamErrorMsg(const char* message) {
    m_object->call(5, message);
}

void CCPamConversationV1Object::setStart(std::function<void()>&& fn) {
    m_listeners.start = std::move(fn);
}

void CCPamConversationV1Object::setFinished(std::function<void()>&& fn) {
    m_listeners.finished = std::move(fn);
}

void CCPamConversationV1Object::setPamResponseChannel(std::function<void(int)>&& fn) {
    m_listeners.pam_response_channel = std::move(fn);
}

CCHyprauthPamV1Impl::CCHyprauthPamV1Impl(uint32_t ver) : m_version(ver) {
    ;
}

static auto                 hyprauthPamV1Spec = makeShared<CHyprauthPamV1ProtocolSpec>();

SP<Hyprwire::IProtocolSpec> CCHyprauthPamV1Impl::protocol() {
    return hyprauthPamV1Spec;
}

std::vector<SP<Hyprwire::SClientObjectImplementation>> CCHyprauthPamV1Impl::implementation() {
    return {

        makeShared<Hyprwire::SClientObjectImplementation>(Hyprwire::SClientObjectImplementation{
            .objectName = "pam_conversation_v1",
            .version    = m_version,
        }),
    };
}
