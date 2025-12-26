// Generated with hyprwire-scanner 0.2.1. Made with vaxry's keyboard and ❤️.
// hyprauth_pam_v1

/*
 This protocol's authors' copyright notice is:


    Hyprauth contributors. #TODO:
  
*/


#define private public
#include "hyprauth_pam_v1-server.hpp"
#undef private

using namespace Hyprutils::Memory;
#define SP CSharedPointer
    
static void pamConversationManagerV1_method0(Hyprwire::IObject* r, uint32_t seq) {
    auto& fn = rc<CPamConversationManagerV1Object*>(r->getData())->m_listeners.make_conversation;
    if (fn)
        fn(seq);
}

CPamConversationManagerV1Object::CPamConversationManagerV1Object(Hyprutils::Memory::CSharedPointer<Hyprwire::IObject>&& object) : m_object(std::move(object)) {
    m_object->setData(this);
            
    m_object->listen(0, rc<void*>(::pamConversationManagerV1_method0));
}

CPamConversationManagerV1Object::~CPamConversationManagerV1Object() {
    ; // TODO: call destructor if present
}
void CPamConversationManagerV1Object::sendDestroy() {
    m_object->call(0);
}

void CPamConversationManagerV1Object::setMakeConversation(std::function<void(uint32_t)>&& fn) {
    m_listeners.make_conversation = std::move(fn);
}

static void pamConversationV1_method0(Hyprwire::IObject* r, const char* message) {
    auto& fn = rc<CPamConversationV1Object*>(r->getData())->m_listeners.pam_prompt;
    if (fn)
        fn(message);
}

static void pamConversationV1_method1(Hyprwire::IObject* r, const char* message) {
    auto& fn = rc<CPamConversationV1Object*>(r->getData())->m_listeners.pam_text_info;
    if (fn)
        fn(message);
}

static void pamConversationV1_method2(Hyprwire::IObject* r, const char* message) {
    auto& fn = rc<CPamConversationV1Object*>(r->getData())->m_listeners.pam_error_msg;
    if (fn)
        fn(message);
}

static void pamConversationV1_method3(Hyprwire::IObject* r, const char* token_bytes) {
    auto& fn = rc<CPamConversationV1Object*>(r->getData())->m_listeners.success;
    if (fn)
        fn(token_bytes);
}

static void pamConversationV1_method4(Hyprwire::IObject* r, const char* token_bytes, const char* message) {
    auto& fn = rc<CPamConversationV1Object*>(r->getData())->m_listeners.fail;
    if (fn)
        fn(token_bytes, message);
}

CPamConversationV1Object::CPamConversationV1Object(Hyprutils::Memory::CSharedPointer<Hyprwire::IObject>&& object) : m_object(std::move(object)) {
    m_object->setData(this);
            
    m_object->listen(0, rc<void*>(::pamConversationV1_method0));
    m_object->listen(1, rc<void*>(::pamConversationV1_method1));
    m_object->listen(2, rc<void*>(::pamConversationV1_method2));
    m_object->listen(3, rc<void*>(::pamConversationV1_method3));
    m_object->listen(4, rc<void*>(::pamConversationV1_method4));
}

CPamConversationV1Object::~CPamConversationV1Object() {
    ; // TODO: call destructor if present
}
void CPamConversationV1Object::sendResponseChannel(int messageFd) {
    m_object->call(0, messageFd);
}

void CPamConversationV1Object::setPamPrompt(std::function<void(const char*)>&& fn) {
    m_listeners.pam_prompt = std::move(fn);
}

void CPamConversationV1Object::setPamTextInfo(std::function<void(const char*)>&& fn) {
    m_listeners.pam_text_info = std::move(fn);
}

void CPamConversationV1Object::setPamErrorMsg(std::function<void(const char*)>&& fn) {
    m_listeners.pam_error_msg = std::move(fn);
}

void CPamConversationV1Object::setSuccess(std::function<void(const char*)>&& fn) {
    m_listeners.success = std::move(fn);
}

void CPamConversationV1Object::setFail(std::function<void(const char*, const char*)>&& fn) {
    m_listeners.fail = std::move(fn);
}

CHyprauthPamV1Impl::CHyprauthPamV1Impl(uint32_t ver, std::function<void(Hyprutils::Memory::CSharedPointer<Hyprwire::IObject>)>&& bindFn) : m_version(ver), m_bindFn(bindFn) {
    ;
}

static auto hyprauthPamV1Spec = makeShared<CHyprauthPamV1ProtocolSpec>();

SP<Hyprwire::IProtocolSpec> CHyprauthPamV1Impl::protocol() {
    return hyprauthPamV1Spec;
}

std::vector<SP<Hyprwire::SServerObjectImplementation>> CHyprauthPamV1Impl::implementation() {
    return {

            makeShared<Hyprwire::SServerObjectImplementation>(Hyprwire::SServerObjectImplementation{
                .objectName = "pam_conversation_manager_v1",
                .version    = m_version,
                .onBind = [this] (Hyprutils::Memory::CSharedPointer<Hyprwire::IObject> r) { if (m_bindFn) m_bindFn(r); }
            }),

            makeShared<Hyprwire::SServerObjectImplementation>(Hyprwire::SServerObjectImplementation{
                .objectName = "pam_conversation_v1",
                .version    = m_version,
            }),
};
}
