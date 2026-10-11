#include "shadowhook/utils/thread_quiescence.hpp"
#include <utility>
namespace shadowhook::threading {
execution_scope::~execution_scope() { if (domain_) domain_->leave(); }
execution_scope::execution_scope(execution_scope&& o) noexcept : domain_(std::move(o.domain_)) {}
execution_scope& execution_scope::operator=(execution_scope&& o) noexcept {
    if (this != &o) {
        if (domain_) domain_->leave();
        domain_ = std::move(o.domain_);
    }
    return *this;
}
execution_scope execution_domain::enter() {
    auto owner = shared_from_this();
    std::unique_lock<std::mutex> lock(mutex_);
    changed_.wait(lock, [this] { return !patching_; });
    if (!healthy_) return {};
    ++active_;
    return execution_scope(std::move(owner));
}
void execution_domain::leave() {
    std::lock_guard<std::mutex> lock(mutex_);
    --active_;
}
bool execution_domain::try_begin_patch() {
    std::lock_guard<std::mutex> lock(mutex_);
    if (patching_ || active_) return false;
    patching_ = true;
    return true;
}
void execution_domain::finish_patch(bool healthy) {
    {
        std::lock_guard<std::mutex> lock(mutex_);
        healthy_ = healthy;
        patching_ = false;
    }
    changed_.notify_all();
}
std::size_t execution_domain::active_calls() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return active_;
}
bool execution_domain::healthy() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return healthy_ && !patching_;
}
void execution_domain::close() {
    std::lock_guard<std::mutex> lock(mutex_);
    healthy_ = false;
}
bool execution_domain::bind(const void* owner) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (!owner || (owner_ && owner_ != owner) || !healthy_) return false;
    owner_ = owner;
    return true;
}
void execution_domain::unbind(const void* owner) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (owner_ == owner) owner_ = nullptr;
}
patch_scope::patch_scope(std::shared_ptr<execution_domain> d) : domain_(std::move(d)) {
    if (domain_) {
        healthy_ = domain_->healthy();
        acquired_ = domain_->try_begin_patch();
    }
}
patch_scope::~patch_scope() { if (acquired_) domain_->finish_patch(healthy_); }
} // namespace shadowhook::threading
