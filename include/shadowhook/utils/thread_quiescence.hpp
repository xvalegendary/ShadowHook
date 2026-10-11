#pragma once
#include <condition_variable>
#include <cstddef>
#include <memory>
#include <mutex>

namespace shadowhook::threading {
class execution_domain;

class execution_scope final {
public:
    execution_scope() = default;
    ~execution_scope();
    execution_scope(execution_scope&& other) noexcept;
    execution_scope& operator=(execution_scope&& other) noexcept;
    execution_scope(const execution_scope&) = delete;
    execution_scope& operator=(const execution_scope&) = delete;
    explicit operator bool() const noexcept { return !!domain_; }
private:
    friend class execution_domain;
    explicit execution_scope(std::shared_ptr<execution_domain> d) : domain_(std::move(d)) {}
    std::shared_ptr<execution_domain> domain_;
};

class execution_domain final : public std::enable_shared_from_this<execution_domain> {
public:
    execution_scope enter();
    bool try_begin_patch();
    void finish_patch(bool healthy);
    std::size_t active_calls() const;
    bool healthy() const;
    void close();
    bool bind(const void* owner);
    void unbind(const void* owner);
private:
    friend class execution_scope;
    void leave();
    mutable std::mutex mutex_;
    std::condition_variable changed_;
    std::size_t active_{};
    bool patching_{};
    bool healthy_{true};
    const void* owner_{}; 
};
class patch_scope final {
public:
    explicit patch_scope(std::shared_ptr<execution_domain> domain);
    ~patch_scope();
    patch_scope(const patch_scope&) = delete;
    patch_scope& operator=(const patch_scope&) = delete;
    explicit operator bool() const noexcept { return acquired_; }
    void healthy(bool value) noexcept { healthy_ = value; }
private:
    std::shared_ptr<execution_domain> domain_;
    bool acquired_{};
    bool healthy_{};
};
} // namespace shadowhook::threading
