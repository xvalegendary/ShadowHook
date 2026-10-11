#pragma once
#include <memory>
#include <type_traits>
#include <utility>

namespace shadowhook {
class original_lease final {
public:
    original_lease() = default;
    original_lease(std::shared_ptr<void> lifetime, void* address) noexcept
        : lifetime_(std::move(lifetime)), address_(address) {}

    explicit operator bool() const noexcept { return address_ && lifetime_; }
    void* address() const noexcept { return lifetime_ ? address_ : nullptr; }

    template<typename FunctionPointer>
    FunctionPointer as() const noexcept {
        static_assert(std::is_pointer_v<FunctionPointer> &&
                      std::is_function_v<std::remove_pointer_t<FunctionPointer>>,
                      "original_lease requires a function pointer type");
        return reinterpret_cast<FunctionPointer>(address());
    }

private:
    std::shared_ptr<void> lifetime_;
    void* address_{};
};

} // namespace shadowhook
