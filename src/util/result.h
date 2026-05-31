#pragma once
#include <string>
#include <utility>

namespace util {

template <typename T, typename E = std::string> class Result {
    bool ok_;
    T val_;
    E err_;

  public:
    Result(T v) : ok_(true), val_(std::move(v)), err_() {}
    Result(E e, bool /*dummy*/) : ok_(false), val_(), err_(std::move(e)) {}

    static Result Ok(T v) { return Result(std::move(v)); }
    static Result Err(E e) { return Result(std::move(e), false); }

    bool is_ok() const { return ok_; }
    const T &value() const { return val_; }
    T &value() { return val_; }
    const E &error() const { return err_; }
};

// Void specialization
template <typename E> class Result<void, E> {
    bool ok_;
    E err_;

  public:
    Result() : ok_(true), err_() {}
    Result(E e, bool /*dummy*/) : ok_(false), err_(std::move(e)) {}

    static Result Ok() { return Result(); }
    static Result Err(E e) { return Result(std::move(e), false); }

    bool is_ok() const { return ok_; }
    const E &error() const { return err_; }
};

} // namespace util
