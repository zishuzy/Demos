/**
 * @file result.hpp
 * @author zishu (zishuzy@gmail.com)
 * @brief The result template with error messages.
 * @version 0.1
 * @date 2024-11-27
 *
 * @copyright Copyright (c) 2024
 *
 */
#ifndef __RESULT_RESULT__
#define __RESULT_RESULT__

#include <string>

namespace utils
{
namespace result
{

struct ResultNone {
};

template <typename _Td = ResultNone, typename _Te = std::string>
class Result
{
public:
    constexpr Result(bool ok = true) noexcept
        : ok_(ok)
    {
    }

    void SetOk(bool ok) noexcept { ok_ = ok; }
    bool IsOk() const noexcept { return ok_; }

    void SetError(const _Te &err)
    {
        SetOk(false);
        err_ = err;
    }
    void SetError(_Te &&err)
    {
        SetOk(false);
        err_ = std::move(err);
    }
    const _Te &GetError() const noexcept { return err_; }

    void SetData(const _Td &data) { data_ = data; }
    void SetData(_Td &&data) noexcept { data_ = std::move(data); }
    const _Td &GetData() const noexcept { return data_; }

    operator bool() const noexcept { return ok_; }

private:
    bool ok_;
    _Te err_;
    _Td data_;
};
} // namespace result
} // namespace utils

#endif /* __RESULT_RESULT__ */
