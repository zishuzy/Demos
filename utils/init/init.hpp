#ifndef __UTILS_INIT_INIT_HPP__
#define __UTILS_INIT_INIT_HPP__

#include "utils/result/result.hpp"

namespace utils
{
namespace init
{
class IInit
{
public:
    IInit() = default;
    virtual ~IInit() = default;

    virtual result::Result<> Init(void) = 0;
    virtual void Uninit(void) = 0;
};
} // namespace init
} // namespace utils

#endif /* __UTILS_INIT_INIT_HPP__ */
