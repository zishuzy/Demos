/**
 * @file utils_x11.h
 * @author zishu (zishuzy@gmail.com)
 * @brief Utils for X11.
 * @version 0.1
 * @date 2024-11-27
 *
 * @copyright Copyright (c) 2024
 *
 */
#ifndef __X11_UTILS_X11__
#define __X11_UTILS_X11__

#include <X11/X.h>
#include <X11/Xlib.h>

#include <string>

#include "utils/result/result.hpp"

namespace utils
{
namespace x11
{
struct WindowProperty {
    Window w;
    Atom property;

    int format;
    unsigned long item_num;
    unsigned char *data; // 记得释放
    int data_len;
};

struct WindowGeometry {
    int x;
    int y;
    int width;
    int height;
};

/**
 * @brief 获取窗口指定 Atom 的属性
 *
 * @param display
 * @param window
 * @param property
 * @return result::Result<WindowProperty>
 */
result::Result<WindowProperty> GetWindowProperty(Display *display, Window window,
                                                 Atom property);

/**
 * @brief 获取窗口pid
 *
 * @param display
 * @param win
 * @return result::Result<pid_t>
 */
result::Result<pid_t> GetWindowPid(Display *display, Window win);

/**
 * @brief 获取窗口标题
 *
 * @param display
 * @param win
 * @return result::Result<std::string>
 */
result::Result<std::string> GetWindowTitle(Display *display, Window win);

/**
 * @brief 获取窗口几何信息
 *
 * @param display
 * @param win
 * @return result::Result<WindowGeometry>
 */
result::Result<WindowGeometry> GetWindowGeometry(Display *display, Window win);

/**
 * @brief 获取当前活动窗口
 *
 * @param display
 * @return result::Result<Window>
 */
result::Result<Window> GetActiveWindow(Display *display);

/**
 * @brief 判断 win_child 是否是 win_parent 的子窗口
 *
 * @param display
 * @param win_parent
 * @param win_child
 * @return result::Result<bool>
 */
result::Result<bool> IsWindowChildren(Display *display, Window win_parent,
                                      Window win_child);

/**
 * @brief 关闭窗口
 *
 * @param display
 * @param win
 * @return result::Result<>
 */
result::Result<> CloseWindow(Display *display, Window win);

/**
 * @brief 激活窗口
 *
 * @param display
 * @param win
 * @return result::Result<>
 */
result::Result<> ActiveWindow(Display *display, Window win);
} // namespace x11
} // namespace utils

#endif /* __X11_UTILS_X11__ */
