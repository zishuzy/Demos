/**
 * @file win_monitor.h
 * @author zishu (zishuzy@gmail.com)
 * @brief Window monitor for X11.
 * @version 0.1
 * @date 2024-11-27
 *
 * @copyright Copyright (c) 2024
 *
 */
#ifndef X11_MONITOR_WIN
#define X11_MONITOR_WIN

#include "utils/x11/utils_x11.h"

#include <thread>
#include <string>
#include <functional>
#include <list>
#include <mutex>

struct WindowInfo {
    unsigned long w;
    pid_t pid;
    std::string title;

    utils::x11::WindowGeometry geometry;
};

class CMonitorWin
{
public:
    using FnActiveWindow = std::function<void(const WindowInfo &win_info)>;

public:
    CMonitorWin();
    virtual ~CMonitorWin();

    bool Init();
    void Uninit();

    bool RegActiveWindowCb(FnActiveWindow cb);
    void UnregActiveWindowCb(FnActiveWindow cb);

private:
    bool init();
    void uninit();
    bool initX11();
    void uninitX11();
    bool initThread();
    void uninitThread();

    utils::result::Result<WindowInfo> fillWindowInfo(Window w);
    void activeWindow(Window w);

    void threadFunc();

private:
    bool inited_;
    Display *display_;
    Window win_root_id_;
    Atom atom_active_window_;
    std::thread thread_;
    bool thread_flag_;
    std::list<FnActiveWindow> list_active_window_cb_;
    std::mutex mutex_active_window_cb_;
};

#endif /* X11_MONITOR_WIN */
