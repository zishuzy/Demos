#include "win_monitor.h"

#include "utils/log/log.h"

static int x11ErrorEvent(Display *dpy, XErrorEvent *event)
{
    LOG_ERROR("display[%p]", dpy);
    LOG_ERROR("event: ");
    LOG_ERROR("          type: %d", event->type);
    LOG_ERROR("       display: %p", event->display);
    LOG_ERROR("    resourceid: %lu", event->resourceid);
    LOG_ERROR("        serial: %lu", event->serial);
    LOG_ERROR("    error_code: %d", event->error_code);
    LOG_ERROR("  request_code: %d", event->request_code);
    LOG_ERROR("    minor_code: %d", event->minor_code);
    return 0;
}

CMonitorWin::CMonitorWin()
    : inited_(false)
    , display_(nullptr)
    , thread_flag_(false)
{
}

CMonitorWin::~CMonitorWin() {}

bool CMonitorWin::Init()
{
    if (inited_) {
        return true;
    }
    inited_ = init();
    return inited_;
}

void CMonitorWin::Uninit()
{
    if (!inited_) {
        return;
    }
    uninit();
    inited_ = false;
}

bool CMonitorWin::RegActiveWindowCb(FnActiveWindow cb)
{
    std::lock_guard<std::mutex> locker(mutex_active_window_cb_);
    list_active_window_cb_.push_back(cb);
    return true;
}

void CMonitorWin::UnregActiveWindowCb(FnActiveWindow cb)
{
    std::lock_guard<std::mutex> locker(mutex_active_window_cb_);
    for (auto it = list_active_window_cb_.begin(); it != list_active_window_cb_.end();) {
        if (it->target<void (*)(Window)>() == cb.target<void (*)(Window)>()) {
            it = list_active_window_cb_.erase(it);
        } else {
            it++;
        }
    }
}

bool CMonitorWin::init()
{
    bool ok = false;
    do {
        if (initX11() == false) {
            LOG_ERROR("Failed to init X11");
            break;
        }

        if (initThread() == false) {
            LOG_ERROR("Failed to init thread");
            uninitX11();
            break;
        }

        ok = true;
    } while (false);

    return ok;
}

void CMonitorWin::uninit()
{
    uninitThread();
    uninitX11();
}

bool CMonitorWin::initX11()
{
    display_ = XOpenDisplay(NULL);
    if (display_ == NULL) {
        LOG_ERROR("Failed to open display");
        return false;
    }
    win_root_id_ = DefaultRootWindow(display_);
    atom_active_window_ = XInternAtom(display_, "_NET_ACTIVE_WINDOW", False);
    XSelectInput(display_, win_root_id_, PropertyChangeMask | SubstructureNotifyMask);
    XSetErrorHandler(x11ErrorEvent);
    return true;
}

void CMonitorWin::uninitX11()
{
    if (display_ != NULL) {
        XCloseDisplay(display_);
        display_ = NULL;
    }
}

bool CMonitorWin::initThread()
{
    thread_flag_ = true;
    thread_ = std::thread(&CMonitorWin::threadFunc, this);
    return true;
}

void CMonitorWin::uninitThread()
{
    thread_flag_ = false;
    thread_.join();
}

utils::result::Result<WindowInfo> CMonitorWin::fillWindowInfo(Window w)
{
    utils::result::Result<WindowInfo> result(false);
    do {
        WindowInfo winfo;
        winfo.w = w;

        auto res_pid = utils::x11::GetWindowPid(display_, w);
        if (!res_pid.IsOk()) {
            LOG_ERROR("Failed to get pid of window[%#lX]", w);
            break;
        }
        auto res_title = utils::x11::GetWindowTitle(display_, w);
        if (!res_title.IsOk()) {
            LOG_ERROR("Failed to get title of window[%#lX]", w);
            break;
        }
        auto res_geometry = utils::x11::GetWindowGeometry(display_, w);
        if (!res_geometry.IsOk()) {
            LOG_ERROR("Failed to get geometry of window[%#lX]", w);
            break;
        }
        winfo.pid = res_pid.GetData();
        winfo.title = res_title.GetData();
        winfo.geometry = res_geometry.GetData();

        result.SetData(winfo);
        result.SetOk(true);
    } while (false);
    return result;
}

void CMonitorWin::activeWindow(Window w)
{
    auto res_winfo = fillWindowInfo(w);
    if (!res_winfo.IsOk()) {
        return;
    }

    {
        std::lock_guard<std::mutex> locker(mutex_active_window_cb_);
        for (const auto &cb : list_active_window_cb_) {
            cb(res_winfo.GetData());
        }
    }
}

void CMonitorWin::threadFunc()
{
    XEvent event;

    LOG_INFO("CMonitorWin thread[%d] start.", gettid());

    while (thread_flag_) {
        XNextEvent(display_, &event);
        LOG_DEBUG("Get xevent: %d", event.type);
        switch (event.type) {
        case PropertyNotify: {
            if (event.xproperty.window != win_root_id_ ||
                event.xproperty.atom != atom_active_window_) {
                break;
            }

            // TODO: 确认 event.xproperty.window 和 res_winid 有无差别
            auto res_winid = utils::x11::GetActiveWindow(display_);
            if (!res_winid.IsOk()) {
                LOG_ERROR("Failed to get active window");
                break;
            }

            activeWindow(res_winid.GetData());
            break;
        }
        case ConfigureNotify: {
            auto res_winid = utils::x11::GetActiveWindow(display_);
            if (!res_winid.IsOk()) {
                LOG_ERROR("Failed to get active window");
                break;
            }

            activeWindow(res_winid.GetData());
            break;
        }
        default:
            break;
        }
    }

    LOG_INFO("CMonitorWin thread[%d] exit.", gettid());
}
