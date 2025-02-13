#include "utils_x11.h"

// #include <X11/Intrinsic.h>
#include <X11/Xatom.h>
#include <X11/extensions/XRes.h>

#include <queue>

namespace utils
{
namespace x11
{
static int clientMsg(Display *display, Window win, const char *msg, unsigned long data0,
                     unsigned long data1, unsigned long data2, unsigned long data3,
                     unsigned long data4)
{
    XEvent event;
    long mask = SubstructureRedirectMask | SubstructureNotifyMask;

    event.xclient.type = ClientMessage;
    event.xclient.serial = 0;
    event.xclient.send_event = True;
    event.xclient.message_type = XInternAtom(display, msg, False);
    event.xclient.window = win;
    event.xclient.format = 32;
    event.xclient.data.l[0] = data0;
    event.xclient.data.l[1] = data1;
    event.xclient.data.l[2] = data2;
    event.xclient.data.l[3] = data3;
    event.xclient.data.l[4] = data4;

    if (XSendEvent(display, DefaultRootWindow(display), False, mask, &event)) {
        return EXIT_SUCCESS;
    } else {
        return EXIT_FAILURE;
    }
}

result::Result<WindowProperty> GetWindowProperty(Display *display, Window window,
                                                 Atom property)
{
    result::Result<WindowProperty> result(false);

    do {
        Atom actual_type_return;
        int actual_format_return;
        unsigned long nitems_return;
        unsigned long size, bytesleft, actual_size_return;
        unsigned char *buffer = nullptr;
        int err;

        err = XGetWindowProperty(display, window, property, 0, 0, False, AnyPropertyType,
                                 &actual_type_return, &actual_format_return,
                                 &nitems_return, &size, &buffer);
        if (err != 0 || size == 0) {
            result.SetError("Failed to get size of property!");
            break;
        }

        err =
            XGetWindowProperty(display, window, property, 0, size, False, AnyPropertyType,
                               &actual_type_return, &actual_format_return, &nitems_return,
                               &bytesleft, &buffer);
        if (err != 0) {
            result.SetError("Failed to get data of property!");
            break;
        }
        // FIXME: 这里没有考虑一次没有读完的情况，也即 bytesleft != 0 的情况。
        actual_size_return = size - bytesleft;
        if (actual_size_return == 0) {
            result.SetError("Get empty data of property!");
            break;
        }
        WindowProperty wp;
        wp.w = window;
        wp.property = property;
        wp.format = actual_format_return;
        wp.item_num = nitems_return;
        wp.data = buffer;
        wp.data_len = actual_size_return;

        result.SetData(wp);
        result.SetOk(true);
    } while (false);

    return result;
}

// TODO: 通过 _NET_WM_PID 获取 pid
result::Result<pid_t> GetWindowPid(Display *display, Window win)
{
    result::Result<pid_t> result(false);

    do {
        XResClientIdValue *client_ids;
        XResClientIdSpec spec;
        Status status;
        long num_ids;
        pid_t client_pid = -1;

        spec.client = win;
        spec.mask = XRES_CLIENT_ID_PID_MASK;

        status = XResQueryClientIds(display, 1, &spec, &num_ids, &client_ids);
        if (status != Success) {
            result.SetError("Failed to query client ids!");
            break;
        }

        for (int c = 0; c < num_ids; ++c) {
            XResClientIdValue *value = client_ids + c;
            if (XResGetClientIdType(value) == XRES_CLIENT_ID_PID) {
                client_pid = XResGetClientPid(value);
                break;
            }
        }
        XResClientIdsDestroy(num_ids, client_ids);

        if (client_pid < 0) {
            result.SetError("Failed to get client pid from client ids!");
            break;
        }
        result.SetData(client_pid);
        result.SetOk(true);
    } while (false);

    return result;
}

result::Result<std::string> GetWindowTitle(Display *display, Window win)
{
    result::Result<std::string> result(false);

    do {
        {
            Atom atom_net_wm_name = XInternAtom(display, "_NET_WM_NAME", False);
            auto ret = GetWindowProperty(display, win, atom_net_wm_name);
            if (ret.IsOk()) {
                const auto &data = ret.GetData();
                result.SetData(
                    std::string(reinterpret_cast<char *>(data.data), data.data_len));
                XFree(data.data);
                result.SetOk(true);
                break;
            }
        }

        {
            Atom atom_wm_name = XInternAtom(display, "WM_NAME", False);
            auto ret = GetWindowProperty(display, win, atom_wm_name);
            if (ret.IsOk()) {
                const auto &data = ret.GetData();
                result.SetData(
                    std::string(reinterpret_cast<char *>(data.data), data.data_len));
                XFree(data.data);
                result.SetOk(true);
                break;
            }
        }

    } while (false);

    return result;
}

result::Result<WindowGeometry> GetWindowGeometry(Display *display, Window win)
{

    result::Result<WindowGeometry> result(false);
    do {
        WindowGeometry wg;
        XWindowAttributes attr;
        if (XGetWindowAttributes(display, win, &attr) == 0) {
            result.SetError("Failed to get window attributes!");
            break;
        }
        wg.width = attr.width;
        wg.height = attr.height;

        {
            Window unused_child;
            Window win_root;
            Window win_parent;
            Window *win_chlidren = nullptr;
            unsigned int nchildren_return = 0;
            if (XQueryTree(display, win, &win_root, &win_parent, &win_chlidren,
                           &nchildren_return) == 0) {
                result.SetError("Failed to query window from tree!");
                break;
            }
            XFree(win_chlidren);
            if (win_parent == attr.root) {
                wg.x = attr.x;
                wg.y = attr.y;
            } else {
                XTranslateCoordinates(display, win, attr.root, attr.x, attr.y, &wg.x,
                                      &wg.y, &unused_child);
            }
        }
        result.SetData(wg);
        result.SetOk(true);
    } while (false);

    return result;
}

result::Result<Window> GetActiveWindow(Display *display)
{
    result::Result<Window> result(false);

    do {
        Window win_root_id = DefaultRootWindow(display);
        Atom atom_active = XInternAtom(display, "_NET_ACTIVE_WINDOW", False);
        Window *data = NULL;
        int data_len = 0;
        Window win_id;

        auto ret = GetWindowProperty(display, win_root_id, atom_active);
        if (!ret.IsOk()) {
            result.SetError(ret.GetError());
            break;
        }
        // FIXME: 这里没有校验返回的数据类型
        data = (Window *)ret.GetData().data;
        win_id = *data;
        XFree(data);
        if (win_id == 0) {
            result.SetError("Get invalid window id!");
            break;
        }

        result.SetData(win_id);
        result.SetOk(true);
    } while (false);

    return result;
}

result::Result<bool> IsWindowChildren(Display *display, Window win_parent,
                                      Window win_child)
{
    result::Result<bool> result(true);
    bool found = false;

    std::queue<Window> queueWin;
    queueWin.push(win_parent);
    while (!queueWin.empty() && !found) {
        Window winTmp = queueWin.front();
        queueWin.pop();
        Window winActRoot;
        Window winActParent;
        Window *pWinActChlidren = nullptr;
        unsigned int unChlidrnCount = 0;
        int nOpeRet = XQueryTree(display, winTmp, &winActRoot, &winActParent,
                                 &pWinActChlidren, &unChlidrnCount);
        if (nOpeRet == 0) {
            result.SetError("Failed to query window from tree!");
            break;
        }
        for (unsigned int i = 0; i < unChlidrnCount; i++) {
            queueWin.push(pWinActChlidren[i]);
            if (pWinActChlidren[i] == win_child) {
                found = true;
                break;
            }
        }
        XFree(pWinActChlidren);
    }
    return result;
}

result::Result<> CloseWindow(Display *display, Window win)
{
    int ret = clientMsg(display, win, "_NET_CLOSE_WINDOW", 0, 0, 0, 0, 0);
    return result::Result<>(ret == 0);
}

result::Result<> ActiveWindow(Display *display, Window win)
{
    int ret = clientMsg(display, win, "_NET_ACTIVE_WINDOW", 0, 0, 0, 0, 0);
    return result::Result<>(ret == 0);
}
} // namespace x11
} // namespace utils