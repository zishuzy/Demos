#include <signal.h>

#include "utils/log/log.h"

#include "win_monitor.h"

bool g_run_flag = true;

static void signal_exit_handler(int sig)
{
    g_run_flag = false;
    LOG_INFO("recv sig = [%d]", sig);
    return;
}

void activeWindow(const WindowInfo &win_info)
{
    LOG_INFO("active window: w[%#lX] pid[%d] title[%s] x[%d] y[%d] width[%d] height[%d]",
             win_info.w, win_info.pid, win_info.title.c_str(), win_info.geometry.x,
             win_info.geometry.y, win_info.geometry.width, win_info.geometry.height);
}

int main(int argc, char *argv[])
{
    signal(SIGTERM, signal_exit_handler);

    CMonitorWin monitor_win;

    if (monitor_win.Init() == false) {
        LOG_ERROR("Failed to init monitor win");
        return -1;
    }
    monitor_win.RegActiveWindowCb(activeWindow);

    while (g_run_flag) {
        sleep(1);
    }

    monitor_win.Uninit();

    LOG_INFO("Main process exit.");

    return 0;
}