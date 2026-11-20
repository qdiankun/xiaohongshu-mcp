package configs

import "os"

// VNCURL 返回供调用方跳转的人工验证桌面地址（noVNC）。
// 由部署方通过 XHS_VNC_URL 配置，例如 https://vnc.example.com/ 。
// 留空时工具只返回截图，不附带地址。
func VNCURL() string {
	return os.Getenv("XHS_VNC_URL")
}
