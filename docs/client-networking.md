# 客户端网络

TUN 客户端会修改设备路由、DNS 或过滤规则。RustBox 将这些修改视为一组有生命周期的
系统事务：启动时应用，停止或失败时回滚，切网与唤醒后重新收敛。

## TUN

从 [`examples/tun-transparent.toml`](../examples/tun-transparent.toml) 开始。已有其他
VPN 时保持 `auto_route = false`；全局接管需要先停止冲突的 VPN，再以系统要求的权限
运行并启用自动路由。

- Windows 使用 Wintun；
- Linux 使用 `/dev/net/tun`；
- macOS 使用 utun；
- 路由、redirect 和系统 DNS 修改通常需要提升权限。

`strict_route` 依赖 `auto_route`。`route_excludes` 用于保留不能被接管的前缀；代理
服务器、bootstrap DNS 和控制连接必须始终具有防回环路径。

## Windows 交付

Windows 安装包需要在可执行文件旁携带与进程架构一致的官方 `wintun.dll`。开发环境
可通过绝对路径 `RUSTBOX_WINTUN_DLL` 指定文件；缺失或架构错误会在启动时失败。

RustBox 使用默认物理接口绑定 direct 与 bootstrap 流量，并通过动态 WFP 会话实现
严格路由和 DNS 防泄漏。网络热路径不调用 PowerShell；系统 DNS 的低频快照与恢复是
例外。

## 切网、睡眠与恢复

客户端监听原生网络变化。默认接口、地址或 DNS 变化后，运行时重新选择物理接口并
重建相关路由和绑定；已有 flow 有界排空，新 flow 使用新状态。重复通知会被合并，
防止频繁切换造成重建风暴。

所有系统修改都应满足：

1. 应用前记录足够的恢复信息；
2. 部分失败时逆序回滚已完成步骤；
3. 正常停止与重复停止都安全；
4. 恢复时不覆盖用户在运行期间做出的无关修改；
5. 异常退出后，宿主或 watchdog 可以识别并清理遗留状态。

应用层应将网络事务与 engine 生命周期绑定，不应绕过 RustBox 单独修改同一组路由或
DNS 设置。
