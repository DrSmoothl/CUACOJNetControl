CUACOJ NetControl
==================

一个用于 OJ/竞赛环境的“网络管控”系统：服务端统一管理客户端，远程下发“仅允许访问指定域名”的策略，实时查看客户端状态和网络事件。

功能特性
- 统一管理
  - 客户端在线/离线状态、心跳、最近活动时间
  - 一键开启/关闭“访问控制”（全局）
  - 配置允许访问的域名列表（自动解析为 IP）
- 精细控制
  - 白名单客户端（完全不受限制）
  - 按客户端覆盖全局策略（启用/禁用/继承）与批量下发
- 实时监控
  - 客户端上报 TCP 连接事件（含是否被允许、远端 IP/端口、域名映射）
  - 事件去抖与速率限制，防止事件风暴
- 前端管理界面（内置静态页面）
  - 5 个面板：总管理、客户端管理、白名单管理、最近事件（仅最新 50 条）、版本管理
  - 客户端行内“加入白名单”快捷操作
  - 美化与动效（DaisyUI/Tailwind）
- 配置与持久化
  - 服务器配置文件：`config/server.json`，热重载（监听文件变化）
  - 客户端配置文件：`config/client.json`，热加载（触发自动重连）
  - 完整持久化（全局/白名单/客户端覆盖/版本/更新目录）
- 安全与部署
  - Bearer Token 客户端鉴权、可选 TLS/WSS
  - Windows 客户端管理员权限/UAC 自动提权，支持安装为系统服务
- 日志与更新
  - 服务端/客户端滚动文件日志（logs/）
  - 客户端自更新：服务端提供版本元信息与二进制下载，客户端启动前自检并替换
- 平台与协议
  - Windows 防火墙（netsh）出站默认拒绝，允许 DNS 与白名单 IP（含 IPv6）
  - Server-Client 通过 WebSocket 传输 JSON 消息

目录结构（关键）
- `cmd/server`：服务端入口
- `cmd/client`：客户端入口（含 Windows 专属实现）
- `pkg/proto`：通信协议消息类型
- `pkg/fw`：Windows 防火墙封装
- `pkg/config`：配置加载（服务器/客户端）
- `web/admin`：内置管理前端（静态）
- `config/`：默认配置文件
- `logs/`：滚动日志输出目录

构建
- 需要 Go 1.21+
- Windows（PowerShell）：
  - 构建服务端：`go build -o server.exe ./cmd/server`
  - 构建客户端：`go build -o client.exe ./cmd/client`

  安装 (Windows)
  ----------------
  方式一：Inno Setup 安装包
  1. 确保已构建 `client.exe` (以及可选 `server.exe`) 放在仓库根目录。
  2. 安装 Inno Setup，打开 `installer/NetControl.iss`，编译生成 `dist/CUACOJNetControl_Setup.exe`。
  3. 运行安装包，默认目录 `C:\Program Files\CUACOJNetControl`，安装后自动以服务方式启动客户端并开机自启。

  方式二：脚本快速安装
  ```
  powershell -ExecutionPolicy Bypass -File installer/install.ps1 -InstallDir "C:\Program Files\CUACOJNetControl" -ServerURL "ws://SERVER_IP:8080/ws" -ClientName "node01" -Token "YOUR_TOKEN"
  ```
  卸载：
  ```
  powershell -ExecutionPolicy Bypass -File installer/uninstall.ps1 -InstallDir "C:\Program Files\CUACOJNetControl"
  ```

  说明：
  - 服务名：`CUACOJNetControlClient` 可在服务管理器中查看状态。
  - 安装脚本会覆盖已有服务同名旧版本（先删除再创建）。
  - 若需要自更新，可继续使用服务器端的 `/api/client_update` 机制。
  - 若要定制日志路径或更多选项，可修改脚本或 Inno Setup 脚本中的参数。

运行（示例）
- 服务端：
  - 默认读取 `config/server.json`；也可通过参数/环境变量覆盖（详见源码 `pkg/config`）。
  - 启动后访问 `http://<host>:<port>/` 打开管理界面。
- 客户端：
  - 需要管理员权限（防火墙规则）。程序会自动尝试 UAC 提权。
  - 示例：`client.exe -server ws://SERVER_IP:8080/ws -name PC-001`
  - 可安装为服务：`client.exe -service install -svcname CUACOJNetControlClient`

管理界面
- 总管理：开关访问控制、编辑允许域名
- 客户端管理：筛选/批量操作/行内“加入白名单”
- 白名单管理：集中编辑保存
- 最近事件：仅显示最新 50 条，支持搜索与“允许/阻止”过滤
- 版本管理：查看当前版本、各平台包存在性、上传替换并可更新版本号

配置文件
- 服务器 `config/server.json`（示例字段）
  - `addr`：监听地址（如 `:8080`）
  - `tls`：TLS 相关配置（可选）
  - `client_token`：客户端鉴权 Token
  - `static_dir`：前端静态文件目录（默认内置）
  - `initial_domains`/`control_enabled`：全局策略
  - `whitelist_clients`：白名单
  - `per_client`：按客户端覆盖
  - `client_version`/`update_dir`：客户端版本与二进制存放目录
  - 支持热重载，保存即生效并广播
- 客户端 `config/client.json`（示例字段）
  - `server_url`：WebSocket 地址（如 `ws://host:8080/ws`）
  - `name`：客户端名称（默认主机名）
  - `token`：鉴权 Token
  - 变更后会自动触发重连

接口（部分）
- WebSocket：`/ws`（消息类型：Register/Heartbeat/State/Config/NetEvent）
- REST：
  - `GET /api/clients`、`POST /api/clients/batch_config`
  - `GET/POST /api/config`（含持久化并广播）
  - `GET/POST /api/whitelist`
  - `GET /api/events`
  - `GET /api/client_update`，`GET|HEAD /download/client`，`POST /admin/upload`

日志
- 滚动文件日志位于 `logs/` 目录，支持最大大小、保留份数、保留天数配置（环境变量）。
- 客户端事件上报含去抖（10s）与速率限制（每 Tick / 每分钟）。
 - 调试：设置环境变量 `NETCTRL_DEBUG=1` 可输出更详细的调试日志（DNS 解析、策略应用、以及 Windows 防火墙执行的 `netsh advfirewall` 命令与输出）。

安全
- 客户端通过 Bearer Token 鉴权，服务端可选择开启 TLS/WSS。
- Windows 客户端支持以系统服务运行，并有可选停止密码（环境变量或参数）。

实现要点与限制
- 防火墙策略：出站默认阻止，允许 DNS（53）与被允许域名解析得到的 IP（支持 IPv4/IPv6）。
- 仅对 Windows 强制策略（其他平台提供占位实现）。
- 基于 IP 的 allow 策略，不做 SNI/HTTP Host 深度识别（若需可后续通过代理方式扩展）。

常见问题
- “允许 bing.com 但仍被拦截？”
  - 已支持 IPv6。请确保客户端更新至当前版本并收到最新配置；等待 20 秒自动重应用或重启客户端。
- “客户端连不上服务端？”
  - 已在应用策略时自动放行服务端的 IP:端口；如服务端地址变更，请在配置中更新并重新应用。
- “DNS 解析失败？”
  - 已默认放行 UDP/TCP 53 端口出站，确保系统 DNS 正常配置。

许可证
- 本项目用于教学/竞赛场景示例，按仓库 LICENSE（如未设置，可自定义）。
