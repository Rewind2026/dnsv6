# IPv6 DDNS 服务 - v1.6.5

一个支持 IPv6 前缀自动检测和后缀拼接的动态 DNS 服务，配合阿里云 DNS 使用。

## 功能特点

- **IPv6 前缀拼接**：自动获取公网 IPv6 前缀 + 预设后缀 → 拼接后自动更新 AAAA 记录
- **IPv4 支持**：支持 A 记录更新
- **双栈模式**：可同时支持 IPv4 和 IPv6
- **手动模式**：支持手动输入完整 IPv4/IPv6 地址
- **异地 DDNS**：支持从域名解析 IP，适合远程设备
- **Web 管理界面**：可视化配置（密码保护）
- **自动检测**：定时检测 IP 变化并更新（默认 3 分钟）
- **多 DNS 商**：支持阿里云、Cloudflare
- **日志记录**：完整的操作日志

## 环境要求

- Docker
- Docker Compose
- 阿里云 DNS 账号（需要 AccessKey）

## 快速开始

### 1. 准备项目

将项目文件夹复制到目标机器（NAS、服务器等）。

docker pull rewind2030/dnsv6:latest

### 2. 启动服务

```bash
# 进入项目目录
cd /path/to/dnsv6

# 构建并启动容器
docker-compose up -d

# 查看运行状态
docker-compose ps

# 查看日志
docker-compose logs -f
```
# 示例
version: '3.8'

services:
  ddns:
    build: .
    container_name: ipv6-ddns
    restart: unless-stopped
    
    # 使用host网络模式（与宿主机同一网络）
    network_mode: host
    
    # 数据目录映射到宿主机（便于备份）
    volumes:
      - ./data:/app/data
    
    environment:
      - PORT=5000
    
    # 健康检查（兼容Linux/Windows/Docker）
    healthcheck:
      test: ["CMD-SHELL", "wget -qO- http://localhost:5000/health 2>/dev/null || curl -fs http://localhost:5000/health 2>/dev/null || exit 1"]
      interval: 30s
      timeout: 5s
      retries: 3
      start_period: 10s
    
    logging:
      driver: "json-file"
      options:
        max-size: "10m"
        max-file: "3"


### 3. 访问 Web 界面

浏览器打开：`http://<宿主机IP>:5000`

首次登录时，输入你想要的**用户名和密码**，系统会自动创建为管理员账号。

## 网络配置

本项目使用 Docker **host 网络模式**，容器与宿主机共享同一网络。

### 访问地址

```
http://<宿主机IP>:5000
```

### 端口

- `5000` - Web 管理界面

## 配置说明

### 首次配置

1. 登录 Web 界面，首次登录时输入你想要的账号和密码，系统会自动创建为管理员
2. 进入「DNS 配置」页面，填写阿里云 AccessKey
3. 进入「基本设置」页面，配置检测间隔
4. 添加设备并启用

### 添加设备

| 参数 | 说明 |
|------|------|
| 设备 ID | 标识名称（如 `nas`、`router`） |
| 域名 | 要更新的完整域名（如 `nas.example.com`） |
| IP 类型 | 仅 IPv6 / 仅 IPv4 / 同时支持 |
| IPv6 后缀 | 内网设备 IPv6 后 64 位（如 `1873:99ec:ef23:7b56`） |
| 数据源 | `自动获取` 或 `从域名解析`（异地 DDNS） |
| 源域名 | 数据源为「从域名解析」时填写 |

### 数据源说明

- **自动获取本机 IP**：自动检测当前公网 IP
- **从域名解析**：从指定域名解析 IP（适合异地 DDNS）

### IPv6 拼接说明

```
公网前缀（自动获取） + :: + 后缀（手动配置）
示例：2408:822e:8a7:40f0::1873:99ec:ef23:7b56
```

## Docker 命令

```bash
# 启动
docker-compose up -d

# 停止
docker-compose down

# 重启
docker-compose restart

# 查看日志
docker-compose logs -f

# 重新构建（代码修改后）
docker-compose build --no-cache
docker-compose up -d

# 进入容器（调试用）
docker exec -it ipv6-ddns /bin/sh
```

## 数据备份

数据库映射到宿主机的 `./data` 目录：

```bash
# 备份
cp -r ./data ./data.backup

# 恢复
cp -r ./data.backup ./data
```

## 版本信息

- **版本**：v1.6.5
- **发布日期**：2026-03-12
- **基础镜像**：Python 3.11-slim
- **Web 框架**：Flask 3.0.0
- **前端框架**：Vue 3 + Element Plus

## 更新日志

### v1.6.5 (2026-03-12)

**Bug修复**
- **设置状态显示修复**：修复设置页面开关状态显示不正确的问题，后端返回配置时将整数转换为布尔值，前端使用正确的类型判断逻辑

### v1.6.4 (2026-03-09)

**安全增强**
- **扩展内网IP识别**：扩展私有IP判断范围，支持更多内网段，包括 172.168-254.x.x、192.0.x.x、100.64-127.x.x 等常见内网段
- **同网段判断**：新增同网段判断功能，即使非标准私有IP段，只要与服务器在同一C段内即可识别为内网访问
- **前端状态显示**：访问状态页面显示更详细的内网/同网段识别信息

### v1.6.3 (2026-03-09)

**移动端优化**
- **响应式布局**：全面适配各种屏幕尺寸，包括平板横竖屏、大手机(414-767px)、标准手机(375-413px)、小手机(320-374px)、超小屏幕、折叠屏和横屏模式
- **日期显示修复**：修复iPhone上时间显示"na:na:na:na"的问题，增强日期格式解析
- **触摸优化**：按钮最小高度44px符合触控标准，禁用触摸高亮，iPhone X+安全区域支持

### v1.6.2 (2026-03-08)

**Bug修复**
- **强制同步时间持久化**：修复24小时强制同步每次都执行的问题，现在时间会保存到数据库，重启后继续计时

### v1.6.1 (2026-03-07)

**安全增强**
- **公网访问控制**：开启公网访问后，访问API仍需登录认证，保护敏感操作
- **IP白名单**：支持配置允许访问的公网IP或IP段，增强安全隔离
- **智能关闭保护**：关闭公网访问需要内网IP、白名单IP或已登录账号，防止误操作导致无法访问

### v1.6.0 (2026-03-06)

**新功能**
- **临时IPv6地址识别**：自动识别并优先使用稳定的EUI-64地址，避免使用临时隐私地址
- **数据库自动备份**：每7天自动备份数据库，保留最近10个备份文件
- **完善的输入校验**：
  - 设备ID：只允许字母、数字、下划线、连字符，长度1-50字符
  - 域名：支持通配符(*)和国际化域名(punycode)，符合DNS规范
  - IPv6后缀：验证格式和后64位非零
  - IP地址：验证IPv4非私有/回环，IPv6必须是GUA

**Bug修复**
- **SQL注入漏洞修复**：日志清理使用参数化查询，防止SQL注入攻击
- **线程安全修复**：登录失败记录添加线程锁，防止并发竞态条件
- **资源泄漏修复**：所有socket使用try-finally确保关闭，防止文件描述符泄漏
- **NTP时间同步**：使用NTP服务器获取真实UTC时间，不依赖系统时区设置，兼容所有环境

### v1.5.0 (2026-03-05)

**长期运行稳定性优化**
- **指数退避重试机制**：DNS更新失败时自动重试3次（间隔5s, 15s, 30s），应对网络波动
- **无状态设计**：每次调度从数据库重新加载设备配置，Web配置修改立即生效
- **24小时强制同步**：每隔24小时强制与DNS云端比对，确保记录一致性
- **超时控制**：所有DNS API请求都有超时保护
- **数据库自动瘦身**：每次更新后自动清理30天前的旧日志，防止数据库膨胀
- **IP频繁跳变保护**：5分钟内IP变化超过3次时自动触发15分钟冷却期，防止DNS服务商封禁
- **暗黑模式**：支持浅色/深色/自动三种模式，自动模式根据日落时间智能切换

### v1.4.0 (2026-03-05)

**核心优化**
- IPv6处理使用Python标准库`ipaddress`模块，替代字符串切割
- 添加IPv6地址过滤，只保留全球单播地址（GUA），过滤fe80::和fd00::
- SQLite添加超时参数（10秒），避免database is locked

**安全增强**
- DNS凭证（AccessKey）加密存储，使用Fernet对称加密
- Docker容器以非特权用户（ddnsuser）运行，提升安全性
- 自动创建加密密钥文件`data/.secret_key`

**代码清理**
- 删除无用的`.env.example`文件
- 移除`python-dotenv`依赖
- 所有配置通过docker-compose.yml环境变量管理

### v1.3.0 (2026-03-05)

**安全增强**
- 添加公网访问控制开关（默认关闭，仅允许内网访问）
- 添加登录失败次数限制（5次失败后锁定15分钟）
- 添加登录日志记录（记录到 data/logs/login-YYYY-MM-DD.log）

**日志优化**
- 统一使用logger，移除所有print语句
- 日志格式简化为：时间、级别、内容
- 日志轮转：按天生成文件，保留30天
- IP变化检测日志显示中文"是"/"否"

**Bug修复**
- 修复settings接口死循环问题（允许公网用户开启公网访问）
- 修复auth.py缺少hashlib导入的问题

### v1.2.1 (2026-03-05)

**Bug修复**
- 修复IPv6地址点击复制不生效的问题（添加备用复制方案）

**优化**
- 精简调度器日志，移除APScheduler内部日志，只保留业务日志

### v1.2.0 (2026-03-05)

**架构优化**
- 调度器从 schedule 迁移到 APScheduler（支持动态修改间隔、任务持久化）
- 添加 `/health` 健康检查接口
- SQLite 启用 WAL 模式，减少锁表

**功能增强**
- 设备列表增加状态图标（🟢在线/🟡更新中/🔴已禁用）

**Docker优化**
- 添加 healthcheck 健康检查
- Dockerfile 添加 curl 支持健康检查
- 调度器日志保存到 data/logs/scheduler.log（JSON格式）

**调度器增强**
- 添加任务执行日志（成功/失败/耗时）
- 添加 misfire_grace_time=60 秒容错
- 添加任务执行回调监听
- 线程池执行器（5线程），任务与Web隔离

**功能增强**
- 添加 `ip -6 route` 自动识别IPv6前缀（支持DHCPv6-PD）
- 跨平台支持：Windows使用netsh，Linux使用ip命令

### v1.0.1 (2026-03-05)

**Bug修复**
- 修复 `ipv4_changed` 未定义导致定时任务崩溃的问题
- 修复未配置DNS时显示"无需更新"而非"请先配置DNS"的问题

**优化**
- 优化删除设备交互体验：添加确认对话框和loading状态
- 前端多处API调用添加错误处理

## 目录结构

```
dnsv6/
├── app/                    # 应用代码
│   ├── main.py            # 入口文件
│   ├── models.py          # 数据模型
│   ├── routes/            # 路由
│   │   ├── api.py        # API 接口
│   │   ├── web.py        # Web 页面
│   │   ├── auth.py       # 认证
│   │   └── notify.py     # 通知
│   └── services/         # 业务逻辑
│       ├── ddns.py       # DDNS 核心
│       ├── ip_detector.py # IP 检测
│       ├── notifier.py   # 通知服务
│       └── dns_provider/ # DNS 商
├── templates/              # 前端页面
├── data/                  # 数据目录（运行时生成）
├── Dockerfile            # Docker 镜像配置
├── docker-compose.yml    # 容器编排配置
├── requirements.txt       # Python 依赖
└── README.md            # 使用说明
```

## 常见问题

### Q: 无法获取公网 IPv6？

A: 检查宿主机是否有公网 IPv6 访问能力。部分家庭网络可能没有公网 IPv6。

### Q: 阿里云 API 调用失败？

A: 确认 AccessKey 正确，且已开通阿里云 DNS 权限。

### Q: 如何修改登录密码？

A: 登录后点击右上角头像 -> 修改密码。

---

**注意**：请妥善保管阿里云 AccessKey，不要泄露到公开代码库中。
