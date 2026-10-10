# AI_CONTEXT — waywardkoi

> 给 AI 的交接文件。目标：读取本文件后**无需再遍历源码**即可作业。
> 生成基准：源码最后修改 `2026-06-18 19:12:36`；行号取自实际文件。
> 配套详述文档：`docs/CODEBASE_OVERVIEW.md`（人类可读，含 Mermaid 图与完整风险论证）。**本文件是索引与结论的压缩版；冲突时以源码为准。**

## 0. 使用须知（重要）

- 本文件**只覆盖已深读的模块**：`configd`、`mqtt`。带 🔸 的是**未深读**，勿据此下结论。
- 引用格式 `文件:行号`。已核对行号与内容一致，无陈旧偏移。
- 标注「不确定」处未经验证，勿当事实。

## 1. 一句话定位

Linux 物联网设备端 C 项目（**非 Windows、非 Web 前端项目**）。核心是一个自研 HTTP 网关 `configd`，用 `dlopen` 动态加载 `.so` 插件分发业务；三个插件分别管管理员认证、证书生命周期、MQTT 设备接入。

## 2. 技术栈 / 构建 / 运行

| 项 | 值 |
|---|---|
| 语言 | C（GNU/C99）+ Python3（仅阿里云 SDK 桥接）+ 单文件 HTML |
| 构建 | 目录级 `Makefile`，`gcc`，**无包管理器、无 CMake** |
| 系统依赖 | `libmicrohttpd` `cjson` `paho-mqtt3a/as/c` `protobuf-c` `openssl` `libcurl` `pthread` |
| 入口 | ① `workspace/configd/configd.c:749` main ② `workspace/mqtt/client/client.c:52` ③ `workspace/admin_auth/auth.c`（独立 login 程序） |
| 测试 | **完全没有**（无 test/、无 CI、无 .git） |
| 运行 | `make install` 后：`configd` 常驻 :8081 → 按 `/var/json/*.json` 路由 `dlopen` 插件 |

部署产物对照（`make install` 落点 = 排障时该找的真实文件）：

| 产物 | 安装路径 | 路由表 |
|---|---|---|
| `configd` | `/usr/local/bin/` | — |
| `libadmin.so` | `/lib/work_lib/` | `/var/json/admin.json` |
| `libcert_manager.so` | `/lib/work_lib/` | `/var/json/cert.json` |
| `libmqtt_config.so` | `/lib/work_lib/` | `/var/json/mqtt.json` |
| `mqtt_daemon` | `/usr/local/bin/` | — |
| `login` | `/usr/local/bin/` | — |
| `auth_config.json` | `/etc/auth_config.json` | （`auth.c:41` 读取） |
| `sms.conf` | `/etc/sms.conf` | （Python 脚本读取，**仓库内不存在**） |

## 3. 架构与进程模型

```
浏览器 ──Nginx(:443,TLS卸载)──┬─ /api/*   → auth:8080
                              └─ /config/ → configd:8081 ──dlopen──> 3 个 .so
                                                            │
                              libmqtt_config.so ──Unix socket /tmp/mqtt_daemon.sock──>
                                                            mqtt_daemon (client.c)
                                                              ├─ 父进程: mqtt_cmd_server_loop
                                                              ├─ CLIENT 子进程: 设备身份
                                                              └─ CLOUD  子进程: 云端身份
```

- `configd` **纯 HTTP 8081，不做 TLS**（`configd.c:774-782`）。TLS 由 Nginx 卸载（模板见 `configd.c:22-57`）。**`configd/cert/` 与 `admin_auth/cert/` 的证书未被代码引用。**
- `configd` 用 `MHD_USE_SELECT_INTERNALLY` 且**无线程池 → 单线程串行**（`configd.c:775-782`）。代码里的 `pthread_rwlock`/`refcnt` 当前不产生并发收益。
- 插件**不允许建 MQTT 连接**（`mqtt_plugin.c:4-5`），长连接全部交给独立守护进程 `mqtt_daemon`。
- `mqtt_daemon` **直接编译 `common/*.c`，不链接 `libmqtt_common.so`**（`plugin/Makefile:5,11`）；后者无消费者，属冗余产物。

## 4. 插件 ABI（改动业务的核心契约）

网关侧 typedef，`configd.c:550-551`：

```c
typedef char* (*plugin_func)(const char*, int*);
// in : data 对象序列化 JSON（无 data 时为 "{}"，configd.c:530）
// out: 出参 int* 写期望 HTTP 状态码（初值 200，configd.c:561）
// ret: 堆分配 JSON 字符串；返回 NULL → 网关回 -99（configd.c:566-569）
```

**三个插件已核对签名一致**：`char* f(const char *data_json, int *out_status)`。

## 5. 文件与符号索引

### 5.1 `workspace/configd/`（网关，已深读）

`configd.c` 804 行，单文件。

| 符号 | 行 | 备注 |
|---|---|---|
| `main` | 749 | 仅识别 `-d` 守护模式 |
| `ahc` | 582 | MHD 请求回调；**不校验 url**，所有路径等价 |
| `process_request` | 496 | 分发核心 |
| `get_real_client_ip` | 105 | **无条件信任** `X-Real-IP`/`X-Forwarded-For` |
| `is_https_from_nginx` | 150 | 读 `X-Forwarded-Proto`/`-Port` |
| `libcache_get` | 178 | 锁外 `dlopen`（`RTLD_LAZY\|RTLD_NODELETE`，:194） |
| `libcache_release` | 231 | `refcnt<=0` 时 `dlclose`（每请求一次，见 R3） |
| `is_path_safe` | 433 | 必须落在 `TRUSTED_LIB_DIR "/lib/work_lib/"`（:431） |
| `load_routes_from_file` | 316 | 校验 action/library/function 三字段 |
| `load_all_routes` | 383 | 扫 `/var/json/*.json`；O(n²) 查重仅告警 |
| `find_route` | 419 | 线性查找 |
| `send_json_response` | 467 | `MHD_RESPMEM_MUST_FREE` → **接管 json 所有权并 free** |
| `create_error_json` | 486 | 返回堆串，调用方释放 |
| `daemonize` | 711 | 双 fork；**成功分支未处理 fd 0**（:720-734） |
| `log_write` | 267 | 带 mutex；`g_log_fp` 空则退 stderr |
| 常量 | 84-89 | `PORT 8081`、`JSON_DIR /var/json`、`LOG_FILE /var/log/work_log/configd.log`、`MAX_BODY_SIZE 1MB`；`MAX_HEADER_SIZE`(:89) **未使用** |

错误码：`-1` 缺 action 或方法非 POST；`-2` 未知 action；`-3` JSON 非法；`-4` 插件路径不安全(403)/dlopen 失败(500)/dlsym 失败(500)；`-5` 超 1MB(413)/OOM(500)；`-99` 插件返回 NULL。

### 5.2 `workspace/mqtt/`（已深读）

| 文件 | 行 | 职责 |
|---|---|---|
| `common/mqtt_lib.c` | 624 | 配置加载 + Unix socket 服务端 + `mqtt_cmd_handle` |
| `common/mqtt_lib.h` | 178 | `Context`(:39) `Mqtt_data`(:79) `MsgTypeConfig`(:72)；`CONFIG_FILE_PATH`(:25) **硬编码** |
| `common/mqtt_cmd.h` | 43 | 命令协议常量 + `MqttCmd`(:23) `MqttCmdResp`(:28) |
| `common/mqtt_cmd.c` | 46 | `mqtt_cmd_send`(:4)，**当前无调用方** |
| `common/client_auth.c` | 1556 | **核心业务**：连接/认证握手/上报/落盘 |
| `common/sensor.proto` | 8 | `SensorData{device_id,timestamp,value,type,payload_json}`；`.pb-c.*` 是生成物 |
| `client/client.c` | 186 | 守护进程入口：socket→双 fork→pipe→父进程收命令 |
| `plugin/mqtt_plugin.c` | 738 | 13 个 action |
| `plugin/cloud_server.{c,h}` | 393/52 | **孤儿代码**（见 §9） |
| `plugin/device_client.{c,h}` | 294/37 | **孤儿代码**（见 §9） |
| `file/mqtt.json` | 83 | 13 条路由 |
| `file/config.json` | 22 | Broker/主题/QoS/TLS/凭据 |

`mqtt_lib.c` 关键符号：`config_init`(:42，失败即 `exit(1)`)、`config_get_string`(:82)、`config_get_int`(:96)、`config_get_msg_array`(:111)、`mqtt_config_load`(:143，**忽略 path 参数**)、`mqtt_config_free`(:246，**顺带销毁全局 `g_config_root`**)、`mqtt_cmd_server_create`(:272，**`chmod 0666`** :288)、`mqtt_cmd_server_loop`(:499，`while(1)`)、`mqtt_cmd_handle`(:308)、`mqtt_generate_random_string`(:551，`srand(time(NULL))+rand()`)、`save_auth_channel`(:583，**写回 config.json 本体**)、`save_devices_list`(:611，写 `/tmp/mqtt_devices.json`，**无调用方**)；全局 `g_client_cmd_fd`(:36)。

`client_auth.c` 关键符号（42 个函数）：`write_client_auth_status`(:54)、`get_system_info_json`(:85)、`get_hardware_info_json`(:164)、`pb_encode_sensor_data`(:285)、`send_device_info`(:309)、`send_hardware_info`(:325，**不更新 last_send**)、`send_network_info`(:340)、`send_log_info`(:356)、`send_all_enabled_msgs`(:373)、`get_next_timeout_ms`(:408)、`handle_epoll_timeout`(:453)、`mqtt_onConnect`(:512)、`mqtt_connlost`(:554)、`cloud_dev_msg_subscribe`(:610，无调用方)、`cloud_store_device_data`(:637)、`cloud_remove_device`(:697)、`cloud_save_device`(:746)、`cloud_msg_mqtt_handle`(:816)、`client_msg_mqtt_handle`(:947)、`mqtt_msgarrvd`(:1032)、**`mqtt_msg_handle`(:1107，子进程主函数)**、`async_send`(:1537)；全局 `mqtt_usr`(:38) `g_mqtt_data`(:41) `sub_finished/sub_subscribed/sub_disc_finished`(:34-36)。

`mqtt_plugin.c`：`log_write`(:34)、`on_plugin_load`(:54，`__attribute__((constructor))`)、`create_response`(:59)、`send_cmd_to_daemon`(:74，**recv 无超时** :108)、`ensure_work_dir`(:261)、`base64_encode/decode`(:270/:290)。

### 5.3 🔸 未深读（勿臆断）

- `workspace/admin_auth/auth.c` 1738 行 — 仅知：`AUTH_CONFIG_FILE /etc/auth_config.json`(:41)、`TOKEN_SECRET` 硬编码(:56)、`generate_token`(:883)、`verify_password`(:295)、`hmac_sha256` 用于签名(:889)、`auth.c:1168,1182` 两处 `TODO: 验证App Token`。
- `workspace/admin_auth/admin_plugin.c` 918 行 — 仅知：8 个 `admin_*` action，`hash_password`(:160) 用 **SHA256 裸哈希无盐**，`validate_password`(:221)、常用密码表(:47-70)、`admin_plugin.c:117` 默认口令哈希取自字面量 `"passwd"`。
- 🔸 `workspace/cert_manager/cert_plugin.c` 488 行 — 仅知：9 个 action，多处 `system(cmd)` 拼串(:135,136,165,434,514) 与 `popen`(:174,184)，`TODO: 调用邮件发送接口`(:538)。
- 🔸 `workspace/libs/`：`sms/`(C+popen 调 py :73,115)、`email/`、`totp/`(RFC6238，`totp_verify`(:197) `totp_generate_secret`(:270))、`cert/`(`cert_init`(:188))。**未深读，细节勿断言。**
- 🔸 `workspace/mqtt/plugin/cloud_server.c` `device_client.c`：**孤儿代码**，不在 `plugin/Makefile:11,14` 源列表，全库无 `#include`。
- `workspace/game.html` 1134 行：孤立页面，已扫确认**无密钥、无后端地址**。

## 6. 数据模型（无数据库，全是文件）

| 载体 | 结构 | 生产 → 消费 |
|---|---|---|
| `/tmp/cloud_devices.json` | `{"devices":[{dev_uuid,data_types,auth_time,online}]}` | `cloud_save_device:746` → `mqtt_lib.c:437` |
| `/tmp/cloud_device_<uuid>.json` | `{device:{},hardware:{},network:{},log:{}}` | `cloud_store_device_data:637` → `mqtt_lib.c:466` |
| `/data/work/client_auth_status` | 整数 0/1 | `client_auth.c:54` → `mqtt_plugin.c:711` |
| `/data/work/mqtt_test_result.json` | `{test_ok,msg,dev_uuid}` | `client_auth.c:973` → `mqtt_plugin.c:577` |
| `/data/work/client_state.b64` | base64(JSON) | `mqtt_plugin.c:666` → `:694` |
| `/data/work/mqtt_addr.b64` | base64(地址) | `mqtt_plugin.c:322` → `:360` |
| `<CONFIG_FILE_PATH>` | 原配置 + `auth_channel` 字段 | `mqtt_lib.c:588` → `client_auth.c:1177` |
| 🔸 `/data/admins.json` | 管理员表（`admin_plugin.c` 内） | 未深读 |

`SensorData`（proto3）：`device_id`=1,`timestamp`=2,`value`=3,`type`=4,`payload_json`=5。**`value` 恒为 `0.0`（`client_auth.c:290`），真数据在 `payload_json`**；Protobuf 只当「带元数据的信封」。

## 7. MQTT 主题与命令协议

主题（全部经载荷字段嗅探路由，非主题分层）：

| 主题 | pub → sub | 载荷 |
|---|---|---|
| `client/auth` | CLIENT→CLOUD | `{auth_request:1,dev_uuid,upload_types[]}` / `{test:1,dev_uuid}` / `{device_stop:1,dev_uuid}` |
| `cloud/auth` | CLOUD→CLIENT | `{authorized:true,dev_channel,net_channel,log_channel}` |
| `cloud/<uuid>/test` | CLOUD→CLIENT | `{test_ok,msg,dev_uuid}` |
| `client/dev/<ch>` `client/net/<ch>` `client/log/<ch>` | CLIENT→CLOUD | `SensorData`(type=device/hardware/network/log) |
| `client/dev/#` `client/net/#` `client/log/#` | sub | CLOUD 通配订阅(:912-914) |

命令协议 = **裸结构体直传，等价 ABI，无版本号**（`mqtt_cmd.h:23-32`；`MqttCmd` 1028B / `MqttCmdResp` 1284B）：

| cmd | 值 | 转发到 client 子进程 |
|---|---|---|
| `CMD_DEVICE_AUTH` | 1 | ✅ |
| `CMD_DEVICE_STOP` | 2 | ✅ |
| `CMD_CLOUD_CONNECT` | 3 | ❌ **空操作** |
| `CMD_CLOUD_DISCONNECT` | 4 | ❌ **空操作** |
| `CMD_GET_DEVICES` | 5 | ❌ |
| `CMD_GET_DEVICE_DETAIL` | 6 | ❌ |
| `CMD_DEVICE_TEST` | 7 | ✅ |

## 8. 三条核心链路（编号步骤）

**A. 设备认证握手**
1. 前端 `device_auth` → 插件 → socket → 父进程回 `code=0` → `write(pipe)`
2. CLIENT 子进程 epoll 唤醒(:1336)，解析 `data_types` 设三类 enabled(:1363-1393)
3. publish `client/auth` `{auth_request:1,...}`(:1400-1412)
4. CLOUD 子进程 `mqtt_msgarrvd` 嗅探 `auth_request`(:1051) → `cloud_msg_mqtt_handle`(:816)
5. `mqtt_generate_random_string` 生成 20 位通道 ID(:892) → 拼 dev/net/log(:897-899)
6. 订阅三通配(:912-914) → `cloud_save_device`(:920)
7. publish `cloud/auth`(:928-935)
8. CLIENT 收 `client_msg_mqtt_handle`(:947) → 置 `client_auth_received=1`(:1011)
9. `save_auth_channel` 写回 config.json(:1014) + `write_client_auth_status(1)`(:1015)
10. `send_all_enabled_msgs(initial=1)` 首报(:1021)
- ⚠️ 认证**异步**：`device_auth` 返回 200 ≠ 已授权，前端须另查。

**B. 定时上报**
`epoll_wait` 超时(:1320) → `handle_epoll_timeout`(:453) → 校验 `client_auth_received`(:454) → 三类各自到期判断 → `pb_encode_sensor_data`(:285) → `async_send`(:1537)。
- 间隔来源两层：`config.json:12-14` + 前端 `data_types`（只覆盖 enabled）；network/log 间隔**硬编码 30/60**（:1130,:1135）。

**C. 连通性测试 `device_test`**（唯一横穿全链路，排障首选）
1. `device_test`(:464) → socket + `SO_RCVTIMEO 5s`(:523-525) → `CMD_DEVICE_TEST`
2. 父进程转发并回 `code=0`(:331-343)
3. `unlink` 旧结果(:565) → **进入 200ms×25 轮询(:573-599)**
4. CLIENT 订阅 `cloud/<uuid>/test`(:1442-1447) → publish `{test:1}`(:1453-1457)
5. CLOUD 识别 test(:834-835) → publish 结果(:871-875)
6. CLIENT 写 `/data/work/mqtt_test_result.json`(:973-981)
7. 插件读到 → 解析(:577-597) → 返回 `{passed,msg}`
- ⚠️ 该请求会**阻塞网关最多 5 秒**；且 daemon 不可用/出错都返回 HTTP 200+`code:0`+`passed:0`，前端只能看 `passed`。

## 9. 风险清单（仅已深读模块；每条带证据）

| ID | 级别 | 问题 | 证据 |
|---|---|---|---|
| R1 | 高 | 网关**零鉴权**，管理能力全暴露 | `configd.c:496-572` 无 token 校验 |
| R2 | 高 | CORS `*` 且 `Allow-Credentials: true` | `configd.c:478` + `:623` |
| R21 | 高 | `device_test` 同步阻塞 5s **冻结整个网关** | `mqtt_plugin.c:573-599` + `configd.c:775-782` |
| R16 | 高 | Unix socket `chmod 0666`，任意本地用户可下发命令 | `mqtt_lib.c:288` |
| R18 | 高 | 授权态写进 config.json，**重启免认证直接上报**，无 TTL | 写 `client_auth.c:1014`→`mqtt_lib.c:591`；读 `:1177-1184` |
| R15 | 高 | 命令协议裸结构体无版本号，版本不一致只读出错乱数据 | `mqtt_cmd.h:23-32`、`mqtt_cmd.c:30` |
| R25 | 中 | 通道 ID 用 `srand(time(NULL))+rand()`，26 小写字母，**是数据唯一凭据** | `mqtt_lib.c:551-562`、`client_auth.c:892` |
| R26 | 中 | `/tmp/cloud_device_<dev_uuid>.json` 路径由**攻击者可控的 dev_uuid** 拼接，未过滤 `/` `..` | `client_auth.c:657,700`、`mqtt_lib.c:365,467` |
| R3 | 中 | 插件**每请求 `dlclose`**，static 状态语义脆弱 | `libcache_release:237-243`、`process_request:564` |
| R5 | 中 | 单线程无超时；插件内同步 `system("openssl")` 会冻结网关 | `configd.c:775-782`、`cert_plugin.c:165` |
| R4 | 中 | 客户端 IP 可伪造（无条件信任转发头） | `configd.c:111-132` |
| R6 | 中 | 路由无热重载；重复 action 仅告警、结果依赖 `readdir` 顺序 | `configd.c:404-410` |
| R19 | 中 | 节流逻辑重复两处且已语义漂移 | `client_auth.c:373-404` vs `:453-475` |
| R20 | 中 | `send_hardware_info` 不更新 `last_send`，节流失效 | `client_auth.c:337` |
| R22 | 中 | 靠载荷字段嗅探路由，`mqtt_data->type` 是上轮遗留状态 | `client_auth.c:1046-1057` |
| R23 | 中 | 用全局变量做进程角色判别（`mqtt_usr`/`g_mqtt_data`/`sub_*`） | `client_auth.c:34-41,1042,1278` |
| R24 | 中 | 二进制 Protobuf 当字符串打日志 | `client_auth.c:1036-1037,862,953` |
| R17 | 中 | base64 当加密用（存地址/状态） | `mqtt_plugin.c:270,290` |
| R27 | 低 | `mqtt_config_free` 顺带销毁全局配置，副作用非直觉 | `mqtt_lib.c:246-252` |
| R28 | 低 | `get_config` 把整份 config.json（含账号）返回 | `mqtt_plugin.c:217-251` |
| R29 | 低 | 孤儿代码 776 行 + 误导性 TODO | `cloud_server.c/h`、`device_client.c/h` 无引用；`device_client.c:236` |
| R7 | 低 | 工作区曾存在**过期/不完整产物** | `configd` 早于 `configd.c`；`libadmin.so` 从未存在 |
| R8 | 低 | `is_path_safe` 前缀比较非目录边界；`..` 检查是死代码 | `configd.c:450-460` |
| R9 | 低 | 每请求打 INFO 日志；日志**无轮转** | `configd.c:462,497`；`init_log:304` |
| R11 | 低 | `daemonize` 成功分支未处理 fd 0 | `configd.c:720-734` |
| R13 | 低 | `ahc` 不校验 URL，所有路径等价（依赖 Nginx 隔离） | `configd.c:582-696` |
| R31 | 低 | `mqtt_cmd_server_loop` 无退出路径，`EINTR` 未单独处理 | `mqtt_lib.c:505,512` |
| R32 | 低 | `get_next_timeout_ms` 秒/毫秒混用同一变量 | `client_auth.c:414,449` |
| R33 | 低 | cloud 子进程把同一 fd 注册 epoll 两次，`EEXIST` 被静默容忍 | `client.c:116-117`、`client_auth.c:1295,1305` |

**源码内硬编码密钥（.gitignore 拦不住，必须改代码）**：`workspace/admin_auth/auth.c:56` `#define TOKEN_SECRET "your-secret-key-change-in-production-2025"`（用于 `:889` HMAC 签名登录 Token）。

## 10. 改什么动哪里

| 需求 | 要动的文件 |
|---|---|
| 加/改业务接口 | 对应插件 `.c` + `/var/json/*.json`；**不必改 `configd.c`** |
| 改请求/响应包格式 | `configd.c:496-572` + **全部**插件 |
| 加网关鉴权 | `configd.c:516-541` 之间插入 + 前端/Nginx |
| 提高并发 | `configd.c:775-782` + 三插件线程安全审计 |
| 改端口/日志/体积上限 | `configd.c:84-88` |
| 改受信插件目录 | `configd.c:431` + 各 `Makefile` install |
| 改 MQTT 命令协议 | `mqtt_cmd.h` + `mqtt_cmd.c` + `mqtt_lib.c:499-545` + `mqtt_plugin.c:74-117`（**插件与 daemon 须同时重编重装**） |
| 改上报频率/开关 | `mqtt/file/config.json:12-14` + `client_auth.c:1129-1137`（硬编码间隔）+ `:1363-1393` |
| 改 Broker/TLS | `config.json` + `client_auth.c:1236-1260`（首连）**和** `:572-601`（重连，两处须同步） |
| 改认证握手 | `client_auth.c:1344-1415` + `:816-944` |
| 改设备数据落盘 | `client_auth.c:637` + `mqtt_lib.c:432-487` + `mqtt_plugin.c:183-216` |
| 改连通性测试 | `mqtt_plugin.c:464-624` + `client_auth.c:1416-1463,858-885,962-988` |
| 删孤儿代码 | `mqtt/plugin/cloud_server.{c,h}`、`device_client.{c,h}`（确认 Makefile 未引用即可安全删） |
| 改配置文件路径 | `mqtt_lib.h:25` + `mqtt_plugin.c:221`（**两处硬编码须同步**）+ Makefile install |

## 11. 与 Git 上传相关的当前状态

- 12 个敏感文件（5 私钥 + 5 `.crt` + `auth_config.json` + `config.json`）已移入 `waywardkoi_secrets/`（仓库根下的隔离目录），并由 `.gitignore:14` 保护。
- 3 个二进制（`configd`、`libcert_manager.so`、`-Wall`）已删除。
- 仓库内已校验**无** `.key`/私钥内容/AccessKey/Broker IP/明文口令。
- ⚠️ `waywardkoi_secrets/` 在仓库**内部**，仅靠 `.gitignore` 保护；网页端整目录上传或无视 ignore 的客户端仍会带上去。
- ⚠️ 移出后 `make install` 会因缺这些文件失败；真实配置应部署到 `/etc/auth_config.json` 与 `/etc/sms.conf`。

## 12. 未验证 / 不确定（勿当事实）

- 🔸 `auth.c`、`admin_plugin.c`、`cert_plugin.c`、`libs/*` 的函数级细节与数据表结构**未深读**。
- 「`login` 与网关鉴权是否断链」——**未完成调查**。已知线索：`login` 是独立可执行程序；`auth.c:1168,1182` 有 `TODO: 验证App Token`；`configd` 零鉴权（R1）。方向：查 `login` 签发什么、网关是否本该校验、`auth_config.json:57-63` 的 `role` 由谁强制。
- `configd/cert/`、`admin_auth/cert/` 的证书**是否被 Nginx 实际使用未知**（代码未引用）。
- `mqtt_common.so` 是否被工作区外的东西链接——未查。
- 本文件行号基于 `2026-06-18` 源码；若源码变动需重新核对。
