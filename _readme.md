# gsignver — 通用软件激活码服务端

纯 Go 标准库实现的软件授权服务端：**零第三方依赖、单文件存储、落盘加密、容器内约 3 MB 内存**。

- 协议规范（唯一真源）：[SPEC.md](SPEC.md)
- 适用场景：桌面/移动软件的正版授权、订阅校验、功能开关下发、多设备管理
- 已在 1 GB 内存的 ARM64 设备上以 scratch 容器实际部署验证

---

## 目录

1. [它解决什么问题](#1-它解决什么问题)
2. [快速开始](#2-快速开始)
3. [运行原理](#3-运行原理)
4. [HTTP 接口](#4-http-接口)
5. [配置](#5-配置)
6. [部署](#6-部署)
7. [数据目录与备份](#7-数据目录与备份)
8. [实测数据](#8-实测数据)
9. [安全模型与取舍](#9-安全模型与取舍)
10. [测试](#10-测试)
11. [代码结构](#11-代码结构)
12. [常见问题](#12-常见问题)

---

## 1. 它解决什么问题

软件需要「证明用户有资格使用」。常见的三种做法各有毛病：

| 做法 | 问题 |
|---|---|
| 客户端本地校验 | 客户端可被破解，判定逻辑全在攻击者手里 |
| 每次启动联网校验 | 断网就不能用，服务端压力大 |
| 简单序列号 | 一码多机、无法吊销、无法踢设备 |

gsignver 给出的是第四条路：**一次激活换取长期凭据，之后按需联网**。

- 激活时服务端下发一张**由服务端私钥签名的许可证**（`license`），客户端内置应用公钥，可离线验证真伪与有效期
- 同时下发一把**每设备唯一的对称密钥 K**，之后业务通信全部加密
- 服务端保存设备列表，用户可查看与踢出；配额、吊销、续期都在服务端裁决
- 客户端**不需要**任何私钥签名能力，也不需要计算设备指纹

---

## 2. 快速开始

    # 构建（无第三方依赖，不需要联网拉包）
    go build -o gsignver ./cmd/gsignver
    go build -o gsigtest  ./cmd/gsigtest

    # 1) 创建应用：输出客户端要内置的应用公钥
    ./gsignver init -data ./data -app com.example.app -name "示例应用" -max-devices 3

    # 2) 签发激活码：明文只打印这一次
    ./gsignver issue -data ./data -app com.example.app -edition pro -features export,api

    # 3) 启动服务
    ./gsignver serve -data ./data -addr :8080

    # 4) 用虚拟验证客户端跑一遍协议场景
    ./gsigtest -url http://127.0.0.1:8080 -app com.example.app -pub <应用公钥> -code <激活码>

预编译二进制见 [Releases](https://github.com/wzmwayne/gsignver/releases)（amd64 / arm64 / armv7 / armv6）。

---

## 3. 运行原理

### 3.1 全局视图

整条链路只有三把密钥在起作用，各自的职责不重叠：

    客户端                                          服务端
    ┌──────────────────────┐                     ┌────────────────────────────┐
    │ app_pub（内置）        │                     │ app_priv（master key 封装）  │
    │ device_enc_priv/pub   │                     │ master key                 │
    │ K（对称，激活后持有）    │                     │ KV：应用/码/许可证/设备/K/nonce │
    │ license（服务端签名）   │                     └────────────────────────────┘
    └──────────────────────┘

| 密钥 | 算法 | 谁生成 | 谁持有 | 用途 |
|---|---|---|---|---|
| app_priv / app_pub | Ed25519 | 服务端 | 私钥只在服务端（KMS 封装） | **服务端签名响应**，客户端用内置公钥验签 |
| device_enc_priv / device_enc_pub | X25519 | 客户端 | 私钥永不出设备 | 一次性接收对称密钥 K |
| K | AES-256 | 服务端 | 双方各存一份 | 业务请求与响应的对称加密 |

关键点：**客户端没有签名私钥**。它证明「我是合法设备」的方式是「我能生成用 K 加密的合法密文」——
AES-GCM 的认证标签本身就是凭据。这让客户端实现变得极简（不需要 Ed25519 密钥对、不需要请求签名）。

### 3.2 外层信封

所有请求与响应都是同一个 JSON 信封：

    {
      "app_id":    "com.example.app",
      "device_id": "srv_01J8XK...",     // 未注册的请求固定填 "anonymous"
      "data":      "标准 Base64",
      "sig":       "Base64URL 无填充"    // 只出现在响应里
    }

- `data` 用**标准 Base64（带 = 填充）**，`sig` 用 **Base64URL 无填充**
- 签名覆盖的是 **data 这个字符串的 UTF-8 字节**，不是 JSON 对象、不是解码后的明文
  （这样两端不必就 JSON 键序、空格、转义达成一致）
- **不签 `app_id`、不签 `device_id`**

### 3.3 一次激活的完整过程

    客户端                                            服务端
      │  ① 本地生成 X25519 密钥对 device_enc            │
      │  ② nonce = 16 字节随机                          │
      │  ③ data = base64(激活请求 JSON)                 │
      │     {action, activation_code, device_desc,      │
      │      device_enc_pub, nonce, ts}                 │
      │  ④ {app_id, device_id:"anonymous", data}        │
      ├────────────────────────────────────────────────►│
      │                                                 │ ⑤ 按 app_id 找应用配置
      │                                                 │ ⑥ code_hash = HMAC(pepper, app_id:码)
      │                                                 │ ⑦ 查码、校验状态/过期/nonce/ts
      │                                                 │ ⑧ 【事务】认领 nonce
      │                                                 │     统计该码 active 设备数
      │                                                 │     满 → 2003；超 → 2007；否则继续
      │                                                 │ ⑨ 生成 device_id（ULID + 查重）
      │                                                 │ ⑩ K = 32 字节随机
      │                                                 │ ⑪ enc_key = Seal(device_enc_pub, K)
      │                                                 │ ⑫ 写 DEVICES / LICENSES / SHARED_KEYS
      │  ⑬ {app_id, device_id, data, sig}                │ ⑬ 组装响应 JSON → 签名
      │◄────────────────────────────────────────────────┤
      │  ⑭ 用内置 app_pub 验 sig（不通过直接丢弃）         │
      │  ⑮ 检查 nonce 回显、ts 合理                      │
      │  ⑯ K = Unseal(device_enc_priv, enc_key)          │
      │  ⑰ 保存 device_id / K / license                  │
      │  ⑱ device_enc 密钥对完成使命，此后不再使用         │

第 ⑧ 步的「认领 nonce + 数设备 + 建身份」必须在**同一个事务**里完成，否则并发请求会
双双通过配额检查（见 3.10）。

### 3.4 一次业务请求的完整过程

    客户端                                            服务端
      │  ① data = base64( IV(12) ‖ AES-GCM(K, JSON) ‖ tag(16) )
      │  ② {app_id, device_id, data}   ← 没有 sig
      ├────────────────────────────────────────────────►│
      │                                                 │ ③ 按 (app_id, device_id) 取 K
      │                                                 │ ④ GCM 解密并认证
      │                                                 │    失败/密钥已销毁 → 1010，直接拒
      │                                                 │ ⑤ 解出 JSON，校验 nonce / ts
      │                                                 │ ⑥ 校验 license 归属、状态、有效期
      │                                                 │ ⑦ 执行动作（列设备/踢设备/续期/取数据）
      │                                                 │ ⑧ 更新 last_seen_at
      │                                                 │ ⑨ 用 K 加密响应
      │  ⑩ {app_id, device_id, data, sig}                │ ⑩ 再签上应用私钥
      │◄────────────────────────────────────────────────┤
      │  ⑪ 验 sig（不通过直接丢弃）                        │
      │  ⑫ 用 K 解密 → JSON → 业务对象                    │

### 3.5 为什么请求不签名、响应要签名

| 方向 | 认证手段 | 理由 |
|---|---|---|
| 请求 | K 的 AES-GCM 认证标签 | 只有持有 K 的一方能生成合法密文；篡改任何一个字节都会导致认证失败 |
| 响应 | 应用私钥签名 **+** K 的认证标签 | 客户端需要独立于 K 确认「这确实来自服务端」；K 只证明「能解开」，不证明「谁写的」 |

如果响应只靠 K 加密，那么任何拿到过 K 的人（例如设备本身被入侵）都能伪造服务端响应。
加上应用签名后，伪造响应需要应用私钥，而应用私钥永远不下发。

### 3.6 服务端内部：一次请求穿过哪些层

    HTTP 请求
     └─ internal/server     路由、请求体限长、限流、信封解析
         └─ internal/wire   状态码、Base64 约定、载荷结构
             ├─ internal/store  领域仓储（读写在事务里）
             │    └─ internal/kv  内存索引 + 追加日志 + 快照 + 排他锁 + 落盘加密
             └─ internal/cryptox  Ed25519 验签/签名、AES-GCM、X25519 封装
                  └─ internal/kms  master key / pepper、子密钥派生、私密材料封装

一次 `/v1/activate` 的具体路径：

    handleActivate
      ├─ readEnvelope        限长 64 KiB、JSON 解析、必填字段检查
      ├─ gate                限流桶 ip:<IP> 与 app:<app_id>
      ├─ 校验 device_id == "anonymous"
      ├─ Base64 解码 data → 解析 ActivateRequest → 校验 action/nonce/ts/device_desc
      ├─ codeHash = kms.CodeHash(app_id, 激活码)
      ├─ gate                限流桶 code:<code_hash>
      ├─ repo.Update( 事务 )
      │    ├─ 查应用、查激活码、校验状态与有效期
      │    ├─ ClaimNonce              ← 原子认领，重复即 1004
      │    ├─ CountActiveDevices      ← 配额判定
      │    ├─ 生成 device_id / K / license
      │    ├─ 写 DEVICES / LICENSES / SHARED_KEYS / 次级索引
      │    └─ 组装响应并签名
      └─ writeEnvelope       形态 A 响应

### 3.7 KV 引擎如何工作

不使用 SQLite，也不使用任何第三方库，`internal/kv` 是一个为「单写者 + 小数据量」场景设计的嵌入式存储。

**写入路径**

    db.Update(fn)
      ├─ 持有互斥锁
      ├─ fn 在内存 map 上做「读-改-写」，此时尚未提交
      ├─ fn 返回 nil  → 把写集编码成记录，追加到 kv.log
      ├─ fsync        → 落盘成功后才更新内存并返回
      └─ 日志超过阈值 → 压缩为 kv.snapshot 并清空日志

**读取路径**：`db.View(fn)` 持同一把锁直接读内存 map，因此看到的永远是完整一致的状态。

**落盘记录格式**

    [4B 长度][载荷][4B CRC32]
    载荷     = [1B 加密标记][ 明文记录体 或 AES-GCM(记录体) ]
    记录体   = [1B 操作][4B 键长][4B 值长][键][值]

**崩溃恢复**

    载入 kv.snapshot
      └─ 顺序重放 kv.log
           └─ 遇到长度不足或 CRC 不符 → 停止，并把文件截断到最后一条完整记录

最后一条规则保证「断电写了一半」不会污染数据：半条记录会被识别并丢弃，文件回到最后一个一致点。

**事务的意义**：`Update` 的回调在一把互斥锁内串行执行，回调成功才落盘。
所以「读计数 → 判断 → 写设备」这个序列天然原子，这正是并发配额不会被打穿的原因。

**排他锁**：打开数据目录时对 `kv/kv.lock` 加 flock。第二个进程会启动失败并给出明确报错，
而不是两个进程互相覆盖日志。代价是**同一 data 目录只能有一个进程**（见 3.12）。

### 3.8 落盘加密如何工作

KV 的文件读写层定义了一个可插拔的加密接口：

    type Cipher interface {
        Encrypt(plain []byte) ([]byte, error)
        Decrypt(blob  []byte) ([]byte, error)
    }

- 内置实现是 AES-256-GCM，密文格式 `nonce(12) + ct + tag(16)`
- 服务端默认启用，密钥由 master key 经 HKDF-SHA256 派生：
  `HKDF(master, info="gsignver/kv/v1", 32)`
- 加密粒度是**每条日志记录**与**整个快照**
- 每段落盘数据带 1 字节标记（0 = 明文，1 = 密文），因此：
  - 明文数据可以被启用加密的进程直接读入，之后新写入自动转为密文（平滑迁移）
  - 加密数据如果没有提供相同的密钥，**打开时报错**，而不是静默损坏
- CRC32 覆盖的是**加密后的字节**，所以截断检测依然有效

想换成其它 AEAD 或接外置 KMS，只要实现 `Cipher` 即可。

**关于 master key**：默认首次启动生成 `keys/master.key`。生产环境应当用环境变量注入
（`GSIGNVER_MASTER_KEY`），否则加密密钥和数据文件躺在同一个目录里，
主机一旦被攻破两者同时泄露，加密就失去意义。

### 3.9 防重放：nonce + 时间戳

每个请求都带 `nonce`（16 字节随机）与 `ts`（Unix 秒）：

- 服务端在事务内**原子认领** nonce，已存在则返回 `1004`
- `ts` 与服务端时间相差超过 300 秒则返回 `1003`
- 过期 nonce 由后台任务定期清理（默认 10 分钟一次，TTL 10 分钟）
- 响应会**原样回显** nonce，客户端比对，防止响应被重放或串线

由于请求方向没有签名，攻击者无法伪造新请求，但可以重放抓到的密文——
nonce 去重正是挡住这条路的关键。

### 3.10 设备配额与并发

配额判定必须在事务内完成，否则两个并发请求会双双读到「还有空位」：

| 实现方式 | 结果 |
|---|---|
| 检查与写入都不加锁 | 8 个并发请求 → 写入 2 行，突破配额 |
| 只给写入加锁 | 同样突破配额 |
| **检查 + 写入在同一临界区** | 8 个并发请求 → 只写入 1 行，其余返回 2003 |

`repo.Update` 把回调整个放进临界区，因此第三种是默认行为。真机实测：
`max_devices=1` 时 5 个并发激活 → 1 成功 / 4 被拒。

### 3.11 限流

- 维度：`ip:<客户端IP>`、`app:<app_id>`、`code:<激活码摘要>` 三种桶
- 规则：同一桶内累计失败 10 次 → 锁定 1 小时 → 返回 `429`；任一请求成功即清空该桶
- 只有「参数错误 / 时间戳过期 / nonce 重放 / 激活码无效 / 应用不存在」计入失败，
  配额已满（2003）与内部错误不计

### 3.12 多实例：为什么要各自独立的数据目录

KV 的设计前提是**单写者**：内存里保存全量数据，写入靠追加日志。
如果两个进程同时打开同一目录，各自的日志会互相覆盖，数据必然损坏。
所以打开时加排他 flock，第二个进程直接失败。

在 1 GB 的类树莓派上跑多副本时，请任选其一：

1. **按 app_id 分片（推荐）**：每个副本一份独立数据卷，网关按 `app_id` 路由。
   应用之间本来就不共享状态（各自独立的密钥与激活码命名空间），天然可拆。
2. **每应用一实例**：同上，只是粒度更细。
3. **单实例多应用**：一个副本承载全部应用。实测容器内约 3 MB，普通场景完全够用。

不支持的是「多副本共享同一 data 目录」——当前没有复制或共识机制。

---

## 4. HTTP 接口

    POST /v1/activate            激活（data 为明文 JSON）
    POST /v1/biz                 业务动作（data 为 K 加密的 JSON）
    POST /v1/emergency/kickout   紧急踢出最早注册的设备（未激活可用）
    GET  /v1/health              健康检查
    GET  /admin/v1/apps          管理：列应用（需 Bearer 令牌）
    POST /admin/v1/apps          管理：创建/更新应用
    POST /admin/v1/codes         管理：签发激活码

请求体上限 64 KiB，超限返回 1007。

### 4.1 响应的两种形态

| 形态 | HTTP | 内容 | 用在什么时候 |
|---|---|---|---|
| **A** | 200 | 信封 + 签名 | 所有成功响应；`/v1/biz` 上解密成功后的业务错误（data 仍加密） |
| **B** | 4xx / 5xx | 裸 JSON `{code, message}` | 拿不到 K 的场景：激活与紧急接口的一切错误、`/v1/biz` 解密前的失败 |

客户端按 HTTP 状态码区分，不需要额外标志位。

### 4.2 业务动作（`/v1/biz` 的 `action`）

| action | 说明 |
|---|---|
| `list_devices` | 列出同一激活码下的全部设备 |
| `remove_device` | 踢出指定设备（`target_device_id`），或删除自己 |
| `refresh` | 刷新许可证：重读套餐配置并滑动续期 |
| `fetch_data` | 取服务端持有的业务数据（`key`），演示敏感操作的服务端校验 |

### 4.3 管理接口

KV 有排他锁，**服务端运行期间另一个进程打不开数据目录**，所以不能靠再跑一次
`gsignver issue` 发码。管理接口让发码在服务端进程内完成：

    # 服务端启动前设置令牌
    export GSIGNVER_ADMIN_TOKEN=<随机令牌>

    # 未运行时：直接读写数据目录
    ./gsignver issue -data ./data -app com.example.app -edition pro

    # 运行中：走管理接口
    ./gsignver issue -admin-url http://127.0.0.1:8080 -admin-token <令牌> \
                     -app com.example.app -edition pro

未设置 `GSIGNVER_ADMIN_TOKEN` 时，`/admin/v1/*` 返回 404。
若用隧道向外暴露本服务，**务必不要放行 `/admin/` 前缀**。

---

## 5. 配置

命令行参数优先于环境变量。

| 参数 | 环境变量 | 默认值 | 说明 |
|---|---|---|---|
| `-data` | `GSIGNVER_DATA` | `./data` | 数据目录 |
| `-addr` | `GSIGNVER_ADDR` | `:8080` | 监听地址（serve） |
| `-prune` | — | `10m` | 过期 nonce 清理周期，0 关闭 |
| `-admin-url` | `GSIGNVER_ADMIN_URL` | 空 | 设置后 CLI 走管理接口 |
| `-admin-token` | `GSIGNVER_ADMIN_TOKEN` | 空 | 管理接口令牌；同时用于服务端鉴权 |

| 环境变量 | 说明 |
|---|---|
| `GSIGNVER_MASTER_KEY` | 32 字节 hex / Base64。**生产必须设置**，使数据文件与解密密钥分离 |
| `GSIGNVER_PEPPER` | 32 字节 hex / Base64，激活码 HMAC 的 pepper |
| `GSIGNVER_ENCRYPT` | 置 `0` 关闭落盘加密（仅排障） |
| `GOMEMLIMIT` | Go 软内存上限，镜像默认 48MiB |
| `GOGC` | GC 触发比，镜像默认 50 |

---

## 6. 部署

### 6.1 本地二进制

    ./gsignver serve -data /var/lib/gsignver -addr :8080

建议用 systemd 管理，注意 `GSIGNVER_MASTER_KEY` 从 EnvironmentFile 注入，
而不是写进数据目录。

### 6.2 容器

    docker build -t gsignver:1.0.2 .
    docker run -d --name gsignver \
      -p 127.0.0.1:8080:8080 \
      -e GSIGNVER_MASTER_KEY=<32 字节 hex> \
      -e GSIGNVER_ADMIN_TOKEN=<随机令牌> \
      -v "$PWD/data:/data" gsignver:1.0.2

**数据卷属主必须与镜像内的运行身份一致**。镜像默认 uid 65534，
如果数据目录属于 uid 1000，需要：

    docker build --build-arg APP_UID=1000 --build-arg APP_GID=1000 -t gsignver:1.0.2 .

或者在 compose 里覆盖 `user: "1000:1000"`。scratch 镜像里没有 chown，这一步绕不过去。

### 6.3 资源受限设备部署（ARM64 / 1 GB）

设备上通常没有 Go 工具链、Docker Hub 也不一定通，因此做法是
**本地交叉编译好二进制再打包**，Dockerfile 只做 scratch 打包，不拉任何基础镜像。

    # 本地
    CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -ldflags "-s -w" -o gsignver ./cmd/gsignver
    CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -ldflags "-s -w" -o gsigtest  ./cmd/gsigtest
    scp gsignver gsigtest <设备>:~/gsignver/   # 用显式目标文件名

    # 设备上
    cd ~/gsignver
    docker compose build && docker compose up -d

三个容易踩的点：

1. **运行身份要匹配数据卷属主**（见上）
2. **健康检查用 gsigtest 自己做探针**（scratch 里没有 curl）。
   注意 `-url` 是**基址、不含路径**，路径由 `-health-path` 决定（默认 `/v1/health`）
3. **换二进制后必须 rebuild**：只把新文件拷进去、不重建镜像，容器还跑旧的。
   换完执行 `docker compose build && docker compose up -d`，看到 `Recreated` 才算生效

---

## 7. 数据目录与备份

    <data>/
      keys/master.key     32 字节 master key（0600；从环境注入时不落盘）
      keys/pepper.key     32 字节激活码 pepper（同上）
      kv/kv.lock          排他文件锁
      kv/kv.snapshot      压缩后的全量快照（默认加密）
      kv/kv.log           追加日志（默认加密）

**备份**：停服后直接打包整个目录即可（快照 + 日志构成完整状态）。
运行中备份请用文件系统快照，不要在写入过程中拷日志。

**恢复**：把目录放回去启动即可，尾部的半条记录会自动丢弃。

**换密钥**：`GSIGNVER_MASTER_KEY` 一旦更换，已加密的数据将无法打开（会明确报错）。
需要更换时应先停服，用旧密钥导出、再用新密钥重建。

---

## 8. 实测数据

| 项目 | 数值 |
|---|---|
| x86_64 空载 RSS | 5.8 MB |
| x86_64 200 轮完整场景后 RSS | 8.2 MB |
| **1 GB 内存 ARM64 设备容器内 RSS** | **3.0 MB**（限额 64 MiB） |
| gsignver 二进制（`-s -w`，arm64） | 5.9 MB |
| scratch 镜像 | 12 MB |
| 测试用例 | 26 项全绿 |
| 单次 Ed25519 验签 | 约 128 µs |

该设备上同时运行着数据库、反向隧道等多个容器。gsignver 的常驻内存稳定在 3 MB 左右，
不会与同机服务争抢内存。

---

## 9. 安全模型与取舍

完整的威胁分析见 [SPEC.md](SPEC.md) 第 9 节。这里列出最需要知道的四条。

**1. 必须配合 TLS 1.3 + 证书固定。**
激活请求没有签名，中间人可以替换 `device_enc_pub`，从而获得 K 与 `device_id`，
完全冒用该设备身份。唯一的防护是传输层。

**2. K 即设备身份。**
业务请求没有签名，靠 AES-GCM 的认证标签证明身份。
K 泄露 = 设备身份可被冒用。请把 K 存进系统密钥库（Keychain / Keystore / TPM）。

**3. 紧急踢出是 DoS 原语。**
知道激活码的人可以反复调用，把该码下的设备逐个踢光。
已内置限流（10 次失败锁定 1 小时），仍建议在产品层加二次确认或人工工单。

**4. 激活码摘要依赖 pepper。**
数据库泄露时，pepper 的存在使攻击者无法离线穷举激活码。
所以 `GSIGNVER_PEPPER` 应当与数据文件分开存放，否则这层防护形同虚设。

另外：本项目没有做应用密钥轮换（见 SPEC B8）。应用私钥泄露后，
唯一的处置路径是重建应用与重新签发激活码。

---

## 10. 测试

    go test ./...
    go vet ./...
    gofmt -l .

26 项用例，覆盖：

**KV 引擎（7 项）**：跨重启持久化、尾部半条记录恢复并截断、压缩后键完整、
事务回滚不落盘、排他锁拒绝二次打开、前缀扫描与删除、落盘加密
（含错钥必须失败、明文不得出现在文件里）。

**端到端（18 项）**：激活正常路径、设备上限且 2003 不返回设备列表、
紧急踢出后释放名额、重复激活产生新身份、激活码无效/时间戳越窗/app 不存在、
激活 nonce 重放、业务 nonce 重放返回形态 A、密文篡改、未知设备、
删除自己后失效、刷新续期、请求体超限、非法 device_desc、
并发配额只放行一台、限流最终锁定、篡改响应签名被客户端拒绝、健康检查、管理接口鉴权。

**KMS（1 项）**：激活码摘要必须依赖 pepper 与 app_id 命名空间，且归一化生效。

---

## 11. 代码结构

    cmd/gsignver          服务端与运维子命令（serve / init / issue / apps）
    cmd/gsigtest          虚拟验证客户端，兼作 scratch 容器健康探针
    internal/kv           嵌入式 KV：内存索引 + 追加日志 + 快照 + 事务 + 排他锁 + 可插拔加密
    internal/store        领域仓储：应用/激活码/许可证/设备/共享密钥/nonce/限流
    internal/kms          master key 与 pepper、HKDF 子密钥派生、私密材料封装
    internal/cryptox      X25519 封装、AES-256-GCM、Ed25519
    internal/wire         信封、状态码、载荷结构、Base64 约定
    internal/server       HTTP 端点与业务逻辑
    internal/client       参考客户端实现
    internal/admin        运维操作与对应 CLI/管理接口客户端
    internal/ulid         ULID 生成

约 4400 行 Go，零第三方依赖。

---

## 12. 常见问题

**Q：为什么不用 SQLite？**
A：目标环境是 1 GB 内存的 ARM 小机器与 scratch 容器。SQLite 需要 cgo 或庞大的纯 Go 移植，
而本项目的数据量很小（应用、激活码、许可证、设备），
一个几百行的内存索引 + 追加日志就够用，内存占用与镜像体积都小一个量级。

**Q：客户端丢了激活响应怎么办？**
A：重新激活即可，会得到一个新身份（新 `device_id`、新 K）。如果配额已满，
先调 `/v1/emergency/kickout` 踢掉最早注册的设备再重试。

**Q：用户换电脑了怎么办？**
A：在新设备上激活，配额满时用 `remove_device`（老设备仍在）或紧急踢出释放名额。

**Q：能离线使用吗？**
A：可以。`license` 由应用私钥签名并带 `expires_at`，客户端可离线验证。
断网期间的状态机与宽限期由客户端实现（见 SPEC 第 8 节）。

**Q：怎么改端口？**
A：`-addr :9090` 或 `GSIGNVER_ADDR=:9090`。用 Docker 时记得同步改 `HEALTHCHECK` 里的端口。

**Q：数据能直接看吗？**
A：默认加密，`kv.log` 与 `kv.snapshot` 都是密文。设 `GSIGNVER_ENCRYPT=0` 可关闭，
但已有加密数据在关闭后会拒绝打开（防止误读造成的静默损坏）。

**Q：怎么发新版本的激活码但让老客户端继续可用？**
A：应用签名密钥不轮换，老客户端内置的 `app_pub` 一直有效。
新增功能通过 `license.features` 下发即可。

---

## 许可

本仓库尚未附带开源许可证文件。若计划让他人使用或分发，建议先补一个（如 MIT / Apache-2.0）。
