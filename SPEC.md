# gsignver 协议规范 v1.0（澄清版）

本规范是《通用软件激活码服务端通讯方案（完整版）》的**规范性替代**：原文档中含糊、自相矛盾、经实测有缺陷之处，一律以本规范为准。原文档保留为背景材料。

配套实现：Go 1.24（仅标准库 + cgo 直连系统 libsqlite3）、SQLite 单文件存储、自建 KMS。

---

## 0. 相对原文档的裁定（Change Log）

| 编号 | 原文档 | 本规范裁定 | 依据 |
|---|---|---|---|
| A1 | 外层只有 app_id/data/sig 三键 | 外层增加明文 **device_id**；未注册请求固定填字面量 **"anonymous"** | 实测 T8：无 device_id 则服务端无法取 K，只能全表扫描 |
| A2 | 未定义阶段区分方式 | **拆分端点**：/v1/activate、/v1/biz、/v1/emergency/kickout | 两阶段 data 都是单个 Base64 串，action 在密文内 |
| A3 | 未定义 IV/tag 传输 | data = Base64( IV(12) + ct + tag(16) )，IV 每条消息 CSPRNG 随机，AAD 为空 | 实测 T3：无 IV 无法解密；IV 复用即明文 XOR 泄露 |
| B4 | 设备签名密钥对 device_sign_priv/pub | **整对移除**。不再有设备签名、不再有请求方向验签 | 用户裁定；客户端实现大幅简化 |
| A4 | 激活码 status = unused/used/revoked | **移除 used**；status 仅取 **active / revoked**。是否已兑换由 DEVICES 派生 | 实测 T6：used 会把第 2..N 台设备全部挡在 2002 |
| A4/A6 | 2003 要求用户从返回列表中踢设备，但未激活客户端无法调用 remove_device | 新增 **紧急踢出接口**：凭 app_id + activation_code 调用，踢出**最早注册**的设备；2003 **不再返回设备列表** | 实测 T7：原流程无出口 |
| A5 | 未定义激活幂等 | 重复 activate **一律视为新身份**（新 device_id、新 K）；配额已满则先调紧急踢出再重试 | 用户裁定 |
| B1 | LICENSES.device_id 单值 vs ER 图 1:N 矛盾 | **每台设备一张 license**；ACTIVATION_CODES 1:N LICENSES 1:1 DEVICES。设备 = 注册身份，非物理机 | 用户裁定 |
| B2 | license.product_id 与 app_id 概念重叠 | **取消 product_id，一律用 app_id**；状态码 2004 语义并入 1001 | 用户裁定 |
| B3 | code_hash 主键 = HMAC(pepper, 明文码) | 改为 **HMAC_SHA256(pepper, app_id + 冒号 + 归一化码)**；归一化 = 去掉连字符与空白后转大写 | 实测 T10：不含 app_id 会导致跨应用主键冲突与重放 |
| B5/B6 | 错误响应必须签名，但未定义加密 | 分端点处理，见 §3.5 | 用户裁定 |
| B7 | 2003 返回全量设备描述 | **不返回设备列表**，直接返回 2003 并引导调用紧急踢出 | 用户裁定 |
| B8 | 支持通过 key_id 轮换应用密钥 | **不支持密钥轮换**；换密钥唯一路径 = 删除设备后重新注册 | 用户裁定 |
| C4 | 内层 Base64（JSON->Base64->加密->Base64） | **移除内层 Base64**，直接加密 UTF-8 JSON 字节 | 实测 T11：冗余 +30.6% 且无收益 |
| C5 | device_id 示例是 ULID 形状，正文写 base62 | 统一为 **ULID**（srv_ + 26 位 Crockford Base32） | 用户接受创建时间可见 |
| C7 | refresh / fetch_data 字段未定义 | 本规范 §4.2 补齐 | 用户授权 |
| — | X25519_Seal 具体构造未定义 | 本规范 §2.4 定义（实测 T4：不同构造线上字节数不同） | 文档缺口 |
| — | nonce 去重依赖 Redis | 改为内置 KV 的 nonce: 记录（无外部资源约束） | 用户裁定 D2 |
| — | 存储层 | **不使用 SQLite**，改为纯 Go 内置 KV 引擎（快照 + 追加日志） | 用户后续裁定 |

---

## 1. 术语

- **应用 (app)**：一个 app_id 对应一组应用签名密钥对与一个激活码命名空间。
- **设备 (device)**：一次注册产生的**身份**，由服务端生成 device_id。一个物理机可以注册多个身份；数据迁移到别的物理机仍算同一身份。
- **K**：每设备唯一的 AES-256 共享对称密钥，激活时由服务端生成并用 device_enc_pub 包裹下发。
- **anonymous**：保留字面量，仅用于未注册请求的 device_id 字段。真实 device_id 形如 srv_<ULID>，因此不会冲突。

---

## 2. 密码学原语

全部使用 Go 标准库实现，无第三方模块。

### 2.1 应用签名（响应方向）

- 算法：**Ed25519**。
- 私钥：每个 app 一把，存于服务端自建 KMS（用 master key 封装后落库），永不下发。
- 客户端：内置对应 app 的公钥（32 字节 raw）。
- 签名对象：见 §3.3。

### 2.2 业务对称加密

- 算法：**AES-256-GCM**。
- 密钥：K（32 字节）。
- IV：12 字节，每条消息 CSPRNG 重新生成。
- AAD：**空**。
- tag：16 字节。
- 线上的密文字节串固定为：IV(12) + ciphertext + tag(16)，再整体做标准 Base64。解密时按此切分。

### 2.3 激活阶段的 K 分发

- K = 32 字节 CSPRNG。
- enc_key = Seal(device_enc_pub, K)。

### 2.4 Seal / Unseal（本规范新增定义）

原文档只写 X25519_Seal，未定义构造。本规范固定为 **X25519 + HKDF-SHA256 + AES-256-GCM**：

    Seal(recipient_pub32, msg32):
      1. eph = X25519 临时密钥对
      2. shared = X25519(eph.priv, recipient_pub32)      // 32 字节
      3. kek = HKDF-SHA256(ikm=shared, salt=空, info="gsignver/kem/v1", len=32)
      4. iv = 12 字节 CSPRNG
      5. ct = AES-256-GCM(kek, iv, msg32, aad=空)        // 32 字节密文 + 16 字节 tag
      6. 输出 = eph_pub32 + iv(12) + ct+tag(48)          // 合计 92 字节

    Unseal(recipient_priv, blob92):
      按同样切分，用 recipient_priv 与 blob 前 32 字节做 ECDH，其余同上解密。

- 编码：标准 Base64（含等号填充），因此 enc_key 字符串长度固定为 124 字符。
- 该构造**不是** libsodium crypto_box_seal（后者用 XSalsa20-Poly1305，Go 标准库不含）。两端必须都用本规范。

### 2.5 激活码摘要

    code_hash = hex(HMAC_SHA256(pepper, app_id + ":" + normalize(code)))
    normalize(code) = 去掉所有连字符与空白，然后转大写

- pepper：32 字节随机，存于 keys 目录下的独立文件（0600），不进数据库。
- 明文激活码格式：PROD-XXXX-XXXX-XXXX-XXXX 或同等熵的随机串；服务端只存 code_hash。

### 2.6 自建 KMS

- master key：32 字节。优先从环境变量 GSIGNVER_MASTER_KEY 读取（hex / 标准 Base64 / Base64URL）；
  未设置时才首次生成并写 <data-dir>/keys/master.key（0600）。
  **生产部署应当用环境变量注入，使数据文件与其解密密钥分离。**
- pepper：32 字节，同样支持 GSIGNVER_PEPPER 注入，未设置时生成 keys/pepper.key。
- 库中所有敏感私密材料（K、应用 Ed25519 私钥）以 AES-256-GCM 用 master key 封装后存储，格式 IV(12) + ct + tag(16)。
- 子密钥派生：DeriveKey(info, n) = HKDF-SHA256(master, info, n)，用于隔离不同用途的密钥。
- 密钥轮换：不支持（见 B8）。

### 2.7 落盘加密（可插拔）

KV 的文件读写层提供可扩展的加密后端抽象：

    type Cipher interface {
        Encrypt(plain []byte) ([]byte, error)
        Decrypt(blob []byte) ([]byte, error)
    }

- 内置实现 NewAESGCMCipher(key)：AES-256-GCM，密文格式 nonce(12) + ct + tag(16)。
- 服务端默认启用：密钥 = HKDF-SHA256(master, "gsignver/kv/v1", 32)。设置 GSIGNVER_ENCRYPT=0 可关闭。
- 加密粒度：**每条追加日志记录**与**快照整体**。
- 自描述：每段落盘数据带 1 字节标记（0 = 明文，1 = 密文），因此
  - 明文数据可以被开启加密的进程直接读取（写入即刻转为密文，平滑迁移）；
  - 加密数据若未提供 Cipher，打开时立即报错，不会静默损坏。
- 校验：CRC32 仍然覆盖**落盘（加密后）字节**，因此仍可检测截断与损坏；AEAD 另行提供完整性。
- 扩展点：实现 Cipher 即可换成其它 AEAD、外置 KMS 包装、或带密钥版本的轮换方案。

---

## 3. 线路格式

### 3.1 外层信封

一行 JSON 对象：

    {
      "app_id":    "com.example.app",      // 必填
      "device_id": "srv_01J8XK...",        // 必填；未注册请求为 "anonymous"
      "data":      "标准 Base64 字符串",     // 必填
      "sig":       "Base64URL 无填充"       // 仅响应，见 §3.5
    }

- 编码约定：**data 用标准 Base64（含等号填充）**；**sig 用 Base64URL 无填充**；nonce 也是 Base64URL 无填充。
- 未知字段一律忽略；缺失必填字段 -> 1001。

### 3.2 data 载荷矩阵

| 端点 / 方向 | data 的明文载荷 | 是否加密 |
|---|---|---|
| /v1/activate 请求 | UTF-8 JSON | 否 |
| /v1/activate 成功响应 | UTF-8 JSON（含 enc_key、license） | 否 |
| /v1/emergency/kickout 请求 | UTF-8 JSON | 否 |
| /v1/emergency/kickout 响应 | UTF-8 JSON | 否 |
| /v1/biz 请求 | UTF-8 JSON，整体用 K 加密 | 是 |
| /v1/biz 响应 | UTF-8 JSON，整体用 K 加密 | 是 |

### 3.3 签名对象

    sig = Base64URL_nopad( Ed25519_sign(app_priv, UTF8(data 字符串本身)) )

- 签名覆盖的是 data **字符串**的 UTF-8 字节，不是 JSON 对象、不是原始明文字节。
- **不签 app_id、不签 device_id**。
- 请求方向**完全没有签名**（B4 裁定）。

### 3.4 键序与规范化

- 两端都不得对 data 字符串做任何再编码；客户端必须拿服务端返回的 data 字符串**原样字节**参与验签。
- JSON 键序不参与签名，因此不做规范化要求。

### 3.5 响应形态与错误策略

响应分两种物理形态，客户端用 HTTP 状态码区分：

**形态 A —— 信封响应（HTTP 200）**

    { "app_id": ..., "device_id": ..., "data": ..., "sig": ... }

- 用于：所有成功响应；以及 /v1/biz 上服务端**已经成功解出请求**后产生的错误（如 3001/3002/2006）。
- 一定有 sig。业务错误响应的 data 仍用 K 加密。
- 业务含义（code）在解密后的 JSON 里。

**形态 B —— 裸错误（HTTP 4xx/5xx）**

    { "code": 1004, "message": "nonce 重放" }

- 无信封、无 sig、无加密。
- 用于：/v1/activate 与 /v1/emergency/kickout 的**一切错误**；以及 /v1/biz 上服务端**在解密之前**就失败的场景（app_id 未知、device_id 未知、K 已销毁、密文格式非法、GCM tag 校验失败）。

理由：这些场景下服务端拿不到 K，且请求本身没有签名，无法产生可信的信封响应。

### 3.6 HTTP 约定

- 方法：POST，Content-Type: application/json; charset=utf-8。
- 请求体上限 **64 KiB**，超限 -> 1007。
- 除 429/5xx 外，形态 A 一律 HTTP 200。

---

## 4. 端点与动作

### 4.1 POST /v1/activate

请求 data（明文 JSON）：

    {
      "action": "activate",
      "activation_code": "PROD-7K9M-2Q4X-8T1F-9L6C",
      "device_desc": "base64(设备描述 JSON)",
      "device_enc_pub": "base64(32 字节 X25519 公钥)",
      "nonce": "base64url(16 字节)",
      "ts": 1710000000
    }

成功响应 data（明文 JSON）：

    {
      "code": 0,
      "message": "ok",
      "nonce": "<原样回显>",
      "ts": 1710000001,
      "device_id": "srv_01J8XK...",
      "enc_key": "base64(92 字节 Seal 结果)",
      "license": {
        "license_id": "lic_01J...",
        "app_id": "com.example.app",
        "edition": "pro",
        "features": ["export", "api"],
        "device_id": "srv_01J8XK...",
        "not_before": 1710000001,
        "expires_at": 1740000000
      }
    }

服务端步骤：

    1. 读外层 app_id/device_id/data；device_id 必须是 "anonymous"
    2. 标准 Base64 解码 data -> JSON.parse（设深度与大小上限）
    3. 校验 action、nonce、ts（正负 300 秒）
    4. 按 app_id 查应用配置（不存在 -> 1006）
    5. 查 code_hash（含 app_id）-> 不存在或已撤销或 app_id 不符 -> 1001（统一）
    6. 校验激活码 expires_at
    7. 事务内：认领 nonce -> 统计该码 active 设备数
       - 等于 max_devices -> 2003（不返回设备列表）
       - 大于 max_devices -> 2007
    8. 生成 device_id（ULID + 查重）
    9. 生成 K；enc_key = Seal(device_enc_pub, K)
    10. 生成 license；写 DEVICES / LICENSES / SHARED_KEYS
    11. 提交事务；组装响应 JSON -> data -> sig
    12. 返回形态 A

- 重复 activate 一律建新身份（A5）。配额满时客户端先调紧急踢出。
- device_desc 校验：必须是合法标准 Base64，字符串长度不超过 4096，解码后不超过 2048 字节。

### 4.2 POST /v1/biz

请求 data：K 加密的 JSON。

    {
      "action": "list_devices" | "remove_device" | "refresh" | "fetch_data",
      "license_id": "lic_01J...",
      "nonce": "base64url(16 字节)",
      "ts": 1710000100
    }

服务端步骤：

    1. 读 app_id / device_id / data（device_id 不得为 "anonymous"）
    2. 按 (app_id, device_id) 取 K（不存在或已销毁 -> 1010，形态 B）
    3. Base64 解码 data，长度必须不小于 28，切分 IV+ct+tag
    4. GCM 解密（失败 -> 1010，形态 B）
    5. UTF-8 解码 + JSON.parse
    6. 校验 nonce（重放 -> 1004）与 ts（越窗 -> 1003）
    7. 校验 license 属于该 device_id（不符 -> 2006；不存在 -> 3003）
    8. 校验 license 状态（revoked -> 3002；过期 -> 3001）与设备状态（removed -> 2005）
    9. 执行动作
    10. 更新 last_seen_at
    11. 用 K 加密响应 JSON，签名，返回形态 A

**注意**：第 6 步之前的失败（1004/1003）已是"解出请求后"，因此返回**形态 A**（加密+签名），code 在密文里。

#### 动作 list_devices

响应 data 内层：

    { "code":0, "message":"ok", "nonce":"<回显>", "ts":...,
      "max_devices":3,
      "devices":[ {"device_id":..., "device_desc":..., "registered_at":..., "last_seen_at":...} ] }

#### 动作 remove_device

请求额外字段：target_device_id。目标必须属于同一激活码。

- 踢其他设备：释放名额。
- 删自己：等价于密钥重置第一步（见 §6.3）。
- 服务端：DEVICES 标记 removed；LICENSES 标记 revoked；SHARED_KEYS 中 K 标记 destroyed 并清除密文。
- 响应：{ code:0, ..., "removed_device_id": ... }
- 幂等：目标已是 removed 仍返回 0。

#### 动作 refresh

- 重新从 ACTIVATION_CODES 读取 edition/features（C9：管理员改套餐可生效）。
- expires_at = now + APPLICATIONS.license_ttl_seconds（C8：滑动续期）。
- 响应：{ code:0, ..., "license": { ... 新的完整 license ... } }

#### 动作 fetch_data（示例业务动作）

- 请求额外字段：key（业务数据键，字符串）。
- 响应：{ code:0, ..., "payload": 任意 JSON }
- 本轮实现为服务端持有的简单键值对，用于演示"敏感操作服务端校验"。

### 4.3 POST /v1/emergency/kickout

未激活客户端可用；无加密、无签名。

请求 data（明文 JSON）：

    { "action":"emergency_kickout", "activation_code":"...", "nonce":"...", "ts":... }

服务端：

    1. 校验 app_id / nonce / ts
    2. 查 code_hash（含 app_id）-> 不存在或撤销 -> 1001
    3. 事务内：取该码 active 设备中 registered_at 最早的一台
       - 无 -> 2009
       - 有 -> 同 remove_device 的清理动作
    4. 返回形态 A（有 sig，明文 data）

响应 data（明文 JSON）：

    { "code":0, "message":"ok", "nonce":"<回显>", "ts":..., "kicked_device_id":"srv_..." }

- 错误一律形态 B。
- **安全说明**：这是一个 DoS 原语（知道激活码者可反复踢最旧设备），必须限流；见 §9。

### 4.4 GET /v1/health

    200 {"ok":true,"version":"1.0"}

### 4.5 管理接口（/admin/v1/*）

**为什么需要**：KV 对数据目录持有排他 flock（见 §5），因此服务端运行期间，
另外的进程无法打开数据目录执行 init/issue/apps。若没有管理接口，
上线后就只能停服才能签发激活码。管理接口让运维动作在服务端进程内完成。

- 仅在设置了 GSIGNVER_ADMIN_TOKEN 时挂载；未设置时这些路径返回 404。
- 鉴权：请求头 Authorization: Bearer <token>，使用常量时间比较。
- 同样受 64 KiB 请求体上限约束。

    GET  /admin/v1/apps    列出应用（含 active 应用公钥）
    POST /admin/v1/apps    创建/更新应用
                           入参 {app_id, name, max_devices, ttl_seconds}
                           出参 {app_id, public_key}
    POST /admin/v1/codes   签发激活码
                           入参 {app_id, edition, features, max_devices, code_ttl_seconds}
                           出参 {app_id, activation_code, edition, max_devices}

- 命令行等价用法：

    gsignver issue -admin-url http://127.0.0.1:8080 -admin-token <TOKEN> \
                   -app com.example.app -edition pro
    gsignver apps  -admin-url http://127.0.0.1:8080 -admin-token <TOKEN>

  未提供 -admin-url 时，CLI 直接打开数据目录（要求服务端未运行）。

- **部署注意**：若通过反向隧道暴露本服务，务必不要放行 /admin/ 前缀。

---

## 5. 服务端存储（纯 Go 内置 KV 引擎）

不使用 SQLite，不使用任何第三方 Go 模块。本节描述的是**逻辑记录模型**；物理上由 internal/kv 提供的嵌入式 KV 引擎承载：

- 内存中保存全部键值（map），进程内视为真相源。
- 持久化采用「快照 + 追加日志」：写操作追加到 kv.log；日志超过阈值时压缩为 kv.snapshot 并截断日志。
- 每次提交先 write 再 fsync，然后才向调用方返回成功。
- 崩溃恢复 = 载入快照 + 重放日志；日志尾部未写完的记录自动丢弃。
- 事务：Update 回调在单把互斥锁内串行执行，回调返回成功后才把写集落盘；因此「读-改-写」天然原子，§11 的并发配额用例由此保证。
- 单进程独占 data-dir，不支持多进程同时打开。

以下「表/列」写法仅为可读性；物理键名见 5.9。

    1 APPLICATIONS
      app_id                TEXT PRIMARY KEY
      name                  TEXT
      max_devices_default   INTEGER
      license_ttl_seconds   INTEGER
      created_at            INTEGER

    2 SIGNING_KEYS
      key_id                TEXT PRIMARY KEY
      app_id                TEXT NOT NULL
      algorithm             TEXT                  -- 固定 "Ed25519"
      public_key            TEXT                  -- 标准 Base64，32 字节 raw
      private_key_blob      BLOB                  -- master key 封装后
      status                TEXT                  -- active / retired（不支持轮换，仅一把 active）
      created_at            INTEGER

    3 ACTIVATION_CODES
      code_hash             TEXT PRIMARY KEY      -- §2.5，已含 app_id
      app_id                TEXT NOT NULL
      edition               TEXT
      features              TEXT                  -- JSON 数组字符串
      max_devices           INTEGER
      status                TEXT                  -- active / revoked（已移除 used）
      expires_at            INTEGER
      created_at            INTEGER

    4 LICENSES
      license_id            TEXT PRIMARY KEY      -- lic_ + ULID
      app_id                TEXT NOT NULL
      activation_code_hash  TEXT NOT NULL
      edition               TEXT
      features              TEXT
      device_id             TEXT NOT NULL UNIQUE  -- 每设备一张（B1）
      key_id                TEXT
      issued_at             INTEGER
      not_before            INTEGER
      expires_at            INTEGER
      status                TEXT                  -- active / revoked

    5 DEVICES
      device_id             TEXT PRIMARY KEY
      app_id                TEXT NOT NULL
      activation_code_hash  TEXT NOT NULL
      license_id            TEXT NOT NULL
      device_enc_pub        TEXT NOT NULL
      device_desc           TEXT NOT NULL         -- 原样存，服务端不解析
      registered_at         INTEGER NOT NULL
      last_seen_at          INTEGER
      status                TEXT                  -- active / removed

    6 SHARED_KEYS
      app_id                TEXT NOT NULL
      device_id             TEXT NOT NULL
      key_blob              BLOB                  -- master key 封装后的 K
      created_at            INTEGER
      status                TEXT                  -- active / destroyed
      PRIMARY KEY (app_id, device_id)

    7 NONCES
      nonce_key             TEXT PRIMARY KEY      -- app_id + ":" + nonce
      expires_at            INTEGER NOT NULL

    8 RATE_LIMIT
      bucket                TEXT PRIMARY KEY
      failures              INTEGER
      window_start          INTEGER
      locked_until          INTEGER

### 5.9 物理键名

    app:<app_id>                          -> Application(JSON)
    sk:<app_id>:<key_id>                  -> SigningKey(JSON)
    ska:<app_id>                          -> 当前 active 的 key_id
    code:<code_hash>                      -> ActivationCode(JSON)
    dev:<device_id>                       -> Device(JSON)
    lic:<license_id>                      -> License(JSON)
    key:<app_id>:<device_id>              -> SharedKey(JSON, K 已封装)
    idx:dev2lic:<device_id>               -> license_id
    idx:code2dev:<code_hash>:<device_id>  -> 空串（该码下的设备集合）
    nonce:<app_id>:<nonce>                -> 过期时间（十进制）
    rl:<bucket>                           -> RateLimit(JSON)
    dat:<app_id>:<key>                    -> 业务数据 payload(JSON)，供 fetch_data 使用

- 次级索引（idx:）与主记录在同一事务内更新，保证一致。
- "踢出最早注册的设备" = 扫描 idx:code2dev:<code_hash>: 前缀，取 registered_at 最小的 active 设备（该码设备数有上限，扫描代价可忽略）。
- 唯一性由事务内的显式检查保证：license_id、device_id 均需查重后再写；device_enc_pub 无唯一约束（B4 已移除设备签名密钥，无需按公钥去重）。

---

## 6. 关键流程

### 6.1 激活

    客户端                                     服务端
      | 生成 device_enc 密钥对                    |
      | nonce=16B, ts=now                        |
      | POST /v1/activate                        |
      |   {app_id, device_id:"anonymous", data}  |
      |----------------------------------------->|
      |                                          | 查码/配额/生成 device_id 与 K
      |                                          | Seal(device_enc_pub, K)
      |  {app_id, device_id, data, sig}          |
      |<-----------------------------------------|
      | 验 sig(app_pub) -> 解 data -> 校验 nonce |
      | Unseal(device_enc_priv, enc_key) -> K    |
      | 本地保存 device_id / K / license          |
      | （device_enc 密钥对此后不再使用）          |

### 6.2 配额外的自救路径（A5/A6/B7）

    activate -> 2003（不返回设备列表）
      -> POST /v1/emergency/kickout {activation_code}
      -> 服务端踢出最早注册设备
      -> 重新 activate

### 6.3 密钥重置（唯一路径）

    1. 设备调用 /v1/biz remove_device，target_device_id = 自己
    2. 服务端：DEVICES->removed，LICENSES->revoked，SHARED_KEYS->destroyed
    3. 客户端清除本地 device_id / K / license / device_enc 密钥对
    4. 重新生成 device_enc 密钥对，重新 activate（拿到新身份、新 K）

若客户端在第 2 步之后、第 3 步之前崩溃（或响应丢失），旧身份已 removed，直接重新 activate 即可。**不存在唯一约束卡死问题**（B4 已移除 device_sign_pub）。

---

## 7. 状态码

| code | 含义 | 形态 |
|---|---|---|
| 0 | 成功 | A |
| 1001 | 参数错误 / 激活码无效（统一承载原 2002、2004） | B |
| 1002 | 签名无效（保留：客户端本地判定服务端响应时使用，服务端不再返回） | — |
| 1003 | 时间戳超出窗口 | A（biz）/ B（activate、emergency） |
| 1004 | nonce 重放 | A（biz）/ B（activate、emergency） |
| 1006 | app_id 不存在 | B |
| 1007 | 请求体超过 64 KiB | B |
| 1010 | 密文格式非法 / 解密失败 / K 不存在或已销毁 | B |
| 2001 | 激活码无效（保留定义，不再单独返回） | — |
| 2002 | 激活码已使用（**已废弃**，统一并入 1001） | — |
| 2003 | 设备数已达上限（不返回设备列表，引导紧急踢出） | B |
| 2004 | 产品不匹配（**已废弃**，统一并入 1001） | — |
| 2005 | 设备已被移除 | A |
| 2006 | 设备不属于该 license | A |
| 2007 | 设备数异常超过上限（内部不一致） | B |
| 2009 | 无设备可踢出 | B |
| 3001 | 许可证过期 | A |
| 3002 | 许可证被吊销 | A |
| 3003 | license 不存在 | A |
| 429 | 请求过于频繁 | B |
| 5000 | 服务端内部错误 | B |

- 形态 A = HTTP 200 信封（加密+签名，或激活/紧急的明文+签名）。
- 形态 B = HTTP 4xx/5xx 裸 JSON，无签名无加密（429 -> 429，5000 -> 500）。

---

## 8. 客户端职责

1. 生成 device_enc 密钥对；生成 nonce。
2. 组信封、发请求。
3. 对响应：先用内置 app_pub 验 sig（覆盖 data 字符串的 UTF-8 字节），失败直接丢弃。
4. 再做业务校验：nonce 必须等于自己刚发的、ts 在正负 300 秒内。
5. biz 响应的 data 就是 IV+ct+tag 的 Base64，解密后直接是 UTF-8 JSON。
6. 激活成功后保存 device_id / K / license；device_enc 私钥保留但不再使用。

### 8.1 授权状态机（本地）

    [*] -> Unactivated
    Unactivated --用户输入激活码--> Activating
    Activating  --成功--> Activated
    Activating  --失败--> Unactivated
    Activated   --刷新成功--> Activated
    Activated   --刷新失败--> GracePeriod
    Activated   --now > expires_at--> GracePeriod
    GracePeriod --刷新成功--> Activated
    GracePeriod --now > grace_ends_at--> Expired
    Expired     --重新激活--> Activating

- 宽限期时长由产品配置（默认 7 天）。
- 刷新触发：启动时、每 N 小时、剩余时间小于 ttl/3、网络恢复时（C14 裁定）。
- 注意：宽限期是**客户端本地**状态，可被破解者篡改；高价值功能必须走 §4.2 的服务端校验。

---

## 9. 安全分析与已知取舍

### 9.1 相对原方案的削弱（B4 的直接后果，用户已知悉并接受）

| 项 | 后果 |
|---|---|
| 激活请求无签名 | 知道激活码者可注册设备（受 max_devices 限制）。原方案同样如此（验签公钥取自消息自身，实测 T1），故**无实质回归** |
| 业务请求无签名 | **K 即设备身份**；K 泄露 = 身份可被冒用。原方案下泄露 K 还需 device_sign_priv 才能伪造请求，故此处**确有削弱** |
| 中间人可替换 device_enc_pub | 未签名的激活请求中 device_enc_pub 可被替换，攻击者取得 K 与 device_id，从而完全冒用该身份。**唯一防护是 TLS 1.3 + 证书固定** |
| 无应用密钥轮换 | 应用私钥泄露后无法快速轮换，只能重建 |

### 9.2 新增攻击面

| 风险 | 说明 | 缓解 |
|---|---|---|
| 紧急踢出是 DoS 原语 | 知道激活码者可反复调用，把该码下所有设备逐个踢光 | 限流（§9.4）；建议产品侧对紧急踢出加二次确认 |
| 踢"最早注册"可能误伤 | 重试激活的客户端调紧急踢出，踢掉的可能是另一台正常设备 | 产品决策；如需精确可改为踢"最久未活跃" |
| DB 与 master key 同机 | master.key 与 sqlite 在同一目录时，主机被攻破 = 全部 K 与私钥泄露 | 部署上拆开：master key 走环境变量或独立挂载 |

### 9.3 铁律（修订版）

原文档"验签不过业务代码一行都不执行"在请求方向已不适用。修订为：

1. **响应方向**：客户端必须先验 sig，不通过直接丢弃，不进入任何业务逻辑。
2. **请求方向**：服务端必须先完成 GCM 解密（认证），不通过直接拒，不进入业务逻辑。
3. 验签/解密前允许的操作只有：读外层字段、按 device_id 取 K、Base64 解码、GCM 解密。
4. 错误响应也必须按 §3.5 的形态规则产生（形态 A 的场景必须有 sig）。

### 9.4 限流

- 维度：IP + app_id 与 激活码 两条桶。
- 规则：对应桶内连续失败 10 次 -> 锁定 1 小时 -> 429。
- 成功即清零。

---

## 10. 部署形态

- 单进程、单文件 KV（<data>/kv/ 下 kv.snapshot + kv.log + kv.lock）。
- 二进制：Go 1.24 编译，**纯 Go、无 cgo**（CGO_ENABLED=0 亦可构建）。
- 零 Go 第三方模块依赖，无网络也能构建。
- 内存实测：x86_64 开发机空载 5.8 MB / 200 轮压测后 8.2 MB；
  1 GB 内存的 ARM64 设备容器内实测 3.0 MB。
- 镜像实测：scratch 镜像 12 MB（含 gsignver 与 gsigtest）。
- 容器：scratch 镜像、非 root（uid 65534）、GSIGNVER_ADDR / GSIGNVER_DATA 环境变量、
  GOMEMLIMIT=48MiB 与 GOGC=50 默认、/v1/health 供健康检查、优雅关闭。
- **多实例限制**：KV 在打开时对数据目录加排他 flock，同一 data-dir 只能被一个进程打开，
  第二个进程启动即失败。横向扩容请按 app_id 分片路由，每个副本使用独立 data 卷。

### 10.1 运维子命令

    gsignver serve   -addr :8080 -db data/gsignver.db -keys data/keys
    gsignver init    -app com.example.app -name 示例应用 -max-devices 3 -ttl 2592000 -keys data/keys
    gsignver issue   -app com.example.app -edition pro -features export,api -max-devices 3 -ttl 2592000 -keys data/keys
    gsignver apps    -keys data/keys

- init 创建/更新应用与签名密钥对，并打印内置用的 app 公钥（Base64）。
- issue 签发一枚激活码并打印明文码（仅此一次可见）。

---

## 11. 验证计划

| 用例 | 期望 |
|---|---|
| 激活正常路径 | code=0，拿到 device_id / enc_key / license，客户端能解出 K |
| 同一激活码注册 max_devices 台 | 全部成功 |
| 第 max_devices+1 次激活 | 2003，且**响应体不含设备列表** |
| 2003 后调紧急踢出再激活 | 紧急踢出返回 kicked_device_id，随后激活成功 |
| 重复 activate（模拟响应丢失） | 建**新身份**（新 device_id、新 K） |
| 激活码不存在 / app_id 不符 / 被撤销 | 统一 1001 |
| ts 超窗 | 1003 |
| 激活 nonce 重放 | 1004 |
| biz 请求 nonce 重放 | 形态 A，解密后 code=1004 |
| 篡改 biz 密文任一字节 | 形态 B，1010 |
| biz 使用别的设备的 device_id | 形态 B，1010（K 不匹配） |
| 设备被 remove 后再发 biz | 形态 B，1010（K 已销毁） |
| 篡改响应 data 后客户端验签 | 客户端拒绝 |
| 篡改响应 sig | 客户端拒绝 |
| 激活请求体超过 64 KiB | 1007 |
| 配额并发 | DEVICES 实际行数不超过 max_devices |
| 限流 | 连续 10 次失败后返回 429 |
| device_desc 非法 Base64 | 1001 |
