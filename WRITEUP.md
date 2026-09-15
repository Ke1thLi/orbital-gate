# Orbital Gate 官方 Writeup

> 出题人：keith  
> 类型：Web + JavaScript Reverse  
> 难度：★★★★☆

---

## 一、所需工具

本题**不需要任何冷门工具**，也**不需要商业反混淆工具**。推荐准备：

| 工具 | 用途 | 是否必须 |
|---|---|---|
| Chrome / Edge / Firefox DevTools | Network、Sources、Console | ✅ 必须 |
| 浏览器内置 Sources 搜索 | 阅读 `portal.js` / `badge.js` | ✅ 必须 |
| 浏览器内置 Console | 调用公开 JS 函数、构造请求 | ✅ 必须 |
| Python 3 + `requests` | 可选：用 Python 复现算法 | ⭕ 可选 |
| `curl` | 可选：命令行测试接口 | ⭕ 可选 |
| CyberChef | 可选：辅助 Base64 / Hex 验证 | ⭕ 可选 |

**不需要：**

- 不需要 AES / RSA / JWT 解密工具
- 不需要自动 JS 反混淆器
- 不需要暴力破解工具
- 不需要 Burp 插件

> 核心能力是“读 JS + 追数据流 + 自己构造请求”。

---

## 二、题目概览

玩家打开页面后会看到一个员工门户：

- 注册 / 登录
- 显示 UID、部门
- 一个“同步门禁徽章”按钮

点击按钮后 Network 出现：

```
POST /api/internal/bootstrap
401 Unauthorized

{ "error": "unauthorized" }
```

说明存在隐藏接口，且需要一个特殊 Header。

---

## 三、攻击链总览

```text
访问首页
-> 注册/登录
-> 获取 Session
-> 点击“同步门禁徽章”
-> Network 发现 POST /api/internal/bootstrap 返回 401
-> Sources 分析 portal.js
-> 找到 PortalCrypto.buildPortalToken()
-> 逆向第一阶段算法
-> 构造 X-Portal-Token
-> POST /api/internal/bootstrap
-> 获得 nonce + ticket
-> Sources 分析 badge.js
-> 找到 BadgeV2.prepareBadge()
-> parseTicket()
-> randomClientNonce()
-> deriveSessionProof()
-> BadgeV2.signFinal(state)
-> 生成 v2 signature
-> POST /api/internal/final
   body: { nonce, client_nonce, signature }
-> Flag
```

---

## 四、逐阶段解题

### 阶段 0：注册登录

打开首页，注册：

```text
用户名：alice
密码：password123
```

登录后打开 DevTools → Network → 点击“同步门禁徽章”。

观察到：

```
POST /api/internal/bootstrap
401 Unauthorized

{ "error": "unauthorized" }
```

同时在 Sources 里能看到：

```
/static/js/admin.js
/static/js/portal.js
/static/js/badge.js
```

### 阶段 1：逆向 `portal.js`

查看 `static/js/portal.js`。

关键函数：

```js
PortalCrypto.buildPortalToken(username, uid, ts)
```

算法流程：

1. 拼接：

   ```js
   raw = `${username}|${uid}|${ts}|${P_SALT}`
   ```

   其中 `P_SALT = "ORBITAL_GATE_V2"`。

2. 派生 32 位 key：

   ```js
   key = (Math.imul(uid, 2654435761) ^ 0x9e3779b9) >>> 0
   ```

3. 对 `raw` 的 UTF-8 字节逐字节处理：

   ```
   k = key 第 (i % 4) 个字节
   x = b XOR k
   x = 循环左移 3 位
   ```

4. 将结果按 5-bit 分组，映射到自定义字母表：

   ```js
   ALPHA = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
   ```

5. 计算 FNV-1a 校验和，取低 16 位十六进制。

6. 最终：

   ```
   v1.<ts>.<encoded>.<checksum>
   ```

服务端校验（可从接口行为推断）：

- 格式正确
- `ts` 与服务器时间相差 ≤ 180 秒
- `username` / `uid` 与 Session 一致
- 重算结果完全一致

在 Console 中生成：

```js
const me = await (await fetch('/api/me')).json();
const token = PortalCrypto.buildPortalToken(me.username, me.uid);
console.log('token =', token);
```

### 阶段 2：调用 bootstrap

继续在 Console：

```js
const boot = await (await fetch('/api/internal/bootstrap', {
  method: 'POST',
  headers: { 'X-Portal-Token': token }
})).json();

console.log('boot =', boot);
```

预期：

```json
{
  "ok": true,
  "nonce": "....",
  "ticket": "ORB-....",
  "next": "/api/internal/final",
  "expires_in": 180
}
```

此时**不能跳过**，因为 `nonce` 是服务器动态生成的。

### 阶段 3：逆向 `badge.js`

查看 `static/js/badge.js`。核心函数：

```
BadgeV2.prepareBadge(challenge, uid)
BadgeV2.signFinal(state)
```

调用链：

```
prepareBadge
  -> parseTicket(ticket)
  -> randomClientNonce()
  -> deriveSessionProof(state)
  -> 返回 state（stage = "prepared"）

signFinal(state)
  -> 校验 state.stage === "prepared"
  -> 使用 state.uid / nonce / ticket / clientNonce / sessionProof
  -> 生成 v2 signature
```

ticket 结构：

```
ORB-<uidPart>-<randomPart>-<checkPart>
```

- `uidPart`：uid 的 base36 大写
- `randomPart`：16 位 hex
- `checkPart`：FNV-1a(uidPart:randomPart:T_SALT) 低 16 位

`prepareBadge` 会：

1. 解析 ticket
2. 生成随机 `clientNonce`
3. 派生 `sessionProof`
4. 返回带 `stage` 的 state

`signFinal` 会：

1. 要求 state 已 `prepareBadge`
2. 拼接 `uid:ticket:nonce:clientNonce:F_SALT`
3. FNV-1a + 反转 + rotl32(13) + XOR sessionProof
4. 取 `nonce` 前 8 位、`uidPart`、`checkPart`、`h` 的 hex、`sessionProof` 前 4 位
5. 用 `F_SALT` XOR 后 Base64URL
6. checksum = FNV-1a(payload + ticket + F_SALT) 低 16 位

### 阶段 4：生成 signature 并调用 final

在 Console：

```js
const state = BadgeV2.prepareBadge(boot, me.uid);
const sig = BadgeV2.signFinal(state);

console.log('client_nonce =', state.clientNonce);
console.log('signature =', sig);

const final = await (await fetch('/api/internal/final', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({
    nonce: boot.nonce,
    client_nonce: state.clientNonce,
    signature: sig
  })
})).json();

console.log('final =', final);
```

预期：

```json
{ "ok": true, "flag": "flag{...}" }
```

---

## 五、为什么不能跳过 bootstrap

服务器端：

```python
nonces[nonce] = {
    "uid": uid,
    "ticket": ticket,
    "created": time.time(),
    "used": False,
}
```

`/api/internal/final` 只根据 `nonce` 去查服务器保存的状态，**不接受客户端提交的 ticket**。

因此：

- 没有 bootstrap → 没有有效 nonce → final 失败
- 伪造 nonce → 查不到记录 → 失败
- 重放 nonce → `used = True` → 失败
- 跨 Session 使用 nonce → `rec["uid"] != user["uid"]` → 失败

---

## 六、可选：用 Python 复现

如果不想在 Console 直接调用，可以完全用 Python 复现。核心是把 `portal.js` / `badge.js` 的逻辑翻译成 Python。

```python
import time, secrets, hashlib, base64, re
import requests

BASE = "http://127.0.0.1:5000"
P_SALT = "ORBITAL_GATE_V2"
F_SALT = "FINAL_DOCK_7"
ALPHA = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"


def fnv1a(s: str) -> int:
    h = 0x811c9dc5
    for b in s.encode("utf-8"):
        h ^= b
        h = (h * 0x01000193) & 0xffffffff
    return h


def rotl32(x: int, n: int) -> int:
    return ((x << n) | (x >> (32 - n))) & 0xffffffff


def to_base32_like(data: bytes) -> str:
    bits = 0
    value = 0
    out = []
    for b in data:
        value = (value << 8) | b
        bits += 8
        while bits >= 5:
            out.append(ALPHA[(value >> (bits - 5)) & 31])
            bits -= 5
            value &= (1 << bits) - 1 if bits else 0
    if bits > 0:
        out.append(ALPHA[(value << (5 - bits)) & 31])
    return "".join(out)


def build_portal_token(username: str, uid: int, ts: int = None) -> str:
    ts = ts or int(time.time())
    raw = f"{username}|{uid}|{ts}|{P_SALT}"
    key = ((uid * 2654435761) ^ 0x9e3779b9) & 0xffffffff
    out = bytearray()
    for i, b in enumerate(raw.encode()):
        k = (key >> ((i % 4) * 8)) & 0xff
        x = b ^ k
        x = ((x << 3) | (x >> 5)) & 0xff
        out.append(x)
    encoded = to_base32_like(bytes(out))
    checksum = f"{fnv1a(raw) & 0xffffffff:08x}"[-4:]
    return f"v1.{ts}.{encoded}.{checksum}"


def parse_ticket(ticket: str):
    m = re.fullmatch(r"ORB-([0-9A-Z]+)-([0-9A-F]{16})-([0-9A-F]{4})", ticket)
    return {"uidPart": m.group(1), "randomPart": m.group(2), "checkPart": m.group(3)}


def derive_session_proof(uid, ticket, nonce, client_nonce):
    seed = f"{uid}:{ticket}:{nonce}:{client_nonce}:{P_SALT}"
    h1 = fnv1a(seed)
    h2 = fnv1a(seed[::-1])
    proof = rotl32(h1 ^ h2, 7)
    return f"{proof:08x}"


def sign_final(uid, ticket, nonce, client_nonce):
    parts = parse_ticket(ticket)
    proof = derive_session_proof(uid, ticket, nonce, client_nonce)
    seed = f"{uid}:{ticket}:{nonce}:{client_nonce}:{F_SALT}"
    h1 = fnv1a(seed)
    h2 = fnv1a(seed[::-1])
    h = (h1 ^ rotl32(h2, 13) ^ int(proof, 16)) & 0xffffffff
    payload = f"{nonce[:8]}.{parts['uidPart']}.{parts['checkPart']}.{h:08x}.{proof[:4]}"
    xored = bytes([b ^ F_SALT.encode()[i % len(F_SALT)] for i, b in enumerate(payload.encode())])
    b64 = base64.urlsafe_b64encode(xored).decode().rstrip("=")
    checksum = f"{fnv1a(payload + ticket + F_SALT) & 0xffff:04x}"
    return f"v2.{b64}.{checksum}"


s = requests.Session()
s.post(f"{BASE}/api/register", json={"username": "alice", "password": "password123"})
me = s.get(f"{BASE}/api/me").json()

token = build_portal_token(me["username"], me["uid"])
boot = s.post(f"{BASE}/api/internal/bootstrap",
              headers={"X-Portal-Token": token}).json()

client_nonce = secrets.token_hex(8)
sig = sign_final(me["uid"], boot["ticket"], boot["nonce"], client_nonce)

final = s.post(f"{BASE}/api/internal/final", json={
    "nonce": boot["nonce"],
    "client_nonce": client_nonce,
    "signature": sig,
}).json()

print(final)
```

---

## 七、常见误区

| 误区 | 为什么错 |
|---|---|
| 只改 HTML `disabled` 属性 | 服务器仍然校验 |
| 直接 POST `/api/internal/final` | 缺 nonce，查不到服务器状态 |
| 只看 HTML 找 Flag | Flag 在环境变量中，前端不存在 |
| 试图绕过 bootstrap | final 只认服务器保存的 `nonces[nonce]` |
| 只截取 ticket 的一部分 | 完整 ticket 参与 proof 和 checksum |
| 尝试调用 `AdminLegacy.generateAdminToken` | 该接口返回 403，是干扰项 |
| 修改 `client_nonce` 后复用旧 signature | 签名与 client_nonce 严格绑定 |
| 重放旧 nonce | `used = True` 之后失效 |
| 用别的 Session 提交 nonce | `rec["uid"] != user["uid"]` |
| 修改 `X-Portal-Token` 里的 timestamp | 超出 ±180 秒即失效 |

---

## 八、总结

本题考察的核心能力：

1. **Network 分析**：从 401 发现隐藏接口
2. **JS Reverse**：阅读 `portal.js` / `badge.js`
3. **算法还原**：FNV-1a、rotl32、XOR、自定义 Base32、Base64URL
4. **状态追踪**：`nonce` / `ticket` / `client_nonce` / `sessionProof` 的数据依赖
5. **请求构造**：手动构造 Header 与 JSON body

不是通过改一个参数、跑一个工具、Base64 解码一次就能拿 Flag 的题。

---

> Challenge by Keith