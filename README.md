# Orbital Gate

> Web + JavaScript Reverse CTF  
> Author: Ke1th  
> 难度：★★★★☆

---

## 一、项目介绍

**Orbital Gate** 是一道以“商业航天公司内部员工门户”为背景的 Web + JavaScript 逆向题目。

题目核心不是传统 Web 漏洞（IDOR / SQLi / XSS），而是：

- 浏览器 DevTools 使用
- JavaScript 代码阅读与逆向
- 自定义签名算法还原
- 多阶段动态请求构造

玩家需要：

1. 注册 / 登录获取 Session
2. 在 Network 中发现隐藏接口 `/api/internal/bootstrap`
3. 阅读 `static/js/portal.js`，还原 `PortalCrypto.buildPortalToken()`，构造 `X-Portal-Token`
4. 调用 `bootstrap` 获得服务器动态生成的 `nonce` 与 `ticket`
5. 阅读 `static/js/badge.js`，理解 `prepareBadge()` / `deriveSessionProof()` / `signFinal()` 的数据流
6. 生成 `v2` 签名，调用 `/api/internal/final`
7. 获取 Flag

---

## 二、目录结构

```text
orbital-gate/
├── app.py                    # Flask 后端
├── requirements.txt          # Python 依赖
├── Dockerfile                # 单 worker gunicorn
├── docker-compose.yml        # 本地调试
├── README.md                 # 本文件
├── WRITEUP.md                # 官方题解
├── templates/
│   └── index.html            # 前端页面
└── static/
    ├── css/
    │   └── style.css
    └── js/
        ├── admin.js          # 遗留代码 / 干扰项
        ├── portal.js         # 第一阶段算法
        └── badge.js          # 第二阶段算法
```

---

## 三、部署过程

### 3.1 环境要求

- Python 3.11+（或 Docker / Docker Desktop）
- 浏览器（Chrome / Edge / Firefox 均可）
- 可选：Python `requests` 用于脚本解题

---

### 3.2 本地 Flask 运行（无 Docker）

Linux / macOS：

```bash
export SECRET_KEY=$(python3 -c "import secrets; print(secrets.token_hex(32))")
export FLAG='flag{local_test}'

pip install -r requirements.txt
python app.py
```

Windows PowerShell：

```powershell
$env:SECRET_KEY = -join ((1..64) | ForEach-Object { '{0:x}' -f (Get-Random -Max 16) })
$env:FLAG = 'flag{local_test}'

pip install -r requirements.txt
python app.py
```

访问：`http://127.0.0.1:5000`

---

### 3.3 Docker Compose 运行（推荐）

`docker-compose.yml` 中的 `SECRET_KEY=${SECRET_KEY}` 会从当前 shell 环境变量读取，因此必须先设置 `SECRET_KEY`。

Linux / macOS：

```bash
export SECRET_KEY=$(python3 -c "import secrets; print(secrets.token_hex(32))")
export FLAG='flag{local_test}'

docker compose up --build -d
```

Windows PowerShell：

```powershell
$env:SECRET_KEY = -join ((1..64) | ForEach-Object { '{0:x}' -f (Get-Random -Max 16) })
$env:FLAG = 'flag{local_test}'

docker compose up --build -d
```

访问：`http://127.0.0.1:5000`

查看日志：

```bash
docker compose logs -f orbital-gate
```

查看状态：

```bash
docker compose ps
```

---

### 3.4 Docker Compose 删除 / 重启

停止并删除容器（保留镜像）：

```bash
docker compose down
```

停止、删除容器并删除本地网络：

```bash
docker compose down --remove-orphans
```

删除镜像：

```bash
docker compose down --rmi local
```

完全清理（容器 + 网络 + 卷 + 本地镜像）：

```bash
docker compose down --rmi local --volumes --remove-orphans
```

修改代码后重新构建并启动：

```bash
docker compose up --build -d
```

---

### 3.5 手动 Docker 运行（不使用 Compose）

构建镜像：

```bash
docker build -t orbital-gate .
```

Linux / macOS：

```bash
docker run -d -p 5000:5000 \
  -e SECRET_KEY=$(python3 -c "import secrets; print(secrets.token_hex(32))") \
  -e FLAG='flag{local_test}' \
  --name orbital-gate \
  orbital-gate
```

Windows PowerShell（注意用单引号，避免 `{}` 被解析）：

```powershell
docker run -d -p 5000:5000 `
  -e 'SECRET_KEY=abc123' `
  -e 'FLAG=flag{local_test}' `
  --name orbital-gate `
  orbital-gate
```

停止并删除容器：

```bash
docker stop orbital-gate
docker rm orbital-gate
```

删除镜像：

```bash
docker rmi orbital-gate
```

---

### 3.6 单 worker gunicorn 运行（无 Docker，生产环境）

Linux / macOS：

```bash
export SECRET_KEY=$(python3 -c "import secrets; print(secrets.token_hex(32))")
export FLAG='flag{local_test}'

gunicorn -w 1 -b 0.0.0.0:5000 app:app
```

Windows PowerShell：

```powershell
$env:SECRET_KEY = -join ((1..64) | ForEach-Object { '{0:x}' -f (Get-Random -Max 16) })
$env:FLAG = 'flag{local_test}'

gunicorn -w 1 -b 0.0.0.0:5000 app:app
```

---

### 3.7 部署注意事项

| 项目 | 要求 |
|---|---|
| `SECRET_KEY` | **必须** 注入随机值，缺失或使用默认值进程拒绝启动 |
| Gunicorn worker 数 | **必须** 为 `1`，因为 `users` / `nonces` 保存在进程内存 |
| `FLAG` | 通过环境变量注入，不要写死在前端 |
| 前端源码 | 不要生成 `.map`，不要泄露后端源码 |
| 端口 | 默认 `5000`，可自行映射 |

---

## 四、GZCTF 部署

1. 使用本目录的 `Dockerfile` 构建镜像。
2. 在 GZCTF 中创建“容器题”，端口填 `5000`。
3. 环境变量注入：

   ```text
   FLAG=flag{平台动态注入}
   SECRET_KEY=随机 64 位 hex
   ```

4. 健康检查：`GET /`
5. 资源限制建议：

   ```text
   CPU: 0.5
   内存: 128MB
   ```

6. 动态 Flag 由平台注入，`/api/internal/final` 成功后返回该环境变量。

---

## 五、题目核心机制

本题由两个阶段组成：

1. **第一阶段：Portal Token**
   - `PortalCrypto.buildPortalToken(username, uid, ts)`
   - 绑定 Session 的 `username` / `uid`，带 180 秒时间窗
   - 算法：FNV-1a + XOR + 循环移位 + 自定义 Base32-like + 校验和

2. **第二阶段：Badge Signature**
   - `BadgeV2.prepareBadge(challenge, uid)` 生成 state
   - `BadgeV2.signFinal(state)` 生成 `v2` signature
   - 依赖服务器动态生成的 `nonce` / `ticket`
   - `nonce` 一次性、绑定 Session、180 秒过期

Flag 仅在 `/api/internal/final` 全部校验通过后返回。

---

## 六、常见问题

**Q：启动报 `SECRET_KEY must be set to a random value`？**  
A：忘记设置 `SECRET_KEY`。

Linux / macOS：

```bash
export SECRET_KEY=$(python3 -c "import secrets; print(secrets.token_hex(32))")
```

Windows PowerShell：

```powershell
$env:SECRET_KEY = -join ((1..64) | ForEach-Object { '{0:x}' -f (Get-Random -Max 16) })
```

**Q：`docker compose up` 提示 `The "SECRET_KEY" variable is not set`？**  
A：当前 shell 没有导出 `SECRET_KEY`。先设置环境变量，或在项目根目录创建 `.env`：

```text
SECRET_KEY=local_dev_secret_please_change
FLAG=flag{local_dev_flag}
```

**Q：容器启动后立刻 `Exited`？**  
A：查看日志：

```bash
docker compose logs --tail=50 orbital-gate
```

大多数情况是 `SECRET_KEY` 为空。

**Q：注册后登录失败 / bootstrap 随机失败？**  
A：Gunicorn 使用了多 worker。改成 `-w 1`。

**Q：浏览器 Console 找不到 `requestBootstrap`？**  
A：这是预期行为，该函数已封装在 IIFE 内，不挂 `window`。玩家需要自己根据 `PortalCrypto` 构造请求。

**Q：我想直接看题解？**  
A：见 `WRITEUP.md`。

---

## 七、许可

本项目仅用于 CTF 教学与训练用途。  
Author: Ke1th