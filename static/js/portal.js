// =====================================================
// 第一阶段：公开算法，允许 Console 调用
// =====================================================
const PortalCrypto = (() => {
    const P_SALT = "ORBITAL_GATE_V2";
    const ALPHA = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";

    function fnv1a(str) {
        let h = 0x811c9dc5;
        const bytes = new TextEncoder().encode(str);
        for (const b of bytes) {
            h ^= b;
            h = Math.imul(h, 0x01000193) >>> 0;
        }
        return h >>> 0;
    }

    function toBase32Like(bytes) {
        let bits = 0;
        let value = 0;
        let out = "";
        for (const b of bytes) {
            value = (value << 8) | b;
            bits += 8;
            while (bits >= 5) {
                out += ALPHA[(value >>> (bits - 5)) & 31];
                bits -= 5;
                value &= bits ? ((1 << bits) - 1) : 0;
            }
        }
        if (bits > 0) {
            out += ALPHA[(value << (5 - bits)) & 31];
        }
        return out;
    }

    function transformPortalBytes(raw, key) {
        const data = new TextEncoder().encode(raw);
        const out = new Uint8Array(data.length);
        for (let i = 0; i < data.length; i++) {
            const k = (key >>> ((i % 4) * 8)) & 0xff;
            let x = data[i] ^ k;
            x = ((x << 3) | (x >>> 5)) & 0xff;
            out[i] = x;
        }
        return out;
    }

    function buildPortalToken(username, uid, ts = Math.floor(Date.now() / 1000)) {
        const raw = `${username}|${uid}|${ts}|${P_SALT}`;
        const key = (Math.imul(uid, 2654435761) ^ 0x9e3779b9) >>> 0;
        const bytes = transformPortalBytes(raw, key);
        const encoded = toBase32Like(bytes);
        const checksum = (fnv1a(raw) >>> 0)
            .toString(16)
            .padStart(8, "0")
            .slice(-4);
        return `v1.${ts}.${encoded}.${checksum}`;
    }

    return {
        buildPortalToken,
        fnv1a
    };
})();

window.PortalCrypto = PortalCrypto;

// =====================================================
// 页面业务逻辑（IIFE，不挂 window）
// =====================================================
(() => {
    const $ = (id) => document.getElementById(id);

    async function api(path, options = {}) {
        const headers = {
            "Content-Type": "application/json",
            ...(options.headers || {})
        };
        const r = await fetch(path, {
            credentials: "same-origin",
            ...options,
            headers
        });
        return r.json();
    }

    function checkPassword(p) {
        return typeof p === "string" && p.length >= 6;
    }

    async function loadMe() {
        const r = await fetch("/api/me", { credentials: "same-origin" });
        if (!r.ok) return null;
        return r.json();
    }

    async function showDashboard(me) {
        $("auth").hidden = true;
        $("dashboard").hidden = false;
        $("who").textContent = me.username;
        $("uid").textContent = me.uid;
        $("dept").textContent = me.dept;
    }

    $("register").onclick = async () => {
        const username = $("username").value.trim();
        const password = $("password").value;
        if (!checkPassword(password)) {
            alert("密码至少 6 位");
            return;
        }
        const data = await api("/api/register", {
            method: "POST",
            body: JSON.stringify({ username, password })
        });
        if (data.ok) await showDashboard(data);
        else alert(data.error || "注册失败");
    };

    $("login").onclick = async () => {
        const username = $("username").value.trim();
        const password = $("password").value;
        const data = await api("/api/login", {
            method: "POST",
            body: JSON.stringify({ username, password })
        });
        if (data.ok) await showDashboard(data);
        else alert(data.error || "登录失败");
    };

    $("syncBadge").onclick = async () => {
        const out = $("out");
        out.textContent = "尝试普通同步...";
        const r = await fetch("/api/internal/bootstrap", {
            method: "POST",
            credentials: "same-origin"
        });
        const data = await r.json();
        out.textContent = JSON.stringify(data, null, 2);
    };

    (async () => {
        const me = await loadMe();
        if (me) await showDashboard(me);
    })();
})();