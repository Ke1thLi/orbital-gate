// =====================================================
// 第二阶段：公开算法，允许 Console 调用
// =====================================================
const BadgeV2 = (() => {
    const F_SALT = "FINAL_DOCK_7";
    const P_SALT = "ORBITAL_GATE_V2";

    function fnv1a(str) {
        let h = 0x811c9dc5;
        const bytes = new TextEncoder().encode(str);
        for (const b of bytes) {
            h ^= b;
            h = Math.imul(h, 0x01000193) >>> 0;
        }
        return h >>> 0;
    }

    function rotl32(x, n) {
        return ((x << n) | (x >>> (32 - n))) >>> 0;
    }

    function xorWithSalt(text, salt) {
        const t = new TextEncoder().encode(text);
        const s = new TextEncoder().encode(salt);
        const out = new Uint8Array(t.length);
        for (let i = 0; i < t.length; i++) {
            out[i] = t[i] ^ s[i % s.length];
        }
        return out;
    }

    function base64Url(bytes) {
        let bin = "";
        for (const b of bytes) {
            bin += String.fromCharCode(b);
        }
        return btoa(bin)
            .replace(/\+/g, "-")
            .replace(/\//g, "_")
            .replace(/=+$/g, "");
    }

    function parseTicket(ticket) {
        const m = /^ORB-([0-9A-Z]+)-([0-9A-F]{16})-([0-9A-F]{4})$/.exec(ticket);
        if (!m) throw new Error("bad ticket");
        return {
            raw: ticket,
            uidPart: m[1],
            randomPart: m[2],
            checkPart: m[3]
        };
    }

    function randomClientNonce() {
        const a = new Uint8Array(8);
        crypto.getRandomValues(a);
        return [...a].map(b => b.toString(16).padStart(2, "0")).join("");
    }

    function deriveSessionProof(state) {
        const seed = `${state.uid}:${state.ticket}:${state.nonce}:${state.clientNonce}:${P_SALT}`;
        const h1 = fnv1a(seed);
        const h2 = fnv1a([...seed].reverse().join(""));
        const proof = rotl32((h1 ^ h2) >>> 0, 7);
        return proof.toString(16).padStart(8, "0");
    }

    function prepareBadge(challenge, uid) {
        if (!challenge || !challenge.nonce || !challenge.ticket) {
            throw new Error("invalid challenge");
        }
        const parts = parseTicket(challenge.ticket);
        const clientNonce = randomClientNonce();

        const state = {
            stage: "prepared",
            uid,
            nonce: challenge.nonce,
            ticket: challenge.ticket,
            parts,
            clientNonce
        };

        state.sessionProof = deriveSessionProof(state);
        return state;
    }

    function signFinal(state) {
        if (!state || state.stage !== "prepared") {
            throw new Error("badge state not prepared");
        }

        const { uid, nonce, ticket, parts, clientNonce, sessionProof } = state;

        const seed = `${uid}:${ticket}:${nonce}:${clientNonce}:${F_SALT}`;
        const h1 = fnv1a(seed);
        const h2 = fnv1a([...seed].reverse().join(""));
        const h = (h1 ^ rotl32(h2, 13) ^ parseInt(sessionProof, 16)) >>> 0;

        const a = nonce.slice(0, 8);
        const b = parts.uidPart;
        const c = parts.checkPart;
        const d = h.toString(16).padStart(8, "0");
        const e = sessionProof.slice(0, 4);
        const payload = `${a}.${b}.${c}.${d}.${e}`;

        const xored = xorWithSalt(payload, F_SALT);
        const b64 = base64Url(xored);
        const checksum = (fnv1a(payload + ticket + F_SALT) & 0xffff)
            .toString(16)
            .padStart(4, "0");

        return `v2.${b64}.${checksum}`;
    }

    return {
        prepareBadge,
        signFinal,
        parseTicket,
        deriveSessionProof,
        fnv1a
    };
})();

window.BadgeV2 = BadgeV2;