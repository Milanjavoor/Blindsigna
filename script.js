"use strict";

const API = "";
const $ = (id) => document.getElementById(id);

const requestButton = $("request-button");
const redeemButton = $("redeem-button");
const copyButton = $("copy-button");
let currentPackage = null;

function hexToBytes(hex) {
    if (hex.length % 2 !== 0 || !/^[0-9a-f]*$/i.test(hex)) {
        throw new Error("Invalid hexadecimal data.");
    }
    return Uint8Array.from(hex.match(/.{2}/g) || [], byte => parseInt(byte, 16));
}

function bytesToHex(bytes) {
    return Array.from(bytes, b => b.toString(16).padStart(2, "0")).join("");
}

function bytesToBigInt(bytes) {
    return BigInt("0x" + bytesToHex(bytes));
}

function bigIntToHex(value, byteLength) {
    return value.toString(16).padStart(byteLength * 2, "0");
}

function modPow(base, exponent, modulus) {
    let result = 1n;
    base %= modulus;
    while (exponent > 0n) {
        if (exponent & 1n) result = (result * base) % modulus;
        exponent >>= 1n;
        base = (base * base) % modulus;
    }
    return result;
}

function gcd(a, b) {
    while (b !== 0n) [a, b] = [b, a % b];
    return a;
}

function modInverse(a, modulus) {
    let [oldR, r] = [a, modulus];
    let [oldS, s] = [1n, 0n];
    while (r !== 0n) {
        const q = oldR / r;
        [oldR, r] = [r, oldR - q * r];
        [oldS, s] = [s, oldS - q * s];
    }
    if (oldR !== 1n) throw new Error("Blinding factor has no modular inverse.");
    return (oldS % modulus + modulus) % modulus;
}

function randomCoprime(modulus) {
    const byteLength = Math.ceil(modulus.toString(2).length / 8);
    while (true) {
        const randomBytes = crypto.getRandomValues(new Uint8Array(byteLength));
        const candidate = bytesToBigInt(randomBytes) % modulus;
        if (candidate > 1n && gcd(candidate, modulus) === 1n) return candidate;
    }
}

async function api(path, options = {}) {
    const response = await fetch(API + path, {
        ...options,
        headers: { "Content-Type": "application/json", ...(options.headers || {}) }
    });
    const data = await response.json();
    if (!response.ok) throw new Error(data.detail || "Request failed.");
    return data;
}

function addActivity(title, description) {
    const list = $("activity-list");
    const empty = list.querySelector(".empty-activity");
    if (empty) empty.remove();

    const item = document.createElement("div");
    item.className = "activity-item";
    const text = document.createElement("div");
    text.className = "activity-text";
    const heading = document.createElement("h3");
    heading.textContent = title;
    const detail = document.createElement("p");
    detail.textContent = description;
    const time = document.createElement("span");
    time.className = "activity-time";
    time.textContent = new Date().toLocaleTimeString();
    text.append(heading, detail);
    item.append(text, time);
    list.prepend(item);
}

function showResult(message, success) {
    const box = $("redemption-result");
    box.hidden = false;
    box.textContent = message;
    box.className = success ? "result-message success" : "result-message error";
}

function encodeBase64Url(bytes) {
    let binary = "";
    bytes.forEach(byte => binary += String.fromCharCode(byte));
    return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function decodeBase64Url(value) {
    const base64 = value.replace(/-/g, "+").replace(/_/g, "/");
    const padded = base64 + "=".repeat((4 - base64.length % 4) % 4);
    const binary = atob(padded);
    return Uint8Array.from(binary, char => char.charCodeAt(0));
}

async function refreshMetrics() {
    const metrics = await api("/api/metrics");
    $("request-count").textContent = metrics.total_requests;
    $("redeemed-count").textContent = metrics.redeemed_tokens;
}

async function checkBackend() {
    try {
        await api("/api/health");
        $("system-status").textContent = "Online";
        $("system-detail").textContent = "Backend connected";
        await refreshMetrics();
        addActivity("Dashboard connected", "FastAPI backend is online");
    } catch (error) {
        $("system-status").textContent = "Offline";
        $("system-detail").textContent = "Start the Python backend";
        addActivity("Backend unavailable", error.message);
    }
}

requestButton.addEventListener("click", async () => {
    requestButton.disabled = true;
    requestButton.textContent = "Creating blind signature...";
    try {
        // 1. Fetch issuer's public RSA key.
        const key = await api("/api/public-key");
        const n = BigInt("0x" + key.n_hex);
        const e = BigInt("0x" + key.e_hex);
        const k = key.signature_bytes;

        // 2. Create a random token payload in the browser.
        const serialBytes = crypto.getRandomValues(new Uint8Array(32));
        const payload = {
            version: 1,
            serial: bytesToHex(serialBytes),
            purpose: $("token-purpose").value,
            created_at: Math.floor(Date.now() / 1000)
        };
        const messageBytes = new TextEncoder().encode(JSON.stringify(payload));

        // 3. Hash the domain separator and payload, matching the Python backend.
        const prefix = new TextEncoder().encode("BlindToken-v1:");
        const combined = new Uint8Array(prefix.length + messageBytes.length);
        combined.set(prefix);
        combined.set(messageBytes, prefix.length);
        const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", combined));
        const m = bytesToBigInt(digest);

        // 4. Blind the message: m' = m * r^e mod n.
        const r = randomCoprime(n);
        const blinded = (m * modPow(r, e, n)) % n;
        const blindedHex = bigIntToHex(blinded, k);

        // 5. Ask issuer to sign only the blinded message.
        const signed = await api("/api/issuance/blind-sign", {
            method: "POST",
            body: JSON.stringify({ blinded_message_hex: blindedHex })
        });
        const blindSignature = BigInt("0x" + signed.blind_signature_hex);

        // 6. Unblind: s = s' * inverse(r) mod n.
        const signature = (blindSignature * modInverse(r, n)) % n;
        const signatureHex = bigIntToHex(signature, k);

        // Token ID is a base64url encoding of the signed payload.
        const tokenId = encodeBase64Url(messageBytes);
        currentPackage = { token_id: tokenId, signature: signatureHex };

        $("empty-token").hidden = true;
        $("token-details").hidden = false;
        $("token-id").textContent = tokenId;
        $("signature-value").textContent = signatureHex;
        $("display-purpose").textContent = payload.purpose;
        $("token-state").textContent = "Blind signature created";
        $("redeem-id").value = tokenId;
        $("redeem-signature").value = signatureHex;
        $("redemption-result").hidden = true;

        addActivity("Blind-signed token created", payload.purpose + " | " + tokenId.slice(0, 18) + "...");
        await refreshMetrics();
    } catch (error) {
        addActivity("Token request failed", error.message);
        alert("Could not create token: " + error.message);
    } finally {
        requestButton.disabled = false;
        requestButton.textContent = "Create Blind-Signed Token";
    }
});

redeemButton.addEventListener("click", async () => {
    const tokenId = $("redeem-id").value.trim();
    const signatureHex = $("redeem-signature").value.trim();

    if (!tokenId || !signatureHex) {
        showResult("Enter both the token ID and signature.", false);
        return;
    }

    redeemButton.disabled = true;
    redeemButton.textContent = "Verifying...";
    try {
        const messageBytes = decodeBase64Url(tokenId);
        const result = await api("/api/tokens/redeem", {
            method: "POST",
            body: JSON.stringify({
                message_hex: bytesToHex(messageBytes),
                signature_hex: signatureHex
            })
        });
        showResult(result.message, true);
        if (currentPackage && currentPackage.token_id === tokenId) {
            $("token-state").textContent = "Redeemed";
        }
        addActivity("Token redeemed", result.message);
        await refreshMetrics();
    } catch (error) {
        showResult(error.message, false);
        addActivity("Redemption rejected", error.message);
        await refreshMetrics();
    } finally {
        redeemButton.disabled = false;
        redeemButton.textContent = "Verify and Redeem Token";
    }
});

copyButton.addEventListener("click", async () => {
    if (!currentPackage) return;
    try {
        await navigator.clipboard.writeText(JSON.stringify(currentPackage, null, 2));
        copyButton.textContent = "Copied";
        setTimeout(() => copyButton.textContent = "Copy package", 1500);
    } catch {
        copyButton.textContent = "Copy unavailable";
    }
});

checkBackend();
