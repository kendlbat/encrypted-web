const Buffer = require('buffer/').Buffer 
const createHash = require("create-hash");

const ivlen = 12;

/**
* @param {string} key
* @returns {crypto.CryptoKey}
*/
async function convertToCryptoKey(key) {
    return await crypto.subtle.importKey(
        "raw",
        createHash('sha256').update(key).digest(),
        { name: "AES-GCM", length: 256 },
        true,
        ["decrypt", "encrypt"]
    );
}

/**
* @param {ArrayBuffer} data
* @returns {{iv: Buffer; pepper: Buffer; data: Buffer;}}
*/
function getCryptMetadata(data) {
    let iv = data.slice(0, ivlen);
    let pepper = data.slice(ivlen, ivlen + 64);
    let enc = data.slice(ivlen + 64);

    return { iv, pepper, data: enc };
}

/**
* @param {Buffer} data
* @param {Buffer} iv
* @param {string} key
* @param {Buffer} pepper
* @returns {Promise<Buffer>}
*/
async function decrypt(data, iv, key, pepper) {
    try {
        console.log(data)
        return crypto.subtle.decrypt({ name: "AES-GCM", iv: iv }, await convertToCryptoKey(key + pepper.toString()), data);
    } catch (e) {
        console.error(e);
    }
}

async function reloadHash() {
    document.body.innerHTML = "";

    if (!crypto) {
        document.body.innerText = "Crypto library not available. This page is not able to function in a browser without webcrypto capabilities.";
        return;
    }

    if (!window.location.hash) {
        document.body.innerText = "No page specified.";
        return;
    }

    let hash = window.location.hash.replace(/^#/, "");
    let page = window.location.hash.split("|key=")[0];
    let key = window.location.hash.split("|key=")[1];

    let res = await fetch("encrypted/" + page);

    if (res.status != 200) {
        document.body.innerText = "An error occurred";
        return;
    }

    let mime = res.headers.get("content-type");
    let data = await res.arrayBuffer();

    let crypt = await getCryptMetadata(data);

    data = await decrypt(crypt.data, crypt.iv, key, crypt.pepper);

    let iframe = document.createElement("iframe");
    iframe.src = `data:${mime};base64,${data.toString("base64")}`;
    document.body.appendChild(iframe);

}

document.addEventListener("hashchange", () => reloadHash());
document.addEventListener("DOMContentLoaded", () => reloadHash());