#!/usr/bin/env node

const stream = require('node:stream');
const crypto = require('node:crypto');
const fs = require('fs');
const path = require('path');

const baseurl = "https://vault.kendlbat.dev/"

const ivlen = 12;

/**
 * 
 * @param {ArrayBuffer} stream 
 * @param {string} key 
 * @returns {Promise<{data: Buffer; iv: Buffer;}>}
 */
async function encrypt(stream, key) {
    const iv = crypto.getRandomValues(new Uint8Array(ivlen));

    const cryptkey = await convertToCryptoKey(key);

    return {
        data: await crypto.subtle.encrypt({ name: "AES-GCM", iv: iv }, cryptkey, stream),
        iv: Buffer.from(iv)
    };
}

/**
 * @param {Buffer} data
 * @param {Buffer} iv
 * @param {string} key
 * @returns {Promise<Buffer>}
 */
async function decrypt(data, iv, key) {
    return Buffer.from(await crypto.subtle.decrypt({ name: "AES-GCM", iv: iv }, await convertToCryptoKey(key), data));
}

/**
 * @param {string} key
 * 
 */
async function decryptWithMetadataExtraction(data, key) {
    let crypt = getCryptMetadata(data);
    return await decrypt(crypt.data, crypt.iv, key);
}

/**
 * 
 * @param {Buffer} data 
 * @param {Buffer} iv 
 * @returns 
 */
function addCryptMetadata(data, iv) {
    return Buffer.concat([iv, Buffer.from(data)]);
}

/**
 * @param {Buffer} data
 * @returns {{iv: Buffer; data: Buffer;}}
 */
function getCryptMetadata(data) {
    let iv = data.subarray(0, ivlen);
    let enc = data.subarray(ivlen);

    return { iv, data: enc };
}

async function encryptAllDirectory(dir, key) {
    let proms = [];

    for (let file of fs.readdirSync(dir)) {
        if (file.startsWith(".")) {
            console.warn("Ignoring files with . at beginning: " + file);
            continue;
        }

        proms.push(encryptFile(path.join(dir, file), key));
    }

    return await Promise.allSettled(proms);
}

async function encryptFile(file, key) {
    let data = fs.readFileSync(file);

    let newloc = file.replace(/^unencrypted/, "encrypted");

    let crypt = await encrypt(data, key);

    let raw = addCryptMetadata(crypt.data, crypt.iv);
    fs.writeFileSync(newloc, raw);

    console.log(`URL: ${baseurl}index.html#${file.replace(/^unencrypted\//, "")}~~key=${encodeURIComponent(key)}`)
}

/**
 * @param {string} key
 * @returns {crypto.CryptoKey}
 */
async function convertToCryptoKey(key) {
    return await crypto.subtle.importKey(
        "raw",
        crypto.createHash('sha256').update(key).digest(),
        { name: "AES-GCM", length: 256 },
        true,
        ["decrypt", "encrypt"]
    );
}

async function main() {

    if (process.argv.length !== 4) {
        console.log("Usage:");
        console.log("  node encrypt.js FILENAME_IN_UNENCRYPTED KEY");
        console.log();
        console.log("Use the following to generate a secure key:");
        console.log("  npm run genkey");
        return;
    }

    await encryptFile("unencrypted/" + process.argv[2], process.argv[3]);

    //fs.writeFileSync("testdec.txt", await decryptWithMetadataExtraction(fs.readFileSync("encrypted/test.txt.enc"), "test"))
}

main();

