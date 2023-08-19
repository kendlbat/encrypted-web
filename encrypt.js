#!/usr/bin/env node

const stream = require('node:stream');
const crypto = require('node:crypto');
const fs = require('fs');
const path = require('path');

const pepperlen = 32;
const ivlen = 12;

/**
 * 
 * @param {ArrayBuffer} stream 
 * @param {string} key 
 * @returns {Promise<{data: Buffer; iv: Buffer; pepper: Buffer;}>}
 */
async function encrypt(stream, key) {
    let pepper = Buffer.from(crypto.randomBytes(pepperlen).toString('hex')).toString();
    const iv = crypto.getRandomValues(new Uint8Array(ivlen));

    return {
        data: await crypto.subtle.encrypt({ name: "AES-GCM", iv: iv }, await convertToCryptoKey(key + pepper), stream),
        iv: Buffer.from(iv),
        pepper: Buffer.from(pepper)
    };
}

/**
 * @param {Buffer} data
 * @param {Buffer} iv
 * @param {string} key
 * @param {Buffer} pepper
 * @returns {Promise<Buffer>}
 */
async function decrypt(data, iv, key, pepper) {
    return Buffer.from(await crypto.subtle.decrypt({ name: "AES-GCM", iv: iv }, await convertToCryptoKey(key + pepper.toString()), data));
}

/**
 * @param {string} key
 * 
 */
async function decryptWithMetadataExtraction(data, key) {
    let crypt = getCryptMetadata(data);
    console.log(crypt)
    return await decrypt(crypt.data, crypt.iv, key, crypt.pepper);
}

/**
 * 
 * @param {Buffer} data 
 * @param {Buffer} iv 
 * @param {Buffer} pepper 
 * @returns 
 */
function addCryptMetadata(data, iv, pepper) {
    return Buffer.concat([iv, pepper, Buffer.from(data)]);
}

/**
 * @param {Buffer} data
 * @returns {{iv: Buffer; pepper: Buffer; data: Buffer;}}
 */
function getCryptMetadata(data) {
    let iv = data.subarray(0, ivlen);
    let pepper = data.subarray(ivlen, ivlen + 64);
    let enc = data.subarray(ivlen + 64);

    return {iv, pepper, data: enc};
}

async function encryptAllDirectory(dir, key) {
    for (let file of fs.readdirSync(dir)) {
        if (file.startsWith(".")) {
            console.warn("Ignoring files with . at beginning: " + file);
            continue;
        }
        
        let data = fs.readFileSync(path.join(dir, file));

        let newloc = path.join(dir, file).replace(/^unencrypted/,"encrypted");

        let crypt = await encrypt(data, key);

        console.log(crypt)

        let raw = addCryptMetadata(crypt.data, crypt.iv, crypt.pepper);
        console.log(newloc)
        fs.writeFileSync(newloc, raw);
    }
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
    await encryptAllDirectory("unencrypted", "test");
    fs.writeFileSync("testdec.txt", await decryptWithMetadataExtraction(fs.readFileSync("encrypted/test.txt.enc"), "test"))
}

main();

