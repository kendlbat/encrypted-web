/**
 * 
 * @param {string} string 
 * @returns {ArrayBuffer}
 */
async function createSHA256Hash(string) {
    const data = new TextEncoder().encode(string);
    return await crypto.subtle.digest('SHA-256', data);
}

function buf2hex(buffer) { // buffer is an ArrayBuffer
    return [...new Uint8Array(buffer)]
        .map(x => x.toString(16).padStart(2, '0'))
        .join('');
}


const ivlen = 12;

/**
* @param {string} key
* @returns {crypto.CryptoKey}
*/
async function convertToCryptoKey(key) {
    return await crypto.subtle.importKey(
        "raw",
        (await createSHA256Hash(key)),
        { name: "AES-GCM", length: 256 },
        true,
        ["decrypt", "encrypt"]
    );
}

/**
* @param {ArrayBuffer} data
* @returns {{iv: ArrayBuffer; data: ArrayBuffer;}}
*/
function getCryptMetadata(data) {
    let iv = data.slice(0, ivlen);
    let enc = data.slice(ivlen);

    return { iv, data: enc };
}

/**
* @param {ArrayBuffer} data
* @param {ArrayBuffer} iv
* @param {string} key
* @returns {Promise<ArrayBuffer>}
*/
async function decrypt(data, iv, key) {
    try {
        console.log(buf2hex(data))
        console.log(buf2hex(iv))
        console.log(key)
        const cryptkey = await convertToCryptoKey(key);
        let crypt = await crypto.subtle.decrypt({ name: "AES-GCM", iv: iv }, cryptkey, data);
        console.log(crypt)
        return crypt;
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
    let page = hash.split("|key=")[0];
    let key = hash.split("|key=")[1];

    if (!key) {
        document.body.innerText = "No key specified.";
        return;
    }

    let res = await fetch("encrypted/" + page);

    if (res.status != 200) {
        document.body.innerText = "An error occurred";
        return;
    }

    let mime = res.headers.get("content-type");
    let data = await res.arrayBuffer();

    console.log(buf2hex(data))

    let crypt = await getCryptMetadata(data);

    data = await decrypt(crypt.data, crypt.iv, key);

    if (data === undefined) {
        document.body.innerText = "The file was not able to be decrypted.";
        return;
    }

    data = new Blob([ data ]);

    let reader = new FileReader();

    reader.addEventListener("loadend", () => {
        let iframe = document.createElement("iframe");
        iframe.src = `data:${mime};base64,${reader.result.split(",", 2)[1]}`;
        document.body.appendChild(iframe);
    });

    reader.readAsDataURL(data);


}

document.addEventListener("hashchange", () => reloadHash());
document.addEventListener("DOMContentLoaded", () => reloadHash());