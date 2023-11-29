const forge = require('node-forge');
const rsa = forge.pki.rsa;
const fs = require('fs').promises;
const readline = require("readline");

const generateSessionKey = () => {
    try {
        return {sessionKey: forge.random.getBytesSync(32), iv: forge.random.getBytesSync(16)};
    } catch (error) {
        throw new Error('Failed to generate session key');
    }
}


const generateKeyPair = async () => {
    try {
        const keypair = await new Promise((resolve, reject) => {
            rsa.generateKeyPair({bits: 2048, workers: 2}, (err, keypair) => {
                if (err) {
                    reject(new Error('Failed to generate key pair'));
                } else {
                    resolve(keypair);
                }
            });
        });

        // Convert the keys to PEM format
        const privateKeyPem = forge.pki.privateKeyToPem(keypair.privateKey);
        const publicKeyPem = forge.pki.publicKeyToPem(keypair.publicKey);
        console.log('Private key: ' + privateKeyPem);
        console.log('Public key: ' + publicKeyPem);

        // Write the keys to separate PEM files
        await fs.writeFile('private.pem', privateKeyPem);
        console.log('Private key saved to private.pem');

        await fs.writeFile('public.pem', publicKeyPem);
        console.log('Public key saved to public.pem');
    } catch (err) {
        console.error(err);
    }
};

const getPublicKey = async () => {
    try {
        const publicKeyString = await fs.readFile('public.pem', 'binary');

        const publicKeyPem = forge.pki.publicKeyFromPem(publicKeyString)
        return {publicKeyString, publicKeyPem};
    } catch (error) {
        throw new Error('Failed to get public key');
    }
};

const encryptMessage = (iv, sessionKey, plainText, mode) => {
    const ecnryptMode = ['CBC', 'CFB'].includes(mode) ? mode : 'CBC';

    const cipher = forge.cipher.createCipher('AES-' + ecnryptMode, sessionKey);
    cipher.start({iv: iv});
    cipher.update(forge.util.createBuffer(plainText, 'utf8'));
    cipher.finish();
    return cipher.output;
}

const asymmetricEncrypt = async (data) => {
    const {publicKeyPem} = await getPublicKey()
    const encrypted = publicKeyPem.encrypt(data, "RSA-OAEP");
    const encryptedSymmetricKey = forge.util.encode64(encrypted);
    return encryptedSymmetricKey;
};


const decryptData = async ({initVector, key, encryptedMessage, mode}) => {
    try {
    const ecnryptMode = ['CBC', 'CFB'].includes(mode) ? mode : 'CBC';

    const privateKeyString = await fs.readFile('private.pem', 'binary');
    const privateKeyPem = forge.pki.privateKeyFromPem(privateKeyString)


    const decodedKey = forge.util.decode64(key)
    const decodedIv = forge.util.decode64(initVector)
    console.log({initVector, key});

    const decryptedKey = privateKeyPem.decrypt(decodedKey, 'RSA-OAEP');
    const decryptedIv = privateKeyPem.decrypt(decodedIv, 'RSA-OAEP');

    const decipher = forge.cipher.createDecipher('AES-' + ecnryptMode, decryptedKey);
    decipher.start({iv: decryptedIv});
    decipher.update(forge.util.createBuffer(encryptedMessage));
    decipher.finish();

    return decipher.output.toString();
    } catch (error) {
        console.error(error)
        throw new Error('Failed to decrypt data');
    }
};
const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout
});

rl.question('What type of encryption do you want to use? (CBС/CFB) ', (encryptionType) => {
    rl.question('Enter a message to encrypt: ', async (message) => {
        const encryptionTypeNormalized = encryptionType.toUpperCase().trim();
        const messageTrimmed = message.trim();

        await generateKeyPair()

        const {sessionKey, iv} = generateSessionKey();
        console.log('Session key: ', sessionKey);
        console.log('IV: ', iv);

        const encryptedMessage = encryptMessage(iv, sessionKey, messageTrimmed, encryptionTypeNormalized);
        console.log('Encrypted message: ', encryptedMessage);

        const encryptedIv = await asymmetricEncrypt(iv);
        console.log("Encrypted IV: ", encryptedIv)

        const encryptedSessionKey = await asymmetricEncrypt(sessionKey);
        console.log("Encrypted Session Key: ", encryptedSessionKey)

        const decryptedMessage = await decryptData({
            initVector: encryptedIv,
            key: encryptedSessionKey,
            encryptedMessage,
            mode: encryptionTypeNormalized
        });
        console.log("Decrypted message: ", decryptedMessage);
    });
});