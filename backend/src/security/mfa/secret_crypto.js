const crypto = require('node:crypto');
function getEncryptionKey(){
    const keyHex = process.env.MFA_ENCRYPTION_KEY;
    if(!keyHex || !/^[0-9a-fA-F]{64}$/.test(keyHex)){
        throw new Error('MFA_ENCRYPTION_KEY must contain 64 hexadecimal characters. ')
    }
    return Buffer.from(keyHex, 'hex');
}

function encryptSecret(secret){
    if (typeof secret !== 'string' || secret.length === 0){
        throw new Error('MFA secret must be a non-empty string.')
    }
    const key = getEncryptionKey();
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
    const encrypted = Buffer.concat([cipher.update(secret, 'utf8'), cipher.final()]);

    const authTag = cipher.getAuthTag();

    return [
        iv.toString('hex'),
        authTag.toString('hex'),
        encrypted.toString('hex')
    ].join(':');

}
//Prepares Stored value for decryption.
function decryptSecret(storedSecret) {
    if(typeof storedSecret !== 'string'){
        throw new Error('Encrypted MFA secret must be a string.');
    }
    const parts = storedSecret.split(':');

    if(parts.length !== 3){
        throw new Error('Invalid encrypted MFA secret format');
    }
    const [ivHex, authTagHex, encryptedHex] = parts;

    if(
        !/^[0-9a-fA-F]{24}$/.test(ivHex) ||
        !/^[0-9a-fA-F]{32}$/.test(authTagHex) ||
        !/^(?:[0-9a-fA-F]{2})+$/.test(encryptedHex)
    ){
        throw new Error('Invalid encrypted MFA secret format.');
    }

    const key = getEncryptionKey();
    const iv = Buffer.from(ivHex, 'hex');
    const authTag = Buffer.from(authTagHex, 'hex');
    const encrypted = Buffer.from(encryptedHex, 'hex');

    const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
    decipher.setAuthTag(authTag);

    const decrypted = Buffer.concat([
        decipher.update(encrypted),
        decipher.final()
    ]);

    return decrypted.toString('utf8');
}
module.exports = { encryptSecret, decryptSecret };
