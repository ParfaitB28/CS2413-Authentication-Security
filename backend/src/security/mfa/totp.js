const { generateSecret, generateURI, verify } = require('otplib');
const { encryptSecret, decryptSecret } = require('./secret_crypto');

function createEnrollment(email){
    const secret =  generateSecret();
    const uri = generateURI({
        issuer: 'CS2413 Security Project',
        label: email,
        secret: secret   
    });
    const encryptedSecret = encryptSecret(secret);
    return{
        uri: uri,
        encryptedSecret: encryptedSecret
    };
}

async function verifyCode(encryptedSecret, token) {
    if(typeof token !== 'string' || !/^[0-9]{6}$/.test(token)){
        return false;
    }
    const secret = decryptSecret(encryptedSecret);
    const result = await verify({
        secret: secret,
        token: token
    });
    return result.valid;
}

async function verifyCodeDetails(encryptedSecret, token, lastUsedStep = null) {
    if (typeof token !== 'string' || !/^[0-9]{6}$/.test(token)) {
        return { valid: false };
    }

    const secret = decryptSecret(encryptedSecret);

    return verify({
        secret: secret,
        token: token,
        afterTimeStep: lastUsedStep === null
            ? undefined
            : Number(lastUsedStep)
    });
}

module.exports = { createEnrollment, verifyCode, verifyCodeDetails };