
const { validatePassword } = require("./passwordPolicy");
const { isPasswordBlocklisted } = require("./passwordBlocklist");

function checkPasswordSecurity(password) {
    const policyResult = validatePassword(password);

    if (!policyResult.valid) {
        return {
            valid: false,
            errors: policyResult.errors
        };
    }

    if (isPasswordBlocklisted(password)) {
        return {
            valid: false,
            errors: ["This password is commonly used and is not allowed."]
        };
    }

    return {
        valid: true,
        errors: []
    };
}

module.exports = { checkPasswordSecurity };