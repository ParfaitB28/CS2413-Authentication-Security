const BLOCKED_PASSWORDS = new Set([
    "password",
    "password123",
    "password123!",
    "password123456!",
    "123456",
    "12345678",
    "qwerty",
    "qwerty123",
    "qwerty123!",
    "admin",
    "admin123",
    "admin123!",
    "welcome",
    "welcome123",
    "letmein",
    "iloveyou"
]);

function isPasswordBlocklisted(password) {
    if (typeof password !== "string") {
        return true;
    }

    return BLOCKED_PASSWORDS.has(password.toLowerCase());
}

module.exports = {
    isPasswordBlocklisted
};