'use strict';

const { evaluate } = require('../passwordStrength');

function checkPasswordSecurity(password, userInputs = []) {
    return evaluate(password, userInputs);
}

module.exports = { checkPasswordSecurity };