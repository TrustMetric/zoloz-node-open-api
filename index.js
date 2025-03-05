const { OpenAPIClient } = require("./src/open-api-client")

function greet(name) {
    return `Hello ${name}!`;
}

module.exports = {greet, OpenAPIClient}