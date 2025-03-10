import { OpenAPIClient } from "./src/open-api-client.js";
import { getFormattedTime } from "./src/utils/time-utils.js";

function greet(name) {
    return `Hello ${name}!`;
}

export {greet, getFormattedTime, OpenAPIClient}