// Imported Standard Libraries
import * as crypto from "crypto";
import querystring from "querystring";

// Imported Local Libraries
import * as logger from "./logger.js";

function decodeBase64PrivateKey(base64String) {
    if (!base64String || typeof base64String !== "string") {
        throw new Error("Invalid input: Base64 string is required.");
    }
    return Buffer.from(base64String, "base64");
}

// TODO This function accepts .pem, need to create normalize PEM.
// Because of this, no need to decode the private key before calling this function.
/**
 * Creates a signature for the given content using an RSA private key.
 * @param {string} unsignedContent - The content to sign.
 * @param {string} privateKey - The RSA private key in PEM format.
 * @returns {string} - The base64 URL-encoded signature.
 */
function createSignature(unsignedContent, privateKey) {
    privateKey = normalizePEM(privateKey, "PRIVATE");
    logger.log(logger.log_level.INFO, "Normalized Private Key: "+privateKey);

    // Step 1: Create a sign object
    const sign = crypto.createSign("sha256");
    sign.update(unsignedContent);
    sign.end();
    logger.log(logger.log_level.INFO, "Sign: "+ sign);

    // Step 2: Sign with explicit padding
    const signature = sign.sign({
        key: privateKey,
        format: "pem",
        padding: crypto.constants.RSA_PKCS1_PADDING // Ensure PKCS#1 v1.5
        // saltLength: 0, // Disable salt for exact match
    });

    logger.log(logger.log_level.INFO, "Signature: "+signature.toString("base64"));

    // Step 3: Encode using Go-equivalent query escaping
    const encodedSignature = querystring.escape(signature.toString("base64"));
    console.log("Encoded Signature:", encodedSignature);

    return encodedSignature;
}

/**
 * Normalizes a PEM-formatted key by removing unnecessary headers/footers and reformatting it.
 * @param {string} keyPEM - The raw PEM string.
 * @param {string} keyType - Either "PUBLIC" or "PRIVATE".
 * @returns {string} - The normalized PEM string.
 */
function normalizePEM(keyPEM, keyType) {
    // Remove headers/footers using a single regex pattern
    keyPEM = keyPEM.replace(/-----BEGIN (?:RSA )?(?:PUBLIC|PRIVATE) KEY-----|-----END (?:RSA )?(?:PUBLIC|PRIVATE) KEY-----/g, "").trim();

    let header, footer;

    if (keyType === "PUBLIC") {
        header = "-----BEGIN PUBLIC KEY-----";
        footer = "-----END PUBLIC KEY-----";
    } else {
        header = "-----BEGIN PRIVATE KEY-----";
        footer = "-----END PRIVATE KEY-----";
    }

    return header + "\n" + keyPEM + "\n" + footer;
}


export {
    decodeBase64PrivateKey,
    createSignature,
    normalizePEM
};