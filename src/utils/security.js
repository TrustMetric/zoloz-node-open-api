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

/**
 * Generate a random AES key of the specified length.
 * @param {number} length - Length of the key in bytes (e.g., 16, 24, 32 for AES)
 * @returns {Buffer} Generated key as a Buffer
 * @throws {Error} If key generation fails
 */
function generateAESKey(length) {
    if (![16, 24, 32].includes(length)) {
        throw new Error("Invalid AES key length. Must be 16, 24, or 32 bytes.");
    }
    logger.log(logger.log_level.INFO, "Generating AES Key...");

    return crypto.randomBytes(length);
}

/**
 * AES Encrypt function (ECB mode with PKCS5 padding)
 * @param {Buffer} key - 256-bit (32-byte) AES key
 * @param {string} content - Plaintext content to encrypt
 * @returns {string} Base64 encoded ciphertext
 */
function aesEncrypt(key, content) {
    if (key.length !== 32) {
        throw new Error("Invalid key length. AES-256 requires a 32-byte key.");
    }
    logger.log(logger.log_level.INFO, "AES Key is valid, adding paddings...")

    const blockSize = 16; // AES block size (128 bits)
    const paddedContent = pkcs5Padding(Buffer.from(content, "utf-8"), blockSize);

    const cipher = crypto.createCipheriv("aes-256-ecb", key, null);
    cipher.setAutoPadding(false); // We handle padding manually

    const encrypted = Buffer.concat([cipher.update(paddedContent), cipher.final()]);
    return encrypted.toString("base64");
}

/**
 * PKCS5 Padding function
 * @param {Buffer} buffer - Data to pad
 * @param {number} blockSize - AES block size (16 bytes)
 * @returns {Buffer} Padded data
 */
function pkcs5Padding(buffer, blockSize) {
    const paddingSize = blockSize - (buffer.length % blockSize);
    const padding = Buffer.alloc(paddingSize, paddingSize); // Fill with padding value
    return Buffer.concat([buffer, padding]);
}

/**
 * Encrypt data using RSA public key (PKCS#1 v1.5).
 * @param {string} publicKeyPEM - The RSA public key in PEM format.
 * @param {Buffer} content - The content to encrypt.
 * @returns {string} Base64-encoded encrypted content.
 * @throws {Error} If encryption fails.
 */
function rsaEncrypt(publicKeyPEM, content) {
    try {
        // Normalize PEM format if needed
        publicKeyPEM = normalizePEM(publicKeyPEM, "PUBLIC");

        // Encrypt the content using RSA public key
        const encryptedBuffer = crypto.publicEncrypt(
            {
                key: publicKeyPEM,
                padding: crypto.constants.RSA_PKCS1_PADDING, // Equivalent to PKCS#1 v1.5
            },
            content
        );

        // Convert the encrypted content to Base64
        return encryptedBuffer.toString("base64");
    } catch (error) {
        throw new Error("RSA encryption failed: " + error.message);
    }
}


export {
    decodeBase64PrivateKey,
    createSignature,
    normalizePEM,
    generateAESKey,
    aesEncrypt,
    rsaEncrypt
};