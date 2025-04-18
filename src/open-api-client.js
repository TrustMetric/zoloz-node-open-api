import axios from "axios";
import querystring from "querystring";

import * as timeUtils from "./utils/time-utils.js";
import * as logger from "./utils/logger.js";
import * as security from "./utils/security.js";
import * as parser from "./utils/parser.js";
import { error } from "console";

class OpenAPIClient {
    hostURL;
    clientID;
    merchantPrivateKey;
	openAPIPublicKey;
	encrypted = false;
	isLoadTest = false;
	aesLength = 32;

    constructor(hostURL, encrypted){
        this.hostURL = hostURL;
        this.encrypted = encrypted;
    }

    async callOpenAPI(apiName, request){
        let requestString = JSON.stringify(request);
        let formattedTime = timeUtils.getFormattedTime();
        logger.log(logger.log_level.INFO, "Formatted Time is: " + formattedTime);

        let requestConfig = {
            headers: {},
            responseType: "json"
        };

        if (this.encrypted){
            // create encrypted key
            let aesKey = security.generateAESKey(this.aesLength);
            logger.log(logger.log_level.INFO, "AES Key is: " + aesKey.toString());

            requestString = security.aesEncrypt(aesKey, requestString);
            logger.log(logger.log_level.INFO, "Encrypted Request Key is: " + request);

            let encryptedAESKey = security.rsaEncrypt(this.openAPIPublicKey, aesKey);
            logger.log(logger.log_level.INFO, "Encrypted AES Key is: " + encryptedAESKey);

            // set encrypted headers
            requestConfig.headers["Content-Type"] = "text/plain; charset=UTF-8";
            requestConfig.headers["Encrypt"] = "algorithm=RSA_AES, symmetricKey=" + querystring.escape(encryptedAESKey);
        } else {
            requestConfig.headers["Content-Type"] = "application/json; charset=UTF-8";
        }

        let unsignedContent = "POST " + apiName + "\n" + this.clientID + "." + formattedTime + "." + requestString;
        logger.log(logger.log_level.INFO, "Unsigned Content is: " + unsignedContent);

        let requestSignature = security.createSignature(unsignedContent, this.merchantPrivateKey);

        requestConfig.headers["Client-Id"] = this.clientID;
        requestConfig.headers["Request-Time"] = formattedTime;
        requestConfig.headers["Signature"] = "algorithm=RSA256, signature="+requestSignature;

        logger.log(logger.log_level.INFO, "Headers: " + JSON.stringify(requestConfig.headers));

        if (this.isLoadTest) {
            requestConfig.headers["loadTestMode"] = "true";
        }

        let apiURL = this.hostURL + apiName;

        try {
            logger.log(logger.log_level.INFO, "Sending request...")
            const response = await axios.post(apiURL, requestString, requestConfig);

            let responseSignatureHeader = response.headers["signature"];
            logger.log(logger.log_level.INFO, "Response Signature Header is: "+responseSignatureHeader);

            let responseSignature = responseSignatureHeader.split("signature=");
            if (responseSignature.length < 2) {
                throw new Error("signature not found");
            }

            responseSignature = querystring.unescape(responseSignature[1]);
            logger.log(logger.log_level.INFO, "Response Signature is: "+responseSignature);

            let responseTime = response.headers["response-time"].trim();
            logger.log(logger.log_level.INFO, "Response Time is: "+responseTime);

            let unverifiedContent = "POST " + apiName + "\n" + this.clientID + "." + responseTime + "." + parser.safeStringify(response.data);
            logger.log(logger.log_level.INFO, "Unverified Content is: "+unverifiedContent);

            let isVerified = security.verifySignature(this.openAPIPublicKey, responseSignature, unverifiedContent);
            if (!isVerified) {
                throw new Error("signature verification failed!");
            }
            logger.log(logger.log_level.INFO, "Signature verified...");
            
            if (this.encrypted) {
                let encryptHeader = response.headers["encrypt"];
                logger.log(logger.log_level.INFO, "Encrypt Header Response: " + encryptHeader);
                
                const parts = encryptHeader.split("symmetricKey=");
                if (parts.length < 2) {
                    throw new Error("symmetricKey not found");
                }

                let unescapedAESKey = querystring.unescape(parts[1]);
                logger.log(logger.log_level.INFO, "Unescaped AES Key: " + unescapedAESKey);

                let decryptedAESKey = security.rsaDecrypt(this.merchantPrivateKey, unescapedAESKey);
                logger.log(logger.log_level.INFO, "Decrypted AES Key: " + decryptedAESKey);

                let decryptedResponse = security.aesDecrypt(decryptedAESKey, response.data);

                return JSON.parse(decryptedResponse);
            }

            return response.data;
        } catch (error) {
            // TODO throws exception
            return null;
        }
        // HeaderEncrypt      = "Encrypt"
        // ContentTypePlainText = "text/plain; charset=UTF-8"

        // requestConfig.headers
    }
}

export { OpenAPIClient };