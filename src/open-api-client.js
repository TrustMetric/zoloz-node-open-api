import axios from "axios";

import * as timeUtils from "./utils/time-utils.js";
import * as logger from "./utils/logger.js";
import * as security from "./utils/security.js";

class OpenAPIClient {
    hostURL;
    clientID;
    merchantPrivateKey;
	openAPIPublicKey;
	encrypted = false;
	isLoadTest = false;
	aesLength;

    constructor(hostURL, encrypted){
        this.hostURL = hostURL;
        this.encrypted = encrypted;
    }

    async callOpenAPI(apiName, request){
        let formattedTime = timeUtils.getFormattedTime();
        logger.log(logger.log_level.INFO, "Formatted Time is: " + formattedTime);


        let aesKey;
        let encryptedAESKey;

        if (this.encrypted) {
            // TODO
            // Create AES key and encrypt it here
        }

        let unsignedContent = "POST " + apiName + "\n" + this.clientID + "." + formattedTime + "." + JSON.stringify(request);
        logger.log(logger.log_level.INFO, "Unsigned Content is: " + unsignedContent);

        let requestSignature = security.createSignature(unsignedContent, this.merchantPrivateKey);

        let requestConfig = {
            headers: {},
            responseType: "json"
        }

        if (this.encrypted){
            // set encrypted headers
        } else {
            requestConfig.headers["Content-Type"] = "application/json; charset=UTF-8";
        }

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
            const response = await axios.post(apiURL, request, requestConfig);

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