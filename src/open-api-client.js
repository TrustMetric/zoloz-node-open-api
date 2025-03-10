import axios from "axios";
import querystring from "querystring";

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
            // req.Header.Set(net_utils.HeaderContentType, net_utils.ContentTypePlainText)
		    // req.Header.Set(net_utils.HeaderEncrypt, "algorithm=RSA_AES, symmetricKey="+url.QueryEscape(encryptedAESKey))
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