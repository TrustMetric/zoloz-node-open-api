class OpenAPIClient {
    hostURL;
    merchantPrivateKey;
	openAPIPublicKey;
	encrypted = false;
	isLoadTest = false;
	aesLength;

    constructor(hostURL, encrypted){
        this.hostURL = hostURL;
        this.encrypted = encrypted;
    }

    callOpenAPI(apiName, request){
        console.log("You got this!")
    }
}

module.exports = { OpenAPIClient };