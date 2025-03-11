function safeStringify(value) {
    if (typeof value === "string"){
        return value;
    }
    if (typeof value === "object") {
        return JSON.stringify(value);
    }
    return null;
}

export {safeStringify}