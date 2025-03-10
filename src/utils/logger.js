const log_level = {
    INFO: "INFO",
    WARN: "WARN",
    ERROR: "ERROR",
    DEBUG: "DEBUG",
};

function log(level, message) {
    const now = new Date();
    const timestamp = now.toISOString().replace("T", " ").replace("Z", "");

    const logMessage = `[${level}] ${timestamp} - ${message}`;

    if (level === log_level.ERROR) {
        console.error(logMessage); // Send errors to stderr
    } else {
        console.log(logMessage); // Send everything else to stdout
    }
}

export {log_level, log}