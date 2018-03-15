// This script allows to log to a file the HTTP messages sent/received by ZAP.
// The main methods are "isMessageToLog" and "writeMessage" which tell when and how to log the messages.

// Declare classes used throughout the script:
var Integer = Java.type("java.lang.Integer");
var Locale = Java.type("java.util.Locale");
var Files = Java.type("java.nio.file.Files");
var Paths = Java.type("java.nio.file.Paths");
var StandardOpenOption = Java.type("java.nio.file.StandardOpenOption");
var BufferedOutputStream = Java.type("java.io.BufferedOutputStream");
var StandardCharsets = Java.type("java.nio.charset.StandardCharsets");
var HttpHeader = Java.type("org.parosproxy.paros.network.HttpHeader");
var HttpSender = Java.type("org.parosproxy.paros.network.HttpSender");
var HttpSenderListener = Java.type("org.zaproxy.zap.network.HttpSenderListener");

// The content type that the request and/or the response must contain to log the message.
var TARGET_CONTENT_TYPE = "json";
// The file where to log the messages.
var FILE_PATH = "/tmp/json.log";
// The write options.
var WRITE_OPTIONS = [StandardOpenOption.CREATE, StandardOpenOption.APPEND];
// Message request/response separator.
var CRLF_CRLF = "\r\n\r\n".getBytes(StandardCharsets.US_ASCII);
// The HTTP Sender listener used to log the messages.
var listener = new HttpSenderListener {

    getListenerOrder: function() {
        // Last listener to be notified to include all changes done by other scripts.
        return Integer.MAX_INT;
    },

    onHttpRequestSend: function(msg, initiator, sender) {
        // Nothing to do, message is checked when the response is received.
    },

    onHttpResponseReceive: function (msg, initiator, sender) {
        if (isMessageToLog(msg)) {
            Java.synchronized(function() writeMessage(msg), listener)();
        }
    }
}

function isMessageToLog(msg) {
    return hasContentType(msg.getRequestHeader(), TARGET_CONTENT_TYPE) ||
            hasContentType(msg.getResponseHeader(), TARGET_CONTENT_TYPE);
}

function hasContentType(header, contentType) {
    var headerContentType = header.getHeader(HttpHeader.CONTENT_TYPE);
    return headerContentType && headerContentType.toLowerCase(Locale.ROOT).contains(contentType);
}

function writeMessage(msg) {
    var bos;
    try {
        bos = new BufferedOutputStream(Files.newOutputStream(Paths.get(FILE_PATH), WRITE_OPTIONS));

        // Write request header and body:
        bos.write(msg.getRequestHeader().toString().getBytes(StandardCharsets.US_ASCII));
        bos.write(msg.getRequestBody().getBytes());
        bos.write(CRLF_CRLF);

        // Write response header and body:
        bos.write(msg.getResponseHeader().toString().getBytes(StandardCharsets.US_ASCII));
        bos.write(msg.getResponseBody().getBytes());
        bos.write(CRLF_CRLF);
    } catch (e) {
        print("An error occurred while writing the message: " + e);
    } finally {
        if (bos) {
            bos.close();
        }
    }
}

function install(helper) {
    HttpSender.addListener(listener);
}

function uninstall(helper) {
    HttpSender.removeListener(listener);
}