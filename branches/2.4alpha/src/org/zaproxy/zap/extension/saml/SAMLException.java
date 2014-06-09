package org.zaproxy.zap.extension.saml;

/**
 * To be thrown in case of any error during the message encode/decode process
 */
public class SAMLException extends Exception {
    public SAMLException() {
    }

    public SAMLException(String message) {
        super(message);
    }

    public SAMLException(String message, Throwable cause) {
        super(message, cause);
    }
}
