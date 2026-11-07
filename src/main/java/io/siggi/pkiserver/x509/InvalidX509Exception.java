package io.siggi.pkiserver.x509;

/**
 * Thrown when input that should contain certificates or CRLs can't be decoded.
 * The message is meant to be shown to the uploader.
 */
public class InvalidX509Exception extends Exception {
    public InvalidX509Exception(String message) {
        super(message);
    }

    public InvalidX509Exception(String message, Throwable cause) {
        super(message, cause);
    }
}
