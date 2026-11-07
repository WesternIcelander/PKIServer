package io.siggi.pkiserver.store;

/** A store operation was refused (conflict, unknown CA, invalid name) or failed. */
public class StoreException extends Exception {
    public StoreException(String message) {
        super(message);
    }

    public StoreException(String message, Throwable cause) {
        super(message, cause);
    }
}
