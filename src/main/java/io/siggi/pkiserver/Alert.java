package io.siggi.pkiserver;

import com.google.gson.JsonObject;

import java.time.Instant;

/**
 * A condition worth notifying the admin about.
 *
 * @param key     identifies the condition, so it is notified once (and then repeated) while active
 * @param type    one of the {@code TYPE_*} constants
 * @param slug    the signing certificate concerned
 * @param serial  the end-entity certificate concerned, or null
 * @param at      the moment that matters: coverage end, the stale CRL's nextUpdate, or notAfter
 * @param message one line, human-readable
 */
record Alert(String key, String type, String slug, String serial, Instant at, String message) {
    static final String TYPE_CRL_COVERAGE_LOW = "crl-coverage-low";
    static final String TYPE_CRL_STALE = "crl-stale";
    static final String TYPE_SIGNING_CERT_EXPIRING = "signing-cert-expiring";
    static final String TYPE_CERT_EXPIRING = "cert-expiring";

    JsonObject toJson() {
        JsonObject j = new JsonObject();
        j.addProperty("type", type);
        j.addProperty("slug", slug);
        if (serial != null) j.addProperty("serial", serial);
        j.addProperty("at", at.toString());
        j.addProperty("message", message);
        return j;
    }
}
