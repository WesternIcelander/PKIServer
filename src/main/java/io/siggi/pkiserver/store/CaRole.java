package io.siggi.pkiserver.store;

/** Role of a signing certificate on this server. */
public enum CaRole {
    /** Self-signed: a trust anchor. */
    ROOT,
    /** Issued by another CA. */
    INTERMEDIATE;

    public String id() {
        return name().toLowerCase(java.util.Locale.ROOT);
    }
}
