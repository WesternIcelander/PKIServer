package io.siggi.pkiserver.store;

import java.util.Locale;

/**
 * State of a stored CRL. Discarded CRLs are not stored (their files are deleted); they are
 * only recorded as {@link DiscardedCrl}s.
 */
public enum CrlState {
    CURRENT,
    PENDING,
    SUPERSEDED;

    public String id() {
        return name().toLowerCase(Locale.ROOT);
    }

    public static CrlState fromId(String id) {
        for (CrlState s : values()) {
            if (s.id().equals(id)) return s;
        }
        throw new IllegalArgumentException("unknown CRL state: " + id);
    }
}
