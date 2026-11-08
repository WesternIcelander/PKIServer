package io.siggi.pkiserver;

import io.siggi.pkiserver.store.Store;

import java.util.Set;

/** Slug policy for new signing certificates (existing ones are never re-checked). */
public final class Slugs {
    /**
     * Top-level URL paths the server uses itself. A slug equal to one of these would make
     * {@code /<slug>/<serial>/...} collide with them.
     */
    public static final Set<String> RESERVED = Set.of(
            "api", "index.html", "favicon.ico", "robots.txt", ".well-known");

    private Slugs() {
    }

    public static boolean isReserved(String slug) {
        return RESERVED.contains(slug);
    }

    /**
     * Why {@code slug} can't be used for a new signing certificate, or null if it can.
     * Doesn't check whether it's already taken.
     */
    public static String problem(String slug) {
        if (!Store.isStorableSlug(slug)) {
            return "invalid slug \"" + slug + "\": use only lowercase letters, digits and - . _ ~"
                    + " (and not \".\" or \"..\")";
        }
        if (isReserved(slug)) {
            return "slug \"" + slug + "\" is reserved (it collides with a server path)";
        }
        return null;
    }
}
