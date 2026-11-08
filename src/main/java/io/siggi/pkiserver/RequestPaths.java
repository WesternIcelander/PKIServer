package io.siggi.pkiserver;

import io.siggi.pkiserver.store.Store;

/**
 * Strict validation of request paths, applied to every request before it's routed.
 * <p>
 * SiggiHTTP hands us the path already percent-decoded, so {@code %2e%2e} arrives as {@code ..}
 * and {@code %2f} as {@code /}. Every URL the server publishes uses only RFC 3986 unreserved
 * characters and {@code /}, so anything else (backslashes, NULs, control or non-ASCII
 * characters, {@code %}, {@code :} …), dot segments and empty segments are refused with
 * {@code 400} before any lookup, whatever the endpoint.
 */
final class RequestPaths {
    /** Longer than any path the server publishes (slugs and serials are short). */
    static final int MAX_LENGTH = 512;

    private RequestPaths() {
    }

    /** Why {@code path} is malformed, or null if it's acceptable for routing. */
    static String problem(String path) {
        if (path == null || path.isEmpty() || path.charAt(0) != '/') return "the path must start with /";
        if (path.length() > MAX_LENGTH) return "the path is too long";
        if (path.equals("/")) return null;
        for (int i = 0; i < path.length(); i++) {
            char c = path.charAt(i);
            if (!isUnreserved(c) && c != '/') return "the path contains a character that isn't allowed";
        }
        String[] segments = path.substring(1).split("/", -1);
        for (String segment : segments) {
            if (segment.isEmpty()) return "the path contains an empty segment";
            if (segment.equals(".") || segment.equals("..")) return "the path contains a . or .. segment";
        }
        return null;
    }

    /** RFC 3986 unreserved characters (upper case included: harmless, merely never published). */
    static boolean isUnreserved(char c) {
        return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
                || c == '-' || c == '.' || c == '_' || c == '~';
    }

    /** Why {@code slug} isn't a syntactically valid slug path segment, or null if it is. */
    static String slugProblem(String slug) {
        if (Store.isStorableSlug(slug)) return null;
        return "invalid name \"" + slug + "\": names use only lowercase letters, digits and - . _ ~";
    }

    /** Why {@code serial} isn't a syntactically valid serial path segment, or null if it is. */
    static String serialProblem(String serial) {
        if (PublicFiles.isFormattedSerial(serial)) return null;
        return "invalid serial number \"" + serial + "\": use lowercase hex without leading zeros";
    }
}
