package io.siggi.pkiserver;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParseException;
import com.google.gson.JsonParser;
import com.google.gson.JsonPrimitive;
import io.siggi.http.iphelper.IP;

import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

/**
 * Server configuration, read from {@code config.json}.
 *
 * <pre>
 * {
 *   "listen": "0.0.0.0:8080",
 *   "trustedProxies": ["127.0.0.1", "10.0.0.0/8"],
 *   "dataDir": ".",
 *   "limits": {
 *     "maxUploadBytes": 1048576,
 *     "uploadsPerMinutePerIp": 60,
 *     "crlMaxFutureDays": 366,
 *     "coverageWarningDays": 30
 *   },
 *   "notifications": { ... see {@link Notifications} ... }
 * }
 * </pre>
 * <p>
 * Every key is optional. Relative {@code dataDir} paths are resolved against the directory
 * containing the config file. Unknown keys are rejected so typos don't go unnoticed.
 */
public record Config(
        InetSocketAddress listen,
        List<String> trustedProxies,
        Path dataDir,
        Limits limits,
        Notifications notifications
) {
    public static final String DEFAULT_LISTEN = "0.0.0.0:8080";

    public Config {
        trustedProxies = List.copyOf(trustedProxies);
    }

    public record Limits(
            long maxUploadBytes,
            int uploadsPerMinutePerIp,
            int crlMaxFutureDays,
            int coverageWarningDays
    ) {
        public static final Limits DEFAULT = new Limits(1024 * 1024, 60, 366, 30);
    }

    /** Whether uploads can be accepted at all (they need a trusted proxy doing TLS). */
    public boolean uploadsEnabled() {
        return !trustedProxies.isEmpty();
    }

    public static Config load(Path file) throws IOException, ConfigException {
        String json = Files.readString(file, StandardCharsets.UTF_8);
        Path base = file.toAbsolutePath().getParent();
        return parse(json, base);
    }

    public static Config parse(String json, Path baseDir) throws ConfigException {
        JsonElement rootElement;
        try {
            rootElement = JsonParser.parseString(json);
        } catch (JsonParseException e) {
            throw new ConfigException("invalid JSON: " + e.getMessage(), e);
        }
        if (!rootElement.isJsonObject()) {
            throw new ConfigException("top level must be a JSON object");
        }
        JsonObject root = rootElement.getAsJsonObject();
        checkKeys(root, "", Set.of("listen", "trustedProxies", "dataDir", "limits", "notifications"));

        InetSocketAddress listen = parseListen(getString(root, "listen", DEFAULT_LISTEN));

        List<String> trustedProxies = new ArrayList<>();
        if (root.has("trustedProxies") && !root.get("trustedProxies").isJsonNull()) {
            JsonElement el = root.get("trustedProxies");
            if (!el.isJsonArray()) throw new ConfigException("trustedProxies must be an array of strings");
            JsonArray arr = el.getAsJsonArray();
            for (JsonElement item : arr) {
                if (!isString(item)) throw new ConfigException("trustedProxies must be an array of strings");
                String proxy = item.getAsString().trim();
                try {
                    IP.getIP(proxy);
                } catch (RuntimeException e) {
                    throw new ConfigException("trustedProxies: invalid address or CIDR range: " + proxy, e);
                }
                trustedProxies.add(proxy);
            }
        }

        String dataDirString = getString(root, "dataDir", ".");
        if (dataDirString.isEmpty()) throw new ConfigException("dataDir must not be empty");
        Path dataDir = baseDir.resolve(dataDirString).normalize();

        Limits d = Limits.DEFAULT;
        Limits limits = d;
        if (root.has("limits") && !root.get("limits").isJsonNull()) {
            JsonElement el = root.get("limits");
            if (!el.isJsonObject()) throw new ConfigException("limits must be an object");
            JsonObject l = el.getAsJsonObject();
            checkKeys(l, "limits.", Set.of("maxUploadBytes", "uploadsPerMinutePerIp", "crlMaxFutureDays", "coverageWarningDays"));
            limits = new Limits(
                    getPositiveLong(l, "limits.", "maxUploadBytes", d.maxUploadBytes()),
                    (int) getPositiveLong(l, "limits.", "uploadsPerMinutePerIp", d.uploadsPerMinutePerIp()),
                    (int) getPositiveLong(l, "limits.", "crlMaxFutureDays", d.crlMaxFutureDays()),
                    (int) getPositiveLong(l, "limits.", "coverageWarningDays", d.coverageWarningDays())
            );
            if (limits.maxUploadBytes() > Integer.MAX_VALUE) {
                throw new ConfigException("limits.maxUploadBytes is too large");
            }
        }

        Notifications notifications = Notifications.NONE;
        if (root.has("notifications") && !root.get("notifications").isJsonNull()) {
            notifications = parseNotifications(root.get("notifications"));
        }

        return new Config(listen, trustedProxies, dataDir, limits, notifications);
    }

    /**
     * Where and when to send notifications (CRL coverage running low, stale CRL, signing or
     * published certificates nearing expiry). Both channels are optional; with neither,
     * notifications are off.
     *
     * <pre>
     * "notifications": {
     *   "name": "pki.siggi.io",
     *   "certExpiryWarningDays": 30,
     *   "checkIntervalMinutes": 60,
     *   "repeatHours": 24,
     *   "webhook": {"url": "https://hooks.example.com/x", "headers": {"Authorization": "Bearer ..."}},
     *   "email": {
     *     "host": "smtp.example.com", "port": 587, "security": "starttls",
     *     "username": "pki", "password": "...",
     *     "from": "pki@example.com", "to": ["admin@example.com"]
     *   }
     * }
     * </pre>
     *
     * @param name                  shown in messages to tell servers apart; null = local host name
     * @param certExpiryWarningDays warn about certificates expiring less than this many days away
     * @param checkIntervalMinutes  how often the conditions are checked
     * @param repeatHours           repeat a still-active alert this often; 0 = only once
     * @param webhook               the webhook, or null
     * @param email                 the email settings, or null
     */
    public record Notifications(String name, int certExpiryWarningDays, int checkIntervalMinutes, int repeatHours,
                                Webhook webhook, Email email) {
        public static final Notifications NONE = new Notifications(null, 30, 60, 24, null, null);

        public boolean enabled() {
            return webhook != null || email != null;
        }
    }

    /** A webhook: alerts are POSTed to {@code url} as JSON, with the extra {@code headers}. */
    public record Webhook(URI url, Map<String, String> headers) {
        public Webhook {
            headers = Map.copyOf(headers);
        }
    }

    /** SMTP settings. {@code security} is {@code starttls}, {@code tls} (implicit) or {@code none}. */
    public record Email(String host, int port, String security, String username, String password, String from,
                        List<String> to) {
        public Email {
            to = List.copyOf(to);
        }

        @Override
        public String toString() {
            // Keep the password out of logs.
            return "Email[host=" + host + ", port=" + port + ", security=" + security + ", username=" + username
                    + ", from=" + from + ", to=" + to + "]";
        }
    }

    private static Notifications parseNotifications(JsonElement el) throws ConfigException {
        if (!el.isJsonObject()) throw new ConfigException("notifications must be an object");
        JsonObject n = el.getAsJsonObject();
        String p = "notifications.";
        checkKeys(n, p, Set.of("name", "certExpiryWarningDays", "checkIntervalMinutes", "repeatHours", "webhook",
                "email"));
        Notifications d = Notifications.NONE;
        String name = getString(n, p, "name", null);
        int certDays = (int) getPositiveLong(n, p, "certExpiryWarningDays", d.certExpiryWarningDays());
        int interval = (int) getPositiveLong(n, p, "checkIntervalMinutes", d.checkIntervalMinutes());
        int repeat = d.repeatHours();
        JsonElement r = n.get("repeatHours");
        if (r != null && !r.isJsonNull()) {
            // 0 is allowed here: "notify once".
            repeat = r.isJsonPrimitive() && r.getAsJsonPrimitive().isNumber() && r.getAsDouble() == 0
                    ? 0 : (int) getPositiveLong(n, p, "repeatHours", 0);
        }

        Webhook webhook = null;
        JsonElement w = n.get("webhook");
        if (w != null && !w.isJsonNull()) {
            if (!w.isJsonObject()) throw new ConfigException(p + "webhook must be an object");
            JsonObject wo = w.getAsJsonObject();
            String wp = p + "webhook.";
            checkKeys(wo, wp, Set.of("url", "headers"));
            String urlString = getString(wo, wp, "url", null);
            if (urlString == null) throw new ConfigException(wp + "url is required");
            URI url;
            try {
                url = new URI(urlString);
            } catch (URISyntaxException e) {
                throw new ConfigException(wp + "url is not a valid URL: " + urlString, e);
            }
            if (url.getScheme() == null || !Set.of("http", "https").contains(url.getScheme().toLowerCase(Locale.ROOT))
                    || url.getHost() == null) {
                throw new ConfigException(wp + "url must be an http or https URL: " + urlString);
            }
            Map<String, String> headers = new LinkedHashMap<>();
            JsonElement h = wo.get("headers");
            if (h != null && !h.isJsonNull()) {
                if (!h.isJsonObject()) throw new ConfigException(wp + "headers must be an object of strings");
                for (Map.Entry<String, JsonElement> e : h.getAsJsonObject().entrySet()) {
                    if (!isString(e.getValue())) throw new ConfigException(wp + "headers must be an object of strings");
                    if (!e.getKey().matches("[!#$%&'*+.^_`|~0-9A-Za-z-]+")
                            || e.getValue().getAsString().matches("(?s).*[\\r\\n].*")) {
                        throw new ConfigException(wp + "headers: invalid header " + e.getKey());
                    }
                    headers.put(e.getKey(), e.getValue().getAsString());
                }
            }
            webhook = new Webhook(url, headers);
        }

        Email email = null;
        JsonElement m = n.get("email");
        if (m != null && !m.isJsonNull()) {
            if (!m.isJsonObject()) throw new ConfigException(p + "email must be an object");
            JsonObject mo = m.getAsJsonObject();
            String mp = p + "email.";
            checkKeys(mo, mp, Set.of("host", "port", "security", "username", "password", "from", "to"));
            String host = getString(mo, mp, "host", null);
            if (host == null || host.isBlank()) throw new ConfigException(mp + "host is required");
            String security = getString(mo, mp, "security", "starttls").toLowerCase(Locale.ROOT);
            int defaultPort = switch (security) {
                case "starttls" -> 587;
                case "tls" -> 465;
                case "none" -> 25;
                default -> throw new ConfigException(mp + "security must be starttls, tls or none");
            };
            long port = getPositiveLong(mo, mp, "port", defaultPort);
            if (port > 65535) throw new ConfigException(mp + "port out of range");
            String username = getString(mo, mp, "username", null);
            String password = getString(mo, mp, "password", null);
            if ((username == null) != (password == null)) {
                throw new ConfigException(mp + "username and password must be given together");
            }
            String from = getString(mo, mp, "from", null);
            if (from == null) throw new ConfigException(mp + "from is required");
            checkAddress(mp + "from", from);
            List<String> to = new ArrayList<>();
            JsonElement t = mo.get("to");
            if (t != null && isString(t)) {
                to.add(t.getAsString());
            } else if (t != null && t.isJsonArray()) {
                for (JsonElement item : t.getAsJsonArray()) {
                    if (!isString(item)) throw new ConfigException(mp + "to must be an array of addresses");
                    to.add(item.getAsString());
                }
            } else if (t != null && !t.isJsonNull()) {
                throw new ConfigException(mp + "to must be an array of addresses");
            }
            if (to.isEmpty()) throw new ConfigException(mp + "to needs at least one address");
            for (String a : to) checkAddress(mp + "to", a);
            email = new Email(host.trim(), (int) port, security, username, password, from, to);
        }

        return new Notifications(name, certDays, interval, repeat, webhook, email);
    }

    private static void checkAddress(String what, String address) throws ConfigException {
        if (!address.matches("[^\\s<>@,;:\"]+@[^\\s<>@,;:\"]+")) {
            throw new ConfigException(what + ": invalid email address: " + address);
        }
    }

    static InetSocketAddress parseListen(String listen) throws ConfigException {
        String host;
        String portString;
        if (listen.startsWith("[")) {
            int end = listen.indexOf("]:");
            if (end < 0) throw new ConfigException("listen must be host:port or [ipv6]:port: " + listen);
            host = listen.substring(1, end);
            portString = listen.substring(end + 2);
        } else {
            int colon = listen.lastIndexOf(':');
            if (colon < 0 || listen.indexOf(':') != colon) {
                throw new ConfigException("listen must be host:port or [ipv6]:port: " + listen);
            }
            host = listen.substring(0, colon);
            portString = listen.substring(colon + 1);
        }
        int port;
        try {
            port = Integer.parseInt(portString);
        } catch (NumberFormatException e) {
            throw new ConfigException("listen: invalid port: " + listen);
        }
        if (port < 0 || port > 65535) throw new ConfigException("listen: port out of range: " + listen);
        if (host.isEmpty()) throw new ConfigException("listen: missing host: " + listen);
        try {
            return new InetSocketAddress(InetAddress.getByName(host), port);
        } catch (UnknownHostException e) {
            throw new ConfigException("listen: unknown host: " + host, e);
        }
    }

    private static void checkKeys(JsonObject obj, String prefix, Set<String> allowed) throws ConfigException {
        for (String key : obj.keySet()) {
            if (!allowed.contains(key)) throw new ConfigException("unknown key: " + prefix + key);
        }
    }

    private static boolean isString(JsonElement el) {
        return el.isJsonPrimitive() && el.getAsJsonPrimitive().isString();
    }

    private static String getString(JsonObject obj, String key, String def) throws ConfigException {
        return getString(obj, "", key, def);
    }

    private static String getString(JsonObject obj, String prefix, String key, String def) throws ConfigException {
        JsonElement el = obj.get(key);
        if (el == null || el.isJsonNull()) return def;
        if (!isString(el)) throw new ConfigException(prefix + key + " must be a string");
        return el.getAsString();
    }

    private static long getPositiveLong(JsonObject obj, String prefix, String key, long def) throws ConfigException {
        JsonElement el = obj.get(key);
        if (el == null || el.isJsonNull()) return def;
        if (!el.isJsonPrimitive() || !((JsonPrimitive) el).isNumber()) {
            throw new ConfigException(prefix + key + " must be a number");
        }
        long value;
        try {
            value = el.getAsBigDecimal().longValueExact();
        } catch (ArithmeticException e) {
            throw new ConfigException(prefix + key + " must be an integer");
        }
        if (value <= 0 || value > Integer.MAX_VALUE) {
            throw new ConfigException(prefix + key + " must be between 1 and " + Integer.MAX_VALUE);
        }
        return value;
    }

    public static class ConfigException extends Exception {
        public ConfigException(String message) {
            super(message);
        }

        public ConfigException(String message, Throwable cause) {
            super(message, cause);
        }
    }
}
