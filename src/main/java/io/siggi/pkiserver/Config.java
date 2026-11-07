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
import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
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
 *   }
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
        Limits limits
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
        checkKeys(root, "", Set.of("listen", "trustedProxies", "dataDir", "limits"));

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

        return new Config(listen, trustedProxies, dataDir, limits);
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
        JsonElement el = obj.get(key);
        if (el == null || el.isJsonNull()) return def;
        if (!isString(el)) throw new ConfigException(key + " must be a string");
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
