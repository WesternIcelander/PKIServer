package io.siggi.pkiserver.store;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import io.siggi.pkiserver.Logging;
import io.siggi.pkiserver.x509.InvalidX509Exception;
import io.siggi.pkiserver.x509.X509Util;

import javax.security.auth.x500.X500Principal;
import java.io.IOException;
import java.io.OutputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.security.GeneralSecurityException;
import java.security.PublicKey;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.regex.Pattern;

/**
 * Filesystem store for signing certificates, their CRLs and end-entity certificates.
 *
 * <pre>
 * &lt;dataDir&gt;/ca/&lt;slug&gt;/
 *   cert.der                     the signing certificate (DER; PEM is accepted and rewritten)
 *   meta.json                    role (root/intermediate), subject, SPKI hash (derived)
 *   crl/
 *     &lt;crlNumber&gt;.crl            accepted CRLs, CRL Number in decimal
 *     &lt;crlNumber&gt;.json           state, thisUpdate, nextUpdate, receivedAt
 *     discarded.json             numbers + hashes of discarded pre-signed CRLs
 *   certs/&lt;serial&gt;/
 *     certificate.der
 *     meta.json                  subject, SANs, validity, uploadedAt
 * </pre>
 * <p>
 * DER files are the source of truth. Metadata JSON is derived from them and rewritten at
 * load time when missing or out of date; only the facts that can't be derived
 * ({@code receivedAt}, {@code uploadedAt}, CRL state) are taken from it. Every write goes to
 * a temporary file in the same directory followed by an atomic rename, and the DER file is
 * always written last so its presence means the entry is complete.
 * <p>
 * This class does storage and indexing only. Validation (chains, signatures, CRL rules,
 * slug policy) is the caller's job. All methods are thread-safe.
 */
public final class Store {
    private static final Logger log = Logging.get(Store.class);
    private static final Gson GSON = new GsonBuilder().setPrettyPrinting().disableHtmlEscaping().create();

    public static final String CA_DIR = "ca";
    public static final String CERT_FILE = "cert.der";
    public static final String META_FILE = "meta.json";
    public static final String CRL_DIR = "crl";
    public static final String DISCARDED_FILE = "discarded.json";
    public static final String CERTS_DIR = "certs";
    public static final String EE_CERT_FILE = "certificate.der";
    private static final String TMP_SUFFIX = ".tmp";

    private static final Pattern CRL_NUMBER = Pattern.compile("0|[1-9][0-9]*");
    private static final Pattern SERIAL = Pattern.compile("0|[1-9a-f][0-9a-f]*");

    private final Path caDir;
    /** By slug. */
    private final Map<String, CaData> cas = new TreeMap<>();
    /** By subject DN + SPKI hash. */
    private final Map<SubjectKey, SigningCert> bySubjectAndKey = new HashMap<>();
    /** By subject DN (several certs may share one, e.g. with different keys). */
    private final Map<X500Principal, List<SigningCert>> bySubject = new HashMap<>();

    private record SubjectKey(X500Principal subject, String spkiSha256) {
    }

    private static final class CaData {
        final SigningCert cert;
        final TreeMap<BigInteger, StoredCrl> crls = new TreeMap<>();
        final List<DiscardedCrl> discarded = new ArrayList<>();
        final TreeMap<String, EndEntityCert> endEntities = new TreeMap<>();

        CaData(SigningCert cert) {
            this.cert = cert;
        }

        Path dir(Path caDir) {
            return caDir.resolve(cert.slug());
        }
    }

    private Store(Path dataDir) {
        this.caDir = dataDir.resolve(CA_DIR);
    }

    /**
     * Opens the store under {@code dataDir}, creating {@code ca/} if needed, and loads
     * everything into memory. Entries that can't be loaded are logged and skipped.
     */
    public static Store open(Path dataDir) throws IOException {
        Store store = new Store(dataDir);
        Files.createDirectories(store.caDir);
        store.loadAll();
        return store;
    }

    // ------------------------------------------------------------------ queries

    /** All signing certificates, sorted by slug. */
    public synchronized List<SigningCert> signingCerts() {
        return cas.values().stream().map(d -> d.cert).toList();
    }

    /** The signing certificate with this slug, or null. */
    public synchronized SigningCert signingCert(String slug) {
        CaData data = cas.get(slug);
        return data == null ? null : data.cert;
    }

    /** The signing certificate with this subject DN and public key, or null. */
    public synchronized SigningCert signingCert(X500Principal subject, PublicKey key) {
        return bySubjectAndKey.get(new SubjectKey(subject, X509Util.spkiSha256Hex(key)));
    }

    /** Signing certificates whose subject DN is {@code subject} (e.g. to find a CRL's issuer). */
    public synchronized List<SigningCert> signingCertsBySubject(X500Principal subject) {
        return List.copyOf(bySubject.getOrDefault(subject, List.of()));
    }

    /** CRLs stored for {@code slug}, by increasing number. Empty if the slug is unknown. */
    public synchronized List<StoredCrl> crls(String slug) {
        CaData data = cas.get(slug);
        return data == null ? List.of() : List.copyOf(data.crls.values());
    }

    /** The current CRL of {@code slug}, or null. */
    public synchronized StoredCrl currentCrl(String slug) {
        CaData data = cas.get(slug);
        if (data == null) return null;
        for (StoredCrl crl : data.crls.descendingMap().values()) {
            if (crl.state() == CrlState.CURRENT) return crl;
        }
        return null;
    }

    /** The CRL of {@code slug} with this number, or null. */
    public synchronized StoredCrl crl(String slug, BigInteger number) {
        CaData data = cas.get(slug);
        return data == null ? null : data.crls.get(number);
    }

    /** Discarded CRLs of {@code slug}, in the order they were discarded. */
    public synchronized List<DiscardedCrl> discardedCrls(String slug) {
        CaData data = cas.get(slug);
        return data == null ? List.of() : List.copyOf(data.discarded);
    }

    /**
     * The highest CRL Number ever accepted for {@code slug}, counting stored and discarded
     * CRLs, or null if there are none.
     */
    public synchronized BigInteger highestCrlNumber(String slug) {
        CaData data = cas.get(slug);
        if (data == null) return null;
        BigInteger max = data.crls.isEmpty() ? null : data.crls.lastKey();
        for (DiscardedCrl d : data.discarded) {
            if (max == null || d.number().compareTo(max) > 0) max = d.number();
        }
        return max;
    }

    /** End-entity certificates issued by {@code slug}, sorted by serial. */
    public synchronized List<EndEntityCert> endEntityCerts(String slug) {
        CaData data = cas.get(slug);
        return data == null ? List.of() : List.copyOf(data.endEntities.values());
    }

    /** The end-entity certificate under {@code slug} with this formatted serial, or null. */
    public synchronized EndEntityCert endEntityCert(String slug, String serial) {
        CaData data = cas.get(slug);
        return data == null ? null : data.endEntities.get(serial);
    }

    // ------------------------------------------------------------------ signing certificates

    /** Whether {@code slug} can be used as a directory name (a valid slug, not {@code .}/{@code ..}). */
    public static boolean isStorableSlug(String slug) {
        return X509Util.isValidSlug(slug) && !slug.equals(".") && !slug.equals("..");
    }

    /**
     * Stores a signing certificate under {@code slug}.
     *
     * @return false if this exact certificate is already stored under {@code slug} (no-op)
     * @throws StoreException if the slug is invalid or taken by a different certificate, or
     *                        a certificate with the same subject and key is already stored
     */
    public synchronized boolean addSigningCert(String slug, X509Certificate cert) throws StoreException, IOException {
        if (!isStorableSlug(slug)) throw new StoreException("invalid slug: \"" + slug + "\"");
        SigningCert sc = toSigningCert(slug, cert);
        CaData existing = cas.get(slug);
        if (existing != null) {
            if (Arrays.equals(existing.cert.der(), sc.der())) return false;
            throw new StoreException("slug \"" + slug + "\" is already used by a different certificate ("
                    + existing.cert.subject().getName() + ")");
        }
        SigningCert sameKey = bySubjectAndKey.get(new SubjectKey(sc.subject(), sc.spkiSha256()));
        if (sameKey != null) {
            throw new StoreException("a certificate with the same subject and key is already installed as \""
                    + sameKey.slug() + "\"");
        }
        Path dir = caDir.resolve(slug);
        if (Files.exists(dir.resolve(CERT_FILE))) {
            // Present on disk but not loaded (it failed to load); don't silently overwrite it.
            throw new StoreException("ca/" + slug + "/" + CERT_FILE + " exists on disk but isn't loaded");
        }
        Files.createDirectories(dir);
        writeJson(dir.resolve(META_FILE), caMeta(sc));
        writeAtomic(dir.resolve(CERT_FILE), sc.der());
        index(new CaData(sc));
        log.info("Stored " + sc.role().id() + " " + sc.subject().getName() + " as \"" + slug + "\"");
        return true;
    }

    /**
     * Deletes a signing certificate with its CRLs and end-entity certificates.
     *
     * @throws StoreException if there is no such slug
     */
    public synchronized void removeSigningCert(String slug) throws StoreException, IOException {
        CaData data = cas.get(slug);
        if (data == null) throw new StoreException("no signing certificate \"" + slug + "\"");
        Path dir = data.dir(caDir);
        // cert.der first: a partially deleted directory is then skipped on the next load.
        Files.deleteIfExists(dir.resolve(CERT_FILE));
        unindex(data);
        deleteRecursively(dir);
        log.info("Removed signing certificate \"" + slug + "\"");
    }

    // ------------------------------------------------------------------ CRLs

    /**
     * Stores a CRL for {@code slug} in {@code state}. If {@code state} is
     * {@link CrlState#CURRENT}, the previous current CRL becomes
     * {@link CrlState#SUPERSEDED}.
     *
     * @return the stored CRL; if the identical CRL is already stored, that one, unchanged
     * @throws StoreException if the slug is unknown, the CRL has no number or a different
     *                        issuer, or its number is already used (stored or discarded)
     */
    public synchronized StoredCrl addCrl(String slug, X509CRL crl, CrlState state, Instant receivedAt)
            throws StoreException, IOException {
        CaData data = requireCa(slug);
        BigInteger number;
        try {
            number = X509Util.crlNumber(crl);
        } catch (InvalidX509Exception e) {
            throw new StoreException("invalid CRL Number: " + e.getMessage(), e);
        }
        if (number == null) throw new StoreException("CRL has no CRL Number");
        if (number.signum() < 0) throw new StoreException("CRL Number is negative");
        if (!crl.getIssuerX500Principal().equals(data.cert.subject())) {
            throw new StoreException("CRL issuer " + crl.getIssuerX500Principal().getName()
                    + " is not the subject of \"" + slug + "\"");
        }
        byte[] der = X509Util.der(crl);
        StoredCrl existing = data.crls.get(number);
        if (existing != null) {
            if (Arrays.equals(existing.der(), der)) return existing;
            throw new StoreException("CRL Number " + number + " is already used for \"" + slug + "\"");
        }
        for (DiscardedCrl d : data.discarded) {
            if (d.number().equals(number)) {
                throw new StoreException("CRL Number " + number + " was used by a discarded CRL for \"" + slug + "\"");
            }
        }
        StoredCrl stored = new StoredCrl(number, crl, der, X509Util.sha256Hex(der), state,
                crl.getThisUpdate().toInstant(),
                crl.getNextUpdate() == null ? null : crl.getNextUpdate().toInstant(),
                receivedAt);
        Path crlDir = data.dir(caDir).resolve(CRL_DIR);
        Files.createDirectories(crlDir);
        writeJson(crlDir.resolve(number + ".json"), crlMeta(stored));
        writeAtomic(crlDir.resolve(number + ".crl"), der);
        data.crls.put(number, stored);
        if (state == CrlState.CURRENT) demoteOtherCurrent(data, number);
        return stored;
    }

    /**
     * Changes the state of a stored CRL. Making one {@link CrlState#CURRENT} supersedes the
     * previous current CRL.
     */
    public synchronized StoredCrl setCrlState(String slug, BigInteger number, CrlState state)
            throws StoreException, IOException {
        CaData data = requireCa(slug);
        StoredCrl crl = data.crls.get(number);
        if (crl == null) throw new StoreException("no CRL " + number + " for \"" + slug + "\"");
        if (crl.state() != state) {
            crl = crl.withState(state);
            writeJson(data.dir(caDir).resolve(CRL_DIR).resolve(number + ".json"), crlMeta(crl));
            data.crls.put(number, crl);
        }
        if (state == CrlState.CURRENT) demoteOtherCurrent(data, number);
        return crl;
    }

    private void demoteOtherCurrent(CaData data, BigInteger current) throws IOException {
        for (StoredCrl other : List.copyOf(data.crls.values())) {
            if (other.state() == CrlState.CURRENT && !other.number().equals(current)) {
                StoredCrl superseded = other.withState(CrlState.SUPERSEDED);
                writeJson(data.dir(caDir).resolve(CRL_DIR).resolve(other.number() + ".json"), crlMeta(superseded));
                data.crls.put(other.number(), superseded);
            }
        }
    }

    /**
     * Discards a stored CRL: records it in {@code discarded.json}, then deletes its files.
     *
     * @return the discard record
     */
    public synchronized DiscardedCrl discardCrl(String slug, BigInteger number, Instant discardedAt, String reason)
            throws StoreException, IOException {
        CaData data = requireCa(slug);
        StoredCrl crl = data.crls.get(number);
        if (crl == null) throw new StoreException("no CRL " + number + " for \"" + slug + "\"");
        DiscardedCrl record = new DiscardedCrl(number, crl.sha256(), crl.thisUpdate(), crl.nextUpdate(),
                discardedAt, reason);
        Path crlDir = data.dir(caDir).resolve(CRL_DIR);
        List<DiscardedCrl> all = new ArrayList<>(data.discarded);
        all.add(record);
        // Record first, so the number is never forgotten even if deleting the files fails.
        writeJson(crlDir.resolve(DISCARDED_FILE), discardedJson(all));
        data.discarded.add(record);
        data.crls.remove(number);
        Files.deleteIfExists(crlDir.resolve(number + ".crl"));
        Files.deleteIfExists(crlDir.resolve(number + ".json"));
        return record;
    }

    // ------------------------------------------------------------------ end-entity certificates

    /**
     * Stores an end-entity certificate under its issuer {@code slug}, by serial.
     *
     * @return false if this exact certificate is already stored (no-op)
     * @throws StoreException if the slug is unknown, the issuer DN doesn't match, or a
     *                        different certificate with the same serial is stored
     */
    public synchronized boolean addEndEntityCert(String slug, X509Certificate cert, Instant uploadedAt)
            throws StoreException, IOException {
        CaData data = requireCa(slug);
        if (!cert.getIssuerX500Principal().equals(data.cert.subject())) {
            throw new StoreException("certificate issuer " + cert.getIssuerX500Principal().getName()
                    + " is not the subject of \"" + slug + "\"");
        }
        String serial = X509Util.formatSerial(cert.getSerialNumber());
        byte[] der = X509Util.der(cert);
        EndEntityCert existing = data.endEntities.get(serial);
        if (existing != null) {
            if (Arrays.equals(existing.der(), der)) return false;
            throw new StoreException("a different certificate with serial " + serial
                    + " is already published under \"" + slug + "\"");
        }
        EndEntityCert ee = new EndEntityCert(slug, serial, cert, der, X509Util.sha256Hex(der), uploadedAt);
        Path dir = data.dir(caDir).resolve(CERTS_DIR).resolve(serial);
        Files.createDirectories(dir);
        writeJson(dir.resolve(META_FILE), eeMeta(ee));
        writeAtomic(dir.resolve(EE_CERT_FILE), der);
        data.endEntities.put(serial, ee);
        return true;
    }

    // ------------------------------------------------------------------ loading

    private void loadAll() throws IOException {
        cleanTempFiles(caDir);
        List<Path> dirs = new ArrayList<>();
        try (DirectoryStream<Path> ds = Files.newDirectoryStream(caDir)) {
            for (Path p : ds) dirs.add(p);
        }
        dirs.sort(Comparator.comparing(p -> p.getFileName().toString()));
        for (Path dir : dirs) {
            String slug = dir.getFileName().toString();
            if (!Files.isDirectory(dir)) {
                log.warning("Ignoring ca/" + slug + ": not a directory");
                continue;
            }
            if (!isStorableSlug(slug)) {
                log.warning("Ignoring ca/" + slug + ": not a valid slug (allowed: a-z 0-9 - . _ ~)");
                continue;
            }
            try {
                loadCa(slug, dir);
            } catch (IOException | RuntimeException e) {
                log.log(Level.WARNING, "Failed to load ca/" + slug, e);
            }
        }
        int crlCount = 0;
        int eeCount = 0;
        for (CaData d : cas.values()) {
            crlCount += d.crls.size();
            eeCount += d.endEntities.size();
        }
        log.info("Loaded " + cas.size() + " signing certificate(s), " + crlCount + " CRL(s), "
                + eeCount + " end-entity certificate(s)");
    }

    private void loadCa(String slug, Path dir) throws IOException {
        cleanTempFiles(dir);
        Path certFile = dir.resolve(CERT_FILE);
        if (!Files.isRegularFile(certFile)) {
            log.warning("Ignoring ca/" + slug + ": no " + CERT_FILE);
            return;
        }
        byte[] bytes = Files.readAllBytes(certFile);
        X509Certificate cert;
        try {
            cert = X509Util.parseCertificate(bytes);
        } catch (InvalidX509Exception e) {
            log.warning("Ignoring ca/" + slug + ": " + CERT_FILE + ": " + e.getMessage());
            return;
        }
        SigningCert sc = toSigningCert(slug, cert);
        SigningCert dup = bySubjectAndKey.get(new SubjectKey(sc.subject(), sc.spkiSha256()));
        if (dup != null) {
            log.warning("Ignoring ca/" + slug + ": same subject and key as \"" + dup.slug()
                    + "\" (directories are loaded in name order, the first one wins)");
            return;
        }
        if (!Arrays.equals(bytes, sc.der())) {
            log.info("ca/" + slug + "/" + CERT_FILE + " was PEM, rewriting it as DER");
            writeAtomic(certFile, sc.der());
        }
        updateJson(dir.resolve(META_FILE), caMeta(sc));
        CaData data = new CaData(sc);
        loadCrls(data, dir.resolve(CRL_DIR));
        loadEndEntities(data, dir.resolve(CERTS_DIR));
        index(data);
    }

    private void loadCrls(CaData data, Path crlDir) throws IOException {
        String slug = data.cert.slug();
        if (!Files.isDirectory(crlDir)) return;
        cleanTempFiles(crlDir);

        Path discardedFile = crlDir.resolve(DISCARDED_FILE);
        if (Files.isRegularFile(discardedFile)) {
            try {
                data.discarded.addAll(parseDiscarded(readJson(discardedFile)));
            } catch (RuntimeException e) {
                // Refuse to guess: losing these numbers would allow replaying discarded CRLs.
                throw new IOException("ca/" + slug + "/" + CRL_DIR + "/" + DISCARDED_FILE + " is unreadable", e);
            }
        }

        Instant now = Instant.now();
        try (DirectoryStream<Path> ds = Files.newDirectoryStream(crlDir, "*.crl")) {
            for (Path file : ds) {
                String name = file.getFileName().toString();
                String numberString = name.substring(0, name.length() - ".crl".length());
                String where = "ca/" + slug + "/" + CRL_DIR + "/" + name;
                if (!CRL_NUMBER.matcher(numberString).matches()) {
                    log.warning("Ignoring " + where + ": file name is not a decimal CRL Number");
                    continue;
                }
                BigInteger number = new BigInteger(numberString);
                Path metaFile = crlDir.resolve(numberString + ".json");
                if (data.discarded.stream().anyMatch(d -> d.number().equals(number))) {
                    // A discard was interrupted after recording it: finish it.
                    log.info("Deleting " + where + ": it was discarded");
                    Files.deleteIfExists(file);
                    Files.deleteIfExists(metaFile);
                    continue;
                }
                X509CRL crl;
                BigInteger actual;
                try {
                    crl = X509Util.parseCrl(Files.readAllBytes(file));
                    actual = X509Util.crlNumber(crl);
                } catch (InvalidX509Exception e) {
                    log.warning("Ignoring " + where + ": " + e.getMessage());
                    continue;
                }
                if (!number.equals(actual)) {
                    log.warning("Ignoring " + where + ": its CRL Number is " + actual);
                    continue;
                }
                if (!crl.getIssuerX500Principal().equals(data.cert.subject())) {
                    log.warning("Ignoring " + where + ": issuer " + crl.getIssuerX500Principal().getName()
                            + " is not the subject of the signing certificate");
                    continue;
                }
                byte[] der = X509Util.der(crl);
                if (!Arrays.equals(der, Files.readAllBytes(file))) {
                    writeAtomic(file, der);
                }
                Instant thisUpdate = crl.getThisUpdate().toInstant();
                Instant nextUpdate = crl.getNextUpdate() == null ? null : crl.getNextUpdate().toInstant();
                CrlState state = null;
                Instant receivedAt = null;
                JsonObject meta = readJsonQuietly(metaFile);
                if (meta != null) {
                    try {
                        state = CrlState.fromId(meta.get("state").getAsString());
                        receivedAt = Instant.parse(meta.get("receivedAt").getAsString());
                    } catch (RuntimeException e) {
                        state = null;
                        receivedAt = null;
                    }
                }
                if (state == null) {
                    state = thisUpdate.isAfter(now) ? CrlState.PENDING : CrlState.SUPERSEDED;
                    log.warning(where + ": metadata missing or invalid, rebuilding it as " + state.id());
                }
                if (receivedAt == null) {
                    receivedAt = Files.getLastModifiedTime(file).toInstant();
                }
                StoredCrl stored = new StoredCrl(number, crl, der, X509Util.sha256Hex(der), state,
                        thisUpdate, nextUpdate, receivedAt);
                data.crls.put(number, stored);
            }
        }

        // At most one current CRL, and one whenever a CRL has taken effect: if several are
        // marked current (interrupted state change), the highest-numbered one wins; if none
        // is (lost metadata), the highest-numbered non-pending one becomes current.
        StoredCrl current = null;
        for (StoredCrl crl : data.crls.values()) {
            if (crl.state() == CrlState.CURRENT) current = crl;
        }
        if (current == null) {
            for (StoredCrl crl : data.crls.descendingMap().values()) {
                if (crl.state() != CrlState.PENDING) {
                    current = crl.withState(CrlState.CURRENT);
                    data.crls.put(current.number(), current);
                    break;
                }
            }
        }
        for (StoredCrl crl : List.copyOf(data.crls.values())) {
            if (crl.state() == CrlState.CURRENT && crl != current) {
                log.warning("ca/" + slug + ": CRL " + crl.number() + " was also marked current, superseding it");
                data.crls.put(crl.number(), crl.withState(CrlState.SUPERSEDED));
            }
        }
        for (StoredCrl crl : data.crls.values()) {
            updateJson(crlDir.resolve(crl.number() + ".json"), crlMeta(crl));
        }
    }

    private void loadEndEntities(CaData data, Path certsDir) throws IOException {
        String slug = data.cert.slug();
        if (!Files.isDirectory(certsDir)) return;
        try (DirectoryStream<Path> ds = Files.newDirectoryStream(certsDir)) {
            for (Path dir : ds) {
                String serial = dir.getFileName().toString();
                String where = "ca/" + slug + "/" + CERTS_DIR + "/" + serial;
                if (!Files.isDirectory(dir)) continue;
                if (!SERIAL.matcher(serial).matches()) {
                    log.warning("Ignoring " + where + ": not a serial number in lowercase hex");
                    continue;
                }
                cleanTempFiles(dir);
                Path certFile = dir.resolve(EE_CERT_FILE);
                if (!Files.isRegularFile(certFile)) {
                    log.warning("Ignoring " + where + ": no " + EE_CERT_FILE);
                    continue;
                }
                byte[] bytes = Files.readAllBytes(certFile);
                X509Certificate cert;
                try {
                    cert = X509Util.parseCertificate(bytes);
                } catch (InvalidX509Exception e) {
                    log.warning("Ignoring " + where + ": " + e.getMessage());
                    continue;
                }
                if (!X509Util.formatSerial(cert.getSerialNumber()).equals(serial)) {
                    log.warning("Ignoring " + where + ": certificate serial is "
                            + X509Util.formatSerial(cert.getSerialNumber()));
                    continue;
                }
                if (!cert.getIssuerX500Principal().equals(data.cert.subject())) {
                    log.warning("Ignoring " + where + ": issuer " + cert.getIssuerX500Principal().getName()
                            + " is not the subject of the signing certificate");
                    continue;
                }
                byte[] der = X509Util.der(cert);
                if (!Arrays.equals(bytes, der)) {
                    writeAtomic(certFile, der);
                }
                Instant uploadedAt = null;
                JsonObject meta = readJsonQuietly(dir.resolve(META_FILE));
                if (meta != null) {
                    try {
                        uploadedAt = Instant.parse(meta.get("uploadedAt").getAsString());
                    } catch (RuntimeException ignored) {
                    }
                }
                if (uploadedAt == null) uploadedAt = Files.getLastModifiedTime(certFile).toInstant();
                EndEntityCert ee = new EndEntityCert(slug, serial, cert, der, X509Util.sha256Hex(der), uploadedAt);
                updateJson(dir.resolve(META_FILE), eeMeta(ee));
                data.endEntities.put(serial, ee);
            }
        }
    }

    // ------------------------------------------------------------------ indexes

    private void index(CaData data) {
        SigningCert sc = data.cert;
        cas.put(sc.slug(), data);
        bySubjectAndKey.put(new SubjectKey(sc.subject(), sc.spkiSha256()), sc);
        bySubject.computeIfAbsent(sc.subject(), k -> new ArrayList<>()).add(sc);
    }

    private void unindex(CaData data) {
        SigningCert sc = data.cert;
        cas.remove(sc.slug());
        bySubjectAndKey.remove(new SubjectKey(sc.subject(), sc.spkiSha256()));
        List<SigningCert> list = bySubject.get(sc.subject());
        if (list != null) {
            list.remove(sc);
            if (list.isEmpty()) bySubject.remove(sc.subject());
        }
    }

    private CaData requireCa(String slug) throws StoreException {
        CaData data = cas.get(slug);
        if (data == null) throw new StoreException("no signing certificate \"" + slug + "\"");
        return data;
    }

    private static SigningCert toSigningCert(String slug, X509Certificate cert) {
        byte[] der = X509Util.der(cert);
        return new SigningCert(slug, cert, der, roleOf(cert), X509Util.spkiSha256Hex(cert.getPublicKey()),
                X509Util.sha256Hex(der));
    }

    /** Root if self-signed (subject = issuer and the signature verifies with its own key). */
    static CaRole roleOf(X509Certificate cert) {
        if (!cert.getSubjectX500Principal().equals(cert.getIssuerX500Principal())) return CaRole.INTERMEDIATE;
        try {
            cert.verify(cert.getPublicKey());
            return CaRole.ROOT;
        } catch (GeneralSecurityException e) {
            return CaRole.INTERMEDIATE;
        }
    }

    // ------------------------------------------------------------------ metadata JSON

    private static JsonObject caMeta(SigningCert sc) {
        JsonObject o = new JsonObject();
        o.addProperty("role", sc.role().id());
        o.addProperty("subject", sc.subject().getName());
        o.addProperty("issuer", sc.cert().getIssuerX500Principal().getName());
        o.addProperty("serial", X509Util.formatSerial(sc.cert().getSerialNumber()));
        o.addProperty("spkiSha256", sc.spkiSha256());
        o.addProperty("sha256", sc.sha256());
        o.addProperty("notBefore", sc.cert().getNotBefore().toInstant().toString());
        o.addProperty("notAfter", sc.cert().getNotAfter().toInstant().toString());
        return o;
    }

    private static JsonObject crlMeta(StoredCrl crl) {
        JsonObject o = new JsonObject();
        o.addProperty("state", crl.state().id());
        o.addProperty("thisUpdate", crl.thisUpdate().toString());
        if (crl.nextUpdate() != null) o.addProperty("nextUpdate", crl.nextUpdate().toString());
        o.addProperty("receivedAt", crl.receivedAt().toString());
        o.addProperty("sha256", crl.sha256());
        return o;
    }

    private static JsonObject eeMeta(EndEntityCert ee) {
        JsonObject o = new JsonObject();
        o.addProperty("subject", ee.cert().getSubjectX500Principal().getName());
        JsonArray sans = new JsonArray();
        for (String san : subjectAltNames(ee.cert())) sans.add(san);
        o.add("subjectAltNames", sans);
        o.addProperty("notBefore", ee.cert().getNotBefore().toInstant().toString());
        o.addProperty("notAfter", ee.cert().getNotAfter().toInstant().toString());
        o.addProperty("sha256", ee.sha256());
        o.addProperty("uploadedAt", ee.uploadedAt().toString());
        return o;
    }

    private static final String[] SAN_TYPES = {
            "otherName", "email", "DNS", "x400Address", "dirName", "ediPartyName", "URI", "IP", "RID"};

    /** SANs as {@code type:value} strings, e.g. {@code DNS:example.com}. */
    static List<String> subjectAltNames(X509Certificate cert) {
        Collection<List<?>> names;
        try {
            names = cert.getSubjectAlternativeNames();
        } catch (CertificateParsingException e) {
            return List.of();
        }
        if (names == null) return List.of();
        List<String> result = new ArrayList<>();
        for (List<?> name : names) {
            int type = (Integer) name.get(0);
            Object value = name.get(1);
            String typeName = type >= 0 && type < SAN_TYPES.length ? SAN_TYPES[type] : Integer.toString(type);
            String valueString = value instanceof byte[] b ? X509Util.hex(b) : String.valueOf(value);
            result.add(typeName + ":" + valueString);
        }
        return result;
    }

    private static JsonArray discardedJson(List<DiscardedCrl> list) {
        JsonArray arr = new JsonArray();
        for (DiscardedCrl d : list) {
            JsonObject o = new JsonObject();
            o.addProperty("number", d.number().toString());
            o.addProperty("sha256", d.sha256());
            o.addProperty("thisUpdate", d.thisUpdate().toString());
            if (d.nextUpdate() != null) o.addProperty("nextUpdate", d.nextUpdate().toString());
            o.addProperty("discardedAt", d.discardedAt().toString());
            if (d.reason() != null) o.addProperty("reason", d.reason());
            arr.add(o);
        }
        return arr;
    }

    private static List<DiscardedCrl> parseDiscarded(JsonElement el) {
        List<DiscardedCrl> list = new ArrayList<>();
        for (JsonElement item : el.getAsJsonArray()) {
            JsonObject o = item.getAsJsonObject();
            list.add(new DiscardedCrl(
                    new BigInteger(o.get("number").getAsString()),
                    o.get("sha256").getAsString(),
                    Instant.parse(o.get("thisUpdate").getAsString()),
                    o.has("nextUpdate") ? Instant.parse(o.get("nextUpdate").getAsString()) : null,
                    Instant.parse(o.get("discardedAt").getAsString()),
                    o.has("reason") ? o.get("reason").getAsString() : null));
        }
        return list;
    }

    // ------------------------------------------------------------------ file helpers

    private static JsonElement readJson(Path file) throws IOException {
        return JsonParser.parseString(Files.readString(file, StandardCharsets.UTF_8));
    }

    /** The JSON object in {@code file}, or null if it's missing or not a JSON object. */
    private static JsonObject readJsonQuietly(Path file) {
        try {
            JsonElement el = readJson(file);
            return el.isJsonObject() ? el.getAsJsonObject() : null;
        } catch (IOException | RuntimeException e) {
            return null;
        }
    }

    /** Writes {@code json} to {@code file} unless the file already holds the same JSON. */
    private static void updateJson(Path file, JsonElement json) throws IOException {
        JsonElement existing = null;
        try {
            existing = readJson(file);
        } catch (IOException | RuntimeException ignored) {
        }
        if (!json.equals(existing)) writeJson(file, json);
    }

    private static void writeJson(Path file, JsonElement json) throws IOException {
        writeAtomic(file, (GSON.toJson(json) + "\n").getBytes(StandardCharsets.UTF_8));
    }

    /** Writes to a temporary file in the same directory, syncs it, then renames it over {@code target}. */
    static void writeAtomic(Path target, byte[] data) throws IOException {
        Path dir = target.toAbsolutePath().getParent();
        Files.createDirectories(dir);
        Path tmp = Files.createTempFile(dir, "." + target.getFileName() + ".", TMP_SUFFIX);
        boolean moved = false;
        try {
            try (OutputStream out = Files.newOutputStream(tmp, StandardOpenOption.WRITE,
                    StandardOpenOption.TRUNCATE_EXISTING, StandardOpenOption.SYNC)) {
                out.write(data);
            }
            try {
                Files.move(tmp, target, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
            } catch (AtomicMoveNotSupportedException e) {
                Files.move(tmp, target, StandardCopyOption.REPLACE_EXISTING);
            }
            moved = true;
        } finally {
            if (!moved) Files.deleteIfExists(tmp);
        }
    }

    /** Deletes leftover temporary files from interrupted writes. */
    private static void cleanTempFiles(Path dir) throws IOException {
        try (DirectoryStream<Path> ds = Files.newDirectoryStream(dir, ".*" + TMP_SUFFIX)) {
            for (Path p : ds) {
                if (Files.isRegularFile(p)) Files.deleteIfExists(p);
            }
        }
    }

    private static void deleteRecursively(Path path) throws IOException {
        if (Files.isDirectory(path, java.nio.file.LinkOption.NOFOLLOW_LINKS)) {
            try (DirectoryStream<Path> ds = Files.newDirectoryStream(path)) {
                for (Path child : ds) deleteRecursively(child);
            }
        }
        Files.deleteIfExists(path);
    }
}
