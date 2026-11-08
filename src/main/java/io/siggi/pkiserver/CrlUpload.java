package io.siggi.pkiserver;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import io.siggi.http.HTTPRequest;
import io.siggi.pkiserver.store.CrlState;
import io.siggi.pkiserver.store.DiscardedCrl;
import io.siggi.pkiserver.store.SigningCert;
import io.siggi.pkiserver.store.Store;
import io.siggi.pkiserver.store.StoreException;
import io.siggi.pkiserver.store.StoredCrl;
import io.siggi.pkiserver.x509.InvalidX509Exception;
import io.siggi.pkiserver.x509.X509Util;

import java.io.IOException;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.cert.X509CRL;
import java.security.cert.X509CRLEntry;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;
import java.util.logging.Logger;

/**
 * {@code POST /api/crl}: uploads of CRLs, one DER CRL or PEM with one or more.
 * <p>
 * Each CRL must be signed by an installed signing certificate with the same subject DN (and
 * {@code cRLSign} in its Key Usage, if it has one), carry a CRL Number, be a full CRL (no
 * Delta CRL Indicator), have a {@code nextUpdate} in the future and after {@code thisUpdate},
 * and have a {@code thisUpdate} no further ahead than {@link Config.Limits#crlMaxFutureDays()}.
 * Then the CRL rules of the plan apply:
 * <ol>
 *   <li>its number is higher than every number accepted for that CA so far (stored or
 *       discarded); re-uploading the identical bytes of a stored CRL is a no-op;</li>
 *   <li>its {@code thisUpdate} is not before that of the current CRL nor, for a pending CRL,
 *       of any pending CRL;</li>
 *   <li>if {@code thisUpdate <= now} it becomes current and every pending CRL of the CA is
 *       discarded;</li>
 *   <li>otherwise it becomes pending;</li>
 *   <li>it lists every serial that the current CRL lists.</li>
 * </ol>
 * <p>
 * The CRLs of one body are processed in increasing CRL Number order, so a batch of pre-signed
 * CRLs can be sent in any order. The response holds one result per CRL, in body order; its
 * status is {@code 200} if all were accepted, {@code 409} if every rejection was a conflict
 * with the CRLs already on the server (rules 1, 2 and 5), else {@code 400}.
 */
final class CrlUpload implements Api.UploadHandler {
    private static final Logger log = Logging.get(CrlUpload.class);

    static final String PATH = Api.PREFIX + "/crl";
    /** At most this many missing serials are named in a rule 5 rejection. */
    private static final int MAX_LISTED_SERIALS = 20;

    private final Store store;
    private final Clock clock;
    private final Duration maxFuture;
    private final Runnable onPending;

    CrlUpload(Store store, Clock clock, Duration maxFuture) {
        this(store, clock, maxFuture, () -> {
        });
    }

    /**
     * @param onPending called after a CRL was stored as pending (to wake the
     *                  {@link CrlScheduler} so it can reschedule)
     */
    CrlUpload(Store store, Clock clock, Duration maxFuture, Runnable onPending) {
        this.store = store;
        this.clock = clock;
        this.maxFuture = maxFuture;
        this.onPending = onPending;
    }

    /** Result of processing one CRL. */
    private record Outcome(String result, int status, String slug, BigInteger number, StoredCrl stored,
                           boolean unchanged, List<DiscardedCrl> discarded, String error) {
        static Outcome accepted(String slug, StoredCrl stored, boolean unchanged, List<DiscardedCrl> discarded) {
            return new Outcome(stored.state().id(), 200, slug, stored.number(), stored, unchanged, discarded, null);
        }

        static Outcome rejected(int status, String slug, BigInteger number, String error) {
            return new Outcome("rejected", status, slug, number, null, false, List.of(), error);
        }

        boolean accepted() {
            return status == 200;
        }
    }

    /** Thrown to reject a CRL. */
    private static final class Rejection extends Exception {
        final int status;

        Rejection(int status, String message) {
            super(message, null, false, false);
            this.status = status;
        }
    }

    @Override
    public void handle(HTTPRequest request, byte[] body) throws Exception {
        List<X509CRL> crls;
        try {
            crls = X509Util.parseCrls(body);
        } catch (InvalidX509Exception e) {
            Api.error(request, 400, "Bad Request", "could not parse CRL: " + e.getMessage(), false);
            return;
        }

        List<Integer> order = new ArrayList<>();
        BigInteger[] numbers = new BigInteger[crls.size()];
        for (int i = 0; i < crls.size(); i++) {
            order.add(i);
            try {
                numbers[i] = X509Util.crlNumber(crls.get(i));
            } catch (InvalidX509Exception e) {
                numbers[i] = null;
            }
        }
        order.sort(Comparator.comparing(i -> numbers[i], Comparator.nullsFirst(Comparator.naturalOrder())));

        Outcome[] outcomes = new Outcome[crls.size()];
        Instant now = clock.instant();
        for (int i : order) {
            outcomes[i] = process(crls.get(i), now);
        }

        JsonArray results = new JsonArray();
        boolean allAccepted = true;
        boolean onlyConflicts = true;
        String firstError = null;
        for (int i = 0; i < crls.size(); i++) {
            Outcome o = outcomes[i];
            results.add(toJson(crls.get(i), o));
            if (!o.accepted()) {
                allAccepted = false;
                if (o.status() != 409) onlyConflicts = false;
                if (firstError == null) firstError = o.error();
            }
        }
        JsonObject json = new JsonObject();
        json.add("crls", results);
        if (allAccepted) {
            Api.json(request, 200, "OK", json);
        } else if (onlyConflicts) {
            json.addProperty("error", firstError);
            Api.json(request, 409, "Conflict", json);
        } else {
            json.addProperty("error", firstError);
            Api.json(request, 400, "Bad Request", json);
        }
    }

    /** Validates and stores one CRL. */
    private Outcome process(X509CRL crl, Instant now) throws IOException {
        SigningCert issuer;
        try {
            issuer = findIssuer(crl);
        } catch (Rejection r) {
            return Outcome.rejected(r.status, null, null, r.getMessage());
        }
        String slug = issuer.slug();
        BigInteger number;
        try {
            number = X509Util.crlNumber(crl);
        } catch (InvalidX509Exception e) {
            return Outcome.rejected(400, slug, null, "invalid CRL Number: " + e.getMessage());
        }
        // One CA's CRL state must not change between the checks and the update (the
        // scheduler promoting pending CRLs takes the same lock).
        synchronized (store) {
            try {
                return accept(issuer, crl, number, now);
            } catch (Rejection r) {
                return Outcome.rejected(r.status, slug, number, r.getMessage());
            } catch (StoreException e) {
                return Outcome.rejected(409, slug, number, e.getMessage());
            }
        }
    }

    /** The installed signing certificate whose key verifies {@code crl}. */
    private SigningCert findIssuer(X509CRL crl) throws Rejection {
        String issuerName = crl.getIssuerX500Principal().getName();
        List<SigningCert> candidates = store.signingCertsBySubject(crl.getIssuerX500Principal());
        if (candidates.isEmpty()) {
            throw new Rejection(400, "issuer " + issuerName + " is not installed on this server");
        }
        for (SigningCert sc : candidates) {
            try {
                crl.verify(sc.cert().getPublicKey());
            } catch (GeneralSecurityException | RuntimeException e) {
                continue;
            }
            boolean[] keyUsage = sc.cert().getKeyUsage();
            if (keyUsage != null && (keyUsage.length <= 6 || !keyUsage[6])) {
                throw new Rejection(400, "the Key Usage of the issuer " + issuerName + " (\"" + sc.slug()
                        + "\") does not include cRLSign");
            }
            return sc;
        }
        throw new Rejection(400, "signature does not verify with the key of any installed certificate named "
                + issuerName);
    }

    private Outcome accept(SigningCert issuer, X509CRL crl, BigInteger number, Instant now)
            throws Rejection, StoreException, IOException {
        String slug = issuer.slug();
        if (number == null) throw new Rejection(400, "the CRL has no CRL Number");
        if (number.signum() < 0) throw new Rejection(400, "the CRL Number is negative");
        if (X509Util.isDeltaCrl(crl)) {
            throw new Rejection(400, "delta CRLs are not supported; upload a full CRL");
        }
        Instant thisUpdate = crl.getThisUpdate().toInstant();
        if (crl.getNextUpdate() == null) throw new Rejection(400, "the CRL has no nextUpdate");
        Instant nextUpdate = crl.getNextUpdate().toInstant();
        if (!thisUpdate.isBefore(nextUpdate)) {
            throw new Rejection(400, "thisUpdate (" + thisUpdate + ") is not before nextUpdate (" + nextUpdate + ")");
        }
        if (!nextUpdate.isAfter(now)) {
            throw new Rejection(400, "the CRL expired: its nextUpdate (" + nextUpdate + ") has passed");
        }
        Instant horizon = now.plus(maxFuture);
        if (thisUpdate.isAfter(horizon)) {
            throw new Rejection(400, "thisUpdate (" + thisUpdate + ") is more than " + maxFuture.toDays()
                    + " days in the future");
        }

        byte[] der = X509Util.der(crl);
        StoredCrl same = store.crl(slug, number);
        if (same != null && same.sha256().equals(X509Util.sha256Hex(der))) {
            return Outcome.accepted(slug, same, true, List.of());
        }

        // Rule 1: numbers only go up.
        BigInteger highest = store.highestCrlNumber(slug);
        if (highest != null && number.compareTo(highest) <= 0) {
            throw new Rejection(409, "CRL Number " + number + " is not greater than " + highest
                    + ", the highest CRL Number used so far for \"" + slug + "\"");
        }

        StoredCrl current = store.currentCrl(slug);
        boolean immediate = !thisUpdate.isAfter(now);

        // Rule 2: time goes up with numbers. An immediately effective CRL discards the
        // pending ones (rule 3), so it is only compared with the current CRL.
        if (current != null && thisUpdate.isBefore(current.thisUpdate())) {
            throw new Rejection(409, "thisUpdate (" + thisUpdate + ") is before that of the current CRL #"
                    + current.number() + " (" + current.thisUpdate() + ")");
        }
        List<StoredCrl> pending = new ArrayList<>();
        for (StoredCrl c : store.crls(slug)) {
            if (c.state() == CrlState.PENDING) pending.add(c);
        }
        if (!immediate) {
            for (StoredCrl p : pending) {
                if (thisUpdate.isBefore(p.thisUpdate())) {
                    throw new Rejection(409, "thisUpdate (" + thisUpdate + ") is before that of pending CRL #"
                            + p.number() + " (" + p.thisUpdate() + ")");
                }
            }
        }

        // Rule 5: no un-revoking.
        if (current != null) {
            String unrevoked = unrevokedError(current, crl);
            if (unrevoked != null) throw new Rejection(409, unrevoked);
        }

        if (immediate) {
            // Rule 3. Discard the backups first: if storing the new CRL then fails, no
            // older pre-signed CRL is left that could later replace the current one.
            List<DiscardedCrl> discarded = new ArrayList<>();
            for (StoredCrl p : pending) {
                discarded.add(store.discardCrl(slug, p.number(), now,
                        "superseded by immediately effective CRL #" + number));
            }
            StoredCrl stored = store.addCrl(slug, crl, CrlState.CURRENT, now);
            log.info("CRL #" + number + " of \"" + slug + "\" is now current (thisUpdate " + thisUpdate
                    + ", nextUpdate " + nextUpdate + ")"
                    + (discarded.isEmpty() ? "" : "; discarded " + discarded.size() + " pending CRL(s): "
                    + numbersOf(discarded)));
            return Outcome.accepted(slug, stored, false, discarded);
        }
        // Rule 4.
        StoredCrl stored = store.addCrl(slug, crl, CrlState.PENDING, now);
        log.info("CRL #" + number + " of \"" + slug + "\" is pending until " + thisUpdate
                + " (nextUpdate " + nextUpdate + ")");
        onPending.run();
        return Outcome.accepted(slug, stored, false, List.of());
    }

    /**
     * Rule 5: the error message if {@code next} doesn't list every serial that the current CRL
     * {@code current} lists, else null.
     */
    static String unrevokedError(StoredCrl current, X509CRL next) {
        List<BigInteger> missing = missingSerials(current.crl(), next);
        if (missing.isEmpty()) return null;
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < missing.size() && i < MAX_LISTED_SERIALS; i++) {
            if (i > 0) sb.append(", ");
            sb.append(X509Util.formatSerial(missing.get(i)));
        }
        if (missing.size() > MAX_LISTED_SERIALS) {
            sb.append(" and ").append(missing.size() - MAX_LISTED_SERIALS).append(" more");
        }
        return missing.size() + " serial(s) revoked by the current CRL #" + current.number()
                + " are missing (certificates can't be un-revoked): " + sb;
    }

    /** Serials listed in {@code previous} but not in {@code next}, in increasing order. */
    static List<BigInteger> missingSerials(X509CRL previous, X509CRL next) {
        Set<BigInteger> listed = new TreeSet<>();
        Set<? extends X509CRLEntry> nextEntries = next.getRevokedCertificates();
        if (nextEntries != null) {
            for (X509CRLEntry e : nextEntries) listed.add(e.getSerialNumber());
        }
        Set<BigInteger> missing = new TreeSet<>();
        Set<? extends X509CRLEntry> previousEntries = previous.getRevokedCertificates();
        if (previousEntries != null) {
            for (X509CRLEntry e : previousEntries) {
                if (!listed.contains(e.getSerialNumber())) missing.add(e.getSerialNumber());
            }
        }
        return List.copyOf(missing);
    }

    private static String numbersOf(List<DiscardedCrl> list) {
        StringBuilder sb = new StringBuilder();
        for (DiscardedCrl d : list) {
            if (!sb.isEmpty()) sb.append(", ");
            sb.append('#').append(d.number());
        }
        return sb.toString();
    }

    private static JsonObject toJson(X509CRL crl, Outcome o) {
        JsonObject j = new JsonObject();
        j.addProperty("issuer", crl.getIssuerX500Principal().getName());
        if (o.slug() != null) j.addProperty("slug", o.slug());
        if (o.number() != null) j.addProperty("number", o.number().toString());
        j.addProperty("thisUpdate", crl.getThisUpdate().toInstant().toString());
        if (crl.getNextUpdate() != null) j.addProperty("nextUpdate", crl.getNextUpdate().toInstant().toString());
        j.addProperty("result", o.result());
        if (o.unchanged()) j.addProperty("unchanged", true);
        if (o.stored() != null && o.stored().state() == CrlState.PENDING) {
            j.addProperty("activatesAt", o.stored().thisUpdate().toString());
        }
        if (o.error() != null) j.addProperty("error", o.error());
        if (o.accepted()) {
            JsonArray discarded = new JsonArray();
            for (DiscardedCrl d : o.discarded()) {
                JsonObject dj = new JsonObject();
                dj.addProperty("number", d.number().toString());
                dj.addProperty("thisUpdate", d.thisUpdate().toString());
                if (d.nextUpdate() != null) dj.addProperty("nextUpdate", d.nextUpdate().toString());
                dj.addProperty("sha256", d.sha256());
                discarded.add(dj);
            }
            j.add("discarded", discarded);
        }
        return j;
    }
}
