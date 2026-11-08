package io.siggi.pkiserver;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import io.siggi.pkiserver.store.CrlState;
import io.siggi.pkiserver.store.Store;
import io.siggi.pkiserver.store.StoredCrl;

import java.math.BigInteger;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

/**
 * CRL coverage of one signing certificate: its current CRL, the pending (pre-signed) ones, the
 * highest CRL Number used so far, and when coverage runs out (the last {@code nextUpdate}
 * across current + pending).
 *
 * @param slug           the signing certificate
 * @param now            when this was computed
 * @param current        the current CRL, or null
 * @param pending        pending CRLs, by increasing number
 * @param highestNumber  the highest CRL Number ever accepted (incl. superseded and discarded), or null
 * @param coverageUntil  the last nextUpdate across current + pending, or null if there is none
 * @param warnThreshold  coverage ending less than this far away is warned about
 */
record CrlCoverage(String slug, Instant now, StoredCrl current, List<StoredCrl> pending, BigInteger highestNumber,
                   Instant coverageUntil, Duration warnThreshold) {

    /** The API path prefix: {@code GET /api/crl/<slug>}. */
    static final String API_PREFIX = CrlUpload.PATH + "/";

    CrlCoverage {
        pending = List.copyOf(pending);
    }

    static CrlCoverage of(Store store, String slug, Instant now, Duration warnThreshold) {
        StoredCrl current = null;
        List<StoredCrl> pending = new ArrayList<>();
        Instant until = null;
        for (StoredCrl crl : store.crls(slug)) {
            if (crl.state() == CrlState.CURRENT) {
                current = crl;
            } else if (crl.state() == CrlState.PENDING) {
                pending.add(crl);
            } else {
                continue;
            }
            if (crl.nextUpdate() != null && (until == null || crl.nextUpdate().isAfter(until))) {
                until = crl.nextUpdate();
            }
        }
        return new CrlCoverage(slug, now, current, pending, store.highestCrlNumber(slug), until, warnThreshold);
    }

    /** The current CRL is past its nextUpdate. */
    boolean stale() {
        return current != null && current.nextUpdate() != null && !now.isBefore(current.nextUpdate());
    }

    /** The CRL Number the signer should use next. */
    BigInteger nextNumber() {
        return highestNumber == null ? BigInteger.ONE : highestNumber.add(BigInteger.ONE);
    }

    /** How long until coverage runs out (negative once it has), or null if there's no coverage. */
    Duration remaining() {
        return coverageUntil == null ? null : Duration.between(now, coverageUntil);
    }

    /**
     * Coverage ends (or has ended) less than {@link #warnThreshold} from now. A CA without any
     * CRL isn't warned about: it may simply not publish CRLs (yet).
     */
    boolean warning() {
        return coverageUntil != null && remaining().compareTo(warnThreshold) < 0;
    }

    JsonObject toJson() {
        JsonObject j = new JsonObject();
        j.addProperty("slug", slug);
        j.addProperty("now", now.toString());
        if (current == null) {
            j.add("current", null);
        } else {
            JsonObject c = crlJson(current);
            c.addProperty("stale", stale());
            j.add("current", c);
        }
        JsonArray p = new JsonArray();
        for (StoredCrl crl : pending) p.add(crlJson(crl));
        j.add("pending", p);
        j.addProperty("highestCrlNumber", highestNumber == null ? null : highestNumber.toString());
        j.addProperty("nextCrlNumber", nextNumber().toString());
        j.addProperty("coverageUntil", coverageUntil == null ? null : coverageUntil.toString());
        Duration remaining = remaining();
        j.addProperty("coverageRemainingSeconds", remaining == null ? null : remaining.toSeconds());
        j.addProperty("coverageWarningDays", warnThreshold.toDays());
        j.addProperty("coverageWarning", warning());
        return j;
    }

    private static JsonObject crlJson(StoredCrl crl) {
        JsonObject c = new JsonObject();
        c.addProperty("number", crl.number().toString());
        c.addProperty("thisUpdate", crl.thisUpdate().toString());
        c.addProperty("nextUpdate", crl.nextUpdate() == null ? null : crl.nextUpdate().toString());
        c.addProperty("sha256", crl.sha256());
        return c;
    }

    /** {@code GET /api/crl/<slug>}: the coverage report as JSON. */
    static Api.GetHandler apiHandler(Store store, Clock clock, Duration warnThreshold) {
        return (request, rest) -> {
            String problem = RequestPaths.slugProblem(rest);
            if (problem != null) {
                Api.error(request, 400, "Bad Request", problem, false);
                return;
            }
            if (store.signingCert(rest) == null) {
                Api.error(request, 404, "Not Found", "no signing certificate named " + rest, false);
                return;
            }
            Api.json(request, 200, "OK", of(store, rest, clock.instant(), warnThreshold).toJson());
        };
    }
}
