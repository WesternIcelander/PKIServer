package io.siggi.pkiserver;

import io.siggi.pkiserver.store.EndEntityCert;
import io.siggi.pkiserver.store.SigningCert;
import io.siggi.pkiserver.store.Store;

import javax.security.auth.x500.X500Principal;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

/** Finds the conditions to notify about in the store's current state. */
final class Alerts {
    private Alerts() {
    }

    /**
     * The active alerts:
     * <ul>
     *   <li>CRL coverage (the last nextUpdate across current + pending CRLs) ends less than
     *       {@code coverageWarning} from now, but hasn't ended yet;</li>
     *   <li>the current CRL is past its nextUpdate (stale);</li>
     *   <li>a signing certificate expires less than {@code certWarning} from now, or has expired
     *       (it is still installed, so that needs attention);</li>
     *   <li>a published end-entity certificate expires less than {@code certWarning} from now.
     *       Once it has expired the alert ends: expired certificates stay published, and
     *       nagging about them forever would be noise.</li>
     * </ul>
     */
    static List<Alert> find(Store store, Instant now, Duration coverageWarning, Duration certWarning) {
        List<Alert> alerts = new ArrayList<>();
        for (SigningCert sc : store.signingCerts()) {
            String slug = sc.slug();
            CrlCoverage coverage = CrlCoverage.of(store, slug, now, coverageWarning);
            if (coverage.stale()) {
                alerts.add(new Alert(Alert.TYPE_CRL_STALE + ":" + slug, Alert.TYPE_CRL_STALE, slug, null,
                        coverage.current().nextUpdate(),
                        "The current CRL #" + coverage.current().number() + " of \"" + slug + "\" is stale: its"
                                + " nextUpdate " + coverage.current().nextUpdate() + " has passed. Upload a new CRL"
                                + " (next CRL Number: " + coverage.nextNumber() + ")."));
            }
            if (coverage.warning() && coverage.remaining().isPositive()) {
                alerts.add(new Alert(Alert.TYPE_CRL_COVERAGE_LOW + ":" + slug, Alert.TYPE_CRL_COVERAGE_LOW, slug,
                        null, coverage.coverageUntil(),
                        "CRL coverage of \"" + slug + "\" runs out at " + coverage.coverageUntil() + " ("
                                + describe(coverage.remaining()) + " left, "
                                + coverage.pending().size() + " pending CRL(s)). Upload more pre-signed CRLs"
                                + " (next CRL Number: " + coverage.nextNumber() + ")."));
            }

            Instant notAfter = sc.cert().getNotAfter().toInstant();
            Duration left = Duration.between(now, notAfter);
            if (left.compareTo(certWarning) < 0) {
                String what = sc.role().name().toLowerCase(java.util.Locale.ROOT) + " certificate \"" + slug + "\" ("
                        + cn(sc.subject()) + ")";
                alerts.add(new Alert(Alert.TYPE_SIGNING_CERT_EXPIRING + ":" + slug, Alert.TYPE_SIGNING_CERT_EXPIRING,
                        slug, null, notAfter,
                        left.isPositive()
                                ? "Signing " + what + " expires at " + notAfter + " (in " + describe(left) + ")."
                                : "Signing " + what + " expired at " + notAfter + "."));
            }

            for (EndEntityCert ee : store.endEntityCerts(slug)) {
                Instant eeNotAfter = ee.cert().getNotAfter().toInstant();
                Duration eeLeft = Duration.between(now, eeNotAfter);
                if (!eeLeft.isPositive() || eeLeft.compareTo(certWarning) >= 0) continue;
                alerts.add(new Alert(Alert.TYPE_CERT_EXPIRING + ":" + slug + "/" + ee.serial(),
                        Alert.TYPE_CERT_EXPIRING, slug, ee.serial(), eeNotAfter,
                        "Certificate " + slug + "/" + ee.serial() + " (" + cn(ee.cert().getSubjectX500Principal())
                                + ") expires at " + eeNotAfter + " (in " + describe(eeLeft) + ")."));
            }
        }
        return alerts;
    }

    /** "12 days", "5 hours", "3 minutes". */
    static String describe(Duration d) {
        if (d.toDays() >= 2) return d.toDays() + " days";
        if (d.toHours() >= 2) return d.toHours() + " hours";
        long minutes = Math.max(0, d.toMinutes());
        return minutes + (minutes == 1 ? " minute" : " minutes");
    }

    private static String cn(X500Principal subject) {
        return subject.getName(X500Principal.RFC2253);
    }
}
