package io.siggi.pkiserver;

import io.siggi.pkiserver.store.CaRole;
import io.siggi.pkiserver.store.EndEntityCert;
import io.siggi.pkiserver.store.SigningCert;
import io.siggi.pkiserver.store.Store;
import io.siggi.pkiserver.x509.X509Util;

import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;

/**
 * Builds {@code chain.pem} and {@code fullchain.pem} for published end-entity certificates.
 * <p>
 * The chain is the issuing signing certificate followed by its issuers up to, but excluding,
 * the root. It is built from the installed signing certificates every time it's asked for, so
 * it always matches what the server publishes. For a leaf issued directly by a root the chain
 * is empty.
 * <p>
 * The store never holds two signing certificates with the same subject and key, so the path
 * is normally unique; should several exist, the shortest is used (ties broken by slugs, so
 * the choice is deterministic).
 */
final class ChainBuilder {
    private final Store store;
    private final ChainValidator validator;

    ChainBuilder(Store store) {
        this.store = store;
        this.validator = new ChainValidator(store);
    }

    /**
     * The chain above an end-entity certificate issued by {@code issuerSlug}: that signing
     * certificate followed by its issuers, root excluded.
     *
     * @return the chain, issuer first; empty if the issuer is a root; null if the slug is
     * unknown or no path of installed certificates leads from it to an installed root
     */
    List<SigningCert> chain(String issuerSlug) {
        List<SigningCert> path = path(issuerSlug);
        if (path == null) return null;
        return List.copyOf(path.subList(0, path.size() - 1)); // drop the root
    }

    /**
     * Like {@link #chain} but including the root: the issuing signing certificate followed by
     * its issuers up to and including the root.
     *
     * @return the path, issuer first, never empty; null if the slug is unknown or unchainable
     */
    List<SigningCert> path(String issuerSlug) {
        SigningCert issuer = store.signingCert(issuerSlug);
        if (issuer == null) return null;
        if (issuer.role() == CaRole.ROOT) return List.of(issuer);
        List<List<SigningCert>> paths = new ArrayList<>();
        List<SigningCert> above = new ArrayList<>();
        above.add(issuer);
        validator.findPaths(issuer.cert(), above, paths);
        if (paths.isEmpty()) return null;
        paths.sort(Comparator.<List<SigningCert>>comparingInt(List::size)
                .thenComparing(ChainBuilder::slugKey));
        return List.copyOf(paths.get(0));
    }

    /** {@code chain.pem} for {@code ee}: concatenated PEM, empty string under a root; null if unchainable. */
    String chainPem(EndEntityCert ee) {
        List<SigningCert> chain = chain(ee.issuerSlug());
        if (chain == null) return null;
        return X509Util.pem(certs(chain));
    }

    /** {@code fullchain.pem} for {@code ee}: the certificate followed by its chain; null if unchainable. */
    String fullchainPem(EndEntityCert ee) {
        List<SigningCert> chain = chain(ee.issuerSlug());
        if (chain == null) return null;
        List<X509Certificate> certs = new ArrayList<>();
        certs.add(ee.cert());
        certs.addAll(certs(chain));
        return X509Util.pem(certs);
    }

    private static List<X509Certificate> certs(List<SigningCert> chain) {
        List<X509Certificate> out = new ArrayList<>(chain.size());
        for (SigningCert sc : chain) out.add(sc.cert());
        return out;
    }

    private static String slugKey(List<SigningCert> path) {
        StringBuilder sb = new StringBuilder();
        for (SigningCert sc : path) sb.append(sc.slug()).append('/');
        return sb.toString();
    }
}
