package io.siggi.pkiserver;

import io.siggi.pkiserver.store.SigningCert;
import io.siggi.pkiserver.store.Store;
import io.siggi.pkiserver.store.StoreException;
import io.siggi.pkiserver.store.StoredCrl;
import io.siggi.pkiserver.x509.InvalidX509Exception;
import io.siggi.pkiserver.x509.X509Util;

import java.io.IOException;
import java.io.PrintStream;
import java.nio.file.Files;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

/**
 * Admin commands that work directly on the data directory: installing roots by hand
 * ({@code add-root}), listing signing certificates ({@code list}) and removing them
 * ({@code remove}). A running server only picks up changes when it is restarted.
 */
public final class AdminCli {
    /** Exit codes. */
    public static final int OK = 0;
    public static final int FAILED = 1;
    public static final int USAGE = 2;

    public static final String USAGE_TEXT = """
            Usage:
              java -jar PKIServer.jar [--config <config.json>]                    run the server
              java -jar PKIServer.jar [--config <config.json>] add-root <slug> <file>
              java -jar PKIServer.jar [--config <config.json>] list
              java -jar PKIServer.jar [--config <config.json>] remove <slug>

            Admin commands use the config's dataDir; --data-dir <dir> uses <dir> instead.
            A running server picks up admin changes when it is restarted.
            """;

    private static final List<String> COMMANDS = List.of("add-root", "list", "remove");

    private final Path dataDir;
    private final PrintStream out;
    private final PrintStream err;

    public AdminCli(Path dataDir, PrintStream out, PrintStream err) {
        this.dataDir = dataDir;
        this.out = out;
        this.err = err;
    }

    public static boolean isCommand(String arg) {
        return COMMANDS.contains(arg);
    }

    /** Runs one command ({@code args[0]} is the command name) and returns the exit code. */
    public int run(List<String> args) {
        if (args.isEmpty() || !isCommand(args.get(0))) {
            err.print(USAGE_TEXT);
            return USAGE;
        }
        String command = args.get(0);
        List<String> rest = args.subList(1, args.size());
        try {
            return switch (command) {
                case "add-root" -> rest.size() == 2 ? addRoot(rest.get(0), Path.of(rest.get(1))) : usage();
                case "list" -> rest.isEmpty() ? list() : usage();
                case "remove" -> rest.size() == 1 ? remove(rest.get(0)) : usage();
                default -> usage();
            };
        } catch (IOException e) {
            err.println("error: " + e);
            return FAILED;
        }
    }

    private int usage() {
        err.print(USAGE_TEXT);
        return USAGE;
    }

    private int fail(String message) {
        err.println("error: " + message);
        return FAILED;
    }

    private Store openStore() throws IOException {
        Files.createDirectories(dataDir);
        return Store.open(dataDir);
    }

    // ------------------------------------------------------------------ add-root

    int addRoot(String slug, Path file) throws IOException {
        String slugProblem = Slugs.problem(slug);
        if (slugProblem != null) return fail(slugProblem);

        byte[] bytes;
        try {
            bytes = Files.readAllBytes(file);
        } catch (NoSuchFileException e) {
            return fail("no such file: " + file);
        }
        X509Certificate cert;
        try {
            cert = X509Util.parseCertificate(bytes);
        } catch (InvalidX509Exception e) {
            return fail(file + ": " + e.getMessage());
        }
        String certProblem = rootProblem(cert);
        if (certProblem != null) return fail(file + ": " + certProblem);

        Store store = openStore();
        boolean added;
        try {
            added = store.addSigningCert(slug, cert);
        } catch (StoreException e) {
            return fail(e.getMessage());
        }
        String subject = cert.getSubjectX500Principal().getName();
        if (!added) {
            out.println("Root " + subject + " is already installed as \"" + slug + "\", nothing to do.");
            return OK;
        }
        out.println("Installed root " + subject + " as \"" + slug + "\".");
        out.println("  " + Path.of(Store.CA_DIR, slug, Store.CERT_FILE) + " in " + dataDir.toAbsolutePath());
        Instant now = Instant.now();
        if (cert.getNotAfter().toInstant().isBefore(now)) {
            out.println("Warning: this certificate expired on " + cert.getNotAfter().toInstant() + ".");
        } else if (cert.getNotBefore().toInstant().isAfter(now)) {
            out.println("Note: this certificate is not valid until " + cert.getNotBefore().toInstant() + ".");
        }
        out.println("Restart the server to pick up the change.");
        return OK;
    }

    /** Why {@code cert} can't be installed as a root, or null if it can. */
    static String rootProblem(X509Certificate cert) {
        if (!cert.getSubjectX500Principal().equals(cert.getIssuerX500Principal())) {
            return "not self-signed: issued by " + cert.getIssuerX500Principal().getName()
                    + " (only roots can be installed by hand; intermediates are uploaded)";
        }
        if (cert.getBasicConstraints() < 0) {
            return "not a CA certificate (basicConstraints CA:TRUE is missing)";
        }
        try {
            cert.verify(cert.getPublicKey());
        } catch (GeneralSecurityException e) {
            return "self-signature does not verify: " + e.getMessage();
        }
        return null;
    }

    // ------------------------------------------------------------------ list

    int list() throws IOException {
        Store store = openStore();
        List<SigningCert> certs = store.signingCerts();
        if (certs.isEmpty()) {
            out.println("No signing certificates installed in " + dataDir.toAbsolutePath());
            return OK;
        }
        List<String[]> rows = new ArrayList<>();
        rows.add(new String[]{"SLUG", "ROLE", "SUBJECT", "NOT AFTER", "CRL", "CERTS"});
        for (SigningCert sc : certs) {
            StoredCrl current = store.currentCrl(sc.slug());
            rows.add(new String[]{
                    sc.slug(),
                    sc.role().id(),
                    sc.subject().getName(),
                    sc.cert().getNotAfter().toInstant().toString(),
                    current == null ? "-" : "#" + current.number(),
                    Integer.toString(store.endEntityCerts(sc.slug()).size()),
            });
        }
        int[] widths = new int[rows.get(0).length];
        for (String[] row : rows) {
            for (int i = 0; i < row.length; i++) widths[i] = Math.max(widths[i], row[i].length());
        }
        for (String[] row : rows) {
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < row.length; i++) {
                if (i > 0) sb.append("  ");
                sb.append(i == row.length - 1 ? row[i] : pad(row[i], widths[i]));
            }
            out.println(sb.toString().stripTrailing());
        }
        return OK;
    }

    private static String pad(String s, int width) {
        return s + " ".repeat(width - s.length());
    }

    // ------------------------------------------------------------------ remove

    int remove(String slug) throws IOException {
        Store store = openStore();
        SigningCert sc = store.signingCert(slug);
        if (sc == null) return fail("no signing certificate \"" + slug + "\"");
        int crls = store.crls(slug).size();
        int ees = store.endEntityCerts(slug).size();
        List<String> dependents = new ArrayList<>();
        for (SigningCert other : store.signingCerts()) {
            if (other != sc && other.cert().getIssuerX500Principal().equals(sc.subject())) {
                dependents.add(other.slug());
            }
        }
        try {
            store.removeSigningCert(slug);
        } catch (StoreException e) {
            return fail(e.getMessage());
        }
        out.println("Removed " + sc.role().id() + " " + sc.subject().getName() + " (\"" + slug + "\") with "
                + crls + " CRL(s) and " + ees + " end-entity certificate(s).");
        if (!dependents.isEmpty()) {
            out.println("Warning: certificates issued by it are still installed and will no longer validate: "
                    + String.join(", ", dependents));
        }
        out.println("Restart the server to pick up the change.");
        return OK;
    }
}
