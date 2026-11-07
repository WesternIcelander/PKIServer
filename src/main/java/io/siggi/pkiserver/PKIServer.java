package io.siggi.pkiserver;

import io.siggi.http.HTTPRequest;
import io.siggi.http.HTTPServer;
import io.siggi.http.HTTPServerBuilder;
import io.siggi.http.iphelper.IP;
import io.siggi.pkiserver.store.Store;

import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketException;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.logging.Level;
import java.util.logging.Logger;

/** The HTTP server: owns the listening socket and the SiggiHTTP instance. */
public final class PKIServer {
    private static final Logger log = Logging.get(PKIServer.class);
    private static final long SHUTDOWN_GRACE_MILLIS = 10_000L;

    private final Config config;
    private final Object lock = new Object();
    private boolean started;
    private boolean stopped;
    private ServerSocket serverSocket;
    private HTTPServer httpServer;
    private Store store;
    private ExecutorService executor;
    private Thread acceptThread;
    private volatile boolean stopping;
    private final AtomicInteger activeRequests = new AtomicInteger();
    private final Set<Socket> connections = ConcurrentHashMap.newKeySet();

    public PKIServer(Config config) {
        this.config = config;
    }

    public Config getConfig() {
        return config;
    }

    public void start() throws IOException {
        synchronized (lock) {
            if (started) throw new IllegalStateException("Already started");
            started = true;
            Files.createDirectories(config.dataDir());
            store = Store.open(config.dataDir());

            executor = Executors.newThreadPerTaskExecutor(Thread.ofVirtual().name("PKIServer-http-", 0).factory());
            httpServer = new HTTPServerBuilder()
                    .setExecutor(executor)
                    .build();
            // Only the configured proxies may set X-Forwarded-* headers, not SiggiHTTP's defaults.
            for (IP ip : httpServer.getTrustedIPs()) {
                httpServer.untrustIP(ip.toString());
            }
            for (String proxy : config.trustedProxies()) {
                httpServer.trustIP(proxy);
            }
            httpServer.setPostLimit((int) config.limits().maxUploadBytes());
            httpServer.setUploadLimit(config.limits().maxUploadBytes());
            httpServer.responderRegistry.register("/", this::dispatch);

            ServerSocket socket = new ServerSocket();
            socket.setReuseAddress(true);
            socket.bind(config.listen());
            serverSocket = socket;

            acceptThread = new Thread(this::acceptLoop, "PKIServer-accept");
            acceptThread.start();
        }
        log.info("Listening on " + serverSocket.getLocalSocketAddress() + ", data dir " + config.dataDir());
        if (config.uploadsEnabled()) {
            log.info("Trusted proxies: " + String.join(", ", config.trustedProxies()));
        } else {
            log.info("No trusted proxies configured: uploads are disabled");
        }
    }

    /** The data store, loaded at {@link #start()}. */
    public Store getStore() {
        synchronized (lock) {
            if (store == null) throw new IllegalStateException("Not started");
            return store;
        }
    }

    /** The port actually bound (useful when the config asks for port 0). */
    public int getPort() {
        synchronized (lock) {
            if (serverSocket == null) throw new IllegalStateException("Not started");
            return serverSocket.getLocalPort();
        }
    }

    private void acceptLoop() {
        ServerSocket socket = serverSocket;
        while (true) {
            Socket client;
            try {
                client = socket.accept();
            } catch (SocketException e) {
                if (socket.isClosed()) return;
                log.log(Level.WARNING, "accept failed", e);
                continue;
            } catch (IOException e) {
                log.log(Level.WARNING, "accept failed", e);
                continue;
            }
            connections.removeIf(Socket::isClosed);
            connections.add(client);
            if (stopping) {
                closeQuietly(client);
                return;
            }
            try {
                httpServer.handle(client);
            } catch (RuntimeException e) {
                log.log(Level.WARNING, "failed to handle connection", e);
                closeQuietly(client);
            }
        }
    }

    private static void closeQuietly(Socket socket) {
        try {
            socket.close();
        } catch (IOException ignored) {
        }
    }

    private void dispatch(HTTPRequest request) throws Exception {
        activeRequests.incrementAndGet();
        try {
            handleRequest(request);
        } finally {
            activeRequests.decrementAndGet();
        }
    }

    private void handleRequest(HTTPRequest request) throws Exception {
        request.response.setHeader("404 Not Found");
        request.response.setContentType("text/plain; charset=utf-8");
        request.response.write("Not found\n");
    }

    /**
     * Stops accepting connections, lets requests already being handled finish (up to a grace
     * period), then closes the remaining (idle keep-alive) connections. Idempotent.
     */
    public void stop() {
        ServerSocket socket;
        Thread accept;
        ExecutorService exec;
        synchronized (lock) {
            if (!started || stopped) return;
            stopped = true;
            stopping = true;
            socket = serverSocket;
            accept = acceptThread;
            exec = executor;
        }
        log.info("Shutting down");
        try {
            socket.close();
        } catch (IOException e) {
            log.log(Level.WARNING, "failed to close listening socket", e);
        }
        try {
            accept.join(SHUTDOWN_GRACE_MILLIS);
            long deadline = System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(SHUTDOWN_GRACE_MILLIS);
            while (activeRequests.get() > 0 && System.nanoTime() < deadline) {
                Thread.sleep(20);
            }
            if (activeRequests.get() > 0) {
                log.warning("Requests still running after grace period, closing their connections");
            }
            List<Socket> open = new ArrayList<>(connections);
            connections.clear();
            open.forEach(PKIServer::closeQuietly);
            exec.shutdown();
            if (!exec.awaitTermination(1, TimeUnit.SECONDS)) {
                exec.shutdownNow();
            }
        } catch (InterruptedException e) {
            exec.shutdownNow();
            Thread.currentThread().interrupt();
        }
        log.info("Stopped");
    }
}
