package io.siggi.pkiserver;

import java.io.IOException;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.util.logging.Level;
import java.util.logging.Logger;

public class Main {
    public static void main(String[] args) {
        Logging.configure();
        Logger log = Logging.get(Main.class);

        Path configFile = Path.of("config.json");
        for (int i = 0; i < args.length; i++) {
            if ((args[i].equals("--config") || args[i].equals("-c")) && i + 1 < args.length) {
                configFile = Path.of(args[++i]);
            } else {
                System.err.println("Usage: java -jar PKIServer.jar [--config <config.json>]");
                System.exit(2);
                return;
            }
        }

        Config config;
        try {
            config = Config.load(configFile);
        } catch (NoSuchFileException e) {
            log.severe("Config file not found: " + configFile.toAbsolutePath());
            System.exit(1);
            return;
        } catch (IOException e) {
            log.log(Level.SEVERE, "Could not read config file " + configFile.toAbsolutePath(), e);
            System.exit(1);
            return;
        } catch (Config.ConfigException e) {
            log.severe("Invalid config file " + configFile.toAbsolutePath() + ": " + e.getMessage());
            System.exit(1);
            return;
        }

        PKIServer server = new PKIServer(config);
        Runtime.getRuntime().addShutdownHook(new Thread(server::stop, "PKIServer-shutdown"));
        try {
            server.start();
        } catch (IOException e) {
            log.log(Level.SEVERE, "Failed to start", e);
            System.exit(1);
        }
    }
}
