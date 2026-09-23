package org.jboss.seam.example.booking.test;

import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;

import org.jboss.shrinkwrap.api.exporter.ZipExporter;

/**
 * Starts the hotel application and the PicketLink OIDC server on two WildFly processes.
 */
public final class HotelOidcServers {

    private HotelOidcServers() {
    }

    public static void main(String[] args) throws Exception {
        Path root = Path.of("..", "..", "..", "..").toAbsolutePath().normalize();
        Path demoIt = root.resolve(
                "picketlink-bindings/picketlink-wildfly-common/wildfly-36-oidc-demo/demo-it/target");
        Path hotelHome = demoIt.resolve("wildfly-rp");
        Path idpHome = demoIt.resolve("wildfly-as");
        Path hotelWar = Path.of("target", "seam-booking.war").toAbsolutePath();
        Path idpWar = root.resolve(
                "picketlink-bindings/picketlink-wildfly-common/wildfly-36-oidc-demo/demo-as-war/target/demo-as.war");
        Path agent = root.resolve(
                "picketlink-bindings/picketlink-wildfly-common/wildfly-36-oidc-demo/demo-it/target/picketlink-oidc-keystore-agent.jar");
        System.setProperty("seam.booking.oidc.enabled", "true");
        BookingWildFly36Deployment.create().as(ZipExporter.class).exportTo(hotelWar.toFile(), true);

        String hotelHost = "127.0.0.11";
        String idpHost = "127.0.0.12";
        holdPreviousDeployments(hotelHome);
        holdPreviousDeployments(idpHome);
        Process hotel = start(hotelHome, hotelHost, null, null);
        Process idp = start(idpHome, idpHost,
                idpHome.resolve("standalone/configuration/jbid_test_keystore.jks"), agent);
        try {
            waitFor(idpHome, idpHost, 9990);
            waitFor(hotelHome, hotelHost, 9990);
            deploy(idpHome, idpHost, 9990, idpWar);
            deploy(hotelHome, hotelHost, 9990, hotelWar);
            System.out.println("Hotel http://" + hotelHost + ":8080/seam-booking/home.seam");
            System.out.println("IdP   http://" + idpHost + ":8080/demo-as/");
            hotel.waitFor();
            idp.waitFor();
        } catch (Exception ex) {
            hotel.destroy();
            idp.destroy();
            throw ex;
        }
    }

    private static void holdPreviousDeployments(Path jbossHome) throws Exception {
        Path deployments = jbossHome.resolve("standalone/deployments");
        Path held = jbossHome.resolve("standalone/deployments-held");
        if (!Files.isDirectory(deployments)) {
            return;
        }
        Files.createDirectories(held);
        try (var listing = Files.list(deployments)) {
            for (Path file : listing.toList()) {
                Path dest = held.resolve(file.getFileName());
                if (Files.exists(dest) && !Files.isDirectory(dest)) {
                    Files.delete(dest);
                }
                if (Files.exists(dest)) {
                    dest = held.resolve(file.getFileName().toString() + "." + System.currentTimeMillis());
                }
                Files.move(file, dest, StandardCopyOption.REPLACE_EXISTING);
            }
        }
    }

    /**
     * {@code $1} JBOSS_HOME, {@code $2} agent jar, {@code $3} bridge jar, then {@code standalone.sh}.
     */
    private static final String AGENT_LAUNCH = """
            export JBOSS_HOME="$1"
            AGENT="$2"
            BRIDGE="$3"
            shift 3
            case ",${JBOSS_MODULES_SYSTEM_PKGS:-org.jboss.byteman}," in
              *,org.picketlink.oidc.keystore.bridge,*) ;;
              *) export JBOSS_MODULES_SYSTEM_PKGS="${JBOSS_MODULES_SYSTEM_PKGS:-org.jboss.byteman},org.picketlink.oidc.keystore.bridge" ;;
            esac
            export MODULE_OPTS="-javaagent:${AGENT}"
            unset JAVA_OPTS
            . "$JBOSS_HOME/bin/standalone.conf"
            JAVA_OPTS="-Xbootclasspath/a:${BRIDGE} ${JAVA_OPTS}"
            export JAVA_OPTS
            exec "$@"
            """;

    private static Process start(Path jbossHome, String bind, Path keystore, Path agent) throws Exception {
        List<String> command = new ArrayList<>();
        command.add(jbossHome.resolve("bin/standalone.sh").toString());
        command.add("-b");
        command.add(bind);
        command.add("-bmanagement");
        command.add(bind);
        if (keystore != null) {
            command.add("-Dpicketlink.test.keystore.path=" + keystore);
        }
        if (agent != null) {
            Path bridge = agent.resolveSibling("picketlink-oidc-keystore-bridge.jar");
            command.add(0, bridge.toString());
            command.add(0, agent.toString());
            command.add(0, jbossHome.toString());
            command.add(0, "bash");
            command.add(0, AGENT_LAUNCH);
            command.add(0, "-c");
            command.add(0, "bash");
        }
        ProcessBuilder builder = new ProcessBuilder(command);
        builder.directory(jbossHome.toFile());
        builder.environment().put("JBOSS_HOME", jbossHome.toString());
        builder.redirectErrorStream(true);
        Process process = builder.start();
        drain(process.getInputStream(), bind);
        return process;
    }

    private static void waitFor(Path jbossHome, String bind, int mgmtPort) throws Exception {
        long deadline = System.currentTimeMillis() + Duration.ofMinutes(3).toMillis();
        while (System.currentTimeMillis() < deadline) {
            try {
                cli(jbossHome, bind, mgmtPort, ":read-attribute(name=server-state)");
                return;
            } catch (Exception ignored) {
                Thread.sleep(2000);
            }
        }
        throw new IllegalStateException("Timed out waiting for " + bind);
    }

    private static void deploy(Path jbossHome, String bind, int mgmtPort, Path war) throws Exception {
        cli(jbossHome, bind, mgmtPort, "deploy " + war.toAbsolutePath() + " --force");
    }

    private static void cli(Path jbossHome, String bind, int mgmtPort, String command) throws Exception {
        ProcessBuilder builder = new ProcessBuilder(
                jbossHome.resolve("bin/jboss-cli.sh").toString(),
                "--controller=" + bind + ":" + mgmtPort,
                "--connect",
                "--command=" + command);
        builder.redirectErrorStream(true);
        Process process = builder.start();
        String output;
        try (InputStream in = process.getInputStream()) {
            output = new String(in.readAllBytes());
        }
        if (process.waitFor(60, TimeUnit.SECONDS) && process.exitValue() != 0) {
            throw new IllegalStateException(command + "\n" + output);
        }
        if (process.isAlive()) {
            process.destroyForcibly();
            throw new IllegalStateException("CLI hung: " + command);
        }
    }

    private static void drain(InputStream stream, String prefix) {
        Thread thread = new Thread(() -> {
            try (InputStream in = stream) {
                in.transferTo(System.out);
            } catch (Exception ignored) {
            }
        }, prefix + "-log");
        thread.setDaemon(true);
        thread.start();
    }
}
