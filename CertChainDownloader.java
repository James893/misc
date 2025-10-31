import javax.net.ssl.*;
import javax.net.ServerSocketFactory;
import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.text.SimpleDateFormat;
import java.time.Duration;
import java.util.*;
import java.util.Base64;
import java.util.stream.IntStream;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;

/**
 * CertChainDownloader
 *
 * Connects to an HTTPS server at a specific IP address while:
 *  - Sending the desired hostname via TLS SNI, and
 *  - Sending the same hostname in the HTTP Host header.
 *
 * It captures the peer certificate chain sent by the server and writes it to a PEM file.
 *
 * Usage:
 *   java CertChainDownloader <ip> <hostname> [port=443] [outputPemPath=./<hostname>-chain.pem]
 *
 * Example:
 *   java CertChainDownloader 93.184.216.34 example.org 443 ./example.org-chain.pem
 *
 * Notes:
 *  - Requires Java 8+ for SNI support (SNIHostName).
 *  - The chain is what the server sends; servers typically omit the root CA.
 *  - This uses a trust-all manager to allow retrieval even if the cert is untrusted. Do not reuse
 *    this trust manager for general application traffic.
 */
public class CertChainDownloader {
    
    public static void main(String[] args) {
        if (args.length < 2 || args.length > 4) {
            System.err.println("Usage: java CertChainDownloader <ip> <hostname> [port=443] [outputPemPath]");
            System.err.println("Example: java CertChainDownloader 93.184.216.34 example.org 443 ./example.org-chain.pem");
            System.exit(2);
        }

        final String ip = args[0].trim();
        final String hostname = args[1].trim();
        final int port = (args.length >= 3) ? parsePort(args[2]) : 443;
        final Path outputPem = resolveOutputPath(hostname, (args.length >= 4) ? args[3] : null);

        int connectTimeoutMs = 10000;  // 10s connect timeout
        int readTimeoutMs = 10000;     // 10s read timeout
        boolean sendHeadRequest = true;

        System.out.printf("Connecting to %s:%d (SNI: %s)%n", ip, port, hostname);

        try {
            List<X509Certificate> chain = fetchCertificateChain(ip, hostname, port, connectTimeoutMs, readTimeoutMs, sendHeadRequest);
            if (chain.isEmpty()) {
                System.err.println("No certificates captured from the server.");
                System.exit(1);
            }

            writeChainAsPem(chain, outputPem);
            System.out.printf("Wrote %d certificate(s) to: %s%n", chain.size(), outputPem.toAbsolutePath());

            // Optional: print a concise summary
            printChainSummary(chain);

        } catch (Exception e) {
            System.err.println("Failed: " + e.getMessage());
            e.printStackTrace(System.err);
            System.exit(1);
        }
    }

    private static int parsePort(String s) {
        try {
            int p = Integer.parseInt(s);
            if (p < 1 || p > 65535) throw new IllegalArgumentException("Port out of range");
            return p;
        } catch (Exception e) {
            throw new IllegalArgumentException("Invalid port: " + s, e);
        }
    }

    private static Path resolveOutputPath(String hostname, String provided) {
        if (provided != null && !provided.isEmpty()) {
            return Paths.get(provided);
        }
        // Default: ./<hostname>-chain.pem with timestamp to avoid overwrites
        String ts = new SimpleDateFormat("yyyyMMdd-HHmmss").format(new Date());
        return Paths.get(String.format("%s-chain-%s.pem", hostname, ts));
    }

    /**
     * Performs a TLS connection to the given IP while setting SNI to the provided hostname.
     * Captures the peer certificate chain and (optionally) sends a simple HTTP HEAD request
     * with a Host header for completeness.
     */
    public static List<X509Certificate> fetchCertificateChain(
            String ip,
            String hostname,
            int port,
            int connectTimeoutMs,
            int readTimeoutMs,
            boolean sendHeadRequest
    ) throws Exception {

        // Prepare a TrustManager that trusts all but captures the chain.
        SavingTrustManager stm = new SavingTrustManager();

        SSLContext sc = SSLContext.getInstance("TLS");
        sc.init(null, new TrustManager[]{ stm }, new SecureRandom());
        SSLSocketFactory factory = sc.getSocketFactory();

        try (SSLSocket socket = (SSLSocket) factory.createSocket()) {

            // Limit to modern protocols if available.
            // You can also comment this out to accept the JVM default.
            enablePreferredProtocols(socket, new String[] { "TLSv1.3", "TLSv1.2" });

            // Set SNI to the target hostname (IDN-aware).
            SSLParameters params = socket.getSSLParameters();
            String asciiHost = toAsciiHostname(hostname);
            params.setServerNames(Collections.singletonList(new SNIHostName(asciiHost)));
            socket.setSSLParameters(params);

            // Connect to the target IP address.
            SocketAddress remote = new InetSocketAddress(ip, port);
            socket.connect(remote, connectTimeoutMs);
            socket.setSoTimeout(readTimeoutMs);

            // Start the TLS handshake (this triggers SavingTrustManager to capture chain).
            socket.startHandshake();

            // Optionally send an HTTP HEAD with proper Host header (not required for certs).
            if (sendHeadRequest) {
                sendHttpHead(socket, hostname);
                // Read and discard a small portion of the response (optional).
                readSomeResponse(socket);
            }

            // Prefer the captured chain from TrustManager. Fallback to session peer certs if needed.
            List<X509Certificate> chain = stm.getChain();
            if (chain.isEmpty()) {
                Certificate[] peer = socket.getSession().getPeerCertificates(); // may throw if none
                for (Certificate c : peer) {
                    if (c instanceof X509Certificate) {
                        chain.add((X509Certificate) c);
                    }
                }
            }

            return chain;
        }
    }

    private static void enablePreferredProtocols(SSLSocket socket, String[] preferred) {
        Set<String> supported = new HashSet<>(Arrays.asList(socket.getSupportedProtocols()));
        List<String> enabled = new ArrayList<>();
        for (String p : preferred) {
            if (supported.contains(p)) enabled.add(p);
        }
        if (!enabled.isEmpty()) {
            socket.setEnabledProtocols(enabled.toArray(new String[0]));
        }
    }

    private static String toAsciiHostname(String host) {
        try {
            // Handles IDNs (e.g., bücher.example → xn--bcher-kva.example)
            return java.net.IDN.toASCII(host, IDN.ALLOW_UNASSIGNED);
        } catch (Exception e) {
            return host;
        }
    }

    private static void sendHttpHead(SSLSocket socket, String hostname) throws IOException {
        String req = "HEAD / HTTP/1.1\r\n" +
                     "Host: " + hostname + "\r\n" +
                     "User-Agent: CertChainDownloader/1.0\r\n" +
                     "Accept: */*\r\n" +
                     "Connection: close\r\n\r\n";
        OutputStream out = socket.getOutputStream();
        out.write(req.getBytes(StandardCharsets.US_ASCII));
        out.flush();
    }

    private static void readSomeResponse(SSLSocket socket) {
        try {
            InputStream in = socket.getInputStream();
            byte[] buf = new byte[4096];
            int read = in.read(buf);
            if (read > 0) {
                // Optional: print the first line to confirm.
                String head = new String(buf, 0, Math.min(read, 200), StandardCharsets.ISO_8859_1);
                String firstLine = head.split("\r\n", 2)[0];
                System.out.println("HTTP response (first line): " + firstLine);
            }
        } catch (IOException ignored) {
            // Not critical for certificate capture.
        }
    }

    private static void writeChainAsPem(List<X509Certificate> chain, Path out) throws IOException {
        Files.createDirectories(out.getParent() != null ? out.getParent() : Paths.get("."));
        try (BufferedWriter w = Files.newBufferedWriter(out, StandardCharsets.US_ASCII,
                StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING, StandardOpenOption.WRITE)) {

            Base64.Encoder encoder = Base64.getMimeEncoder(64, "\n".getBytes(StandardCharsets.US_ASCII));
            int idx = 0;
            for (X509Certificate cert : chain) {
                try {
                    byte[] der = cert.getEncoded();
                    String b64 = encoder.encodeToString(der);

                    w.write("-----BEGIN CERTIFICATE-----\n");
                    w.write(b64);
                    w.write("\n-----END CERTIFICATE-----\n");

                    idx++;
                } catch (CertificateEncodingException e) {
                // You can choose to skip the bad cert or fail fast.
                // Here we fail fast, wrapping as IOException to satisfy the method signature.
                throw new IOException("Failed to encode certificate at index " + idx, e);
                }
            }

        }
    }

    private static void printChainSummary(List<X509Certificate> chain) {
        System.out.println("\nCertificate chain:");
        IntStream.range(0, chain.size()).forEach(i -> {
            X509Certificate c = chain.get(i);
            System.out.printf(" [%d] Subject: %s%n", i, c.getSubjectX500Principal());
            System.out.printf("     Issuer : %s%n", c.getIssuerX500Principal());
            System.out.printf("     Serial : %s%n", c.getSerialNumber().toString(16));
            System.out.printf("     NotBefore: %s | NotAfter: %s%n%n",
                    c.getNotBefore(), c.getNotAfter());
        });
    }

    /**
     * A trust-all X509TrustManager that captures the server-provided chain.
     * DO NOT use this in production for general HTTPS traffic—it's intentionally permissive.
     */
    private static final class SavingTrustManager implements X509TrustManager {
        private volatile List<X509Certificate> chain = new ArrayList<>();

        public List<X509Certificate> getChain() {
            return new ArrayList<>(chain);
        }

        @Override
        public void checkClientTrusted(X509Certificate[] chain, String authType) {
            // Not used
        }

        @Override
        public void checkServerTrusted(X509Certificate[] chain, String authType) {
            if (chain != null) {
                this.chain = Arrays.asList(chain);
            }
            // Trust-all: do not throw
        }

        @Override
        public X509Certificate[] getAcceptedIssuers() {
            return new X509Certificate[0];
        }
    }
}
