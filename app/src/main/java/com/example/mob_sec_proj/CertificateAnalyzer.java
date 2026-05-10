package com.example.mob_sec_proj;

import android.os.Handler;
import android.os.Looper;

import java.net.URL;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Date;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicBoolean;

import javax.net.ssl.HttpsURLConnection;

public class CertificateAnalyzer {

    public static class CertResult {
        public boolean valid;
        public boolean expired;
        public boolean notYetValid;
        public boolean selfSigned;
        public boolean domainMatch;
        public String issuer;
        public String checkedUrl;
        public boolean handshakeFailed;
        public boolean timeout;
    }

    public interface Callback {
        void onResult(CertResult result);
    }

    private static final Handler mainHandler = new Handler(Looper.getMainLooper());
    private static final ExecutorService executor = Executors.newCachedThreadPool();

    public static void checkUrl(String resolvedUrl, String originalUrl, Callback callback) {

        // prefer resolved if https, fall back to original if https, else give up
        String target = null;

        if (resolvedUrl != null && resolvedUrl.startsWith("https://")) {
            target = resolvedUrl;
        } else if (originalUrl != null && originalUrl.startsWith("https://")) {
            target = originalUrl;
        }

        final String httpsUrl = target;
        AtomicBoolean finished = new AtomicBoolean(false);

        // no usable https url
        if (httpsUrl == null) {
            CertResult result = new CertResult();
            result.valid = false;
            result.checkedUrl = null;
            mainHandler.post(() -> callback.onResult(result));
            return;
        }

        executor.execute(() -> {

            CertResult result = new CertResult();
            result.checkedUrl = httpsUrl;

            HttpsURLConnection conn = null;

            try {
                URL url = new URL(httpsUrl);
                conn = (HttpsURLConnection) url.openConnection();
                conn.setConnectTimeout(4000);
                conn.setReadTimeout(4000);
                conn.connect();

                Certificate[] certs = conn.getServerCertificates();

                if (certs == null || certs.length == 0) {
                    result.valid = false;
                    postOnce(callback, result, finished);
                    return;
                }

                X509Certificate cert = (X509Certificate) certs[0];
                result.valid = true;
                result.issuer = cert.getIssuerX500Principal().getName();

                // expiry — distinguish expired vs not yet valid
                Date now = new Date();
                if (now.before(cert.getNotBefore())) {
                    result.notYetValid = true;
                    result.expired = false;
                } else if (now.after(cert.getNotAfter())) {
                    result.expired = true;
                    result.notYetValid = false;
                } else {
                    result.expired = false;
                    result.notYetValid = false;
                }

                // self-signed
                result.selfSigned = cert.getSubjectX500Principal()
                        .equals(cert.getIssuerX500Principal());

                // domain match
                String host = url.getHost().toLowerCase();
                result.domainMatch = isDomainValid(cert, host);

            } catch (Exception e) {
                result.valid = false;
                result.handshakeFailed = true;
            } finally {
                if (conn != null) conn.disconnect();
            }

            postOnce(callback, result, finished);
        });

        // timeout fallback
        executor.execute(() -> {
            try {
                Thread.sleep(6000);
            } catch (InterruptedException ignored) {}

            CertResult timeoutResult = new CertResult();
            timeoutResult.timeout = true;
            timeoutResult.valid = false;
            timeoutResult.checkedUrl = httpsUrl;
            postOnce(callback, timeoutResult, finished);
        });
    }

    private static void postOnce(Callback callback, CertResult result, AtomicBoolean finished) {
        if (finished.compareAndSet(false, true)) {
            mainHandler.post(() -> callback.onResult(result));
        }
    }

    private static boolean isDomainValid(X509Certificate cert, String host) {
        try {
            Collection<List<?>> sans = cert.getSubjectAlternativeNames();

            if (sans != null) {
                for (List<?> san : sans) {
                    if (san == null || san.size() < 2) continue;
                    Integer type = (Integer) san.get(0);
                    if (type != 2) continue;

                    String dns = san.get(1).toString().toLowerCase();

                    if (host.equals(dns)) return true;

                    if (dns.startsWith("*.")) {
                        String suffix = dns.substring(1); // e.g. ".example.com"
                        if (host.endsWith(suffix) &&
                                host.indexOf('.') == host.length() - suffix.length()) {
                            return true;
                        }
                    }
                }
                return false;
            }

            // CN fallback
            String dn = cert.getSubjectX500Principal().getName();
            for (String part : dn.split(",")) {
                part = part.trim();
                if (part.toLowerCase().startsWith("cn=")) {
                    String cn = part.substring(3).toLowerCase();
                    return cn.equals(host);
                }
            }

        } catch (Exception ignored) {}

        return false;
    }
}