package com.kanak.pki.path;

import com.kanak.pki.model.X509Certificate;

import java.io.FileInputStream;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.cert.CertificateFactory;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

/**
 * In-memory repository of trusted Root CA trust anchors.
 */
public final class TrustStore {

    private final List<X509Certificate> trustAnchors = new ArrayList<>();

    public TrustStore() {
    }

    public TrustStore(List<X509Certificate> initialAnchors) {
        if (initialAnchors != null) {
            this.trustAnchors.addAll(initialAnchors);
        }
    }

    public static TrustStore createEmpty() {
        return new TrustStore();
    }

    public static TrustStore of(X509Certificate... anchors) {
        return new TrustStore(Arrays.asList(anchors));
    }

    public synchronized void addTrustAnchor(X509Certificate cert) {
        Objects.requireNonNull(cert, "Trust anchor certificate must not be null");
        trustAnchors.add(cert);
    }

    public synchronized void addAll(List<X509Certificate> certs) {
        Objects.requireNonNull(certs, "Certs list must not be null");
        trustAnchors.addAll(certs);
    }

    public synchronized Optional<X509Certificate> findTrustAnchor(X509Certificate candidate) {
        Objects.requireNonNull(candidate, "candidate certificate must not be null");

        for (X509Certificate anchor : trustAnchors) {
            // 1. Exact DER match
            if (Arrays.equals(anchor.getRawDer(), candidate.getRawDer())) {
                return Optional.of(anchor);
            }

            // 2. Subject DN and Public Key match
            if (anchor.getSubject().equals(candidate.getSubject())) {
                try {
                    if (Arrays.equals(anchor.getSubjectPublicKeyInfo().getPublicKeyBits(),
                                      candidate.getSubjectPublicKeyInfo().getPublicKeyBits())) {
                        return Optional.of(anchor);
                    }
                } catch (Exception ignored) {
                }
            }
        }
        return Optional.empty();
    }

    public synchronized List<X509Certificate> getAnchors() {
        return Collections.unmodifiableList(new ArrayList<>(trustAnchors));
    }

    public synchronized int size() {
        return trustAnchors.size();
    }

    public synchronized boolean isEmpty() {
        return trustAnchors.isEmpty();
    }

    /**
     * Loads certificates from a Java KeyStore file (e.g. cacerts).
     */
    public static TrustStore fromKeyStore(String path, char[] password) {
        TrustStore store = new TrustStore();
        try (InputStream is = new FileInputStream(path)) {
            KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
            ks.load(is, password);
            for (String alias : Collections.list(ks.aliases())) {
                if (ks.isCertificateEntry(alias)) {
                    java.security.cert.Certificate cert = ks.getCertificate(alias);
                    store.addTrustAnchor(X509Certificate.fromDer(cert.getEncoded()));
                }
            }
        } catch (Exception e) {
            throw new IllegalStateException("Failed to load trust anchors from KeyStore at " + path, e);
        }
        return store;
    }
}
