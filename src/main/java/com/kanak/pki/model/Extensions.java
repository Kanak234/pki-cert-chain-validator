package com.kanak.pki.model;

import com.kanak.pki.asn1.Asn1Node;
import com.kanak.pki.asn1.Asn1Tag;
import com.kanak.pki.asn1.Oid;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;

/**
 * Registry of X.509 v3 Extensions conforming to RFC 5280 §4.1.2.9 and §4.2.
 */
public final class Extensions {

    public record Entry(String oid, boolean critical, byte[] valueDer) {}

    private final Map<String, Entry> entries;
    private volatile BasicConstraints basicConstraints;
    private volatile KeyUsage keyUsage;
    private volatile ExtendedKeyUsage extendedKeyUsage;
    private volatile GeneralNames subjectAltNames;

    public Extensions(Map<String, Entry> entries) {
        this.entries = Collections.unmodifiableMap(new LinkedHashMap<>(entries));
    }

    public static Extensions fromAsn1(Asn1Node extensionsSeq) {
        Objects.requireNonNull(extensionsSeq, "extensionsSeq must not be null");
        Map<String, Entry> map = new LinkedHashMap<>();

        for (Asn1Node extNode : extensionsSeq.getChildren()) {
            if (extNode.getChildCount() < 2) continue;

            String oid = extNode.getChild(0).asOid().getDottedString();
            boolean critical = false;
            int valueIdx = 1;

            if (extNode.getChild(1).getTagNumber() == Asn1Tag.BOOLEAN) {
                critical = extNode.getChild(1).asBoolean();
                valueIdx = 2;
            }

            if (valueIdx < extNode.getChildCount()) {
                byte[] valDer = extNode.getChild(valueIdx).getContentBytes();
                map.put(oid, new Entry(oid, critical, valDer));
            }
        }

        return new Extensions(map);
    }

    public Optional<Entry> get(String oid) {
        return Optional.ofNullable(entries.get(oid));
    }

    public boolean hasExtension(String oid) {
        return entries.containsKey(oid);
    }

    public Set<String> getCriticalExtensionOids() {
        Set<String> criticalOids = new java.util.HashSet<>();
        for (Entry entry : entries.values()) {
            if (entry.critical()) {
                criticalOids.add(entry.oid());
            }
        }
        return Collections.unmodifiableSet(criticalOids);
    }

    public Optional<BasicConstraints> getBasicConstraints() {
        if (basicConstraints != null) return Optional.of(basicConstraints);
        Optional<Entry> entry = get(Oid.BASIC_CONSTRAINTS);
        if (entry.isPresent()) {
            basicConstraints = BasicConstraints.fromExtensionValue(entry.get().valueDer());
            return Optional.of(basicConstraints);
        }
        return Optional.empty();
    }

    public Optional<KeyUsage> getKeyUsage() {
        if (keyUsage != null) return Optional.of(keyUsage);
        Optional<Entry> entry = get(Oid.KEY_USAGE);
        if (entry.isPresent()) {
            keyUsage = KeyUsage.fromExtensionValue(entry.get().valueDer());
            return Optional.of(keyUsage);
        }
        return Optional.empty();
    }

    public Optional<ExtendedKeyUsage> getExtendedKeyUsage() {
        if (extendedKeyUsage != null) return Optional.of(extendedKeyUsage);
        Optional<Entry> entry = get(Oid.EXTENDED_KEY_USAGE);
        if (entry.isPresent()) {
            extendedKeyUsage = ExtendedKeyUsage.fromExtensionValue(entry.get().valueDer());
            return Optional.of(extendedKeyUsage);
        }
        return Optional.empty();
    }

    public Optional<GeneralNames> getSubjectAlternativeNames() {
        if (subjectAltNames != null) return Optional.of(subjectAltNames);
        Optional<Entry> entry = get(Oid.SUBJECT_ALTERNATIVE_NAME);
        if (entry.isPresent()) {
            subjectAltNames = GeneralNames.fromExtensionValue(entry.get().valueDer());
            return Optional.of(subjectAltNames);
        }
        return Optional.empty();
    }

    public Map<String, Entry> getAll() {
        return entries;
    }

    @Override
    public String toString() {
        return "Extensions" + entries.keySet();
    }
}
