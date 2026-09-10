package com.kanak.pki.model;

import com.kanak.pki.asn1.Asn1Node;
import com.kanak.pki.asn1.DerParser;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Locale;
import java.util.Objects;

/**
 * Collection of GeneralNames conforming to RFC 5280 §4.2.1.6 (GeneralNames syntax).
 */
public final class GeneralNames {

    private final List<GeneralName> names;

    public GeneralNames(List<GeneralName> names) {
        this.names = Collections.unmodifiableList(new ArrayList<>(names));
    }

    public static GeneralNames fromExtensionValue(byte[] extnValueDer) {
        Asn1Node seq = DerParser.parse(extnValueDer);
        List<GeneralName> list = new ArrayList<>();
        for (Asn1Node child : seq.getChildren()) {
            list.add(GeneralName.fromAsn1(child));
        }
        return new GeneralNames(list);
    }

    public List<GeneralName> getNames() {
        return names;
    }

    public List<String> getDnsNames() {
        List<String> dns = new ArrayList<>();
        for (GeneralName gn : names) {
            if (gn.getType() == GeneralName.Type.DNS_NAME) {
                dns.add(gn.getValue());
            }
        }
        return dns;
    }

    public List<String> getIpAddresses() {
        List<String> ips = new ArrayList<>();
        for (GeneralName gn : names) {
            if (gn.getType() == GeneralName.Type.IP_ADDRESS) {
                ips.add(gn.getValue());
            }
        }
        return ips;
    }

    /**
     * Verifies whether target hostname matches any DNS GeneralName per RFC 6125.
     */
    public boolean matchesHostname(String targetHost) {
        Objects.requireNonNull(targetHost, "targetHost must not be null");
        String target = targetHost.toLowerCase(Locale.ROOT).trim();

        for (String pattern : getDnsNames()) {
            String p = pattern.toLowerCase(Locale.ROOT).trim();
            if (matchPattern(target, p)) {
                return true;
            }
        }
        return false;
    }

    public static boolean matchPattern(String target, String pattern) {
        if (target.equals(pattern)) {
            return true;
        }
        if (pattern.startsWith("*.")) {
            String suffix = pattern.substring(2);
            // Must have at least one dot in suffix (e.g. *.example.com)
            if (suffix.contains(".")) {
                int dotIdx = target.indexOf('.');
                if (dotIdx > 0) {
                    String targetSuffix = target.substring(dotIdx + 1);
                    return targetSuffix.equals(suffix);
                }
            }
        }
        return false;
    }

    @Override
    public String toString() {
        return names.toString();
    }
}
