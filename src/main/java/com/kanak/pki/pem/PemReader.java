package com.kanak.pki.pem;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.StringReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Objects;

/**
 * Robust RFC 7468 PEM reader decoding armored ASCII text blocks into binary DER payloads.
 */
public final class PemReader {

    private PemReader() {
        // Utility class
    }

    public static List<byte[]> readBlocks(String pemContent) {
        Objects.requireNonNull(pemContent, "pemContent must not be null");
        try (BufferedReader reader = new BufferedReader(new StringReader(pemContent))) {
            return parseReader(reader);
        } catch (IOException e) {
            throw new IllegalArgumentException("Error reading PEM content", e);
        }
    }

    public static List<byte[]> readBlocks(Path path) throws IOException {
        Objects.requireNonNull(path, "path must not be null");
        try (BufferedReader reader = Files.newBufferedReader(path, StandardCharsets.UTF_8)) {
            return parseReader(reader);
        }
    }

    public static List<byte[]> readBlocks(InputStream in) throws IOException {
        Objects.requireNonNull(in, "InputStream must not be null");
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(in, StandardCharsets.UTF_8))) {
            return parseReader(reader);
        }
    }

    private static List<byte[]> parseReader(BufferedReader reader) throws IOException {
        List<byte[]> blocks = new ArrayList<>();
        String line;
        StringBuilder base64Accumulator = null;

        while ((line = reader.readLine()) != null) {
            line = line.trim();
            if (line.startsWith("-----BEGIN ") && line.endsWith("-----")) {
                base64Accumulator = new StringBuilder();
            } else if (line.startsWith("-----END ") && line.endsWith("-----")) {
                if (base64Accumulator != null) {
                    String b64 = base64Accumulator.toString().replaceAll("\\s+", "");
                    if (!b64.isEmpty()) {
                        blocks.add(Base64.getDecoder().decode(b64));
                    }
                    base64Accumulator = null;
                }
            } else if (base64Accumulator != null) {
                // Accumulate base64 lines, ignoring headers like "Proc-Type:" if any
                if (!line.contains(":")) {
                    base64Accumulator.append(line);
                }
            }
        }
        return blocks;
    }
}
