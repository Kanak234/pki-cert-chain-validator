package com.kanak.pki.path;

import java.time.Instant;
import java.util.Collections;
import java.util.HashSet;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;

/**
 * Configuration parameters and policy settings for RFC 5280 path validation execution.
 */
public final class ValidationContext {

    private final Instant validationTime;
    private final String targetHostname;
    private final Set<String> requiredKeyPurposes;
    private final int maxPathLength;
    private final boolean allowSelfSignedLeaf;

    private ValidationContext(Builder builder) {
        this.validationTime = builder.validationTime != null ? builder.validationTime : Instant.now();
        this.targetHostname = builder.targetHostname;
        this.requiredKeyPurposes = Collections.unmodifiableSet(new HashSet<>(builder.requiredKeyPurposes));
        this.maxPathLength = builder.maxPathLength;
        this.allowSelfSignedLeaf = builder.allowSelfSignedLeaf;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static ValidationContext defaultContext() {
        return builder().build();
    }

    public Instant getValidationTime() {
        return validationTime;
    }

    public Optional<String> getTargetHostname() {
        return Optional.ofNullable(targetHostname);
    }

    public Set<String> getRequiredKeyPurposes() {
        return requiredKeyPurposes;
    }

    public int getMaxPathLength() {
        return maxPathLength;
    }

    public boolean isAllowSelfSignedLeaf() {
        return allowSelfSignedLeaf;
    }

    public static final class Builder {
        private Instant validationTime = Instant.now();
        private String targetHostname;
        private final Set<String> requiredKeyPurposes = new HashSet<>();
        private int maxPathLength = 10;
        private boolean allowSelfSignedLeaf = false;

        public Builder validationTime(Instant time) {
            this.validationTime = Objects.requireNonNull(time);
            return this;
        }

        public Builder targetHostname(String hostname) {
            this.targetHostname = hostname;
            return this;
        }

        public Builder requireKeyPurpose(String oid) {
            this.requiredKeyPurposes.add(Objects.requireNonNull(oid));
            return this;
        }

        public Builder maxPathLength(int len) {
            if (len <= 0) throw new IllegalArgumentException("maxPathLength must be positive");
            this.maxPathLength = len;
            return this;
        }

        public Builder allowSelfSignedLeaf(boolean allow) {
            this.allowSelfSignedLeaf = allow;
            return this;
        }

        public ValidationContext build() {
            return new ValidationContext(this);
        }
    }
}
