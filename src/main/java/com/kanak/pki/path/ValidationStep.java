package com.kanak.pki.path;

import java.util.Objects;

/**
 * Audit log entry capturing an individual validation check within RFC 5280 path evaluation.
 */
public record ValidationStep(
        String stepName,
        boolean passed,
        String subjectDn,
        String details
) {
    public ValidationStep {
        Objects.requireNonNull(stepName, "stepName must not be null");
        Objects.requireNonNull(subjectDn, "subjectDn must not be null");
        Objects.requireNonNull(details, "details must not be null");
    }

    public static ValidationStep pass(String stepName, String subjectDn, String details) {
        return new ValidationStep(stepName, true, subjectDn, details);
    }

    public static ValidationStep fail(String stepName, String subjectDn, String details) {
        return new ValidationStep(stepName, false, subjectDn, details);
    }

    @Override
    public String toString() {
        return "[" + (passed ? "PASS" : "FAIL") + "] " + stepName + " (" + subjectDn + "): " + details;
    }
}
