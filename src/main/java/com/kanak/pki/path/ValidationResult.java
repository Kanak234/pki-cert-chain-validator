package com.kanak.pki.path;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Objects;

/**
 * Detailed outcome of an RFC 5280 path validation evaluation with complete diagnostic audit trace.
 */
public final class ValidationResult {

    private final ValidationStatus status;
    private final List<ValidationStep> auditLog;
    private final String message;

    public ValidationResult(ValidationStatus status, List<ValidationStep> auditLog, String message) {
        this.status = Objects.requireNonNull(status, "status must not be null");
        this.auditLog = auditLog != null ? Collections.unmodifiableList(new ArrayList<>(auditLog)) : Collections.emptyList();
        this.message = Objects.requireNonNull(message, "message must not be null");
    }

    public static ValidationResult success(List<ValidationStep> auditLog) {
        return new ValidationResult(ValidationStatus.VALID, auditLog, "Certification path successfully verified to trusted anchor");
    }

    public static ValidationResult failure(ValidationStatus status, List<ValidationStep> auditLog, String message) {
        return new ValidationResult(status, auditLog, message);
    }

    public ValidationStatus getStatus() {
        return status;
    }

    public boolean isValid() {
        return status.isValid();
    }

    public List<ValidationStep> getAuditLog() {
        return auditLog;
    }

    public String getMessage() {
        return message;
    }

    public String toJson() {
        StringBuilder sb = new StringBuilder();
        sb.append("{\n");
        sb.append("  \"valid\": ").append(isValid()).append(",\n");
        sb.append("  \"status\": \"").append(status.name()).append("\",\n");
        sb.append("  \"message\": \"").append(escapeJson(message)).append("\",\n");
        sb.append("  \"steps\": [\n");
        for (int i = 0; i < auditLog.size(); i++) {
            ValidationStep step = auditLog.get(i);
            sb.append("    {\n");
            sb.append("      \"step\": \"").append(escapeJson(step.stepName())).append("\",\n");
            sb.append("      \"passed\": ").append(step.passed()).append(",\n");
            sb.append("      \"subject\": \"").append(escapeJson(step.subjectDn())).append("\",\n");
            sb.append("      \"details\": \"").append(escapeJson(step.details())).append("\"\n");
            sb.append("    }").append(i < auditLog.size() - 1 ? "," : "").append("\n");
        }
        sb.append("  ]\n");
        sb.append("}");
        return sb.toString();
    }

    private static String escapeJson(String s) {
        return s.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n").replace("\r", "\\r");
    }

    public String toPrettyString() {
        StringBuilder sb = new StringBuilder();
        sb.append("========================================================\n");
        sb.append("RFC 5280 Path Validation Outcome: ").append(status.name()).append("\n");
        sb.append("Summary: ").append(message).append("\n");
        sb.append("Audit Trail (").append(auditLog.size()).append(" steps executed):\n");
        for (ValidationStep step : auditLog) {
            sb.append("  ").append(step).append("\n");
        }
        sb.append("========================================================\n");
        return sb.toString();
    }

    @Override
    public String toString() {
        return "ValidationResult[status=" + status + ", valid=" + isValid() + "]";
    }
}
