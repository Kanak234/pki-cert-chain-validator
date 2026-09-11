# Build stage
FROM maven:3.9.6-eclipse-temurin-21-jammy AS builder
WORKDIR /build
COPY pom.xml .
RUN mvn dependency:go-offline -B
COPY src ./src
RUN mvn clean package -DskipTests -B

# Runtime stage
FROM eclipse-temurin:21-jre-jammy
RUN groupadd -r appgroup && useradd -r -g appgroup appuser
WORKDIR /app
COPY --from=builder /build/target/pki-cert-chain-validator-*.jar /app/validator.jar
USER appuser
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD java -jar /app/validator.jar --help || exit 1
ENTRYPOINT ["java", "-jar", "/app/validator.jar"]
CMD ["--help"]
