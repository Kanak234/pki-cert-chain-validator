FROM eclipse-temurin:21-jdk-jammy

WORKDIR /app

COPY target/pki-cert-chain-validator-1.0.0.jar /app/validator.jar

ENTRYPOINT ["java", "-jar", "/app/validator.jar"]
CMD ["--help"]
