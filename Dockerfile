# ── Stage 1: Build ────────────────────────────────────────────────────────────
FROM maven:3.9.6-eclipse-temurin-17 AS build
WORKDIR /app

# Download dependencies first (layer-cached unless pom.xml changes)
COPY pom.xml .
RUN mvn dependency:go-offline -q

COPY src ./src
RUN mvn package -q -DskipTests

# ── Stage 2: Runtime ───────────────────────────────────────────────────────────
FROM eclipse-temurin:17-jre-jammy
WORKDIR /app

COPY --from=build /app/target/cross-cloud-csfle-0.1.0-SNAPSHOT.jar app.jar

# deployment.properties is mounted at runtime — never baked into the image
# GCP credentials mounted via GOOGLE_APPLICATION_CREDENTIALS

ENTRYPOINT ["java", "-jar", "app.jar"]
# Default: provision mode. Override in docker compose or docker run:
#   docker run ... provision  deployment/deployment.properties
#   docker run ... producer   deployment/deployment.properties
#   docker run ... consumer   deployment/deployment.properties
CMD ["provision", "/config/deployment.properties"]
