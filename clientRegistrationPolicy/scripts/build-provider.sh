#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

log() {
  echo "[build-provider $(date '+%Y-%m-%dT%H:%M:%S')] $*"
}

log "Inicio build"
log "Directorio: $ROOT_DIR"

if [[ ! -f pom.xml ]]; then
  log "ERROR: pom.xml no encontrado en $ROOT_DIR"
  exit 1
fi

run_maven() {
  # -B: modo batch, muestra progreso sin prompts interactivos.
  # -DskipTests: el build del provider no requiere Keycloak en ejecución.
  log "Ejecutando: mvn -B package -DskipTests"
  mvn -B package -DskipTests
}

if command -v mvn >/dev/null 2>&1; then
  log "Maven local detectado: $(command -v mvn)"
  run_maven
else
  log "Maven local no encontrado; usando contenedor Docker"
  log "Imagen: maven:3.9-eclipse-temurin-17"
  log "Montaje: $ROOT_DIR -> /work"

  docker_args=(
    run --rm
    -v "$ROOT_DIR:/work"
    -w /work
  )

  if [[ -d "${HOME}/.m2" ]]; then
    log "Cache Maven: ${HOME}/.m2 -> /root/.m2"
    docker_args+=(-v "${HOME}/.m2:/root/.m2")
  else
    log "Sin cache Maven (~/.m2); la primera ejecución descargará dependencias (puede tardar varios minutos)"
  fi

  log "Descargando imagen Docker si no existe localmente..."
  docker pull maven:3.9-eclipse-temurin-17

  log "Iniciando contenedor Maven (descarga de dependencias visible abajo)"
  docker "${docker_args[@]}" maven:3.9-eclipse-temurin-17 mvn -B package -DskipTests
fi

log "Build completado"
echo "Provider JAR:"
ls -1 target/sfa-software-statement-policy-*.jar
