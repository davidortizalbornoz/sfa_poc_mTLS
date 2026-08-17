package cl.bci.sfa.clientregistration;

import java.io.IOException;
import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import org.jboss.logging.Logger;
import org.keycloak.component.ComponentModel;
import org.keycloak.jose.jwk.JSONWebKeySet;
import org.keycloak.services.clientregistration.policy.ClientRegistrationPolicyException;
import org.keycloak.util.JsonSerialization;

/**
 * Resuelve JWKS locales por cliente para POC: embebe claves en el registro sin fetch HTTP.
 *
 * <p>Convención: {@code {poc-client-jwks-base-dir}/{software_id}/jwks.json}. Overrides opcionales
 * vía {@code poc-client-jwks-uri-mappings} con formato {@code software_jwks_uri=file:/path/jwks.json}.
 */
public final class ClientJwksResolver {

  private static final Logger LOG = Logger.getLogger(ClientJwksResolver.class);

  public static final String CONFIG_BASE_DIR = "poc-client-jwks-base-dir";
  public static final String CONFIG_URI_MAPPINGS = "poc-client-jwks-uri-mappings";

  private ClientJwksResolver() {}

  /**
   * Devuelve el JSON JWKS embebible si hay archivo local configurado; {@code null} si debe
   * usarse {@code software_jwks_uri} remoto (producción).
   */
  public static String resolveEmbeddedJwks(
      ComponentModel config, SfaSoftwareStatementClaims claims)
      throws ClientRegistrationPolicyException {
    ResolvedLocalJwks resolved = resolveLocalJwks(config, claims);
    if (resolved == null) {
      return null;
    }

    try {
      if (!Files.isRegularFile(resolved.path())) {
        throw new ClientRegistrationPolicyException(
            "POC client JWKS file not found: "
                + resolved.fileUri()
                + " (software_id="
                + claims.getSoftwareId()
                + ")");
      }

      String jwksJson = Files.readString(resolved.path());
      validateJwks(jwksJson, resolved.fileUri());
      LOG.debugf(
          "Embedding local JWKS from %s for software_id=%s",
          resolved.fileUri(),
          claims.getSoftwareId());
      return jwksJson;
    } catch (ClientRegistrationPolicyException ex) {
      throw ex;
    } catch (IOException ex) {
      throw new ClientRegistrationPolicyException(
          "Unable to load POC client JWKS from "
              + resolved.fileUri()
              + ": "
              + ex.getMessage());
    }
  }

  private record ResolvedLocalJwks(String fileUri, Path path, boolean explicitMapping) {}

  static ResolvedLocalJwks resolveLocalJwks(
      ComponentModel config, SfaSoftwareStatementClaims claims) {
    String jwksUri = claims.getSoftwareJwksUri();
    if (jwksUri == null || jwksUri.isBlank()) {
      return null;
    }

    List<String> mappings = config.getConfig().getOrDefault(CONFIG_URI_MAPPINGS, List.of());
    for (String mapping : mappings) {
      String fileUri = parseMappingTarget(mapping, jwksUri);
      if (fileUri != null) {
        return new ResolvedLocalJwks(fileUri, Path.of(URI.create(fileUri)), true);
      }
    }

    String baseDir = config.getConfig().getFirst(CONFIG_BASE_DIR);
    if (baseDir == null || baseDir.isBlank()) {
      return null;
    }

    String softwareId = claims.getSoftwareId();
    if (softwareId == null || softwareId.isBlank()) {
      return null;
    }

    String normalizedBase = baseDir.endsWith("/") ? baseDir.substring(0, baseDir.length() - 1) : baseDir;
    String fileUri = normalizedBase + "/" + softwareId + "/jwks.json";
    Path path = Path.of(URI.create(fileUri));
    if (!Files.isRegularFile(path)) {
      return null;
    }

    return new ResolvedLocalJwks(fileUri, path, false);
  }

  private static String parseMappingTarget(String mapping, String jwksUri) {
    if (mapping == null || mapping.isBlank()) {
      return null;
    }

    int separator = mapping.indexOf('=');
    if (separator <= 0) {
      return null;
    }

    String mappedUri = mapping.substring(0, separator).trim();
    String fileUri = mapping.substring(separator + 1).trim();
    if (!jwksUri.equals(mappedUri) || !fileUri.startsWith("file:")) {
      return null;
    }

    return fileUri;
  }

  private static void validateJwks(String jwksJson, String fileUri)
      throws ClientRegistrationPolicyException {
    try {
      JSONWebKeySet jwks = JsonSerialization.readValue(jwksJson, JSONWebKeySet.class);
      if (jwks == null || jwks.getKeys() == null || jwks.getKeys().length == 0) {
        throw new ClientRegistrationPolicyException("POC client JWKS has no keys: " + fileUri);
      }
    } catch (ClientRegistrationPolicyException ex) {
      throw ex;
    } catch (Exception ex) {
      throw new ClientRegistrationPolicyException("Invalid POC client JWKS at " + fileUri);
    }
  }
}
