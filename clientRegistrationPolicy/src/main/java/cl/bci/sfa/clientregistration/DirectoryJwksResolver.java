package cl.bci.sfa.clientregistration;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.time.Duration;
import java.util.Base64;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import org.jboss.logging.Logger;
import org.keycloak.common.util.PemUtils;
import org.keycloak.common.util.Time;
import org.keycloak.component.ComponentModel;
import org.keycloak.crypto.KeyWrapper;
import org.keycloak.jose.jwk.JWK;
import org.keycloak.jose.jwk.JWKParser;
import org.keycloak.jose.jwk.JSONWebKeySet;
import org.keycloak.jose.jws.JWSInput;
import org.keycloak.jose.jws.JWSInputException;
import org.keycloak.models.KeycloakSession;
import org.keycloak.util.JsonSerialization;

/**
 * Resuelve claves públicas del Directorio CMF (JWKS remoto o PEM de respaldo para POC local).
 */
public final class DirectoryJwksResolver {

  private static final Logger LOG = Logger.getLogger(DirectoryJwksResolver.class);
  private static final Duration JWKS_CACHE_TTL = Duration.ofMinutes(5);
  private static final Map<String, CachedJwks> JWKS_CACHE = new ConcurrentHashMap<>();

  private DirectoryJwksResolver() {}

  public record CachedJwks(JSONWebKeySet jwks, long fetchedAtEpochSeconds) {}

  public static KeyWrapper resolveVerificationKey(
      KeycloakSession session,
      ComponentModel config,
      JWSInput jwsInput)
      throws JWSInputException, IOException {
    String kid = jwsInput.getHeader().getKeyId();
    String algorithm = jwsInput.getHeader().getAlgorithm().name();

    JSONWebKeySet jwks = loadJwks(session, config);
    if (jwks != null && jwks.getKeys() != null) {
      for (JWK jwk : jwks.getKeys()) {
        if (kid != null && kid.equals(jwk.getKeyId())) {
          return toKeyWrapper(jwk, algorithm);
        }
      }
      if (jwks.getKeys().length == 1) {
        return toKeyWrapper(jwks.getKeys()[0], algorithm);
      }
      throw new JWSInputException("Signing key with kid '" + kid + "' not found in directory JWKS");
    }

    PublicKey fallback = loadFallbackPublicKey(config);
    if (fallback == null) {
      throw new JWSInputException("Directory JWKS unavailable and no fallback public key configured");
    }

    KeyWrapper keyWrapper = new KeyWrapper();
    keyWrapper.setAlgorithm(algorithm);
    keyWrapper.setKid(kid);
    keyWrapper.setPublicKey(fallback);
    keyWrapper.setUse(org.keycloak.crypto.KeyUse.SIG);
    keyWrapper.setType("RSA");
    return keyWrapper;
  }

  private static KeyWrapper toKeyWrapper(JWK jwk, String algorithm) throws JWSInputException {
    try {
      PublicKey publicKey = JWKParser.create(jwk).toPublicKey();
      KeyWrapper keyWrapper = new KeyWrapper();
      keyWrapper.setKid(jwk.getKeyId());
      keyWrapper.setAlgorithm(jwk.getAlgorithm() != null ? jwk.getAlgorithm() : algorithm);
      keyWrapper.setPublicKey(publicKey);
      keyWrapper.setUse(org.keycloak.crypto.KeyUse.SIG);
      keyWrapper.setType(jwk.getKeyType());
      return keyWrapper;
    } catch (RuntimeException ex) {
      throw new JWSInputException(ex);
    }
  }

  private static JSONWebKeySet loadJwks(KeycloakSession session, ComponentModel config)
      throws IOException {
    String jwksUri = config.getConfig().getFirst(SfaSoftwareStatementClientRegistrationPolicyFactory.CONFIG_DIRECTORY_JWKS_URI);
    if (jwksUri == null || jwksUri.isBlank()) {
      return null;
    }

    long now = Time.currentTime();
    CachedJwks cached = JWKS_CACHE.get(jwksUri);
    if (cached != null && (now - cached.fetchedAtEpochSeconds()) < JWKS_CACHE_TTL.getSeconds()) {
      return cached.jwks();
    }

    LOG.debugf("Fetching directory JWKS from %s", jwksUri);

    JSONWebKeySet jwks;
    if (jwksUri.startsWith("file:")) {
      jwks = loadJwksFromFile(jwksUri);
    } else {
      jwks = fetchRemoteJwks(jwksUri);
    }

    if (jwks != null) {
      JWKS_CACHE.put(jwksUri, new CachedJwks(jwks, now));
    }
    return jwks;
  }

  private static JSONWebKeySet loadJwksFromFile(String jwksUri) throws IOException {
    Path path = Path.of(URI.create(jwksUri));
    return JsonSerialization.readValue(Files.readString(path), JSONWebKeySet.class);
  }

  private static JSONWebKeySet fetchRemoteJwks(String jwksUri) throws IOException {
    HttpClient httpClient = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(10)).build();
    HttpRequest request =
        HttpRequest.newBuilder()
            .uri(URI.create(jwksUri))
            .timeout(Duration.ofSeconds(15))
            .header("Accept", "application/json")
            .GET()
            .build();

    HttpResponse<String> response;
    try {
      response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
    } catch (InterruptedException ex) {
      Thread.currentThread().interrupt();
      throw new IOException("Interrupted while fetching directory JWKS", ex);
    }
    if (response.statusCode() < 200 || response.statusCode() >= 300) {
      LOG.warnf("Directory JWKS request failed (%s): %s", response.statusCode(), jwksUri);
      return null;
    }

    return JsonSerialization.readValue(response.body(), JSONWebKeySet.class);
  }

  private static PublicKey loadFallbackPublicKey(ComponentModel config) {
    String pem = config.getConfig().getFirst(SfaSoftwareStatementClientRegistrationPolicyFactory.CONFIG_DIRECTORY_PUBLIC_KEY_PEM);
    if (pem == null || pem.isBlank()) {
      return null;
    }
    try {
      return PemUtils.decodePublicKey(pem);
    } catch (Exception ex) {
      try {
        return decodePublicKeyPem(pem);
      } catch (Exception inner) {
        LOG.warn("Invalid directory-public-key-pem configuration", inner);
        return null;
      }
    }
  }

  private static PublicKey decodePublicKeyPem(String pem) throws Exception {
    String normalized =
        pem.replace("-----BEGIN PUBLIC KEY-----", "")
            .replace("-----END PUBLIC KEY-----", "")
            .replaceAll("\\s", "");
    byte[] decoded = Base64.getDecoder().decode(normalized);
    return KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(decoded));
  }

  static void clearCacheForTests() {
    JWKS_CACHE.clear();
  }
}
