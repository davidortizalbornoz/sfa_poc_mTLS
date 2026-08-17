package cl.bci.sfa.clientregistration;

import com.fasterxml.jackson.databind.JsonNode;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Set;
import org.keycloak.common.util.Time;
import org.keycloak.component.ComponentModel;
import org.keycloak.crypto.AsymmetricSignatureVerifierContext;
import org.keycloak.crypto.KeyWrapper;
import org.keycloak.jose.jws.JWSInput;
import org.keycloak.jose.jws.JWSInputException;
import org.keycloak.models.KeycloakSession;
import org.keycloak.representations.idm.ClientRepresentation;
import org.keycloak.services.clientregistration.ClientRegistrationContext;
import org.keycloak.services.clientregistration.policy.ClientRegistrationPolicyException;
import org.keycloak.util.JsonSerialization;

/**
 * Valida firma PS256 y claims del SSA según perfil Open Finance / SFA Chile.
 */
public final class SfaSoftwareStatementValidator {

  private static final String CLIENT_AUTHENTICATOR_X509 = "client-x509";
  private static final String CLIENT_AUTHENTICATOR_JWT = "client-jwt";
  private static final Set<String> JWKS_ATTRIBUTE_KEYS =
      Set.of("jwks.url", "use.jwks.url", "use.jwks.string", "jwks.string");

  private SfaSoftwareStatementValidator() {}

  public static SfaSoftwareStatementClaims validateAndParse(
      KeycloakSession session,
      ComponentModel config,
      String softwareStatement)
      throws ClientRegistrationPolicyException {
    if (softwareStatement == null || softwareStatement.isBlank()) {
      throw new ClientRegistrationPolicyException("software_statement is required");
    }

    JWSInput jwsInput;
    try {
      jwsInput = new JWSInput(softwareStatement);
    } catch (JWSInputException ex) {
      throw new ClientRegistrationPolicyException("Invalid software_statement JWT format");
    }

    String expectedAlg =
        config.getConfig().getFirst(SfaSoftwareStatementClientRegistrationPolicyFactory.CONFIG_SIGNATURE_ALGORITHM);
    if (expectedAlg == null || expectedAlg.isBlank()) {
      expectedAlg = "PS256";
    }

    if (!expectedAlg.equalsIgnoreCase(jwsInput.getHeader().getAlgorithm().name())) {
      throw new ClientRegistrationPolicyException(
          "software_statement must be signed with " + expectedAlg);
    }

    KeyWrapper verificationKey;
    try {
      verificationKey = DirectoryJwksResolver.resolveVerificationKey(session, config, jwsInput);
    } catch (JWSInputException | IOException ex) {
      throw new ClientRegistrationPolicyException(
          "Unable to resolve directory verification key: " + ex.getMessage());
    }

    try {
      AsymmetricSignatureVerifierContext verifier =
          new AsymmetricSignatureVerifierContext(verificationKey);
      if (!verifier.verify(
          jwsInput.getEncodedSignatureInput().getBytes(StandardCharsets.UTF_8),
          jwsInput.getSignature())) {
        throw new ClientRegistrationPolicyException("Invalid software_statement signature");
      }
    } catch (Exception ex) {
      throw new ClientRegistrationPolicyException("Invalid software_statement signature");
    }

    JsonNode claims;
    try {
      claims = JsonSerialization.readValue(jwsInput.getContent(), JsonNode.class);
    } catch (IOException ex) {
      throw new ClientRegistrationPolicyException("Invalid software_statement payload");
    }

    validateClaims(config, claims);

    return toClaims(claims);
  }

  private static void validateClaims(ComponentModel config, JsonNode claims)
      throws ClientRegistrationPolicyException {
    String expectedIssuer =
        config.getConfig().getFirst(SfaSoftwareStatementClientRegistrationPolicyFactory.CONFIG_DIRECTORY_ISSUER);
    String issuer = textClaim(claims, "iss");
    if (expectedIssuer != null && !expectedIssuer.isBlank() && !expectedIssuer.equals(issuer)) {
      throw new ClientRegistrationPolicyException("software_statement issuer is not trusted");
    }

    if (!claims.hasNonNull("iat")) {
      throw new ClientRegistrationPolicyException("software_statement must contain iat");
    }

    long iat = claims.get("iat").asLong();
    long maxAge = parseMaxAge(config);
    long now = Time.currentTime();
    if (iat > now + 60) {
      throw new ClientRegistrationPolicyException("software_statement iat is in the future");
    }
    if ((now - iat) > maxAge) {
      throw new ClientRegistrationPolicyException("software_statement is expired");
    }

    if (isBlank(textClaim(claims, "software_id"))) {
      throw new ClientRegistrationPolicyException("software_statement must contain software_id");
    }

    String organisationId = organisationId(claims);
    if (isBlank(organisationId)) {
      throw new ClientRegistrationPolicyException(
          "software_statement must contain organisation_id or organization_id");
    }

    if (isBlank(textClaim(claims, "software_jwks_uri"))) {
      throw new ClientRegistrationPolicyException(
          "software_statement must contain software_jwks_uri");
    }
  }

  public static void enforceRequestMetadata(
      ClientRepresentation client,
      SfaSoftwareStatementClaims claims,
      boolean inlineJwksPresent,
      ClientRegistrationContext context)
      throws ClientRegistrationPolicyException {
    if (OidcContextReader.isTlsClientAuth(context)) {
      enforceTlsClientAuthMetadata(client, claims, context);
    } else {
      enforcePrivateKeyJwtMetadata(client, claims, inlineJwksPresent, context);
    }

    if (!claims.getRedirectUris().isEmpty() && client.getRedirectUris() != null) {
      for (String redirectUri : client.getRedirectUris()) {
        if (!claims.getRedirectUris().contains(redirectUri)) {
          throw new ClientRegistrationPolicyException(
              "redirect_uri is not allowed by software_statement");
        }
      }
    }
  }

  public static void applyClaimsToClient(
      ClientRepresentation client,
      SfaSoftwareStatementClaims claims,
      ComponentModel config)
      throws ClientRegistrationPolicyException {
    applyClaimsToClient(client, claims, config, null);
  }

  public static void applyClaimsToClient(
      ClientRepresentation client,
      SfaSoftwareStatementClaims claims,
      ComponentModel config,
      ClientRegistrationContext context)
      throws ClientRegistrationPolicyException {
    SoftwareStatementExtractor.ensureClientAttributes(client);
    applyCommonClaims(client, claims);

    if (OidcContextReader.isTlsClientAuth(context)) {
      applyTlsClientAuthClient(client, claims, context);
      return;
    }

    applyPrivateKeyJwtClient(client, claims, config);
  }

  private static void enforcePrivateKeyJwtMetadata(
      ClientRepresentation client,
      SfaSoftwareStatementClaims claims,
      boolean inlineJwksPresent,
      ClientRegistrationContext context)
      throws ClientRegistrationPolicyException {
    if (inlineJwksPresent) {
      throw new ClientRegistrationPolicyException(
          "jwks by value is not allowed; use jwks_uri matching software_jwks_uri");
    }

    String requestJwksUri = OidcContextReader.getJwksUri(context);
    if (requestJwksUri == null && client.getAttributes() != null) {
      requestJwksUri = client.getAttributes().get("jwks.url");
    }

    if (requestJwksUri != null && !requestJwksUri.equals(claims.getSoftwareJwksUri())) {
      throw new ClientRegistrationPolicyException(
          "jwks_uri must match software_jwks_uri from software_statement");
    }
  }

  private static void enforceTlsClientAuthMetadata(
      ClientRepresentation client,
      SfaSoftwareStatementClaims claims,
      ClientRegistrationContext context)
      throws ClientRegistrationPolicyException {
    String subjectDn = resolveTlsClientAuthSubjectDn(client, claims, context);
    if (isBlank(subjectDn)) {
      throw new ClientRegistrationPolicyException(
          "tls_client_auth_subject_dn is required for tls_client_auth registration");
    }

    String expectedSubjectDn = defaultTlsClientAuthSubjectDn(claims);
    if (!expectedSubjectDn.equals(subjectDn)) {
      throw new ClientRegistrationPolicyException(
          "tls_client_auth_subject_dn must match transport certificate subject: "
              + expectedSubjectDn);
    }

    String requestJwksUri = OidcContextReader.getJwksUri(context);
    if (requestJwksUri != null && !requestJwksUri.isBlank()) {
      throw new ClientRegistrationPolicyException(
          "jwks_uri is not allowed when token_endpoint_auth_method is tls_client_auth");
    }
  }

  private static void applyCommonClaims(
      ClientRepresentation client, SfaSoftwareStatementClaims claims) {
    if (client.getClientId() == null || client.getClientId().isBlank()) {
      client.setClientId(claims.getSoftwareId());
    }

    if (claims.getSoftwareClientName() != null && !claims.getSoftwareClientName().isBlank()) {
      client.setName(claims.getSoftwareClientName());
    }

    if (claims.getSoftwareClientUri() != null && !claims.getSoftwareClientUri().isBlank()) {
      client.setBaseUrl(claims.getSoftwareClientUri());
    }

    client.getAttributes().put("sfa.software_id", claims.getSoftwareId());
    client.getAttributes().put("sfa.organisation_id", claims.getOrganisationId());
    client.getAttributes().put("sfa.software_jwks_uri", claims.getSoftwareJwksUri());
    if (claims.getSoftwareVersion() != null) {
      client.getAttributes().put("sfa.software_version", claims.getSoftwareVersion());
    }

    if (client.getRedirectUris() == null || client.getRedirectUris().isEmpty()) {
      client.setRedirectUris(new ArrayList<>(claims.getRedirectUris()));
    }

    client.setPublicClient(false);
    client.setBearerOnly(false);
    client.setStandardFlowEnabled(true);
    client.setDirectAccessGrantsEnabled(false);
  }

  private static void applyPrivateKeyJwtClient(
      ClientRepresentation client,
      SfaSoftwareStatementClaims claims,
      ComponentModel config)
      throws ClientRegistrationPolicyException {
    applyClientJwksAttributes(client, claims, config);
    client.getAttributes().put("token.endpoint.auth.signing.alg", "PS256");
    client.getAttributes().put("request.object.signature.alg", "PS256");
    client.getAttributes().put("use.refresh.tokens", "true");
    client.getAttributes().put("dpop.bound.access.tokens", "true");
    client.setServiceAccountsEnabled(true);
    client.setClientAuthenticatorType(CLIENT_AUTHENTICATOR_JWT);
  }

  private static void applyTlsClientAuthClient(
      ClientRepresentation client,
      SfaSoftwareStatementClaims claims,
      ClientRegistrationContext context) {
    clearJwksAttributes(client);

    String subjectDn = resolveTlsClientAuthSubjectDn(client, claims, context);
    Boolean certificateBoundTokens =
        OidcContextReader.getTlsClientCertificateBoundAccessTokens(context);

    client.getAttributes().put("x509.subjectdn", subjectDn);
    client.getAttributes().put("x509.allow.regex.pattern.comparison", "false");
    client.getAttributes()
        .put(
            "tls.client.certificate.bound.access.tokens",
            Boolean.FALSE.equals(certificateBoundTokens) ? "false" : "true");
    client.getAttributes().put("pkce.code.challenge.method", "S256");
    client.getAttributes().put("dpop.bound.access.tokens", "true");
    client.getAttributes().put("use.refresh.tokens", "true");
    client.getAttributes().remove("token.endpoint.auth.signing.alg");
    client.getAttributes().remove("request.object.signature.alg");

    client.setServiceAccountsEnabled(OidcContextReader.requestsClientCredentials(context));
    client.setConsentRequired(true);
    client.setFullScopeAllowed(false);
    client.setClientAuthenticatorType(CLIENT_AUTHENTICATOR_X509);
  }

  static String defaultTlsClientAuthSubjectDn(SfaSoftwareStatementClaims claims) {
    return "CN=" + claims.getSoftwareId() + ",O=" + claims.getOrganisationId() + ",C=CL";
  }

  private static String resolveTlsClientAuthSubjectDn(
      ClientRepresentation client,
      SfaSoftwareStatementClaims claims,
      ClientRegistrationContext context) {
    String subjectDn = OidcContextReader.getTlsClientAuthSubjectDn(context);
    if (isBlank(subjectDn) && client.getAttributes() != null) {
      subjectDn = client.getAttributes().get("x509.subjectdn");
    }
    if (isBlank(subjectDn)) {
      subjectDn = defaultTlsClientAuthSubjectDn(claims);
    }
    return subjectDn;
  }

  private static void clearJwksAttributes(ClientRepresentation client) {
    if (client.getAttributes() == null) {
      return;
    }
    JWKS_ATTRIBUTE_KEYS.forEach(key -> client.getAttributes().remove(key));
  }

  private static void applyClientJwksAttributes(
      ClientRepresentation client,
      SfaSoftwareStatementClaims claims,
      ComponentModel config)
      throws ClientRegistrationPolicyException {
    String embeddedJwks = ClientJwksResolver.resolveEmbeddedJwks(config, claims);
    client.getAttributes().put("jwks.url", claims.getSoftwareJwksUri());

    if (embeddedJwks != null) {
      client.getAttributes().put("use.jwks.url", "false");
      client.getAttributes().put("use.jwks.string", "true");
      client.getAttributes().put("jwks.string", embeddedJwks);
      return;
    }

    client.getAttributes().put("use.jwks.url", "true");
    client.getAttributes().put("use.jwks.string", "false");
  }

  private static SfaSoftwareStatementClaims toClaims(JsonNode claims) {
    List<String> redirectUris = new ArrayList<>();
    JsonNode redirectNode = claims.get("redirect_uris");
    if (redirectNode != null && redirectNode.isArray()) {
      Iterator<JsonNode> it = redirectNode.elements();
      while (it.hasNext()) {
        redirectUris.add(it.next().asText());
      }
    }

    return new SfaSoftwareStatementClaims(
        textClaim(claims, "iss"),
        claims.get("iat").asLong(),
        textClaim(claims, "software_id"),
        organisationId(claims),
        textClaim(claims, "software_jwks_uri"),
        redirectUris,
        firstNonBlank(textClaim(claims, "software_client_name"), textClaim(claims, "client_name")),
        firstNonBlank(textClaim(claims, "software_client_uri"), textClaim(claims, "client_uri")),
        textClaim(claims, "software_version"));
  }

  private static String organisationId(JsonNode claims) {
    return firstNonBlank(textClaim(claims, "organisation_id"), textClaim(claims, "organization_id"));
  }

  private static long parseMaxAge(ComponentModel config) {
    String raw =
        config.getConfig().getFirst(SfaSoftwareStatementClientRegistrationPolicyFactory.CONFIG_MAX_STATEMENT_AGE_SECONDS);
    if (raw == null || raw.isBlank()) {
      return 300L;
    }
    return Long.parseLong(raw);
  }

  private static String textClaim(JsonNode claims, String name) {
    JsonNode node = claims.get(name);
    return node == null || node.isNull() ? null : node.asText();
  }

  private static boolean isBlank(String value) {
    return value == null || value.isBlank();
  }

  private static String firstNonBlank(String first, String second) {
    if (!isBlank(first)) {
      return first;
    }
    return second;
  }
}
