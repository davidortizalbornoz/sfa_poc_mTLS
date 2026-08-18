package cl.bci.sfa.clientregistration;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.keycloak.component.ComponentModel;
import org.keycloak.representations.idm.ClientRepresentation;
import org.keycloak.representations.oidc.OIDCClientRepresentation;
import org.keycloak.services.clientregistration.policy.ClientRegistrationPolicyException;
import org.keycloak.services.clientregistration.oidc.OIDCClientRegistrationContext;

class TlsClientAuthRegistrationTest {

  private ComponentModel config;
  private SfaSoftwareStatementClaims claims;
  private OIDCClientRegistrationContext tlsContext;

  @BeforeEach
  void setUp() {
    config = new ComponentModel();
    claims =
        new SfaSoftwareStatementClaims(
            "https://directorio-qa.finanzasabiertas.cl",
            1L,
            "LIDER-BCI",
            "LIDER-BCI",
            "https://fintech-lider-bci.localtest.me/.well-known/jwks.json",
            List.of("http://localhost:3000/callback"),
            "LIDER BCI (mTLS / X509)",
            null,
            "1.2.9");

    OIDCClientRepresentation oidcRep = new OIDCClientRepresentation();
    oidcRep.setTokenEndpointAuthMethod("tls_client_auth");
    oidcRep.setTlsClientAuthSubjectDn("CN=LIDER-BCI,O=LIDER-BCI,C=CL");
    oidcRep.setTlsClientCertificateBoundAccessTokens(true);
    oidcRep.setGrantTypes(List.of("authorization_code", "refresh_token", "client_credentials"));
    tlsContext = new OIDCClientRegistrationContext(null, new ClientRepresentation(), null, oidcRep);
  }

  @Test
  void defaultTlsSubjectDnMatchesTransportCertificateConvention() {
    assertEquals(
        "C=CL,O=LIDER-BCI,CN=LIDER-BCI",
        SfaSoftwareStatementValidator.defaultTlsClientAuthSubjectDn(claims));
  }

  @Test
  void normalizesCnFirstSubjectDnToKeycloakRfc2253Form() {
    assertEquals(
        "C=CL,O=LIDER-BCI,CN=LIDER-BCI",
        SfaSoftwareStatementValidator.toKeycloakX509SubjectDn("CN=LIDER-BCI,O=LIDER-BCI,C=CL"));
  }

  @Test
  void applyClaimsToClientConfiguresX509LikePreconfiguredRealmClient() throws Exception {
    ClientRepresentation client = new ClientRepresentation();

    SfaSoftwareStatementValidator.applyClaimsToClient(client, claims, config, tlsContext);

    assertEquals("client-x509", client.getClientAuthenticatorType());
    assertEquals("C=CL,O=LIDER-BCI,CN=LIDER-BCI", client.getAttributes().get("x509.subjectdn"));
    assertEquals("false", client.getAttributes().get("x509.allow.regex.pattern.comparison"));
    assertEquals("true", client.getAttributes().get("tls.client.certificate.bound.access.tokens"));
    assertEquals("S256", client.getAttributes().get("pkce.code.challenge.method"));
    assertEquals("true", client.getAttributes().get("dpop.bound.access.tokens"));
    assertTrue(Boolean.TRUE.equals(client.isServiceAccountsEnabled()));
    assertFalse(Boolean.TRUE.equals(client.isFullScopeAllowed()));
    assertNull(client.getAttributes().get("jwks.url"));
    assertNull(client.getAttributes().get("jwks.string"));
    assertNull(client.getAttributes().get("token.endpoint.auth.signing.alg"));
  }

  @Test
  void alwaysEnablesServiceAccountsForTlsClientAuth() throws Exception {
    OIDCClientRepresentation oidcRep = new OIDCClientRepresentation();
    oidcRep.setTokenEndpointAuthMethod("tls_client_auth");
    oidcRep.setTlsClientAuthSubjectDn("CN=LIDER-BCI,O=LIDER-BCI,C=CL");
    oidcRep.setGrantTypes(List.of("authorization_code", "refresh_token"));
    OIDCClientRegistrationContext context =
        new OIDCClientRegistrationContext(null, new ClientRepresentation(), null, oidcRep);

    ClientRepresentation client = new ClientRepresentation();
    SfaSoftwareStatementValidator.applyClaimsToClient(client, claims, config, context);

    assertTrue(Boolean.TRUE.equals(client.isServiceAccountsEnabled()));
  }

  @Test
  void rejectsJwksUriWhenTlsClientAuthRequested() {
    OIDCClientRepresentation oidcRep = new OIDCClientRepresentation();
    oidcRep.setTokenEndpointAuthMethod("tls_client_auth");
    oidcRep.setTlsClientAuthSubjectDn("CN=LIDER-BCI,O=LIDER-BCI,C=CL");
    oidcRep.setJwksUri("https://fintech-lider-bci.localtest.me/.well-known/jwks.json");
    OIDCClientRegistrationContext context =
        new OIDCClientRegistrationContext(null, new ClientRepresentation(), null, oidcRep);

    ClientRegistrationPolicyException ex =
        assertThrows(
            ClientRegistrationPolicyException.class,
            () ->
                SfaSoftwareStatementValidator.enforceRequestMetadata(
                    new ClientRepresentation(), claims, false, context));

    assertTrue(ex.getMessage().contains("jwks_uri is not allowed"));
  }

  @Test
  void rejectsMismatchedTlsSubjectDn() {
    OIDCClientRepresentation oidcRep = new OIDCClientRepresentation();
    oidcRep.setTokenEndpointAuthMethod("tls_client_auth");
    oidcRep.setTlsClientAuthSubjectDn("CN=OTHER,O=OTHER,C=CL");
    OIDCClientRegistrationContext context =
        new OIDCClientRegistrationContext(null, new ClientRepresentation(), null, oidcRep);

    ClientRegistrationPolicyException ex =
        assertThrows(
            ClientRegistrationPolicyException.class,
            () ->
                SfaSoftwareStatementValidator.enforceRequestMetadata(
                    new ClientRepresentation(), claims, false, context));

    assertTrue(ex.getMessage().contains("tls_client_auth_subject_dn"));
  }
}
