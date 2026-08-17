package cl.bci.sfa.clientregistration;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.keycloak.common.crypto.CryptoIntegration;
import org.keycloak.component.ComponentModel;
import org.keycloak.crypto.def.DefaultCryptoProvider;
import org.keycloak.services.clientregistration.policy.ClientRegistrationPolicyException;

class SfaSoftwareStatementValidatorTest {

  private ComponentModel config;
  private String softwareStatement;

  @BeforeAll
  static void initCrypto() {
    CryptoIntegration.setProvider(new DefaultCryptoProvider());
  }

  @BeforeEach
  void setUp() throws Exception {
    DirectoryJwksResolver.clearCacheForTests();

    softwareStatement = TestSoftwareStatementFactory.createSampleStatement();
    Path jwksPath = Path.of("registro_participantes/directory-jwks.json").toAbsolutePath();

    config = new ComponentModel();
    config.getConfig().putSingle(
        SfaSoftwareStatementClientRegistrationPolicyFactory.CONFIG_DIRECTORY_JWKS_URI,
        jwksPath.toUri().toString());
    config.getConfig().putSingle(
        SfaSoftwareStatementClientRegistrationPolicyFactory.CONFIG_DIRECTORY_ISSUER,
        "https://directorio-qa.finanzasabiertas.cl");
    config.getConfig().putSingle(
        SfaSoftwareStatementClientRegistrationPolicyFactory.CONFIG_SIGNATURE_ALGORITHM, "PS256");
    config.getConfig().putSingle(
        SfaSoftwareStatementClientRegistrationPolicyFactory.CONFIG_MAX_STATEMENT_AGE_SECONDS, "300");
  }

  @Test
  void validatesSampleSoftwareStatementWithFallbackPublicKey() throws Exception {
    SfaSoftwareStatementClaims claims =
        SfaSoftwareStatementValidator.validateAndParse(null, config, softwareStatement);

    assertEquals("LIDER-BCI", claims.getSoftwareId());
    assertEquals("LIDER-BCI", claims.getOrganisationId());
    assertEquals(
        "https://fintech-lider-bci.localtest.me/.well-known/jwks.json", claims.getSoftwareJwksUri());
  }

  @Test
  void rejectsMissingSoftwareStatement() {
    assertThrows(
        ClientRegistrationPolicyException.class,
        () -> SfaSoftwareStatementValidator.validateAndParse(null, config, null));
  }
}
