package cl.bci.sfa.clientregistration;

import java.util.List;
import org.keycloak.component.ComponentModel;
import org.keycloak.component.ComponentValidationException;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.provider.ProviderConfigurationBuilder;
import org.keycloak.services.clientregistration.policy.AbstractClientRegistrationPolicyFactory;
import org.keycloak.services.clientregistration.policy.ClientRegistrationPolicy;

public class SfaSoftwareStatementClientRegistrationPolicyFactory
    extends AbstractClientRegistrationPolicyFactory {

  public static final String PROVIDER_ID = "sfa-software-statement";

  public static final String CONFIG_DIRECTORY_JWKS_URI = "directory-jwks-uri";
  public static final String CONFIG_DIRECTORY_ISSUER = "directory-issuer";
  public static final String CONFIG_MAX_STATEMENT_AGE_SECONDS = "max-statement-age-seconds";
  public static final String CONFIG_SIGNATURE_ALGORITHM = "signature-algorithm";
  public static final String CONFIG_DIRECTORY_PUBLIC_KEY_PEM = "directory-public-key-pem";
  public static final String CONFIG_POC_CLIENT_JWKS_BASE_DIR = "poc-client-jwks-base-dir";
  public static final String CONFIG_POC_CLIENT_JWKS_URI_MAPPINGS = "poc-client-jwks-uri-mappings";

  @Override
  public ClientRegistrationPolicy create(KeycloakSession session, ComponentModel model) {
    return new SfaSoftwareStatementClientRegistrationPolicy(session, model);
  }

  @Override
  public String getHelpText() {
    return "Validates CMF Directory Software Statement Assertion (SSA) on anonymous OIDC DCR requests";
  }

  @Override
  public List<ProviderConfigProperty> getConfigProperties() {
    return ProviderConfigurationBuilder.create()
        .property()
        .name(CONFIG_DIRECTORY_JWKS_URI)
        .label("Directory JWKS URI")
        .helpText("JWKS endpoint of the CMF participant directory used to verify SSA signatures")
        .type(ProviderConfigProperty.STRING_TYPE)
        .add()
        .property()
        .name(CONFIG_DIRECTORY_ISSUER)
        .label("Directory issuer (iss)")
        .helpText("Expected iss claim in software_statement JWT")
        .type(ProviderConfigProperty.STRING_TYPE)
        .add()
        .property()
        .name(CONFIG_MAX_STATEMENT_AGE_SECONDS)
        .label("Max SSA age (seconds)")
        .helpText("Maximum allowed age for software_statement iat (default 300)")
        .type(ProviderConfigProperty.STRING_TYPE)
        .defaultValue("300")
        .add()
        .property()
        .name(CONFIG_SIGNATURE_ALGORITHM)
        .label("Signature algorithm")
        .helpText("Expected JWS alg for software_statement (SFA requires PS256)")
        .type(ProviderConfigProperty.STRING_TYPE)
        .defaultValue("PS256")
        .add()
        .property()
        .name(CONFIG_DIRECTORY_PUBLIC_KEY_PEM)
        .label("Directory public key PEM (POC fallback)")
        .helpText(
            "Optional RSA public key PEM used when directory JWKS is unavailable (local POC only)")
        .type(ProviderConfigProperty.TEXT_TYPE)
        .add()
        .property()
        .name(CONFIG_POC_CLIENT_JWKS_BASE_DIR)
        .label("POC client JWKS base directory")
        .helpText(
            "Optional file: URI base path. Local JWKS per client at {base}/{software_id}/jwks.json "
                + "is embedded at registration (no HTTP fetch). Example: file:/opt/keycloak/data/client-jwks")
        .type(ProviderConfigProperty.STRING_TYPE)
        .add()
        .property()
        .name(CONFIG_POC_CLIENT_JWKS_URI_MAPPINGS)
        .label("POC client JWKS URI mappings")
        .helpText(
            "Optional overrides: software_jwks_uri=file:/path/to/jwks.json (one entry per client)")
        .type(ProviderConfigProperty.MULTIVALUED_STRING_TYPE)
        .add()
        .build();
  }

  @Override
  public void validateConfiguration(KeycloakSession session, RealmModel realm, ComponentModel config)
      throws ComponentValidationException {
    String jwksUri = config.getConfig().getFirst(CONFIG_DIRECTORY_JWKS_URI);
    String pem = config.getConfig().getFirst(CONFIG_DIRECTORY_PUBLIC_KEY_PEM);
    if ((jwksUri == null || jwksUri.isBlank()) && (pem == null || pem.isBlank())) {
      throw new ComponentValidationException(
          "Configure directory-jwks-uri and/or directory-public-key-pem");
    }
  }

  @Override
  public String getId() {
    return PROVIDER_ID;
  }
}
