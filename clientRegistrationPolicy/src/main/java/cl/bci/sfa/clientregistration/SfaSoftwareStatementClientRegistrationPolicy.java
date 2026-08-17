package cl.bci.sfa.clientregistration;

import org.keycloak.component.ComponentModel;
import org.keycloak.models.ClientModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.representations.idm.ClientRepresentation;
import org.keycloak.services.clientregistration.ClientRegistrationContext;
import org.keycloak.services.clientregistration.ClientRegistrationProvider;
import org.keycloak.services.clientregistration.policy.ClientRegistrationPolicy;
import org.keycloak.services.clientregistration.policy.ClientRegistrationPolicyException;

public class SfaSoftwareStatementClientRegistrationPolicy implements ClientRegistrationPolicy {

  private final KeycloakSession session;
  private final ComponentModel componentModel;

  public SfaSoftwareStatementClientRegistrationPolicy(
      KeycloakSession session, ComponentModel componentModel) {
    this.session = session;
    this.componentModel = componentModel;
  }

  @Override
  public void beforeRegister(ClientRegistrationContext context)
      throws ClientRegistrationPolicyException {
    process(context);
  }

  @Override
  public void afterRegister(ClientRegistrationContext context, ClientModel clientModel) {}

  @Override
  public void beforeUpdate(ClientRegistrationContext context, ClientModel clientModel)
      throws ClientRegistrationPolicyException {
    process(context);
  }

  @Override
  public void afterUpdate(ClientRegistrationContext context, ClientModel clientModel) {}

  @Override
  public void beforeView(ClientRegistrationProvider provider, ClientModel clientModel) {}

  @Override
  public void beforeDelete(ClientRegistrationProvider provider, ClientModel clientModel) {}

  private void process(ClientRegistrationContext context) throws ClientRegistrationPolicyException {
    String softwareStatement = SoftwareStatementExtractor.extract(context);
    SfaSoftwareStatementClaims claims =
        SfaSoftwareStatementValidator.validateAndParse(session, componentModel, softwareStatement);

    ClientRepresentation client = context.getClient();
    boolean inlineJwks = SoftwareStatementExtractor.hasInlineJwks(context);
    SfaSoftwareStatementValidator.enforceRequestMetadata(client, claims, inlineJwks, context);
    SfaSoftwareStatementValidator.applyClaimsToClient(client, claims, componentModel, context);
  }
}
