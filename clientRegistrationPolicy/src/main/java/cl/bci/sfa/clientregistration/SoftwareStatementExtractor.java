package cl.bci.sfa.clientregistration;

import java.util.HashMap;
import org.keycloak.http.HttpRequest;
import org.keycloak.models.KeycloakSession;
import org.keycloak.representations.idm.ClientRepresentation;
import org.keycloak.services.clientregistration.ClientRegistrationContext;

/**
 * Extrae {@code software_statement} del request OIDC DCR.
 *
 * <p>Keycloak 26 no modela {@code software_statement} en {@code OIDCClientRepresentation} y lo
 * descarta al deserializar el body. Para el POC se aceptan estas fuentes, en orden:
 *
 * <ol>
 *   <li>Header {@code X-Software-Statement} (recomendado en Keycloak 26 hasta soporte nativo)
 *   <li>Atributo de cliente {@code software_statement}
 * </ol>
 */
public final class SoftwareStatementExtractor {

  public static final String ATTRIBUTE_SOFTWARE_STATEMENT = "software_statement";
  public static final String HEADER_SOFTWARE_STATEMENT = "X-Software-Statement";

  private SoftwareStatementExtractor() {}

  public static String extract(ClientRegistrationContext context) {
    KeycloakSession session = context.getSession();

    String fromHeader = readHeader(session);
    if (fromHeader != null && !fromHeader.isBlank()) {
      return fromHeader;
    }

    ClientRepresentation client = context.getClient();
    if (client != null && client.getAttributes() != null) {
      String fromAttributes = client.getAttributes().get(ATTRIBUTE_SOFTWARE_STATEMENT);
      if (fromAttributes != null && !fromAttributes.isBlank()) {
        return fromAttributes;
      }
    }

    return null;
  }

  private static String readHeader(KeycloakSession session) {
    HttpRequest request = session.getContext().getHttpRequest();
    if (request == null || request.getHttpHeaders() == null) {
      return null;
    }
    return request.getHttpHeaders().getHeaderString(HEADER_SOFTWARE_STATEMENT);
  }

  public static boolean hasInlineJwks(ClientRegistrationContext context) {
    return OidcContextReader.getJwks(context) != null;
  }

  public static void ensureClientAttributes(ClientRepresentation client) {
    if (client.getAttributes() == null) {
      client.setAttributes(new HashMap<>());
      return;
    }
    if (!(client.getAttributes() instanceof HashMap)) {
      client.setAttributes(new HashMap<>(client.getAttributes()));
    }
  }
}
