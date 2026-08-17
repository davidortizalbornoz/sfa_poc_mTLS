package cl.bci.sfa.clientregistration;

import org.keycloak.jose.jwk.JSONWebKeySet;
import org.keycloak.services.clientregistration.ClientRegistrationContext;
import org.keycloak.services.clientregistration.oidc.OIDCClientRegistrationContext;

/** Acceso reflexivo a metadatos OIDC DCR no expuestos en {@code ClientRegistrationContext}. */
final class OidcContextReader {

  static final String TOKEN_ENDPOINT_AUTH_TLS_CLIENT = "tls_client_auth";

  private OidcContextReader() {}

  static String getTokenEndpointAuthMethod(ClientRegistrationContext context) {
    return readString(context, "getTokenEndpointAuthMethod");
  }

  static String getTlsClientAuthSubjectDn(ClientRegistrationContext context) {
    return readString(context, "getTlsClientAuthSubjectDn");
  }

  static Boolean getTlsClientCertificateBoundAccessTokens(ClientRegistrationContext context) {
    Object value = read(context, "getTlsClientCertificateBoundAccessTokens");
    return value instanceof Boolean bool ? bool : null;
  }

  static java.util.List<String> getGrantTypes(ClientRegistrationContext context) {
    Object value = read(context, "getGrantTypes");
    if (value instanceof java.util.List<?> list) {
      return list.stream().filter(String.class::isInstance).map(String.class::cast).toList();
    }
    return java.util.List.of();
  }

  static boolean requestsClientCredentials(ClientRegistrationContext context) {
    return getGrantTypes(context).contains("client_credentials");
  }

  static boolean isTlsClientAuth(ClientRegistrationContext context) {
    return TOKEN_ENDPOINT_AUTH_TLS_CLIENT.equalsIgnoreCase(getTokenEndpointAuthMethod(context));
  }

  static String getJwksUri(ClientRegistrationContext context) {
    return readString(context, "getJwksUri");
  }

  static JSONWebKeySet getJwks(ClientRegistrationContext context) {
    Object value = read(context, "getJwks");
    if (value instanceof JSONWebKeySet jwks) {
      return jwks;
    }
    return null;
  }

  private static String readString(ClientRegistrationContext context, String methodName) {
    Object value = read(context, methodName);
    return value instanceof String str ? str : null;
  }

  private static Object read(ClientRegistrationContext context, String methodName) {
    if (!(context instanceof OIDCClientRegistrationContext oidcContext)) {
      return null;
    }

    try {
      var field = OIDCClientRegistrationContext.class.getDeclaredField("oidcRep");
      field.setAccessible(true);
      Object oidcRep = field.get(oidcContext);
      if (oidcRep == null) {
        return null;
      }
      var method = oidcRep.getClass().getMethod(methodName);
      return method.invoke(oidcRep);
    } catch (ReflectiveOperationException ex) {
      return null;
    }
  }
}
