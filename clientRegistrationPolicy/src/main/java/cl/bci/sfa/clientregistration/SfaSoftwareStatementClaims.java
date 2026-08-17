package cl.bci.sfa.clientregistration;

import java.util.Collections;
import java.util.List;

/**
 * Claims relevantes del Software Statement Assertion (SSA) firmado por el Directorio CMF.
 */
public final class SfaSoftwareStatementClaims {

  private final String issuer;
  private final long issuedAt;
  private final String softwareId;
  private final String organisationId;
  private final String softwareJwksUri;
  private final List<String> redirectUris;
  private final String softwareClientName;
  private final String softwareClientUri;
  private final String softwareVersion;

  public SfaSoftwareStatementClaims(
      String issuer,
      long issuedAt,
      String softwareId,
      String organisationId,
      String softwareJwksUri,
      List<String> redirectUris,
      String softwareClientName,
      String softwareClientUri,
      String softwareVersion) {
    this.issuer = issuer;
    this.issuedAt = issuedAt;
    this.softwareId = softwareId;
    this.organisationId = organisationId;
    this.softwareJwksUri = softwareJwksUri;
    this.redirectUris = redirectUris == null ? List.of() : List.copyOf(redirectUris);
    this.softwareClientName = softwareClientName;
    this.softwareClientUri = softwareClientUri;
    this.softwareVersion = softwareVersion;
  }

  public String getIssuer() {
    return issuer;
  }

  public long getIssuedAt() {
    return issuedAt;
  }

  public String getSoftwareId() {
    return softwareId;
  }

  public String getOrganisationId() {
    return organisationId;
  }

  public String getSoftwareJwksUri() {
    return softwareJwksUri;
  }

  public List<String> getRedirectUris() {
    return Collections.unmodifiableList(redirectUris);
  }

  public String getSoftwareClientName() {
    return softwareClientName;
  }

  public String getSoftwareClientUri() {
    return softwareClientUri;
  }

  public String getSoftwareVersion() {
    return softwareVersion;
  }
}
