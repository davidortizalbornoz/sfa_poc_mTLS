package cl.bci.sfa.clientregistration;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.time.Instant;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.keycloak.util.JsonSerialization;

final class TestSoftwareStatementFactory {

  private TestSoftwareStatementFactory() {}

  static String createSampleStatement() throws Exception {
    Map<String, Object> claims = new LinkedHashMap<>();
    claims.put("iss", "https://directorio-qa.finanzasabiertas.cl");
    claims.put("iat", Instant.now().getEpochSecond());
    claims.put("software_id", "LIDER-BCI");
    claims.put("organisation_id", "LIDER-BCI");
    claims.put("software_jwks_uri", "https://fintech-lider-bci.localtest.me/.well-known/jwks.json");
    claims.put("software_client_name", "SFA mTLS POC - DCR + SSA");
    claims.put("redirect_uris", List.of("http://localhost:3000/callback"));
    claims.put("software_version", "1.0.0");

    Map<String, Object> header = Map.of("alg", "PS256", "kid", "sfa-poc-directory-1", "typ", "JWT");

    String headerPart = base64Url(JsonSerialization.writeValueAsBytes(header));
    String payloadPart = base64Url(JsonSerialization.writeValueAsBytes(claims));
    String signingInput = headerPart + "." + payloadPart;

    PrivateKey privateKey = loadPrivateKey(Path.of("registro_participantes/directory-private.pem"));
    Signature signature = Signature.getInstance("RSASSA-PSS");
    signature.setParameter(new java.security.spec.PSSParameterSpec("SHA-256", "MGF1", java.security.spec.MGF1ParameterSpec.SHA256, 32, 1));
    signature.initSign(privateKey);
    signature.update(signingInput.getBytes(StandardCharsets.UTF_8));
    return signingInput + "." + base64Url(signature.sign());
  }

  private static PrivateKey loadPrivateKey(Path pemPath) throws Exception {
    String pem = Files.readString(pemPath);
    String normalized =
        pem.replace("-----BEGIN PRIVATE KEY-----", "")
            .replace("-----BEGIN RSA PRIVATE KEY-----", "")
            .replace("-----END PRIVATE KEY-----", "")
            .replace("-----END RSA PRIVATE KEY-----", "")
            .replaceAll("\\s", "");
    byte[] decoded = Base64.getDecoder().decode(normalized);
    PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(decoded);
    return KeyFactory.getInstance("RSA").generatePrivate(spec);
  }

  private static String base64Url(byte[] value) {
    return Base64.getUrlEncoder().withoutPadding().encodeToString(value);
  }
}
