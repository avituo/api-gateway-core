package com.avituo.gateway.config;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Date;
import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class JwtDecoderTest {

    private static final String SECRET = "tests_secret_key_for_hs256_auth_12345";
    private final SecurityConfig securityConfig = new SecurityConfig();
    private JwtProperties properties;

    @BeforeEach
    void setUp() {
        properties = new JwtProperties();
        properties.setSecret(SECRET);
        properties.setIssuer("https://auth.example.test");
        properties.setAudience("tcc-api-gateway");
    }

    @Test
    void acceptsTokenWithCompleteContract() throws JOSEException {
        assertEquals("gateway-user", decoder()
                .decode(token("https://auth.example.test", "tcc-api-gateway", 300, true))
                .block()
                .getSubject());
    }

    @Test
    void rejectsWrongIssuerAudienceExpiredAndMissingIdentityClaims() throws JOSEException {
        assertRejected(token("https://wrong.example.test", "tcc-api-gateway", 300, true));
        assertRejected(token("https://auth.example.test", "another-audience", 300, true));
        assertRejected(token("https://auth.example.test", "tcc-api-gateway", -10, true));
        assertRejected(token("https://auth.example.test", "tcc-api-gateway", 300, false));
    }

    private ReactiveJwtDecoder decoder() {
        return securityConfig.jwtDecoder(properties);
    }

    private void assertRejected(String token) {
        assertThrows(JwtException.class, () -> decoder().decode(token).block());
    }

    private String token(String issuer, String audience, long expiresIn, boolean complete) throws JOSEException {
        Instant now = Instant.now();
        JWTClaimsSet.Builder claims = new JWTClaimsSet.Builder()
                .issuer(issuer)
                .audience(audience)
                .subject("gateway-user")
                .issueTime(Date.from(now))
                .notBeforeTime(Date.from(now))
                .expirationTime(Date.from(now.plusSeconds(expiresIn)));

        if (complete) {
            claims.jwtID("token-id")
                    .claim("email", "user@example.test")
                    .claim("name", "Test User")
                    .claim("roles", List.of("user"));
        }

        SignedJWT signedJWT = new SignedJWT(new JWSHeader(JWSAlgorithm.HS256), claims.build());
        signedJWT.sign(new MACSigner(SECRET.getBytes(StandardCharsets.UTF_8)));
        return signedJWT.serialize();
    }
}
