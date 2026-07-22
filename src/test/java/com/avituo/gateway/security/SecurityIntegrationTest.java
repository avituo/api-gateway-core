package com.avituo.gateway.security;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Date;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.reactive.AutoConfigureWebTestClient;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.reactive.server.WebTestClient;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.MOCK)
@AutoConfigureWebTestClient
@Import(SecurityIntegrationTest.TestController.class)
@TestPropertySource(properties = {
        "app.jwt.secret=tests_secret_key_for_hs256_auth_12345",
        "app.jwt.issuer=https://auth.example.test",
        "app.jwt.audience=tcc-api-gateway",
        "app.gateway.key=test-gateway-internal-key",
        "app.jwt.public-paths[0]=/public/**",
        "app.jwt.public-paths[1]=/actuator/health"
})
class SecurityIntegrationTest {

    @Autowired
    private WebTestClient webTestClient;

    @Test
    void shouldAllowPublicEndpointWithoutToken() {
        webTestClient.get()
                .uri("/public/ping")
                .exchange()
                .expectStatus().isOk()
                .expectHeader().contentTypeCompatibleWith(MediaType.TEXT_PLAIN)
                .expectBody(String.class).isEqualTo("public-ok");
    }

    @Test
    void shouldBlockPrivateEndpointWithoutToken() {
        webTestClient.get()
                .uri("/api/v1/orders/ping")
                .exchange()
                .expectStatus().isUnauthorized();
    }

    @Test
    void shouldDenyUnknownEndpointEvenWithValidJwt() throws JOSEException {
        webTestClient.get()
                .uri("/private/ping")
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + generateToken("gateway-user"))
                .exchange()
                .expectStatus().isForbidden();
    }

    private String generateToken(String subject) throws JOSEException {
        Instant now = Instant.now();
        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .issuer("https://auth.example.test")
                .audience("tcc-api-gateway")
                .subject(subject)
                .jwtID("test-jti")
                .issueTime(Date.from(now))
                .notBeforeTime(Date.from(now))
                .expirationTime(Date.from(now.plusSeconds(300)))
                .claim("email", "user@example.test")
                .claim("name", "Gateway User")
                .claim("roles", java.util.List.of("user"))
                .build();

        SignedJWT signedJWT = new SignedJWT(new JWSHeader(JWSAlgorithm.HS256), claims);
        signedJWT.sign(new MACSigner("tests_secret_key_for_hs256_auth_12345".getBytes(StandardCharsets.UTF_8)));
        return signedJWT.serialize();
    }

    @RestController
    static class TestController {

        @GetMapping("/public/ping")
        String publicPing() {
            return "public-ok";
        }

        @GetMapping("/private/ping")
        String privatePing() {
            return "private-ok";
        }
    }
}
