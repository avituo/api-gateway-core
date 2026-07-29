package com.avituo.gateway.filter;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.Test;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.http.HttpHeaders;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;

class GatewayIdentityForwardingFilterTest {

    private final GlobalFilter filter = new GatewayIdentityForwardingFilter("test-gateway-internal-key")
            .forwardGatewayIdentity();

    @Test
    void removesSpoofedIdentityHeadersFromUnauthenticatedRequests() {
        ServerWebExchange forwarded = filter(MockServerHttpRequest.get("/public/ping")
                .header("X-User-Id", "attacker")
                .header("x-user-email", "attacker@example.test")
                .header("X-Internal-Signature", "forged"));

        GatewayIdentityForwardingFilter.FORWARDED_HEADERS.forEach(header ->
                assertFalse(forwarded.getRequest().getHeaders().containsKey(header)));
    }

    @Test
    void replacesSpoofedHeadersWithSingleValuesFromJwt() {
        AtomicReference<ServerWebExchange> forwarded = new AtomicReference<>();
        GatewayFilterChain chain = exchange -> {
            forwarded.set(exchange);
            return Mono.empty();
        };
        Jwt jwt = new Jwt(
                "token",
                Instant.now(),
                Instant.now().plusSeconds(300),
                Map.of("alg", "HS256"),
                Map.of(
                        "sub", "42",
                        "email", "user@example.test",
                        "name", "Test User",
                        "roles", List.of("admin", "user")
                )
        );
        TestingAuthenticationToken authentication = new TestingAuthenticationToken(jwt, null);
        authentication.setAuthenticated(true);
        var exchange = MockServerWebExchange.from(MockServerHttpRequest.get("/api/v1/orders")
                .header("X-User-Id", "attacker", "another-attacker")
                .header("X-User-Roles", "superadmin"));

        filter.filter(exchange, chain)
                .contextWrite(ReactiveSecurityContextHolder.withAuthentication(authentication))
                .block();

        HttpHeaders headers = forwarded.get().getRequest().getHeaders();
        assertEquals(List.of("42"), headers.get("X-User-Id"));
        assertEquals(List.of("user@example.test"), headers.get("X-User-Email"));
        assertEquals(List.of("Test User"), headers.get("X-User-Name"));
        assertEquals(List.of("admin,user"), headers.get("X-User-Roles"));
        assertEquals(List.of("test-gateway-internal-key"), headers.get("X-Gateway-Key"));
    }

    private ServerWebExchange filter(MockServerHttpRequest.BaseBuilder<?> request) {
        AtomicReference<ServerWebExchange> forwarded = new AtomicReference<>();
        GatewayFilterChain chain = exchange -> {
            forwarded.set(exchange);
            return Mono.empty();
        };

        filter.filter(MockServerWebExchange.from(request), chain).block();
        return forwarded.get();
    }
}
