package com.avituo.gateway.filter;

import java.util.List;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpHeaders;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;

@Configuration
public class GatewayIdentityForwardingFilter {

    static final List<String> FORWARDED_HEADERS = List.of(
            "X-User-Id",
            "X-User-Email",
            "X-User-Name",
            "X-User-Roles",
            "X-User-Permissions",
            "X-Internal-Signature",
            "X-Gateway-Key"
    );

    private final String gatewayKey;

    public GatewayIdentityForwardingFilter(@Value("${app.gateway.key}") String gatewayKey) {
        if (gatewayKey == null || gatewayKey.isBlank()) {
            throw new IllegalStateException("Configure app.gateway.key");
        }

        this.gatewayKey = gatewayKey;
    }

    @Bean
    public GlobalFilter forwardGatewayIdentity() {
        return (exchange, chain) -> {
            var sanitizedRequest = exchange.getRequest().mutate()
                    .headers(this::removeForwardedHeaders)
                    .build();
            var sanitizedExchange = exchange.mutate().request(sanitizedRequest).build();

            return ReactiveSecurityContextHolder.getContext()
                    .flatMap(context -> {
                        Object principal = context.getAuthentication().getPrincipal();

                        if (principal instanceof Jwt jwt) {
                            String userId = jwt.getSubject();
                            String email = jwt.getClaimAsString("email");
                            String name = jwt.getClaimAsString("name");
                            List<String> rolesList = jwt.getClaimAsStringList("roles");
                            String roles = rolesList == null ? "" : String.join(",", rolesList);

                            var mutatedRequest = sanitizedExchange.getRequest()
                                    .mutate()
                                    .headers(headers -> {
                                        headers.set("X-User-Id", userId);
                                        headers.set("X-User-Email", email);
                                        headers.set("X-User-Name", name);
                                        headers.set("X-User-Roles", roles);
                                        headers.set("X-Gateway-Key", gatewayKey);
                                    })
                                    .build();

                            return chain.filter(
                                    sanitizedExchange.mutate().request(mutatedRequest).build()
                            );
                        }

                        return chain.filter(sanitizedExchange);
                    })
                    .switchIfEmpty(chain.filter(sanitizedExchange));
        };
    }

    private void removeForwardedHeaders(HttpHeaders headers) {
        FORWARDED_HEADERS.forEach(headers::remove);
    }
}
