package com.avituo.gateway.filter;

import java.util.List;

import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;

import reactor.core.publisher.Mono;

@Configuration
public class UserHeaderFilter {

    @Bean
    public GlobalFilter addUserHeaders() {
        return (exchange, chain) ->
            ReactiveSecurityContextHolder.getContext()
                .flatMap(context -> {
                    Object principal = context.getAuthentication().getPrincipal();

                    if (principal instanceof Jwt jwt) {
                        String userId = jwt.getSubject();

                        List<String> rolesList = jwt.getClaimAsStringList("roles");
                        String roles = rolesList == null ? "" : String.join(",", rolesList);

                        var mutatedRequest = exchange.getRequest()
                                .mutate()
                                .header("X-User-Id", userId)
                                .header("X-User-Roles", roles)
                                .build();

                        return chain.filter(
                                exchange.mutate().request(mutatedRequest).build()
                        );
                    }

                    return chain.filter(exchange);
                })
                .switchIfEmpty(chain.filter(exchange));
    }
}