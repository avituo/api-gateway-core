package com.avituo.gateway.config;

import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;

import reactor.core.publisher.Mono;

@Component
@Order(Ordered.HIGHEST_PRECEDENCE)
public class AuthorizationDebugFilter implements WebFilter {

    @Override
    public Mono<Void> filter(
            ServerWebExchange exchange,
            WebFilterChain chain
    ) {
        String authorization = exchange
                .getRequest()
                .getHeaders()
                .getFirst("Authorization");

        System.out.println("Request path: "
                + exchange.getRequest().getURI().getPath());

        if (authorization == null) {
            System.out.println("Authorization header: AUSENTE");
        } else {
            System.out.println("Authorization header recebido: SIM");
            System.out.println("Authorization começa com Bearer: "
                    + authorization.startsWith("Bearer "));
            System.out.println("Authorization length: "
                    + authorization.length());

            String masked = authorization.length() > 25
                    ? authorization.substring(0, 20) + "..."
                    : authorization;

            System.out.println("Authorization parcial: " + masked);
        }

        return chain.filter(exchange);
    }
}