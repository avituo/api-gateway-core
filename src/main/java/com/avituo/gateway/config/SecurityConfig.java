package com.avituo.gateway.config;

import java.nio.charset.StandardCharsets;

import javax.crypto.spec.SecretKeySpec;

import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.oauth2.jose.jws.MacAlgorithm;
import org.springframework.security.oauth2.jwt.NimbusReactiveJwtDecoder;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoders;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.util.StringUtils;

@Configuration
@EnableConfigurationProperties(JwtProperties.class)
public class SecurityConfig {

    @Bean
    SecurityWebFilterChain springSecurityFilterChain(
            ServerHttpSecurity http,
            JwtProperties jwtProperties
    ) {
        String[] publicPaths = jwtProperties.getPublicPaths().toArray(new String[0]);

        return http
                .csrf(ServerHttpSecurity.CsrfSpec::disable)
                .authorizeExchange(exchange -> exchange
                        .pathMatchers(publicPaths).permitAll()
                        .pathMatchers("/api/products/**").authenticated()
                        .pathMatchers("/api/orders/**").authenticated()
                        .anyExchange().denyAll()
                )
                .oauth2ResourceServer(oauth2 -> oauth2
                        .jwt(jwt -> jwt.jwtDecoder(jwtDecoder(jwtProperties)))
                )
                .build();
    }

    @Bean
    ReactiveJwtDecoder jwtDecoder(JwtProperties jwtProperties) {
        System.out.println("JWT secret length: " + jwtProperties.getSecret().length());
        if (StringUtils.hasText(jwtProperties.getIssuerUri())) {
            return ReactiveJwtDecoders.fromIssuerLocation(jwtProperties.getIssuerUri());
        }

        if (!StringUtils.hasText(jwtProperties.getSecret())) {
            throw new IllegalStateException("Configure app.jwt.secret or app.jwt.issuer-uri");
        }

        SecretKeySpec secretKey = new SecretKeySpec(
                jwtProperties.getSecret().getBytes(StandardCharsets.UTF_8),
                "HmacSHA256"
        );

        return NimbusReactiveJwtDecoder.withSecretKey(secretKey)
                .macAlgorithm(MacAlgorithm.HS256)
                .build();
    }
}