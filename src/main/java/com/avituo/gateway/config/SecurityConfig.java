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
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtValidators;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
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
                        .pathMatchers("/api/v1/products/**").authenticated()
                        .pathMatchers("/api/v1/orders/**").authenticated()
                        .anyExchange().denyAll()
                )
                .oauth2ResourceServer(oauth2 -> oauth2
                        .jwt(jwt -> jwt.jwtDecoder(jwtDecoder(jwtProperties)))
                )
                .build();
    }

    @Bean
    ReactiveJwtDecoder jwtDecoder(JwtProperties jwtProperties) {
        if (!StringUtils.hasText(jwtProperties.getSecret()) || jwtProperties.getSecret().length() < 32) {
            throw new IllegalStateException("Configure app.jwt.secret with at least 32 bytes");
        }
        if (!StringUtils.hasText(jwtProperties.getIssuer()) || !StringUtils.hasText(jwtProperties.getAudience())) {
            throw new IllegalStateException("Configure app.jwt.issuer and app.jwt.audience");
        }

        SecretKeySpec secretKey = new SecretKeySpec(
                jwtProperties.getSecret().getBytes(StandardCharsets.UTF_8),
                "HmacSHA256"
        );

        NimbusReactiveJwtDecoder decoder = NimbusReactiveJwtDecoder.withSecretKey(secretKey)
                .macAlgorithm(MacAlgorithm.HS256)
                .build();

        OAuth2TokenValidator<Jwt> audienceValidator = jwt -> jwt.getAudience().contains(jwtProperties.getAudience())
                ? OAuth2TokenValidatorResult.success()
                : validationFailure("invalid_token", "The token audience is invalid");
        OAuth2TokenValidator<Jwt> requiredClaimsValidator = jwt ->
                StringUtils.hasText(jwt.getSubject())
                        && StringUtils.hasText(jwt.getId())
                        && StringUtils.hasText(jwt.getClaimAsString("email"))
                        && StringUtils.hasText(jwt.getClaimAsString("name"))
                        && jwt.hasClaim("roles")
                        ? OAuth2TokenValidatorResult.success()
                        : validationFailure("invalid_token", "The token is missing required identity claims");

        decoder.setJwtValidator(new DelegatingOAuth2TokenValidator<>(
                JwtValidators.createDefaultWithIssuer(jwtProperties.getIssuer()),
                audienceValidator,
                requiredClaimsValidator
        ));

        return decoder;
    }

    private static OAuth2TokenValidatorResult validationFailure(String code, String description) {
        return OAuth2TokenValidatorResult.failure(new OAuth2Error(code, description, null));
    }
}
