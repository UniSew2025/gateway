package com.unisew.gateway.configurations;


import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.security.Key;
import java.util.List;
import java.util.Objects;
import java.util.function.Predicate;

@Component
public class AuthenticationFilter implements GlobalFilter, Ordered {

    @Value("${jwt.secret_key}")
    private String SECRET_KEY;

    public static final List<String> openApiEndpoints = List.of(
            "/api/v1/auth",
            "/swagger-ui.html",
            "/v3/api-docs",
            "/webjars",
            "/account-service/v3/api-docs",
            "/design-service/v3/api-docs",
            "/feedback-service/v3/api-docs",
            "/order-service/v3/api-docs",
            "/profile-service/v3/api-docs"
    );
    
    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        ServerHttpRequest request = exchange.getRequest();

        if(isSecured.test(request)) {
            if(!request.getHeaders().containsKey("Authorization")){
                return onError(exchange);
            }

            String authHeader = Objects.requireNonNull(request.getHeaders().get("Authorization")).get(0);
            if (!authHeader.startsWith("Bearer ")) {
                return onError(exchange);
            }

            String token = authHeader.substring(7);

            try {
                validateToken(token);

                Claims claims = extractAllClaims(token);
                ServerHttpRequest modifiedRequest = exchange.getRequest().mutate()
                        .header("X-Role", claims.get("role", String.class))
                        .header("X-ID", claims.get("id", String.class))
                        .build();

                ServerWebExchange newExchange = exchange.mutate().request(modifiedRequest).build();

                return chain.filter(newExchange);
            } catch (Exception e) {
                return onError(exchange);
            }
        }
        return chain.filter(exchange);
    }

    public Predicate<ServerHttpRequest> isSecured = request -> openApiEndpoints.stream()
                    .noneMatch(uri -> request.getURI().getPath().contains(uri));


    private Mono<Void> onError(ServerWebExchange exchange) {
        ServerHttpResponse response = exchange.getResponse();
        response.setStatusCode(HttpStatus.FORBIDDEN);
        return response.setComplete();
    }

    private void validateToken(String token) {
        Jwts.parserBuilder().setSigningKey(getSignKey()).build().parseClaimsJws(token);
    }

    private Claims extractAllClaims(String token) {
        return Jwts.parserBuilder().setSigningKey(getSignKey()).build().parseClaimsJws(token).getBody();
    }

    private Key getSignKey() {
        return Keys.hmacShaKeyFor(Decoders.BASE64.decode(SECRET_KEY));
    }

    @Override
    public int getOrder() {
        return -1;
    }
}
