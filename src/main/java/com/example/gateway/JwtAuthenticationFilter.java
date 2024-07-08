package com.example.gateway;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import javax.crypto.SecretKey;

@Component
public class JwtAuthenticationFilter extends AbstractGatewayFilterFactory<JwtAuthenticationFilter.Config> { //AbstractGatewayFilterFactory: Spring Cloud Gateway에서 필터를 정의하기 위한 추상 클래스

    @Value("${jwt.secret}") // application.yml에 있는 JWT 시크릿 값 주입
    private String jwtSecret;

    public JwtAuthenticationFilter() {
        super(Config.class);
    }

    @Override
    public GatewayFilter apply(Config config) { // 필터 로직 : 클라이언트 요청 가로채 JWT 검증
        return (exchange, chain) -> {
            if (!isAuthMissing(exchange)) { // Authorization 유무 확인
                final String token = getAuthHeader(exchange); // Bearer 토큰 획득
                try {
                    SecretKey key = Keys.hmacShaKeyFor(jwtSecret.getBytes()); // HMAC SHA 알고리즘 적용 -> 키 생성
                    Claims claims = Jwts.parserBuilder() // JWT 파싱 객체
                            .setSigningKey(key) // 검증에 필요한 키 적용
                            .build()
                            .parseClaimsJws(token) // 토큰 파싱
                            .getBody(); // 바디 반환
                    exchange.getRequest()
                            .mutate()
                            .header("id", String.valueOf(claims.get("id"))) // JWT payload에 있는 id 값을 헤더에 추가
                            .header("name", String.valueOf(claims.get("name"))) // JWT payload에 있는 name 값을 헤더에 추가
                            .header("role", String.valueOf(claims.get("role"))) // JWT payload에 있는 role 값을 헤더에 추가
                            .build();
                } catch (Exception e) {
                    return onError(exchange, "Invalid JWT token", HttpStatus.UNAUTHORIZED);
                }
            } else {
                return onError(exchange, "Missing Authorization Header", HttpStatus.UNAUTHORIZED);
            }
            return chain.filter(exchange);
        };
    }

    private boolean isAuthMissing(ServerWebExchange exchange) {
        return !exchange.getRequest().getHeaders().containsKey("Authorization");
    }

    private String getAuthHeader(ServerWebExchange exchange) {
        return exchange.getRequest().getHeaders().getOrEmpty("Authorization").get(0).replace("Bearer ", "");
    }

    private Mono<Void> onError(ServerWebExchange exchange, String err, HttpStatus httpStatus) {
        exchange.getResponse().setStatusCode(httpStatus);
        return exchange.getResponse().setComplete();
    }

    public static class Config {
    }
}
