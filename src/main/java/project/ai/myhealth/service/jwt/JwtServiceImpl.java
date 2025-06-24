package project.ai.myhealth.service.jwt;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import project.ai.myhealth.service.redis.RedisService;

import java.security.Key;
import java.util.Date;
import java.util.concurrent.TimeUnit;

@Slf4j
@Service
public class JwtServiceImpl implements JwtService {
    @Value("${jwt.secret.key}")
    private String SECRET_KEY;

    @Value("${jwt.access.token.validity}")
    private Long ACCESS_TOKEN_VALIDITY;

    @Value("${jwt.refresh.token.validity}")
    private Long REFRESH_TOKEN_VALIDITY;

    @Autowired
    private RedisService redisService;

    private static final String ACCESS_TOKEN_PREFIX = "access_token:";
    private static final String REFRESH_TOKEN_PREFIX = "refresh_token:";
    private static final String USER_TOKENS_PREFIX = "user_tokens:";
    private static final String BLACKLIST_PREFIX = "blacklist:";

    @Override
    public String generateAccessToken(String username) {
        String token = createToken(username, ACCESS_TOKEN_VALIDITY);

        // Lưu access token vào Redis với TTL
        String tokenKey = ACCESS_TOKEN_PREFIX + token;
        redisService.setWithExpiration(tokenKey, username, ACCESS_TOKEN_VALIDITY, TimeUnit.MILLISECONDS);

        // Lưu mapping user -> access token để có thể revoke
        String userTokenKey = USER_TOKENS_PREFIX + username + ":access";
        redisService.setWithExpiration(userTokenKey, token, ACCESS_TOKEN_VALIDITY, TimeUnit.MILLISECONDS);

        log.info("Generated and stored access token for user: {}", username);
        return token;
    }

    @Override
    public String generateRefreshToken(String username) {
        String token = createToken(username, REFRESH_TOKEN_VALIDITY);

        // Lưu refresh token vào Redis với TTL
        String tokenKey = REFRESH_TOKEN_PREFIX + token;
        redisService.setWithExpiration(tokenKey, username, REFRESH_TOKEN_VALIDITY, TimeUnit.MILLISECONDS);

        // Lưu mapping user -> refresh token để có thể revoke
        String userTokenKey = USER_TOKENS_PREFIX + username + ":refresh";
        redisService.setWithExpiration(userTokenKey, token, REFRESH_TOKEN_VALIDITY, TimeUnit.MILLISECONDS);

        log.info("Generated and stored refresh token for user: {}", username);
        return token;
    }

    @Override
    public String extractUsername(String token) {
        try {
            return Jwts.parser()
                    .setSigningKey(getSignKey())
                    .build()
                    .parseClaimsJws(token)
                    .getBody()
                    .getSubject();
        } catch (ExpiredJwtException e) {
            log.warn("Token expired: {}", e.getMessage());
            return e.getClaims().getSubject();
        }
    }

    @Override
    public Boolean isTokenValid(String token) {
        try {
            // Kiểm tra token có trong blacklist không
            if (isTokenBlacklisted(token)) {
                log.warn("Token is blacklisted");
                return false;
            }

            // Kiểm tra token có tồn tại trong Redis không
            if (!isTokenInRedis(token)) {
                log.warn("Token not found in Redis");
                return false;
            }

            // Kiểm tra tính hợp lệ của JWT
            Claims claims = Jwts.parser()
                    .setSigningKey(getSignKey())
                    .build()
                    .parseClaimsJws(token)
                    .getBody();

            // Kiểm tra expiration
            return !claims.getExpiration().before(new Date());

        } catch (Exception e) {
            log.error("Token validation failed: {}", e.getMessage());
            return false;
        }
    }

    @Override
    public Boolean isTokenInRedis(String token) {
        // Kiểm tra trong cả access token và refresh token
        String accessTokenKey = ACCESS_TOKEN_PREFIX + token;
        String refreshTokenKey = REFRESH_TOKEN_PREFIX + token;

        return redisService.exists(accessTokenKey) || redisService.exists(refreshTokenKey);
    }

    @Override
    public void revokeToken(String token) {
        try {
            String username = extractUsername(token);

            // Thêm token vào blacklist
            String blacklistKey = BLACKLIST_PREFIX + token;
            Claims claims = Jwts.parser()
                    .setSigningKey(getSignKey())
                    .build()
                    .parseClaimsJws(token)
                    .getBody();

            long remainingTime = claims.getExpiration().getTime() - System.currentTimeMillis();
            if (remainingTime > 0) {
                redisService.setWithExpiration(blacklistKey, "revoked", remainingTime, TimeUnit.MILLISECONDS);
            }

            // Xóa token khỏi Redis
            redisService.del(ACCESS_TOKEN_PREFIX + token);
            redisService.del(REFRESH_TOKEN_PREFIX + token);

            log.info("Token revoked for user: {}", username);

        } catch (Exception e) {
            log.error("Failed to revoke token: {}", e.getMessage());
        }
    }

    @Override
    public void revokeAllTokensForUser(String username) {
        try {
            // Lấy và revoke access token
            String userAccessTokenKey = USER_TOKENS_PREFIX + username + ":access";
            String accessToken = redisService.get(userAccessTokenKey);
            if (accessToken != null) {
                revokeToken(accessToken);
            }

            // Lấy và revoke refresh token
            String userRefreshTokenKey = USER_TOKENS_PREFIX + username + ":refresh";
            String refreshToken = redisService.get(userRefreshTokenKey);
            if (refreshToken != null) {
                revokeToken(refreshToken);
            }

            // Xóa mapping keys
            redisService.del(userAccessTokenKey);
            redisService.del(userRefreshTokenKey);

            log.info("All tokens revoked for user: {}", username);

        } catch (Exception e) {
            log.error("Failed to revoke all tokens for user {}: {}", username, e.getMessage());
        }
    }

    @Override
    public String refreshAccessToken(String refreshToken) {
        try {
            if (!isTokenValid(refreshToken)) {
                throw new RuntimeException("Invalid refresh token");
            }

            String username = extractUsername(refreshToken);

            // Kiểm tra refresh token có đúng không
            String refreshTokenKey = REFRESH_TOKEN_PREFIX + refreshToken;
            String storedUsername = redisService.get(refreshTokenKey);

            if (!username.equals(storedUsername)) {
                throw new RuntimeException("Refresh token mismatch");
            }

            // Revoke old access token nếu có
            String userAccessTokenKey = USER_TOKENS_PREFIX + username + ":access";
            String oldAccessToken = redisService.get(userAccessTokenKey);
            if (oldAccessToken != null) {
                revokeToken(oldAccessToken);
            }

            // Tạo access token mới
            return generateAccessToken(username);

        } catch (Exception e) {
            log.error("Failed to refresh access token: {}", e.getMessage());
            throw new RuntimeException("Failed to refresh token", e);
        }
    }

    private boolean isTokenBlacklisted(String token) {
        String blacklistKey = BLACKLIST_PREFIX + token;
        return redisService.exists(blacklistKey);
    }

    private String createToken(String username, long expiration) {
        return Jwts.builder()
                .setSubject(username)
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + expiration))
                .signWith(SignatureAlgorithm.HS256, SECRET_KEY)
                .compact();
    }

    private Key getSignKey() {
        byte[] keyBytes = Decoders.BASE64.decode(SECRET_KEY);
        return Keys.hmacShaKeyFor(keyBytes);
    }

    @Override
    public Date getExpirationDate(String token) {
        try {
            Claims claims = Jwts.parser()
                    .setSigningKey(getSignKey())
                    .build()
                    .parseClaimsJws(token)
                    .getBody();
            return claims.getExpiration();
        } catch (Exception e) {
            log.error("Failed to get expiration date: {}", e.getMessage());
            return null;
        }
    }

    @Override
    public Long getTokenTTL(String token) {
        Date expiration = getExpirationDate(token);
        if (expiration != null) {
            return Math.max(0, expiration.getTime() - System.currentTimeMillis());
        }
        return 0L;
    }
}