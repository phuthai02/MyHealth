package project.ai.myhealth.filter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import project.ai.myhealth.service.jwt.JwtService;
import project.ai.myhealth.service.user.UserServiceImpl;

import java.io.IOException;

@Slf4j
@Component
public class JwtAuthenticationFilter extends OncePerRequestFilter {
    @Autowired
    private JwtService jwtService;

    @Autowired
    private UserServiceImpl userService;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        try {
            String token = getTokenFromRequest(request);

            if (token != null) {
                log.debug("Token found in request: {}", token.substring(0, Math.min(token.length(), 20)) + "...");

                // Kiểm tra token có hợp lệ không (bao gồm expiration, blacklist, Redis check)
                if (jwtService.isTokenValid(token)) {
                    String username = jwtService.extractUsername(token);

                    if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {
                        log.debug("Authenticating user: {}", username);

                        try {
                            UserDetails userDetails = userService.loadUserByUsername(username);

                            // Kiểm tra username trong token có khớp với UserDetails không
                            if (username.equals(userDetails.getUsername())) {
                                UsernamePasswordAuthenticationToken authToken =
                                        new UsernamePasswordAuthenticationToken(
                                                userDetails,
                                                null,
                                                userDetails.getAuthorities()
                                        );

                                // Set authentication details
                                authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                                SecurityContextHolder.getContext().setAuthentication(authToken);

                                log.debug("User {} authenticated successfully", username);
                            } else {
                                log.warn("Username mismatch: token={}, userDetails={}", username, userDetails.getUsername());
                            }

                        } catch (Exception e) {
                            log.error("Failed to load user details for username: {}, error: {}", username, e.getMessage());
                            handleAuthenticationError(response, "User not found");
                            return;
                        }
                    }
                } else {
                    log.warn("Invalid token received");
                    handleAuthenticationError(response, "Invalid or expired token");
                    return;
                }
            } else {
                log.debug("No token found in request");
            }

        } catch (Exception e) {
            log.error("JWT Authentication error: {}", e.getMessage(), e);
            handleAuthenticationError(response, "Authentication failed");
            return;
        }

        filterChain.doFilter(request, response);
    }

    private String getTokenFromRequest(HttpServletRequest request) {
        String bearerToken = request.getHeader("Authorization");
        if (bearerToken != null && bearerToken.startsWith("Bearer ")) {
            return bearerToken.substring(7);
        }
        return null;
    }

    private void handleAuthenticationError(HttpServletResponse response, String message) throws IOException {
        log.debug("Authentication error: {}", message);
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        response.setContentType("application/json");
        response.setCharacterEncoding("UTF-8");
        response.getWriter().write(String.format("{\"error\": \"%s\", \"status\": 401}", message));
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) throws ServletException {
        String path = request.getRequestURI();

        return path.startsWith("/api/auth/login") ||
                path.startsWith("/api/auth/refresh") ||
                path.startsWith("/api/public");
    }
}