package project.ai.myhealth.controller;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;
import project.ai.myhealth.dto.request.LoginRequest;
import project.ai.myhealth.dto.request.RefreshTokenRequest;
import project.ai.myhealth.dto.response.LoginResponse;
import project.ai.myhealth.dto.response.RefreshTokenResponse;
import project.ai.myhealth.dto.response.ValidateTokenResponse;
import project.ai.myhealth.service.jwt.JwtService;

@Slf4j
@Controller
@RequestMapping("/auth")
public class AuthController {

    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private JwtService jwtService;

    @PostMapping("/login")
    @ResponseBody
    public ResponseEntity<?> login(@RequestBody LoginRequest request) {
        try {
            Authentication authentication = authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(request.getUsername(), request.getPassword()));
            SecurityContextHolder.getContext().setAuthentication(authentication);
            String username = request.getUsername();
            String accessToken = jwtService.generateAccessToken(username);
            String refreshToken = jwtService.generateRefreshToken(username);
            return ResponseEntity.ok(new LoginResponse(accessToken, refreshToken, "Bearer", jwtService.getTokenTTL(accessToken)));
        } catch (Exception e) {
            return ResponseEntity.badRequest().body("Invalid username or password");
        }
    }

    @PostMapping("/logout")
    public ResponseEntity<?> logout(@RequestHeader("Authorization") String authHeader) {
        try {
            String token = authHeader.replace("Bearer ", "");
            jwtService.revokeToken(token);
            return ResponseEntity.ok("Logged out successfully");
        } catch (Exception e) {
            log.error("Logout failed: {}", e.getMessage());
            return ResponseEntity.badRequest().body("Logout failed");
        }
    }

    @PostMapping("/logout-all")
    public ResponseEntity<?> logoutAll(@RequestHeader("Authorization") String authHeader) {
        try {
            String token = authHeader.replace("Bearer ", "");
            String username = jwtService.extractUsername(token);
            jwtService.revokeAllTokensForUser(username);
            return ResponseEntity.ok("All sessions logged out successfully");
        } catch (Exception e) {
            log.error("Logout all failed: {}", e.getMessage());
            return ResponseEntity.badRequest().body("Logout all failed");
        }
    }

    @PostMapping("/refresh")
    public ResponseEntity<?> refreshToken(@RequestBody RefreshTokenRequest request) {
        try {
            String newAccessToken = jwtService.refreshAccessToken(request.getRefreshToken());
            return ResponseEntity.ok(new RefreshTokenResponse(newAccessToken, "Bearer", jwtService.getTokenTTL(newAccessToken)));
        } catch (Exception e) {
            log.error("Token refresh failed: {}", e.getMessage());
            return ResponseEntity.badRequest().body("Token refresh failed");
        }
    }

    @GetMapping("/validate")
    public ResponseEntity<?> validateToken(@RequestHeader("Authorization") String authHeader) {
        try {
            String token = authHeader.replace("Bearer ", "");
            boolean isValid = jwtService.isTokenValid(token);
            ValidateTokenResponse validateTokenResponse = new ValidateTokenResponse();
            validateTokenResponse.setIsValid(isValid);
            if (isValid) {
                validateTokenResponse.setUsername(jwtService.extractUsername(token));
                validateTokenResponse.setExpiresIn(jwtService.getTokenTTL(token));
            }
            return ResponseEntity.ok(validateTokenResponse);
        } catch (Exception e) {
            log.error("Token validation failed: {}", e.getMessage());
            return ResponseEntity.badRequest().body("Token validation failed");
        }
    }
}