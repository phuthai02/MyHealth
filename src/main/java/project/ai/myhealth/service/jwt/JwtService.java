package project.ai.myhealth.service.jwt;

import java.util.Date;

public interface JwtService {
    // ===> Tạo access token và lưu vào Redis
    String generateAccessToken(String username);

    // ===> Tạo refresh token và lưu vào Redis
    String generateRefreshToken(String username);

    // ===> Trích xuất username từ token
    String extractUsername(String token);

    // ===> Kiểm tra tính hợp lệ của token (kiểm tra cả JWT và Redis)
    Boolean isTokenValid(String token);

    // ===> Kiểm tra token có tồn tại trong Redis không
    Boolean isTokenInRedis(String token);

    // ===> Revoke một token cụ thể
    void revokeToken(String token);

    // ===> Revoke tất cả token của một user
    void revokeAllTokensForUser(String username);

    // ===> Làm mới access token bằng refresh token
    String refreshAccessToken(String refreshToken);

    // ===> Lấy ngày hết hạn của token
    Date getExpirationDate(String token);

    // ===> Lấy thời gian còn lại của token (milliseconds)
    Long getTokenTTL(String token);
}
