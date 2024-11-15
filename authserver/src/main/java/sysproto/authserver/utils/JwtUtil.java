package sysproto.authserver.utils;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import jakarta.annotation.PostConstruct;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.spec.ECGenParameterSpec;
import java.util.Base64;
import java.util.Collection;
import java.util.Date;
import java.util.List;
import java.util.stream.Collectors;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Component;

/**
 * 服務重啟時會生成新的密鑰對，所以需要確保所有依賴服務都能及時獲取新的公鑰
 * 考慮提供一個 REST endpoint 來分發公鑰
 * 在生產環境中，建議實現密鑰輪換機制
 * 可以考慮將密鑰對保存到文件或數據庫中，這樣服務重啟時可以使用相同的密鑰對
 */
@Component
@Slf4j
public class JwtUtil {

    private KeyPair keyPair;

    @PostConstruct
    public void init() {
        try {
            // 使用 ECDSA P-256 曲線生成密鑰對
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC");
            ECGenParameterSpec ecSpec = new ECGenParameterSpec("secp256r1");  // P-256 曲線
            keyPairGenerator.initialize(ecSpec);
            keyPair = keyPairGenerator.generateKeyPair();

            log.info("Successfully generated ECDSA key pair");
        } catch (Exception e) {
            log.error("Failed to initialize key pair", e);
            throw new RuntimeException("Failed to initialize JWT keys", e);
        }
    }

    public String generateNormalUserToken(
        String username, Collection<? extends GrantedAuthority> authorities) {

        Date now = new Date();
        Date expiryDate = new Date(now.getTime() + 1000 * 60 * 60 * 24); // 24小時

        return Jwts.builder()
                .setSubject(username)
                .claim("authorities", authorities.stream()
                        .map(GrantedAuthority::getAuthority)
                        .collect(Collectors.toList()))
                .setIssuedAt(now)
                .setExpiration(expiryDate)
                .signWith(keyPair.getPrivate(), SignatureAlgorithm.ES256)
                .compact();
    }

    public String generateOrderUserToken(String username, Collection<? extends GrantedAuthority> authorities) {

        Date now = new Date();
        Date expiryDate = new Date(now.getTime() + 1000 * 60 * 60 * 24); // 24小時

        return Jwts.builder()
                .setSubject(username)
                .claim("permissions", List.of("order"))
                .setIssuedAt(now)
                .setExpiration(expiryDate)
                .signWith(keyPair.getPrivate(), SignatureAlgorithm.ES256)
                .compact();
    }

    public boolean validateToken(String token) {
        try {
            Jwts.parserBuilder()
                .setSigningKey(keyPair.getPublic())
                .build()
                .parseClaimsJws(token);
            return true;
        } catch (Exception e) {
            log.error("JWT validation failed: {}", e.getMessage());
            return false;
        }
    }

    public Claims getClaimsFromToken(String token) {

        return Jwts.parserBuilder()
                .setSigningKey(keyPair.getPublic())
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    public String getUsernameFromToken(String token) {
        Claims claims = Jwts.parserBuilder()
                .setSigningKey(keyPair.getPublic())
                .build()
                .parseClaimsJws(token)
                .getBody();
        return claims.getSubject();
    }

    public Collection<? extends GrantedAuthority> getAuthoritiesFromToken(String token) {
        Claims claims = Jwts.parserBuilder()
                .setSigningKey(keyPair.getPublic())
                .build()
                .parseClaimsJws(token)
                .getBody();

        List<String> authorities = claims.get("authorities", List.class);
        return authorities.stream()
                .map(SimpleGrantedAuthority::new)
                .collect(Collectors.toList());
    }

    // 可選：獲取公鑰的方法，用於分發給其他服務
    public String getPublicKeyEncoded() {
        return Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded());
    }
}