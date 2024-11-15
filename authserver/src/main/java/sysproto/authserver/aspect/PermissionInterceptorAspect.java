package sysproto.authserver.aspect;

import io.jsonwebtoken.Claims;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import java.util.Arrays;
import java.util.List;
import org.aspectj.lang.ProceedingJoinPoint;
import org.aspectj.lang.annotation.Around;
import org.aspectj.lang.annotation.Aspect;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;
import org.springframework.web.server.ResponseStatusException;
import sysproto.authserver.annotation.PermissionInterceptor;
import sysproto.authserver.context.UserContext;
import sysproto.authserver.utils.JwtUtil;

@Aspect
@Component
public class PermissionInterceptorAspect {

    @Autowired
    private JwtUtil jwtUtil;

    @Value("${jwt.cookie.name:SESSIONID}")  // 預設 cookie 名稱為 SESSIONID
    private String cookieName;

    @Around("@annotation(permissionInterceptor)")
    public Object checkPermission(
        ProceedingJoinPoint joinPoint, PermissionInterceptor permissionInterceptor) throws Throwable {

        try {

            HttpServletRequest request = ((ServletRequestAttributes) RequestContextHolder
                .currentRequestAttributes()).getRequest();

            // 從 Cookie 獲取 JWT
            String token = extractTokenFromCookie(request);
            if (token == null) {
                throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "No session found");
            }

            // 驗證 JWT 並取得權限
            Claims claims = validateToken(token);
            UserContext.setCurrentUser(UserContext.fromClaims(claims));

            // 檢查是否有所需權限
            String[] requiredPermissions = permissionInterceptor.value();
            if (!hasRequiredPermissions(UserContext.getCurrentUser().getPermissions(), requiredPermissions)) {
                throw new ResponseStatusException(HttpStatus.FORBIDDEN, "Insufficient permissions");
            }

            return joinPoint.proceed();
        } finally {
            UserContext.clear();
        }
    }

    private String extractTokenFromCookie(HttpServletRequest request) {
        Cookie[] cookies = request.getCookies();
        if (cookies == null) {
            return null;
        }

        return Arrays.stream(cookies)
                .filter(cookie -> cookieName.equals(cookie.getName()))
                .map(Cookie::getValue)
                .findFirst()
                .orElse(null);
    }

    private Claims validateToken(String token) {
        if (!jwtUtil.validateToken(token)) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Invalid JWT token");
        }
        return jwtUtil.getClaimsFromToken(token);
    }

    private boolean hasRequiredPermissions(List<String> userPermissions, String[] requiredPermissions) {
        if (userPermissions == null || requiredPermissions.length == 0) {
            return false;
        }
        return Arrays.stream(requiredPermissions)
                .allMatch(userPermissions::contains);
    }
}