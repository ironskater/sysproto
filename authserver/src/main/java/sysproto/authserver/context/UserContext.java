package sysproto.authserver.context;

import io.jsonwebtoken.Claims;
import java.util.List;
import lombok.Data;

@Data
public class UserContext {
    private String username;
    private List<String> permissions;

    private static final ThreadLocal<UserContext> userHolder = new ThreadLocal<>();

    public static void setCurrentUser(UserContext user) {
        userHolder.set(user);
    }

    public static UserContext getCurrentUser() {
        return userHolder.get();
    }

    public static void clear() {
        userHolder.remove();
    }

    public static UserContext fromClaims(Claims claims) {
        UserContext context = new UserContext();
        context.setUsername(claims.getSubject());
        @SuppressWarnings("unchecked")
        List<String> permissions = claims.get("permissions", List.class);
        context.setPermissions(permissions);
        return context;
    }
}