package sysproto.authserver.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import sysproto.authserver.annotation.PermissionInterceptor;
import sysproto.authserver.context.UserContext;

@RestController
@RequestMapping("/public")
public class OrderController {

    @PermissionInterceptor(value = {"order"})
    @GetMapping("/authorized-order")
    public String getAuthorizedOrder() {
        UserContext userContext = UserContext.getCurrentUser();
        return "get authorized order by " + userContext.getUsername();
    }

    @GetMapping("/normal-order")
    public String getNormalOrder() {
        return "get normal order";
    }
}
