package sysproto.authserver.controller;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import sysproto.authserver.model.LoginReq;
import sysproto.authserver.model.LoginRsp;
import sysproto.authserver.model.LogoutRsp;
import sysproto.authserver.utils.JwtUtil;

@RestController
@Slf4j
@RequestMapping("/public")
public class LoginController {

    private final AuthenticationManager authenticationManager;

    private final JwtUtil jwtUtil;

    public LoginController(AuthenticationManager authenticationManager, JwtUtil jwtUtil) {

        this.authenticationManager = authenticationManager;

        this.jwtUtil = jwtUtil;
    }

    @PostMapping("/loginJwt")
    public ResponseEntity<LoginRsp> loginJwt(@RequestBody LoginReq req) {

        Authentication authentication = authenticationManager.authenticate(
            new UsernamePasswordAuthenticationToken(req.getUsername(), req.getPassword())
        );

        UserDetails userDetails = (UserDetails) authentication.getPrincipal();

        String token = jwtUtil.generateNormalUserToken(
            userDetails.getUsername(),
            userDetails.getAuthorities()
        );

        return ResponseEntity.ok(new LoginRsp("登入成功", token, null));
    }

    @PostMapping("/loginAsOrderUser")
    public ResponseEntity<LoginRsp> loginAsOrderUser(@RequestBody LoginReq req) {

        Authentication authentication = authenticationManager.authenticate(
            new UsernamePasswordAuthenticationToken(req.getUsername(), req.getPassword())
        );

        UserDetails userDetails = (UserDetails) authentication.getPrincipal();

        String token = jwtUtil.generateOrderUserToken(
            userDetails.getUsername(),
            userDetails.getAuthorities()
        );

        return ResponseEntity.ok(new LoginRsp("登入成功", token, null));
    }

    @PostMapping("/loginSession")
    public ResponseEntity<LoginRsp> loginSession(@RequestBody LoginReq req, HttpServletRequest request) {

        Authentication authentication = authenticationManager.authenticate(
            new UsernamePasswordAuthenticationToken(req.getUsername(), req.getPassword())
        );

        UserDetails userDetails = (UserDetails) authentication.getPrincipal();

        HttpSession session = request.getSession();

        session.setAttribute("userDetails", userDetails);

        return ResponseEntity.ok(new LoginRsp("登入成功", null, session.getId()));
    }

    @PostMapping("/logout")
    public ResponseEntity<LogoutRsp> logout(@RequestHeader("Authorization") String token) {
        // 如果您需要在登出時執行一些清理工作，可以在這裡處理
        // 例如：將 token 加入黑名單等

        log.info("logout, token: {}", token);

        return ResponseEntity.ok(new LogoutRsp("登出成功"));
    }
}
