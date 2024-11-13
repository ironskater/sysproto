package sysproto.authserver.controller;

import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RestController;
import sysproto.authserver.model.LoginReq;
import sysproto.authserver.model.LoginRsp;
import sysproto.authserver.model.LogoutRsp;
import sysproto.authserver.utils.JwtUtil;

@RestController
@Slf4j
public class LoginController {

    private final AuthenticationManager authenticationManager;

    private final JwtUtil jwtUtil;

    public LoginController(AuthenticationManager authenticationManager, JwtUtil jwtUtil) {

        this.authenticationManager = authenticationManager;

        this.jwtUtil = jwtUtil;
    }

    @PostMapping("/login")
    public ResponseEntity<LoginRsp> login(@RequestBody LoginReq req) {

        Authentication authentication = authenticationManager.authenticate(
            new UsernamePasswordAuthenticationToken(req.getUsername(), req.getPassword())
        );

        UserDetails userDetails = (UserDetails) authentication.getPrincipal();

        String jwt = jwtUtil.generateToken(userDetails);

        return ResponseEntity.ok(new LoginRsp("登入成功", jwt));
    }

    @PostMapping("/logout")
    public ResponseEntity<LogoutRsp> logout(@RequestHeader("Authorization") String token) {
        // 如果您需要在登出時執行一些清理工作，可以在這裡處理
        // 例如：將 token 加入黑名單等

        log.info("logout, token: {}", token);

        return ResponseEntity.ok(new LogoutRsp("登出成功"));
    }
}
