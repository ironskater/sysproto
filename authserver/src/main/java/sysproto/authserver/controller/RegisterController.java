package sysproto.authserver.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;
import sysproto.authserver.model.RegisterReq;

@RestController
public class RegisterController {

    @PostMapping("/register")
    public ResponseEntity<String> register(@RequestBody RegisterReq req) {

        return ResponseEntity.ok("register");
    }
}
