package sysproto.authserver.model;

import lombok.Getter;
import lombok.RequiredArgsConstructor;

@Getter
@RequiredArgsConstructor
public class LoginReq {

    private final String username;

    private final String password;
}
