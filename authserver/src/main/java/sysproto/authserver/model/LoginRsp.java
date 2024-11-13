package sysproto.authserver.model;

import lombok.AllArgsConstructor;
import lombok.Getter;

@Getter
@AllArgsConstructor
public class LoginRsp {

    private final String message;

    private final String token;
}