package sysproto.authserver.model;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class RegisterReq {

    private String username;
    private String password;
}
