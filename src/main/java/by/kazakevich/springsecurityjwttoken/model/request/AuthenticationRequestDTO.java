package by.kazakevich.springsecurityjwttoken.model.request;

import lombok.Data;

// используется для передачи объкта для Authentication
@Data
public class AuthenticationRequestDTO {
     private String email;
     private String password;
}
