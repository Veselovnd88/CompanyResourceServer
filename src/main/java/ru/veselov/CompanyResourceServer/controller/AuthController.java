package ru.veselov.CompanyResourceServer.controller;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.BearerTokenAuthenticationToken;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationProvider;
import org.springframework.security.provisioning.UserDetailsManager;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import ru.veselov.CompanyResourceServer.dto.LoginDTO;
import ru.veselov.CompanyResourceServer.dto.SignupDTO;
import ru.veselov.CompanyResourceServer.dto.TokenDTO;
import ru.veselov.CompanyResourceServer.model.ResourceUser;
import ru.veselov.CompanyResourceServer.security.TokenGenerator;

import java.util.Collections;

@RestController
@RequestMapping("/api/auth")
@Slf4j
public class AuthController {
    private final UserDetailsManager userDetailsManager;

    private final DaoAuthenticationProvider daoAuthenticationProvider;
    @Autowired
    @Qualifier("jwtRefreshTokenAuthProvider")
    JwtAuthenticationProvider refreshTokenAuthProvider;

    private final TokenGenerator tokenGenerator;
    @Autowired
    public AuthController(UserDetailsManager userDetailsManager, DaoAuthenticationProvider daoAuthenticationProvider, TokenGenerator tokenGenerator) {
        this.userDetailsManager = userDetailsManager;
        this.daoAuthenticationProvider = daoAuthenticationProvider;
        this.tokenGenerator = tokenGenerator;
    }

    @PostMapping("/register")
    public ResponseEntity register(@RequestBody SignupDTO signupDTO){
        ResourceUser resourceUser = ResourceUser.builder()
                .username(signupDTO.getUsername())
                .password(signupDTO.getPassword())
                .build();
        userDetailsManager.createUser(resourceUser);
        resourceUser.setId("100");
        Authentication authentication = UsernamePasswordAuthenticationToken
                .authenticated(resourceUser,signupDTO.getPassword(), Collections.emptyList());
        //in response entity we should pass token
        return ResponseEntity.ok(tokenGenerator.createToken(authentication));
    }

    @PostMapping("/login")
    public ResponseEntity login(@RequestBody LoginDTO loginDTO){
        /*if autancitation exists it will create us token*/
        Authentication authentication = daoAuthenticationProvider
                .authenticate(UsernamePasswordAuthenticationToken.unauthenticated(loginDTO.getUsername(),
                        loginDTO.getPassword()));
        return ResponseEntity.ok(tokenGenerator.createToken(authentication));
    }

    @PostMapping("/token")
    public ResponseEntity token(@RequestBody TokenDTO tokenDTO){
        //FIXME неправильно срабатывает authentication
        log.info(tokenDTO.getRefreshToken());
        Authentication authentication = refreshTokenAuthProvider.authenticate(
                new BearerTokenAuthenticationToken(tokenDTO.getRefreshToken())
        );
        return ResponseEntity.ok(tokenGenerator.createToken(authentication));
    }
}
