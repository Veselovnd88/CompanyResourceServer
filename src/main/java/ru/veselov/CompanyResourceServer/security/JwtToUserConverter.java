package ru.veselov.CompanyResourceServer.security;

import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Component;
import ru.veselov.CompanyResourceServer.model.ResourceUser;

import java.util.Collections;
@Component
public class JwtToUserConverter implements Converter<Jwt, UsernamePasswordAuthenticationToken> {
    //Конвертация JWT токена в данные о юзере

    @Override
    public UsernamePasswordAuthenticationToken convert(Jwt jwt) {
        ResourceUser resourceUser = new ResourceUser();
        resourceUser.setId(jwt.getSubject());
        return new UsernamePasswordAuthenticationToken(resourceUser, jwt, Collections.emptyList());
    }
}
