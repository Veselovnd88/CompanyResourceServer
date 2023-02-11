package ru.veselov.CompanyResourceServer.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.stereotype.Component;
import ru.veselov.CompanyResourceServer.dto.TokenDTO;
import ru.veselov.CompanyResourceServer.model.ResourceUser;

import java.text.MessageFormat;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;

@Component
public class TokenGenerator {

    private final JwtEncoder accessTokenEncoder;
    @Qualifier("jwtRefreshTokenEncoder")
    private final JwtEncoder refreshTokenEncoder;
    @Autowired
    public TokenGenerator(JwtEncoder accessTokenEncoder, JwtEncoder refreshTokenEncoder) {
        this.accessTokenEncoder = accessTokenEncoder;
        this.refreshTokenEncoder = refreshTokenEncoder;
    }


    private String createAccessToken(Authentication authentication){
        ResourceUser user = (ResourceUser) authentication.getPrincipal();
        Instant now = Instant.now();

        JwtClaimsSet claimsSet = JwtClaimsSet.builder()
                .issuer("CompanyResourceServer")
                .issuedAt(now)
                .expiresAt(now.plus(30, ChronoUnit.MINUTES))
                .subject(user.getId())
                .build();

        return accessTokenEncoder.encode(JwtEncoderParameters.from(claimsSet)).getTokenValue();
    }

    private String createRefreshToken(Authentication authentication){
        ResourceUser user = (ResourceUser) authentication.getPrincipal();
        Instant now = Instant.now();

        JwtClaimsSet claimsSet = JwtClaimsSet.builder()
                .issuer("CompanyResourceServer")
                .issuedAt(now)
                .expiresAt(now.plus(30, ChronoUnit.DAYS))
                .subject(user.getId())
                .build();

        return refreshTokenEncoder.encode(JwtEncoderParameters.from(claimsSet)).getTokenValue();
    }



    public TokenDTO createToken(Authentication authentication){
        if(!(authentication.getPrincipal() instanceof ResourceUser user)){
            throw new BadCredentialsException(
                    MessageFormat.format("Principal {} is not ResourceUser type",
                            authentication.getPrincipal().getClass()));
        }
        TokenDTO tokenDTO = new TokenDTO();
        tokenDTO.setUserId(user.getId());
        tokenDTO.setAccessToken(createAccessToken(authentication));

        String refreshToken;
        /*if already has jwt - check credentials*/
        if(authentication.getCredentials() instanceof Jwt jwt){
            Instant now = Instant.now();
            Instant expiresAt = jwt.getExpiresAt();
            Duration duration = Duration.between(now,expiresAt);
            long daysUntilExpired = duration.toDays();
            if(daysUntilExpired<7){
                refreshToken = createRefreshToken(authentication);
            } else{
                refreshToken = jwt.getTokenValue();
            }
        }
        else {
            refreshToken = createRefreshToken(authentication);
        }
        tokenDTO.setRefreshToken(refreshToken);
        return tokenDTO;
        }
}
