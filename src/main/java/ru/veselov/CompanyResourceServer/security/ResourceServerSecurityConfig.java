package ru.veselov.CompanyResourceServer.security;

import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import liquibase.pro.packaged.D;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationProvider;
import org.springframework.security.oauth2.server.resource.web.BearerTokenAuthenticationEntryPoint;
import org.springframework.security.oauth2.server.resource.web.access.BearerTokenAccessDeniedHandler;
import org.springframework.security.provisioning.UserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;



@Configuration
@EnableWebSecurity
@Slf4j
public class ResourceServerSecurityConfig {
    private final JwtToUserConverter jwtToUserConverter;
    private final KeyUtils keyUtils;

    private final PasswordEncoder passwordEncoder;

    private final UserDetailsManager userDetailsManager;
    @Autowired
    public ResourceServerSecurityConfig(JwtToUserConverter jwtToUserConverter, KeyUtils keyUtils, PasswordEncoder passwordEncoder, UserDetailsManager userDetailsManager) {
        this.jwtToUserConverter = jwtToUserConverter;
        this.keyUtils = keyUtils;
        this.passwordEncoder = passwordEncoder;
        this.userDetailsManager = userDetailsManager;
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity httpSecurity) throws Exception {
        return httpSecurity.csrf().disable()
                .authorizeHttpRequests((authorize)->authorize
                        .antMatchers(HttpMethod.POST,"api/customer**")
                        .hasAuthority("SCOPE_SAVE_INFO")
                        .antMatchers("api/divs").hasAnyRole("MANAGER,ADMIN")
                        .antMatchers("/api/auth/**").permitAll()
                        .anyRequest().authenticated()
                )
                .cors().disable()
                .httpBasic().disable()
                .oauth2ResourceServer(oauth2->oauth2.jwt(
                        (jwt)-> jwt.jwtAuthenticationConverter(jwtToUserConverter)
                ))//будет кастомизироваться
                .sessionManagement((session)->session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .exceptionHandling(
                        (exceptions)-> exceptions
                                .authenticationEntryPoint( new BearerTokenAuthenticationEntryPoint())
                                .accessDeniedHandler(new BearerTokenAccessDeniedHandler())
                )
                .build();
    }

    @Bean
    @Primary//Primary annotation here because we will have another recorder for the refresh token
    JwtDecoder jwtAccessTokenDecoder(){
        return NimbusJwtDecoder.withPublicKey(keyUtils.getAccessTokenPublicKey()).build();
    }

    @Bean
    @Primary
    JwtEncoder jwtAccessTokenEncoder(){
        //create tokens
        JWK jwk = new RSAKey.Builder(keyUtils.getAccessTokenPublicKey())
                .privateKey(keyUtils.getAccessTokenPrivateKey())
                .build();
        JWKSource<SecurityContext> jwks = new ImmutableJWKSet<>(new JWKSet(jwk));
        return new NimbusJwtEncoder(jwks);
    }

    @Bean
    @Qualifier("jwtRefreshTokenDecoder")
    JwtDecoder jwtRefreshTokenDecoder(){
        return NimbusJwtDecoder.withPublicKey(keyUtils.getRefreshTokenPublicKey()).build();
    }

    @Bean
    @Qualifier("jwtRefreshTokenEncoder")
    JwtEncoder jwtRefreshTokenEncoder(){
        //create tokens
        JWK jwk = new RSAKey.Builder(keyUtils.getRefreshTokenPublicKey())
                .privateKey(keyUtils.getRefreshTokenPrivateKey())
                .build();
        JWKSource<SecurityContext> jwks = new ImmutableJWKSet<>(new JWKSet(jwk));
        return new NimbusJwtEncoder(jwks);
    }

    @Bean
    @Qualifier("jwtRefreshTokenAuthProvider")
    //Authentication provider for checking refresh tokens
    JwtAuthenticationProvider jwtRefreshTokenAuthProvider(){
        JwtAuthenticationProvider jwtAuthenticationProvider = new JwtAuthenticationProvider(jwtRefreshTokenDecoder());
        jwtAuthenticationProvider.setJwtAuthenticationConverter(jwtToUserConverter);
        return jwtAuthenticationProvider;
    }

    @Bean
    DaoAuthenticationProvider daoAuthenticationProvider(){
        DaoAuthenticationProvider daoAuthenticationProvider = new DaoAuthenticationProvider();
        daoAuthenticationProvider.setPasswordEncoder(passwordEncoder);
        daoAuthenticationProvider.setUserDetailsService(userDetailsManager);
        return daoAuthenticationProvider;
    }


}
