package com.pluralsight.security.configuration;

import com.pluralsight.security.validators.CryptoJwtTokenValidator;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.jwt.*;

@Configuration
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.cors().and()
            .authorizeRequests()
            .anyRequest().authenticated()
            .and().oauth2ResourceServer().jwt()
            .decoder(jwtTokenDecoder());
    }

    private JwtDecoder jwtTokenDecoder() {
        NimbusJwtDecoderJwkSupport decoder = (NimbusJwtDecoderJwkSupport) JwtDecoders
            .fromOidcIssuerLocation("http://localhost:8080/auth/realms/CryptoInc");
        OAuth2TokenValidator<Jwt> defaultValidators = JwtValidators
            .createDefaultWithIssuer("http://localhost:8080/auth/realms/CryptoInc");
        OAuth2TokenValidator<Jwt> delegatingValidator = new DelegatingOAuth2TokenValidator<>(defaultValidators,
            new CryptoJwtTokenValidator());
        decoder.setJwtValidator(delegatingValidator);
        return decoder;
    }
}
