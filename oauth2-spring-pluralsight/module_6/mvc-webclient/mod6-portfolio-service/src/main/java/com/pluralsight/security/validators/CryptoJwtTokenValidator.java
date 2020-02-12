package com.pluralsight.security.validators;

import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jwt.Jwt;

// We need to plugin this validator into the Decoder
public class CryptoJwtTokenValidator implements OAuth2TokenValidator<Jwt> {

    @Override
    public OAuth2TokenValidatorResult validate(Jwt token) {
        if (!token.getAudience().contains("portfolio-service")) {
            OAuth2Error oAuth2Error = new OAuth2Error("invalid_token",
                "Expected token audience: portfolio-service", null);
            return OAuth2TokenValidatorResult.failure(oAuth2Error);
        }
        return OAuth2TokenValidatorResult.success();
    }
}
