package com.pluralsight.security.configuration;

import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.DefaultOAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;

import javax.servlet.http.HttpServletRequest;
import java.util.HashMap;
import java.util.Map;

// This implementation is a wrapper around default implementation
public class CryptoOauth2AuthorizationRequestResolver implements OAuth2AuthorizationRequestResolver {

    private final OAuth2AuthorizationRequestResolver defaultResolver;

    public CryptoOauth2AuthorizationRequestResolver(ClientRegistrationRepository clientRegistrationRepository,
                                                    String authorizationRequestBaseUri) {
        this.defaultResolver =
            new DefaultOAuth2AuthorizationRequestResolver(clientRegistrationRepository, authorizationRequestBaseUri);
    }

    @Override
    public OAuth2AuthorizationRequest resolve(HttpServletRequest request) {
        OAuth2AuthorizationRequest authorizationRequest = this.defaultResolver.resolve(request);
        if (authorizationRequest == null) {
            return null;
        }
        Map<String, Object> additionalParameters = new HashMap<>();
        additionalParameters.putAll(authorizationRequest.getAdditionalParameters());
        additionalParameters.put("prompt", "consent"); // Adding additional parameters
        return OAuth2AuthorizationRequest.from(authorizationRequest).additionalParameters(additionalParameters).build();
    }

    @Override
    public OAuth2AuthorizationRequest resolve(HttpServletRequest request, String clientRegistrationId) {
        OAuth2AuthorizationRequest authRequest = this.defaultResolver.resolve(request, clientRegistrationId);
        if (authRequest == null) {
            return null;
        }
        Map<String, Object> additionalParameters = new HashMap<>();
        additionalParameters.putAll(authRequest.getAdditionalParameters());
        additionalParameters.put("prompt", "consent");
        return OAuth2AuthorizationRequest.from(authRequest).additionalParameters(additionalParameters).build();
    }
}
