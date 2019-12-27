package com.maciej.oauth2.authorization.server.handler;

import com.maciej.oauth2.authorization.server.model.AuthorizationCode;

import javax.inject.Named;
import javax.json.Json;
import javax.json.JsonObject;
import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;
import javax.ws.rs.WebApplicationException;
import javax.ws.rs.core.MultivaluedMap;
import java.time.LocalDateTime;

@Named("authorization_code")
public class AuthorizationCodeGrantTypeHandler extends AbstractGrantTypeHandler {

    @PersistenceContext
    private EntityManager entityManager;

    @Override
    public JsonObject createAccessToken(String clientId, MultivaluedMap<String, String> params) throws Exception {

        AuthorizationCode authorizationCode = verifyCode(params.getFirst("code"));
        verifyRedirectUri(params.getFirst("redirect_uri"), authorizationCode);
        verifyClient(clientId, authorizationCode);

        // JWT Payload or claims
        String accessToken = getAccessToken(clientId, authorizationCode.getUserID(), authorizationCode.getApprovedScopes());
        String refreshToken = getRefreshToken(clientId, authorizationCode.getUserID(), authorizationCode.getApprovedScopes());

        return Json.createObjectBuilder()
            .add("token_type", "Bearer")
            .add("access_token", accessToken)
            .add("expires_in", expiresInMin * 60)
            .add("scope", authorizationCode.getApprovedScopes())
            .add("refresh_token", refreshToken)
            .build();
    }

    private AuthorizationCode verifyCode(String code) {
        // Code is required.
        if (code == null || code.isEmpty()) {
            throw new WebApplicationException("invalid_grant");
        }
        // Did code expire?
        AuthorizationCode authorizationCode = entityManager.find(AuthorizationCode.class, code);
        if (!authorizationCode.getExpirationDate().isAfter(LocalDateTime.now())) {
            throw new WebApplicationException("code Expired !");
        }
        return authorizationCode;
    }

    private void verifyRedirectUri(String redirectUri, AuthorizationCode authorizationCode) {
        // RedirectURI matching.
        if (authorizationCode.getRedirectUri() != null && !authorizationCode.getRedirectUri().equals(redirectUri)) {
            throw new WebApplicationException("invalid_grant");
        }
    }

    private void verifyClient(String clientId, AuthorizationCode authorizationCode) {
        // Client matching.
        if (!clientId.equals(authorizationCode.getClientID())) {
            throw new WebApplicationException("invalid_grant");
        }
    }
}
