package com.maciej.oauth2.authorization.server.api;


import com.maciej.oauth2.authorization.server.handler.AuthorizationGrantTypeHandler;
import com.maciej.oauth2.authorization.server.model.AppDataRepository;
import com.maciej.oauth2.authorization.server.model.Client;

import javax.annotation.security.RolesAllowed;
import javax.enterprise.context.RequestScoped;
import javax.enterprise.inject.Instance;
import javax.inject.Inject;
import javax.security.enterprise.SecurityContext;
import javax.security.enterprise.authentication.mechanism.http.FormAuthenticationMechanismDefinition;
import javax.security.enterprise.authentication.mechanism.http.LoginToContinue;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.*;
import java.io.IOException;
import java.security.Principal;

@FormAuthenticationMechanismDefinition(
    loginToContinue = @LoginToContinue(loginPage = "/login.jsp", errorPage = "/login.jsp")
)
@Path("authorize")
@RolesAllowed("USER")
@RequestScoped
public class AuthorizationEndpoint {

    @Inject
    private
    SecurityContext securityContext;

    @Inject
    AppDataRepository appDataRepository;

    @Inject
    Instance<AuthorizationGrantTypeHandler> authorizationGrantTypeHandlers;

    @GET
    @Produces(MediaType.TEXT_HTML)
    public Response doGet(@Context HttpServletRequest request,
                          @Context HttpServletResponse response,
                          @Context UriInfo uriInfo) throws ServletException, IOException {

        MultivaluedMap<String, String> pathParameters = uriInfo.getPathParameters();
        Principal principal = securityContext.getCallerPrincipal();

        //error about redirect_uri && client_id ==> forward user, thus to error.jsp.
        //otherwise ==> sendRedirect redirect_uri?error=error&error_description=error_description

        // 1. client_id
        String clientId = pathParameters.getFirst("clientId");
        if (clientId == null || clientId.isEmpty()) {
            return informUserAboutError(request, response, "Invalid client_id :" + clientId);
        }
        Client client = appDataRepository.getClient(clientId);
        if (client == null) {
            return informUserAboutError(request, response, "Invalid client_id :" + clientId);
        }

        // 2. Client Authorized Grant Type
        String clientError = "";
        if (client.getAuthorizedGrantTypes() != null && !client.getAuthorizedGrantTypes().contains("authorization_code")) {
            return informUserAboutError(request, response,
                "Authorization Grant type, authorization_code, is not allowed for this client :" + clientId);
        }

        // 3. redirectUri
        String redirectUri = pathParameters.getFirst("redirect_uri");
        if (client.getRedirectUri() != null && !client.getRedirectUri().isEmpty()) {
            if (redirectUri != null && !redirectUri.isEmpty() && !redirectUri.equals(client.getRedirectUri())) {
                return informUserAboutError(request, response, "redirect_uri is pre-registered and should match");
            }
            redirectUri = client.getRedirectUri();
            pathParameters.putSingle("resolved_redirect_uri", redirectUri);
        } else {
            if (redirectUri == null || redirectUri.isEmpty()) {
                return informUserAboutError(request, response, "redirect_uri is not pre-registred and should be provided");
            }
            pathParameters.putSingle("resolved_redirect_uri", redirectUri);
        }
        request.setAttribute("client", client);

        // 4. response_type
        String responseType = pathParameters.getFirst("response_type");
        if (!"code".equals(responseType) && !"token".equals(responseType)) {
            //error = "invalid_grant :" + responseType + ", response_type params should be code or token:";
            //return informUserAboutError(error);
        }

        //Save params in session
        request.getSession().setAttribute("ORIGINAL_PARAMS", pathParameters);


        return null;
    }

    private Response informUserAboutError(HttpServletRequest request, HttpServletResponse response, String error)
        throws ServletException, IOException {
        request.setAttribute("error", error);
        request.getRequestDispatcher("/error.jsp").forward(request, response);
        return null;
    }
}
