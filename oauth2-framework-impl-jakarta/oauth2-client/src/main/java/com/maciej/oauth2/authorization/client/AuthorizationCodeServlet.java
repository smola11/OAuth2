package com.maciej.oauth2.authorization.client;

import org.eclipse.microprofile.config.Config;

import javax.inject.Inject;
import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.UUID;

import static java.lang.Thread.currentThread;

@WebServlet(urlPatterns = "/authorize")
public class AuthorizationCodeServlet extends HttpServlet {

    @Inject
    private Config config;

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        request.getSession().removeAttribute("tokenResponse");

        String state = UUID.randomUUID().toString();
        request.getSession().setAttribute("CLIENT_LOCAL_STATE", state);

        String authorizationUri = config.getValue("provider.authorizationUri", String.class);
        String clientId = config.getValue("client.clientId", String.class);
        String redirectUri = config.getValue("client.redirectUri", String.class);
        String scope = config.getValue("client.scope", String.class);

        String authorizationLocation = authorizationUri + "?response_type=code"
            + "&client_id=" + clientId
            + "&redirect_uri=" + redirectUri
            + "&scope=" + scope
            + "&state=" + state;
        response.sendRedirect(authorizationLocation);
    }
}
