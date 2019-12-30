package com.maciej.oauth2.authorization.client;

import org.eclipse.microprofile.config.Config;

import javax.inject.Inject;
import javax.json.JsonObject;
import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.ws.rs.client.Client;
import javax.ws.rs.client.ClientBuilder;
import javax.ws.rs.client.Entity;
import javax.ws.rs.client.WebTarget;
import javax.ws.rs.core.Form;
import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.MediaType;
import java.io.IOException;

@WebServlet(urlPatterns = "/callback")
public class CallbackServlet extends AbstractServlet {

    @Inject
    private Config config;

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        if (isErrorPresent(request, response)) return;
        if (!isStateValid(request, response)) return;

        String code = request.getParameter("code");
        String clientId = config.getValue("client.clientId", String.class);
        String clientSecret = config.getValue("client.clientSecret", String.class);

        // There's no browser interaction for this call.
        Client client = ClientBuilder.newClient();
        WebTarget webTarget = client.target(config.getValue("provider.tokenUri", String.class));
        Form form = new Form();
        form.param("grant_type", "authorization_code");
        form.param("code", code);
        form.param("redirect_uri", config.getValue("client.redirectUri", String.class));

        JsonObject tokenResponse = webTarget.request(MediaType.APPLICATION_JSON_TYPE)
            .header(HttpHeaders.AUTHORIZATION, getAuthorizationHeaderValue(clientId, clientSecret))
            .post(Entity.entity(form, MediaType.APPLICATION_FORM_URLENCODED_TYPE), JsonObject.class);
        request.getSession().setAttribute("tokenResponse", tokenResponse);

        dispatch("/", request, response);
    }

    private boolean isErrorPresent(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String error = request.getParameter("error");
        if (error != null) {
            request.setAttribute("error", error);
            dispatch("/", request, response);
            return true;
        }
        return false;
    }

    private boolean isStateValid(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String localState = (String) request.getSession().getAttribute("CLIENT_LOCAL_STATE");
        if (!localState.equals(request.getParameter("state"))) {
            request.setAttribute("error", "The state attribute doesn't match !!");
            dispatch("/", request, response);
            return false;
        }
        return true;
    }
}
