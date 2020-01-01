package com.maciej.oauth2.authorization.client;

import org.eclipse.microprofile.config.Config;

import javax.inject.Inject;
import javax.json.JsonObject;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.ws.rs.client.*;
import java.io.IOException;
import java.io.PrintWriter;

@WebServlet(urlPatterns = "/downstream")
public class DownstreamCallServlet extends AbstractServlet {

    @Inject
    private Config config;

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
        response.setContentType("text/html;charset=UTF-8");
        String action = request.getParameter("action");
        Client client = ClientBuilder.newClient();
        WebTarget webTarget = client.target(config.getValue("resourceServerUri", String.class));
        WebTarget resourceWebTarget;
        String resourceResponse = null;

        JsonObject tokenResponse = (JsonObject) request.getSession().getAttribute("tokenResponse");
        if (tokenResponse != null) {
            if ("read".equals(action)) {
                resourceWebTarget = webTarget.path("resource/read");
                Invocation.Builder invocationBuilder = resourceWebTarget.request();
                resourceResponse = invocationBuilder
                    .header("authorization", tokenResponse.getString("access_token"))
                    .get(String.class);
            } else if ("write".equals(action)) {
                resourceWebTarget = webTarget.path("resource/write");
                Invocation.Builder invocationBuilder = resourceWebTarget.request();
                resourceResponse = invocationBuilder
                    .header("authorization", tokenResponse.getString("access_token"))
                    .post(Entity.text("body string"), String.class);
            }
        }
        PrintWriter out = response.getWriter();
        out.println(resourceResponse);
        out.flush();
        out.close();
    }
}
