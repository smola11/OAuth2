package com.maciej.oauth2.authorization.server.api;

import com.maciej.oauth2.authorization.server.PEMKeyUtils;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.JWK;
import org.eclipse.microprofile.config.Config;

import javax.enterprise.context.ApplicationScoped;
import javax.inject.Inject;
import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.QueryParam;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import java.io.IOException;
import java.net.URISyntaxException;
import java.util.Arrays;
import java.util.List;

// https://auth0.com/docs/jwks
@Path("jwk")
@ApplicationScoped
public class JWKEndpoint {

    private final List<String> allowedFormats = Arrays.asList("jwk", "pem");

    @Inject
    private Config config;

    @GET
    public Response getKey(@QueryParam("format") String format) throws IOException, URISyntaxException, JOSEException {
        if (format != null && !allowedFormats.contains(format)) {
            return Response.status(Response.Status.BAD_REQUEST)
                .entity("Public Key Format should be : jwk or pem").build();
        }
        String verificationKey = config.getValue("verificationkey", String.class);
        String pemEncodedRSAPublicKey = PEMKeyUtils.readKeyAsString(verificationKey);
        if (format == null || format.equals("jwk")) {
            // JSON Web Keys
            JWK jwk = JWK.parseFromPEMEncodedObjects(pemEncodedRSAPublicKey);
            return Response.ok(jwk.toJSONString()).type(MediaType.APPLICATION_JSON).build();
        } else if (format.equals("pem")) {
            return Response.ok(pemEncodedRSAPublicKey).build();
        }
        return null;
    }
}
