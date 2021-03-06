package com.maciej.oauth2.resource.server.secure;

import org.eclipse.microprofile.jwt.JsonWebToken;

import javax.annotation.security.RolesAllowed;
import javax.enterprise.context.RequestScoped;
import javax.inject.Inject;
import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.core.Response;
import java.util.UUID;

@Path("resource")
@RequestScoped
public class ProtectedResource {

    @Inject
    private JsonWebToken principal;

    @GET
    @RolesAllowed("resource.read")
    @Path("/read")
    public Response read() {
        // Do staff
        return Response.ok("Hello, " + principal.getName() + ". Reading resource").build();
    }

    @POST
    @RolesAllowed("resource.write")
    @Path("/write")
    public Response write() {
        // Do staff
        return Response.ok("Hello, " + principal.getName() + ". Writing resource")
            .header("location", UUID.randomUUID().toString())
            .build();
    }
}
