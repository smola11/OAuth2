## OAuth 2.0 Implementation - Jakarta

This module contains the implementation of OAuth2 with Java EE (Jakarta).

To run the authorization-server, client and protected resource:
1. mvn package (build all modules)
2. mvn liberty:run-server (run libery server for each module)
3. If you want to make a change in code and redeploy, first stop the liberty server "bin/server stop"

### References

- https://www.baeldung.com/java-ee-oauth2-implementation
- https://github.com/eugenp/tutorials/tree/master/oauth2-framework-impl
