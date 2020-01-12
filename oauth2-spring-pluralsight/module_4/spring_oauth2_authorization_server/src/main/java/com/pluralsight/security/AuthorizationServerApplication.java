package com.pluralsight.security;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;

// HERE AUTHORIZATION SERVER ALSO PLAYS A ROLE OF RESOURCE SERVER!!!!!

@SpringBootApplication
@EnableResourceServer
// This will add 3rd filter chain that will look out for the access token in the header before allowing access
// to the /userinfo endpoint. As we will have 3 filter chains, we need to make sure to have them in correct order.
public class AuthorizationServerApplication {

    public static void main(String[] args) {
        SpringApplication.run(AuthorizationServerApplication.class, args);
    }

}
