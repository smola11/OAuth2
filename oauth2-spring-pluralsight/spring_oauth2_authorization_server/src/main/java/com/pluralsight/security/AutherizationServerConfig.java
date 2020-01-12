package com.pluralsight.security;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;

@Configuration
@EnableAuthorizationServer
public class AutherizationServerConfig extends AuthorizationServerConfigurerAdapter {
    // This also created a filter chain.

    private final PasswordEncoder passwordEncoder;

    public AutherizationServerConfig(PasswordEncoder passwordEncoder) {
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    public void configure(AuthorizationServerSecurityConfigurer oauthServer) throws Exception {
        // Any client can request the access token
        oauthServer.tokenKeyAccess("permitAll()")
            // Client will have to be authenticated before it can use the token endpoint to verify the token it possess
            .checkTokenAccess("isAuthenticated()");
    }

    // Register our web application as a client.
    // We should keep client secrets in Secure Secret Store like Vault.
    @Override
    public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
        clients.inMemory().withClient("crypto-portfolio")
            .authorizedGrantTypes("authorization_code")
            // Hashing secret
            .secret(passwordEncoder.encode("secret"))
            .scopes("user_info")
            .redirectUris("http://localhost:8080/login/oauth2/code/crypto-portfolio")
            // This is for the Consent Pop-up - if true authorization server will approve by default any scope
            // defined in supported scopes for this client.
            .autoApprove(false);
    }
}
