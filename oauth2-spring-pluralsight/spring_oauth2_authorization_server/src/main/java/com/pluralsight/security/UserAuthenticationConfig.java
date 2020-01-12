package com.pluralsight.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

@Configuration
@Order(1)
// As we have 3 filter chains, we need to make sure to have them in correct order.
// Now it will be before Resource Server (order = 3). This way the ResourceServer filter chain is only
// evaluated if the OAuth2 flow was successful and the client has access token.
public class UserAuthenticationConfig extends WebSecurityConfigurerAdapter {
    // When we extend this class, we essentially add the filter chain (we can have multiple chains).

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        // This filter chain will intercept authorization URI requests (to authorization endpoint) from Users's Browser.
        // It will then require User to be authenticated, if they are not, it will prompt them to do it via form login.
        http.requestMatchers()
            .mvcMatchers("/login", "/oauth/authorize")
            .and()
            .authorizeRequests()
            .anyRequest()
            .authenticated()
            .and().formLogin();
    }

    // Authentication in Spring is done by AuthenticationManager
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.inMemoryAuthentication()
            .withUser("joe")
            .password(encoder().encode("password"))
            .roles("USER");
    }

    // Return the configured version of AuthenticationManager bean.
    @Override
    @Bean
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }

    @Bean
    public PasswordEncoder encoder() {
        return new BCryptPasswordEncoder();
    }
}