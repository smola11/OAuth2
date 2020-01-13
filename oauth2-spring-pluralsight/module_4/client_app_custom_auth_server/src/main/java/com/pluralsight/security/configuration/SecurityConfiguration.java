package com.pluralsight.security.configuration;

import com.pluralsight.security.service.CryptoOidcUserService;
import com.pluralsight.security.userdetails.CustomOauth2User;
import com.pluralsight.security.userdetails.FacebookConnectUser;
import com.pluralsight.security.userdetails.Oauth2AuthenticationSuccessHandler;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.web.RedirectStrategy;

@Configuration
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class SecurityConfiguration extends WebSecurityConfigurerAdapter {

    @Autowired
    private Oauth2AuthenticationSuccessHandler oauth2AuthenticationSuccessHandler;

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        // @formatter:off (enabled in IntelliJ - IntelliJ does not reformat this piece of code)
		http
			.oauth2Login()
				.loginPage("/login")
				.successHandler(oauth2AuthenticationSuccessHandler)
				.userInfoEndpoint()
					// Here Spring plugs in CustomUserTypesService into the OAuth2LoginAuthenticationProvider and this provider will now return
					// our custom OAuth2User implementation for Facebook and our own Authorization Server (CustomOauth2User)
					.customUserType(FacebookConnectUser.class, "facebook")
                    .customUserType(CustomOauth2User.class, "crypto-portfolio")
					// Spring will plug in the service into OpenID Connect AuthenticationProvider
					. oidcUserService(new CryptoOidcUserService())
				.and()
			    .and()

			.authorizeRequests()
				.mvcMatchers("/register","/login","/login-verified").permitAll()
				.mvcMatchers("/portfolio/**").hasRole("USER")
				.mvcMatchers("/support/**").hasAnyRole("USER","ADMIN")
				.mvcMatchers("/support/admin/**").access("isFullyAuthenticated() and hasRole('ADMIN')")
				.mvcMatchers("/api/users").hasRole("ADMIN")
				.mvcMatchers("/api/users/{username}/portfolio").access("@isPortfolioOwnerOrAdmin.check(#username)")
				.anyRequest().denyAll();
		// @formatter:on
    }

    @Override
    public void configure(WebSecurity web) throws Exception {
        web.ignoring().antMatchers("/css/**", "/webjars/**");
    }

    @Bean
    public RedirectStrategy getRedirectStrategy() {
        return new DefaultRedirectStrategy();
    }
}