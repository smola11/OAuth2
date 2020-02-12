package com.pluralsight.security.configuration;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.authority.mapping.GrantedAuthoritiesMapper;
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

import com.pluralsight.security.service.CryptoOidcUserService;
import com.pluralsight.security.service.KeycloakLogoutHandler;
import com.pluralsight.security.userdetails.CryptoGrantedAuthoritiesMapper;

@Configuration
@EnableGlobalMethodSecurity(prePostEnabled=true)
public class SecurityConfiguration extends WebSecurityConfigurerAdapter {
	
	@Autowired
	@Qualifier("oauth2authSuccessHandler")
	private AuthenticationSuccessHandler oauth2authSuccessHandler;
	@Autowired
	private KeycloakLogoutHandler logoutHandler;	

	
	@Override
	protected void configure(HttpSecurity http) throws Exception {
		// @formatter:off
		http
			.logout().addLogoutHandler(logoutHandler)
			.and()
			.oauth2Login()
				.loginPage("/oauth2/authorization/crypto-portfolio")
				.failureUrl("/login-error")
				.successHandler(oauth2authSuccessHandler)
				.userInfoEndpoint()
				.oidcUserService(new CryptoOidcUserService())				
				.and()
			.and()
			.authorizeRequests()
				.mvcMatchers("/login","/login-error").permitAll()
				.mvcMatchers("/portfolio/**").hasRole("USER")
				.mvcMatchers("/support/**").hasAnyRole("USER","ADMIN")
				.mvcMatchers("/support/admin/**").hasRole("ADMIN")
				.anyRequest().denyAll()
				;
		// @formatter:on
	}
	
	@Override
	public void configure(WebSecurity web) throws Exception {
		web.ignoring().antMatchers("/css/**", "/webjars/**");
	}
	
	@Bean
	protected RedirectStrategy getRedirectStrategy() {
		return new DefaultRedirectStrategy();
	}	
	
	@Bean
	protected GrantedAuthoritiesMapper getGrantedAuthoritiesMapper() {
		return new CryptoGrantedAuthoritiesMapper();
	}
	

}