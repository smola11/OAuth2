package com.pluralsight.security.userdetails;

import com.pluralsight.security.model.UserOAuth2Dto;
import com.pluralsight.security.service.PortfolioCommandService;
import com.pluralsight.security.service.UserRegistrationService;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Map;

@Configuration("oauth2authSuccessHandler")
@RequiredArgsConstructor
public class Oauth2AuthenticationSuccessHandler implements AuthenticationSuccessHandler {

    private final PortfolioCommandService portfolioCommandService;
    private final RedirectStrategy redirectStrategy;
    private final UserRegistrationService userRegistrationService;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication)
        throws IOException {
        if (!this.portfolioCommandService.userHasAportfolio(authentication.getName())) {
            // if authenticated via form login, getName() will be the username;
            // if authenticated by OpenID Connect, getName() will be the claim subject;
            // for non-OpenID providers it can vary
            OAuth2AuthenticationToken token = (OAuth2AuthenticationToken) authentication;
            Map<String, Object> attributes = token.getPrincipal().getAttributes();
            String firstname = null, lastname = null, email = null;
            if (token.getAuthorizedClientRegistrationId().equals("facebook")) {
                String name = attributes.get("name").toString();
                firstname = name.split(" ")[0];
                lastname = name.split(" ")[1];
                email = attributes.get("email").toString();
            }
            UserOAuth2Dto user = new UserOAuth2Dto(firstname, lastname, authentication.getName(), email);
            this.userRegistrationService.registerNewAuth2User(user);
            this.portfolioCommandService.createNewPortfolio(authentication.getName());
        }
        this.redirectStrategy.sendRedirect(request, response, "/portfolio");
    }
}
