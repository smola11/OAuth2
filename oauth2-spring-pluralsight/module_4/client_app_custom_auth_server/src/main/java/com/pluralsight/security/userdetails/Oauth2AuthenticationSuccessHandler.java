package com.pluralsight.security.userdetails;

import com.pluralsight.security.model.UserOAuth2Dto;
import com.pluralsight.security.service.PortfolioCommandService;
import com.pluralsight.security.service.UserRegistrationService;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

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
            CryptoAuthenticatedPrincipal principal = (CryptoAuthenticatedPrincipal) authentication.getPrincipal();
            UserOAuth2Dto user = new UserOAuth2Dto(principal.getFirstName(), principal.getLastName(), authentication.getName(), principal.getEmail());
            this.userRegistrationService.registerNewAuth2User(user);
            this.portfolioCommandService.createNewPortfolio(authentication.getName());
        }
        this.redirectStrategy.sendRedirect(request, response, "/portfolio");
    }
}
