package com.pluralsight.security.configuration;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.client.web.reactive.function.client.ServletOAuth2AuthorizedClientExchangeFilterFunction;
import org.springframework.web.reactive.function.client.WebClient;

@Configuration
public class WebClientConfig {

    @Bean
    public WebClient webClient(ClientRegistrationRepository clientRep, OAuth2AuthorizedClientRepository authClientRepo) {
        ServletOAuth2AuthorizedClientExchangeFilterFunction oauth2 =
            new ServletOAuth2AuthorizedClientExchangeFilterFunction(
                clientRep, new ClientCredentialsAuthorizedClientRepository(authClientRepo)
            );
        oauth2.setDefaultClientRegistrationId("portfolio-service");
        return WebClient.builder().apply(oauth2.oauth2Configuration()).build();
        // Any time this WebClient is used FilterFunction will look up OAuth2AuthorizedClientRepository for an
        // authorized client with that ID ("portfolio-service"). If one does not exist it will look up the
        // ClientRegistrationRepository to retrieve client details and contact the Keycloak (provider) to retrieve the
        // access token using client credential grant flow.
    }

    /**
     * This is a work around until Spring Security 5.2 when the
     * ServletOAuth2AuthorizedClientExchangeFilterFunction will request a new
     * token if the existing one is expired for the client credentials grant.
     * Until then we need to check the expiry manually.
     */
    class ClientCredentialsAuthorizedClientRepository implements OAuth2AuthorizedClientRepository {

        private OAuth2AuthorizedClientRepository oauth2AutherizedRepo;
        private Clock clock = Clock.systemUTC();
        private Duration accessTokenExpiresSkew = Duration.ofMinutes(1);

        public ClientCredentialsAuthorizedClientRepository(OAuth2AuthorizedClientRepository oauth2AutherizedRepo) {
            this.oauth2AutherizedRepo = oauth2AutherizedRepo;
        }

        @Override
        public <T extends OAuth2AuthorizedClient> T loadAuthorizedClient(String clientRegistrationId,
                                                                         Authentication principal, HttpServletRequest request) {
            T authorizedClient = this.oauth2AutherizedRepo.loadAuthorizedClient(clientRegistrationId, principal, request);
            if (authorizedClient == null) {
                return authorizedClient;
            }
            Instant now = this.clock.instant();
            Instant expiresAt = authorizedClient.getAccessToken().getExpiresAt();
            if (now.isAfter(expiresAt.minus(this.accessTokenExpiresSkew))) {
                this.oauth2AutherizedRepo.removeAuthorizedClient(clientRegistrationId, principal, request, null);
                // When we remove it, the ExchangeFiler will not receive the authorized client back and hence will trigger it
                // to acquire a new token from authorization server
                return this.oauth2AutherizedRepo.loadAuthorizedClient(clientRegistrationId, principal, request);
            }
            return authorizedClient;
        }

        @Override
        public void saveAuthorizedClient(OAuth2AuthorizedClient authorizedClient, Authentication principal,
                                         HttpServletRequest request, HttpServletResponse response) {
            this.oauth2AutherizedRepo.saveAuthorizedClient(authorizedClient, principal, request, response);

        }

        @Override
        public void removeAuthorizedClient(String clientRegistrationId, Authentication principal,
                                           HttpServletRequest request, HttpServletResponse response) {
            this.oauth2AutherizedRepo.removeAuthorizedClient(clientRegistrationId, principal, request, response);
        }

    }

}