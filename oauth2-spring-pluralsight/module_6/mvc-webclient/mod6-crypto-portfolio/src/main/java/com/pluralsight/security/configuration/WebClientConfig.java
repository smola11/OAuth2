package com.pluralsight.security.configuration;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.client.web.reactive.function.client.ServletOAuth2AuthorizedClientExchangeFilterFunction;
import org.springframework.web.reactive.function.client.WebClient;

@Configuration
public class WebClientConfig {

    @Bean
    public WebClient webClient(ClientRegistrationRepository clientRegistrationRepository,
                               OAuth2AuthorizedClientRepository authorizedClientRepository) {
        ServletOAuth2AuthorizedClientExchangeFilterFunction oauth2 =
            new ServletOAuth2AuthorizedClientExchangeFilterFunction(
                clientRegistrationRepository, authorizedClientRepository);

        // We want the WebClient to automatically include the token along with our requests
        // in authorization header. To do this the ExchangeFilter is added that intercepts the request
        // before going out and add authorization header.

        // ClientRegistrationRepository - used by the Function to retrieve the registered clients in our
        // application. This is by default the in-memory version that loaded the client information
        // from our configuration file. Function will use the retrieved client details to make the OAuth2
        // authorization request to the authorization server. Once authorized, create authorized client
        // and store it in OAuth2AuthorizedClientRepository.

        // OAuth2AuthorizedClientRepository - repository for authorized client.

        return WebClient.builder()
            .apply(oauth2.oauth2Configuration())
            .build();
    }

}
