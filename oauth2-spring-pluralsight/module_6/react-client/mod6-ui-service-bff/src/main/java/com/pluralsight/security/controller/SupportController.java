package com.pluralsight.security.controller;

import com.pluralsight.security.model.CreateSupportQueryRequest;
import com.pluralsight.security.model.Post;
import com.pluralsight.security.model.SupportQuery;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.reactive.function.BodyInserters;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.util.UriComponentsBuilder;

import java.net.URI;

@RequiredArgsConstructor
@RestController
@CrossOrigin(value = {"http://localhost:3000"})
public class SupportController {

    private static final String SUPPORT_SERVICE_DOMAIN = "http://localhost:8181";
    private final WebClient webClient;

    @GetMapping("/support")
    public SupportQuery[] getQueries(@AuthenticationPrincipal JwtAuthenticationToken principal) {
        String username = principal.getToken().getClaimAsString("preferred_username");
        return this.webClient.get().uri(SUPPORT_SERVICE_DOMAIN + "/support/" + username)
            .headers(headers -> headers.setBearerAuth(principal.getToken().getTokenValue()))
            .retrieve()
            .bodyToMono(SupportQuery[].class)
            .block();
    }

    @GetMapping("/support/query/{id}")
    public Post getQuery(@PathVariable String id, @AuthenticationPrincipal JwtAuthenticationToken principal) {
        return this.webClient.get().uri(SUPPORT_SERVICE_DOMAIN + "/support/query/" + id)
            .headers(headers -> headers.setBearerAuth(principal.getToken().getTokenValue()))
            .retrieve()
            .bodyToMono(Post.class)
            .block();
    }

    @PutMapping("/support")
    public void createNewQuery(@RequestBody CreateSupportQueryRequest request, @AuthenticationPrincipal JwtAuthenticationToken principal) {
        URI targetUri = UriComponentsBuilder.fromHttpUrl(SUPPORT_SERVICE_DOMAIN)
            .path("/support")
            .build().encode().toUri();
        request.setUsername(principal.getToken().getClaimAsString("preferred_username"));
        this.webClient.put()
            .uri(targetUri)
            .headers(headers -> headers.setBearerAuth(principal.getToken().getTokenValue()))
            .body(BodyInserters.fromObject(request))
            .retrieve()
            .bodyToMono(Void.class)
            .block();
    }

    @PostMapping("/support/query/{id}")
    public void postToQuery(@RequestBody Post post, @PathVariable String id, @AuthenticationPrincipal JwtAuthenticationToken principal) {
        URI targetUri = UriComponentsBuilder.fromHttpUrl(SUPPORT_SERVICE_DOMAIN)
            .path("/support/query/" + id)
            .build().encode().toUri();
        this.webClient.post()
            .uri(targetUri)
            .headers(headers -> headers.setBearerAuth(principal.getToken().getTokenValue()))
            .body(BodyInserters.fromObject(post))
            .retrieve()
            .bodyToMono(Void.class)
            .block();
    }

}
