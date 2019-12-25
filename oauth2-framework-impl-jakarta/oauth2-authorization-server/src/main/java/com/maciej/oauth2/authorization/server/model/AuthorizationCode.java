package com.maciej.oauth2.authorization.server.model;

import lombok.Getter;
import lombok.Setter;

import javax.persistence.*;
import java.time.LocalDateTime;

@Getter
@Setter
@Entity
@Table(name = "authorization_code")
public class AuthorizationCode {

    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    @Column(name = "code")
    private String code;
    @Column(name = "client_id")
    private String clientID;
    @Column(name = "user_id")
    private String userID;
    @Column(name = "approved_scopes")
    private String approvedScopes;

    @Column(name = "redirect_uri")
    private String redirectUri;

    @Column(name = "expiration_date")
    private LocalDateTime expirationDate;
}
