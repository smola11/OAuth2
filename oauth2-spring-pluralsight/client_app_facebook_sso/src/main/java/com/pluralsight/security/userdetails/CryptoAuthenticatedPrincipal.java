package com.pluralsight.security.userdetails;

import org.springframework.security.core.AuthenticatedPrincipal;

public interface CryptoAuthenticatedPrincipal extends AuthenticatedPrincipal {

    String getFirstName();

    String getLastName();

    String getFirstAndLastName();

    String getEmail();
}
