package com.pluralsight.security.service;

import com.pluralsight.security.entity.CryptoOauth2User;
import com.pluralsight.security.entity.CryptoUser;
import com.pluralsight.security.model.UserDto;
import com.pluralsight.security.model.UserOAuth2Dto;
import com.pluralsight.security.repository.Oauth2UserRepository;
import com.pluralsight.security.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class UserRegistrationService {

    private final UserRepository repository;
    private final Oauth2UserRepository oauth2Repository;
    private final PasswordEncoder encoder;

    public void registerNewUser(UserDto user) {
        CryptoUser cryptUser = new CryptoUser(
            user.getUsername(),
            user.getFirstname(),
            user.getLastname(),
            user.getEmail(),
            encoder.encode(user.getPassword()),
            encoder.encode(String.valueOf(user.getSecurityPin()))
        );
        cryptUser.setVerified(true);
        repository.save(cryptUser);
    }

    public void registerNewAuth2User(UserOAuth2Dto userDto) {
        CryptoOauth2User user = new CryptoOauth2User(
            userDto.getUsername(),
            userDto.getFirstname(),
            userDto.getLastname(),
            userDto.getEmail());
        oauth2Repository.save(user);
    }
}
