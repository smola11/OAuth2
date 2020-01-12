package com.pluralsight.security.repository;

import com.pluralsight.security.entity.CryptoOauth2User;
import org.springframework.data.mongodb.repository.MongoRepository;

public interface Oauth2UserRepository extends MongoRepository<CryptoOauth2User, String> {
}
