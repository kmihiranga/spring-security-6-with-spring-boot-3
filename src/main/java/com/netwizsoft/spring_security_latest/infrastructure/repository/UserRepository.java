package com.netwizsoft.spring_security_latest.infrastructure.repository;

import com.netwizsoft.spring_security_latest.domain.User;
import org.springframework.data.mongodb.repository.MongoRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface UserRepository extends MongoRepository<User, String> {
    // since email is unique, we'll find users by email
    Optional<User> findByEmail(String email);
}
