package com.example.springsecuritymaster.users.repository;

import com.example.springsecuritymaster.domain.entity.Account;
import org.springframework.data.jpa.repository.JpaRepository;
import java.util.Optional;
public interface UserRepository extends JpaRepository<Account, Long> {
    Optional<Account> findByUsername(String username);
}
