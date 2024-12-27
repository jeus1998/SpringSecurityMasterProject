package com.example.springsecuritymaster.users.service;

import com.example.springsecuritymaster.domain.entity.Account;
import com.example.springsecuritymaster.users.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
public class UserService {
    private final UserRepository userRepository;
    @Transactional
    public void createUser(Account account){
        userRepository.save(account);
    }
}
