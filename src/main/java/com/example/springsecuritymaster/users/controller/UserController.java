package com.example.springsecuritymaster.users.controller;

import com.example.springsecuritymaster.domain.dto.AccountDto;
import com.example.springsecuritymaster.domain.entity.Account;
import com.example.springsecuritymaster.users.service.UserService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.modelmapper.ModelMapper;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.PostMapping;

@Controller
@RequiredArgsConstructor
@Slf4j
public class UserController {
    private final PasswordEncoder passwordEncoder;
    private final UserService userService;
    @PostMapping("/signup")
    public String signup(AccountDto accountDto){
        log.info("accountDto={}", accountDto);
        ModelMapper mapper = new ModelMapper();
        Account account = mapper.map(accountDto, Account.class);
        account.setPassword(passwordEncoder.encode(accountDto.getPassword()));
        log.info("account={}", account);
        userService.createUser(account);
        log.info("account={}", account);
        return "redirect:/";
    }
}
