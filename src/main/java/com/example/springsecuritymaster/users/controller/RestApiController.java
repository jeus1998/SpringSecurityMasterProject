package com.example.springsecuritymaster.users.controller;

import com.example.springsecuritymaster.domain.dto.AccountDto;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api")
public class RestApiController {
    private final SecurityContextLogoutHandler logoutHandler = new SecurityContextLogoutHandler();
    @GetMapping("/user")
    public AccountDto restUser(@AuthenticationPrincipal AccountDto accountDto){
        return accountDto;
    }
    @GetMapping("/manager")
    public AccountDto restManager(@AuthenticationPrincipal AccountDto accountDto){
        return accountDto;
    }
    @GetMapping("/admin")
    public AccountDto restAdmin(@AuthenticationPrincipal AccountDto accountDto){
        return accountDto;
    }
    @GetMapping("/logout")
    public String logout(HttpServletRequest request, HttpServletResponse response){
        Authentication authentication = SecurityContextHolder.getContextHolderStrategy().getContext().getAuthentication();
        logoutHandler.logout(request, response, authentication);
        return "logout";
    }
}
