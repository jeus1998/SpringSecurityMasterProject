package com.example.springsecuritymaster.security.service;

import com.example.springsecuritymaster.domain.dto.AccountDto;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import java.util.Collection;
import java.util.List;

@RequiredArgsConstructor
public class AccountContext implements UserDetails {
    private final AccountDto accountDto;
    private final List<GrantedAuthority> authorities;
    @Override
    public boolean isAccountNonExpired() {
        return true;
    }
    @Override
    public boolean isAccountNonLocked() {
        return true;
    }
    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }
    @Override
    public boolean isEnabled() {
        return true;
    }
    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return authorities;
    }
    @Override
    public String getPassword() {
        return accountDto.getPassword();
    }
    @Override
    public String getUsername() {
        return accountDto.getUsername();
    }
}
