package com.example.springsecuritymaster.domain.dto;

import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
public class AccountDto {
    private Long id;
    private String username;
    private String password;
    private int age;
    private String roles;
}
