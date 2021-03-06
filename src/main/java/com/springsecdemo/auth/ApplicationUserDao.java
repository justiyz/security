package com.springsecdemo.auth;

import org.springframework.stereotype.Service;

import java.util.Optional;

//@Service
public interface ApplicationUserDao {
    Optional<ApplicationUser> selectApplicationUserByUsername(String username);
}
