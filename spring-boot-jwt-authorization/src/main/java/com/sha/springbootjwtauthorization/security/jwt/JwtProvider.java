package com.sha.springbootjwtauthorization.security.jwt;

import com.sha.springbootjwtauthorization.security.UserPrincipal;
import org.springframework.security.core.Authentication;

import javax.servlet.http.HttpServletRequest;

public interface JwtProvider {
    Authentication getAuthentication(HttpServletRequest request);

    boolean isTokenValid(HttpServletRequest request);

    String generateToken(UserPrincipal auth);
}
