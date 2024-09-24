package com.kzyt.controller;

import com.kzyt.LoginReq;
import com.kzyt.service.TokenService;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
public class AuthController {

    private static final Logger log = LoggerFactory.getLogger(AuthController.class);
    private final TokenService tokenService;
    private final AuthenticationManager authenticationManager;

    @PostMapping("/login")
    public String token(@RequestBody LoginReq req) {
        var authentication = authenticationManager
                .authenticate(UsernamePasswordAuthenticationToken.unauthenticated(req.username(), req.password()));
        String token = tokenService.generateToken(authentication);
        log.info("Token granted: {}", token);
        return token;
    }

}
