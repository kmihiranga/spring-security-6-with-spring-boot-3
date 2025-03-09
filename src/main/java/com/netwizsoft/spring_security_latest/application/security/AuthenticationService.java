package com.netwizsoft.spring_security_latest.application.security;

import com.netwizsoft.spring_security_latest.application.security.dto.JwtAuthenticationResponse;
import com.netwizsoft.spring_security_latest.application.security.dto.SignUpRequest;
import com.netwizsoft.spring_security_latest.application.security.dto.SigninRequest;

public interface AuthenticationService {

    JwtAuthenticationResponse signup(SignUpRequest signUpRequest);

    JwtAuthenticationResponse signin(SigninRequest signinRequest);
}
