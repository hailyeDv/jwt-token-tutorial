package com.example.jwttoken.domain.user;

import com.example.jwttoken.domain.authority.Authority;
import com.example.jwttoken.domain.user.repository.UserRepository;
import com.example.jwttoken.dto.UserDto;
import com.example.jwttoken.util.SecutiryUtils;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Collections;
import java.util.Optional;

@Service
public class UserService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    public UserService(UserRepository userRepository, PasswordEncoder passwordEncoder) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
    }

    @Transactional
    public User signup(UserDto saveData) {
        if (userRepository.findOneWithAuthoritiesByUsername(saveData.getUsername()).orElse(null) != null) {
            throw new RuntimeException("이미 가입되어 있는 유저입니다.");
        }

        Authority role_user = Authority.builder()
                .authorityName("ROLE_USER")
                .build();

        User user = User.builder()
                .username(saveData.getUsername())
                .password(passwordEncoder.encode(saveData.getPassword()))
                .nickname(saveData.getNickname())
                .authorities(Collections.singleton(role_user))
                .activated(true)
                .build();

        return userRepository.save(user);
    }

    @Transactional(readOnly = true)
    public Optional<User> getUserWithAuthorities(String username) {
        return userRepository.findOneWithAuthoritiesByUsername(username);
    }

    @Transactional(readOnly = true)
    public Optional<User> getMyUserWithAuthorities() {
        return SecutiryUtils.getCurrentUsername().flatMap(userRepository::findOneWithAuthoritiesByUsername);
    }

}
