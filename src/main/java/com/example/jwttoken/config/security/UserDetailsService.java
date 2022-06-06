package com.example.jwttoken.config.security;

import com.example.jwttoken.domain.user.repository.UserRepository;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Component;

import javax.transaction.Transactional;
import java.util.List;
import java.util.stream.Collectors;

@Component("userDetailsService")
public class UserDetailsService implements org.springframework.security.core.userdetails.UserDetailsService {

    private final UserRepository userRepository;

    public UserDetailsService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @Override
    @Transactional
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        return userRepository.findOneWithAuthoritiesByUsername(username)
                .map(user -> createUser(username, user))
                .orElseThrow(() -> new UsernameNotFoundException(username + ": 데이터베이스에서 찾을 수 없습니다."));
    }

    private User createUser(String username, com.example.jwttoken.domain.user.User user) {
        if (!user.isActivated()) {
            throw new RuntimeException(username + ": 활성화되어있지 않습니다.");
        }

        List<SimpleGrantedAuthority> collect = user.getAuthorities().stream()
                .map(authority -> new SimpleGrantedAuthority(authority.getAuthorityName()))
                .collect(Collectors.toList());

        return new User(user.getUsername(), user.getPassword(), collect);
    }
}
