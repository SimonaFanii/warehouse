package com.sha.springbootjwtauthorization.service;


import com.sha.springbootjwtauthorization.model.Role;
import com.sha.springbootjwtauthorization.model.User;
import com.sha.springbootjwtauthorization.repository.UserRepository;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import javax.transaction.Transactional;
import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;


@Service
public class UserServiceImpl implements UserService {
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    public UserServiceImpl(UserRepository userRepository, PasswordEncoder passwordEncoder) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
    }


    @Override
    public User saveUser(User user){
        user.setPassword(passwordEncoder.encode(user.getPassword()));
        user.setRole(Role.USER);
        user.setCreationTime(LocalDateTime.now() );
        return userRepository.save(user);
    }

    @Override
    public Optional<User> findByUsername(String username)
    {
        return userRepository.findByUsername(username);
    }

    @Override
    @Transactional
    public void changeRole(Role newRole, String username){
        userRepository.updateUserRole(username,newRole);
    }

    @Override
    public List<User> findAllUsers(){
        return userRepository.findAll();
    }
}
