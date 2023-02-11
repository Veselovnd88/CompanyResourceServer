package ru.veselov.CompanyResourceServer.service;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.UserDetailsManager;
import org.springframework.stereotype.Service;
import ru.veselov.CompanyResourceServer.model.ResourceUser;

@Service
@Slf4j
public class UserManager implements UserDetailsManager {

    private final PasswordEncoder passwordEncoder;
    @Autowired
    public UserManager(PasswordEncoder passwordEncoder) {
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    public void createUser(UserDetails user) {
        ((ResourceUser) user).setPassword(passwordEncoder.encode(user.getPassword()));

        //save user to DB
    }

    @Override
    public void updateUser(UserDetails user) {

    }

    @Override
    public void deleteUser(String username) {

    }

    @Override
    public void changePassword(String oldPassword, String newPassword) {

    }

    @Override
    public boolean userExists(String username) {
        return false;
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        //find in repo or else throw Exception
        return ResourceUser.builder().id("100")
                .password(passwordEncoder.encode("vasya")).username("petro").build();
    }
}
