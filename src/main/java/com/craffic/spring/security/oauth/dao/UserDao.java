package com.craffic.spring.security.oauth.dao;

import com.craffic.spring.security.oauth.model.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Component;

@Component
public interface UserDao extends JpaRepository<User, Long> {
    User findUserByUsername(String username);
}
