package com.zuz.calculate.service;

import com.zuz.calculate.domain.Role;
import com.zuz.calculate.domain.User;

import java.util.List;

public interface UserService {
    User saveUser(User user);
    Role saveRole(Role role);
    void addRoleToUser(String username, String roleName);
    User gerUser(String username);
    List<User> getUsers();
}
