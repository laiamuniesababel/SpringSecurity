package es.neesis.security.services;

import es.neesis.security.model.User;
import es.neesis.security.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;

@Service
public class UserServices implements IUserService{

    private final UserRepository userRepository;

    @Autowired
    public UserServices(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @Override
    public UserDetails loadUserByUsername(String username) {
        User user = userRepository.findByUsername(username);
        return (UserDetails) user;
    }

    @Override
    public List<GrantedAuthority> getAuthorities(String username) {
        User user = userRepository.findByUsername(username);

        SimpleGrantedAuthority authority = new SimpleGrantedAuthority(user.getRole());

        return Collections.singletonList(authority);
    }

    @Override
    public boolean authenticate(String username, String password){
        User user = userRepository.findByUsername(username);
        return user != null && user.getPassword().equals(password);
    }

    @Override
    public void nuevoUsuario(User user) {
        userRepository.save(user);
    }

    public String getRole(String username){
        User user = userRepository.findByUsername(username);
        return user.getRole();
    }
}
