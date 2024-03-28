package es.neesis.security.services;

import es.neesis.security.model.User;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.List;

public interface IUserService {

    UserDetails loadUserByUsername(String username);

    List<GrantedAuthority> getAuthorities(String username);

    boolean authenticate(String username, String password);

    void nuevoUsuario(User user);
}
