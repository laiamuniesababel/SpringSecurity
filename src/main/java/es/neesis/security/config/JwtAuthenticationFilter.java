package es.neesis.security.config;

import es.neesis.security.model.User;
import es.neesis.security.services.UserServices;
import es.neesis.security.util.JwtTokenUtil;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Collections;

public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtTokenUtil jwtTokenUtil;
    private final UserServices userServices;

    public JwtAuthenticationFilter(JwtTokenUtil jwtTokenUtil,UserServices userServices){
        this.jwtTokenUtil=jwtTokenUtil;
        this.userServices = userServices;
    }


    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        final String authorization = request.getHeader("Authorization");

        String username = null;
        String token = null;

        if(authorization != null && authorization.startsWith("Bearer ")){
            token = authorization.substring(7);
            username = jwtTokenUtil.getUsernameByToken(token);
        }

        if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {
            User userDetails = (User) userServices.loadUserByUsername(username);

            SimpleGrantedAuthority authority = new SimpleGrantedAuthority(userDetails.getRole());

            // Validar el token y roles
            if (jwtTokenUtil.validateToken(token)) {
                UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(
                        userDetails, null, Collections.singletonList(authority));
                authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                SecurityContextHolder.getContext().setAuthentication(authentication);
            }
        }

        filterChain.doFilter(request, response);


    }
}
