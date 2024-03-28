package es.neesis.security.config;

import es.neesis.security.repository.UserRepository;
import es.neesis.security.services.UserServices;
import es.neesis.security.util.JwtTokenUtil;
import jakarta.servlet.Filter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfiguration;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.config.annotation.web.builders.WebSecurity;


@Configuration
@EnableWebSecurity
public class WebSecurityConfig extends WebSecurityConfiguration{

    @Autowired
    public JwtAuthenticationFilter jwtAuthenticationFilter;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http, UserRepository userRepository) throws Exception {
        http
                .authorizeRequests(authorizeRequests ->
                        authorizeRequests
                                .requestMatchers("/", "/home", "/login").permitAll()
                                .anyRequest().authenticated()
                )
                .addFilterBefore(jwtAuthenticationFilter(jwtTokenUtil(), userServices(userRepository)), UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }

    public UserServices userServices(UserRepository userRepository) {
        return new UserServices(userRepository);
    }

    public JwtTokenUtil jwtTokenUtil() {
        return new JwtTokenUtil();
    }

    @Bean
    public JwtAuthenticationFilter jwtAuthenticationFilter(JwtTokenUtil jwtTokenUtil, UserServices userServices) {
        return new JwtAuthenticationFilter(jwtTokenUtil, userServices);
    }

    @Bean
    public UserDetailsService userDetailsService() {
        UserDetails user = User.withDefaultPasswordEncoder()
            .username("user")
            .password("password")
            .roles("USER")
            .build();
        return new InMemoryUserDetailsManager(user);
    }
}
