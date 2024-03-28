package es.neesis.security.controller;

import es.neesis.security.model.User;
import es.neesis.security.services.UserServices;
import es.neesis.security.util.JwtTokenUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api")
public class Controller {
    @Autowired
    private UserServices userServices;
    @Autowired
    private JwtTokenUtil jwtTokenUtil;

    @Autowired
    public Controller(UserServices userServices, JwtTokenUtil jwtTokenUtil){
        this.userServices = userServices;
        this.jwtTokenUtil = jwtTokenUtil;
    }

    @PostMapping("/login")
    public ResponseEntity<?> authenticateUser(@RequestParam String username, @RequestParam String password){

        if (userServices.authenticate(username, password)){
            String token = jwtTokenUtil.generateToken(username);
            String role = userServices.getRole(username);
            if(role.equals("USER")){
                return ResponseEntity.ok().body("redirect:/user");
            }else if(role.equals("ADMIN")){
                return ResponseEntity.ok().body("redirect:/user");
            }else{
                return ResponseEntity.ok().body("Rol desconocido");
            }
        }else {
            return ResponseEntity.badRequest().body("Username o password invalida");
        }
    }

    @PostMapping("/register")
    public ResponseEntity<?> registerUser(@RequestParam User user){
        String username = user.getUsername();
        if(userServices.loadUserByUsername(username) != null){
            return ResponseEntity.badRequest().body("El usuario ya existe");
        }

        userServices.nuevoUsuario(user);
        String role = userServices.getRole(username);
        if(role.equals("USER")){
            return ResponseEntity.ok().body("redirect:/user");
        }else if(role.equals("ADMIN")){
            return ResponseEntity.ok().body("redirect:/user");
        }else{
            return ResponseEntity.ok().body("Rol desconocido");
        }
    }

}
