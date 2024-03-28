package es.neesis.security.util;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

import java.util.Date;
import java.util.HashMap;
import java.util.Map;

public class JwtTokenUtil {

    private static final String KEY = "password";
    private static final long TIME = 100000;

    public String generateToken(String username){
        Map<String, Object> claims = new HashMap<>();

        return Jwts.builder().setClaims(claims).setSubject(username).setIssuedAt(new Date()).setExpiration(new Date(System.currentTimeMillis() + TIME)).signWith(SignatureAlgorithm.HS512, KEY).compact();
    }

    public String getUsernameByToken(String token){
        Claims claims = Jwts.parser().setSigningKey(KEY).parseClaimsJws(token).getBody();

        return claims.getSubject();
    }

    public boolean validateToken(String token) {
        try {
            Jwts.parser().setSigningKey(KEY).parseClaimsJws(token);
            return true;
        } catch (Exception e) {
            return false;
        }
    }
}
