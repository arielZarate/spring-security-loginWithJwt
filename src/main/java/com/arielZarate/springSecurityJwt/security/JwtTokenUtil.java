package com.arielZarate.springSecurityJwt.security;


import java.io.Serializable;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

import javax.crypto.SecretKey;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;



@Component
public class JwtTokenUtil implements Serializable {
    
    @Value("${spring.jwt.secret-key}")
    private  String SECRET_KEY;    //= "bmVhcmVycmFpbmZvcndhcmRmYWNpbmdzdW5saWdodHNob3dhbnl0aGluZ2RvemVuZGk="; // Cambia esto por una clave más segura
   
    @Value("${spring.jwt.expiration-time}")
    private  long EXPIRATION_TIME ;  //= 1000 * 60 * 60 * 9; // 9 hora en milisegundos

    // Generar el token JWT
    public String generateToken(String email, String role) {
        Map<String, Object> claims = new HashMap<>();
        claims.put("role", role);
        return createToken(claims, email);
    }

    // Crear el token JWT con los claims y el sujeto
    private String createToken(Map<String, Object> claims, String email) {
        return Jwts.builder()
                .claims(claims)
                .subject(email)
                .issuedAt(new Date(System.currentTimeMillis()))
                .expiration(new Date(System.currentTimeMillis() + EXPIRATION_TIME))
                .signWith(getSignInKey(),Jwts.SIG.HS256)
                .compact();
    }



    //metodo agregado 
        private SecretKey getSignInKey() {
        byte[] keyBytes = Decoders.BASE64.decode(SECRET_KEY);
        return Keys.hmacShaKeyFor(keyBytes);
    }

    // Validar el token JWT
    public boolean validateToken(String token, String email) {
        final String username = extractEmail(token);
        return (username.equals(email) && !isTokenExpired(token));
    }

    // Extraer el nombre de email del token
    public String extractEmail(String token) {
        return extractAllClaims(token).getSubject();
    }

    // Verificar si el token ha expirado
    private boolean isTokenExpired(String token) {
        return extractAllClaims(token).getExpiration().before(new Date());
    }

    // Extraer todos los claims del token
    private Claims extractAllClaims(String token) {
        return Jwts.parser()
                .verifyWith(getSignInKey())
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }
}



/*
 
1. Clave secreta (SECRET_KEY)
Actualmente estás usando una clave codificada en Base64 en la variable SECRET_KEY. 
tiempo de expiración en 1 hora (en milisegundos).

Mejora: Dependiendo de tu caso de uso, podrías ajustar el tiempo de expiración a algo más largo o más corto. También podrías permitir que sea configurable a través de propiedades externas.
3. Generar y firmar tokens JWT
El método generateToken genera un token JWT, asignando el rol del usuario y su email como "subject". El método createToken firma el token con la clave y añade información adicional como la fecha de emisión y expiración.

Bien hecho: El uso de claims personalizados (como el rol) es útil para manejar la autorización en diferentes endpoints.
Mejora: Si planeas manejar otros claims o roles adicionales en el futuro, podrías hacer la creación de claims más flexible.
4. Validación del token
El método validateToken compara si el token pertenece al usuario (email) y si no ha expirado. Aquí aseguras que el token sigue siendo válido antes de permitir acceso.

Bien hecho: Este enfoque es correcto para verificar la validez del token.
5. Extracción de claims y email
El método extractEmail extrae el email (que en este caso se guarda como el "subject" del token). También puedes extraer otros claims si es necesario.

Bien hecho: Estás extrayendo correctamente los claims usando extractAllClaims.
6. Manejo de la expiración
El método isTokenExpired revisa si el token ha expirado comparando la fecha de expiración con la fecha actual.

 */