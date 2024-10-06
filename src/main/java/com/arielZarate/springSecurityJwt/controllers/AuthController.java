package com.arielZarate.springSecurityJwt.controllers;

import java.util.Map;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import com.arielZarate.springSecurityJwt.entity.User;
import com.arielZarate.springSecurityJwt.services.AuthService;

@RestController
public class AuthController {

    @Autowired
    private AuthService authService;

    @GetMapping(value = { "/public", "/public/" })
    public ResponseEntity<?> EndpointPublic() {
        var auth = SecurityContextHolder.getContext().getAuthentication();
        System.out.println("Datos del usuario: " + auth.getPrincipal());
        System.out.println("Datos de LOS PERMISOS : " + auth.getAuthorities());
        System.out.println("Esta logueado: " + auth.isAuthenticated());
        return ResponseEntity.status(HttpStatus.OK).body("Welcome a public");
    }

    @GetMapping(value = { "/home", "home/" })
    public ResponseEntity<?> EndpointUser() {

        var auth = SecurityContextHolder.getContext().getAuthentication();
        System.out.println("Datos del usuario: " + auth.getPrincipal());
        System.out.println("Datos de LOS PERMISOS : " + auth.getAuthorities());
        System.out.println("Esta logueado: " + auth.isAuthenticated());
        return ResponseEntity.status(HttpStatus.OK).body("Welcome al Home ");
    }

    @GetMapping(value = { "/dashboard", "/dashboard/" })
    public ResponseEntity<?> EndpointAdmin() {
        var auth = SecurityContextHolder.getContext().getAuthentication();
        System.out.println("Datos del usuario: " + auth.getPrincipal());
        System.out.println("Datos de LOS PERMISOS : " + auth.getAuthorities());
        System.out.println("Esta logueado: " + auth.isAuthenticated());
        return ResponseEntity.status(HttpStatus.OK).body("Welcome al dashboard");
    }

    // registro

    @PostMapping("/auth/register")
    public ResponseEntity<User> register(@RequestBody User user) {

        User result = authService.registerUser(user.getEmail(), user.getPassword(), user.getRole());

        // System.out.println("Controlador:" + result);
        return ResponseEntity.status(HttpStatus.CREATED).body(result);
    }

    @PostMapping("/auth/login")
    public ResponseEntity<?> login(@RequestBody User user) {
     Map<String, Object> result = authService.loginUser(user.getEmail(),
                user.getPassword());

        return ResponseEntity.ok(result);

    }

}
