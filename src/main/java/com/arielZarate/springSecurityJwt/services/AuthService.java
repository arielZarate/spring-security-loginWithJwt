package com.arielZarate.springSecurityJwt.services;

import java.util.HashMap;
import java.util.Map;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import com.arielZarate.springSecurityJwt.entity.Role;
import com.arielZarate.springSecurityJwt.entity.User;
import com.arielZarate.springSecurityJwt.repository.UserRepository;
import com.arielZarate.springSecurityJwt.security.JwtTokenUtil;
import com.arielZarate.springSecurityJwt.utils.ValidateAuth;

@Service
public class AuthService {

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private JwtTokenUtil jwtTokenUtil;

    // register
    public User registerUser(String email, String password, Role role) {

        // Verificar si el rol es válido
        if (role == null) {
            throw new IllegalArgumentException("El rol no puede ser nulo");
        }

        // Validar el email y la contraseña
        if (!ValidateAuth.isValidEmail(email)) {
            throw new IllegalArgumentException("El email no es válido");
        }

        if (!ValidateAuth.isStrongPassword(password)) {
            throw new IllegalArgumentException("La contraseña no es lo suficientemente fuerte");
        }

        // Verificar si el usuario ya existe
        if (userRepository.findByEmail(email).isPresent()) {
            // System.out.println("El usuario ya esta registrado");
            throw new IllegalArgumentException("El email ya está registrado");
        }

        try {
            // Crear un nuevo usuario con la contraseña encriptada
            User user = new User();
            user.setEmail(email);
            // =============== Encriptar la contraseña=================
            user.setPassword(passwordEncoder.encode(password));
            // =========================================================

            user.setRole(role);

            User savedUser = userRepository.save(user);
            // System.out.println("Usuario guardado: " + savedUser);
            return savedUser;

        } catch (Exception e) {
            // Mejor manejo de errores
            throw new RuntimeException("Error al registrar el usuario: " + e.getMessage());

        }

    }

    // login

    public Map<String, Object> loginUser(String email, String password) {

        try {
            // Verificar si el usuario ya está autenticado
            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
            if (authentication != null && authentication.isAuthenticated()
                    && !authentication.getPrincipal().equals("anonymousUser")) {
                throw new IllegalArgumentException("El usuario ya está logueado");
            }

            // Usar AuthenticationManager para autenticar al usuario
            UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(email,
                    password);

            Authentication authResult = authenticationManager.authenticate(authenticationToken);
            // Almacenar el resultado de la autenticación en el contexto de seguridad
            SecurityContextHolder.getContext().setAuthentication(authResult);

            // Obtener el usuario autenticado para saber su rol
            User authenticatedUser = userRepository.findByEmail(email)
                    .orElseThrow(() -> new UsernameNotFoundException("Usuario no encontrado con el email: " + email));

            // ===========================================================================

            // Generar el token JWT
            String token = jwtTokenUtil.generateToken(authenticatedUser.getEmail(), authenticatedUser.getRole().name());
            // System.out.println("Token generado: " + token);

            // Retornar más detalles junto con el token
            // cada hashMap tieene clave:string ,valor :object
            Map<String, Object> response = new HashMap<>();
            // response.put("token", token);
            response.put("email", authenticatedUser.getEmail());
            response.put("role", authenticatedUser.getRole().name());
            response.put("Bearer", token);
            return response;

        } catch (BadCredentialsException e) {
            // Manejar credenciales incorrectas
            throw new BadCredentialsException("Credenciales incorrectas: " + e.getMessage());
        } catch (UsernameNotFoundException e) {
            // Manejar usuario no encontrado
            throw new UsernameNotFoundException("Usuario no encontrado: " + e.getMessage());
        } catch (Exception e) {
            // Manejo general de excepciones
            throw new RuntimeException("Error al autenticar al usuario: " + e.getMessage());
        }

    }
}
