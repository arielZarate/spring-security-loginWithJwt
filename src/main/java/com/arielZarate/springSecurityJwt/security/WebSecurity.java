package com.arielZarate.springSecurityJwt.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import com.arielZarate.springSecurityJwt.entity.Role;
import com.arielZarate.springSecurityJwt.services.UserDetailServiceImpl;

import lombok.AllArgsConstructor;

/*Resumen del flujo:
# Protección de Rutas: Configura qué rutas son públicas y cuáles requieren autenticación.
# JWT en lugar de sesiones: La aplicación utiliza tokens JWT en lugar de sesiones tradicionales,
  lo que hace que la configuración sea stateless (sin estado).
# Autenticación basada en JWT: El filtro JwtAuthFilter se asegura de que las solicitudes contengan un 
  token válido antes de proceder con la autenticación.
# Gestión de usuarios: Se utiliza el servicio UserDetailServiceImpl para cargar los detalles 
  del usuario y el PasswordEncoder para gestionar el hasheo de contraseñas.

  Este enfoque es común en aplicaciones modernas que utilizan JWT para manejar la autenticación 
  sin sesiones en el servidor, lo que es ideal para aplicaciones distribuidas y escalables 
  
  
  
  
  
* csrf.disable(): Desactiva la protección contra CSRF (Cross-Site Request Forgery),
   ya que en una arquitectura con JWT no es necesario debido a que no se gestionan sesiones basadas en cookies.

* authorizeHttpRequests: Configura las rutas de la aplicación:
 "/auth/register", "/auth/login" y "/public/**": Estas rutas son públicas, cualquiera puede acceder a ellas sin autenticarse.
 "/home/**": Solo los usuarios autenticados con los roles ROLE_USER o ROLE_ADMIN pueden acceder.
 "/dashboard/**": Solo los usuarios con el rol ROLE_ADMIN pueden acceder a esta ruta.

* anyRequest().authenticated(): Cualquier otra ruta no especificada requiere autenticación.

* sessionManagement: Configura la política de creación de sesiones. 
  Aquí, se usa SessionCreationPolicy.STATELESS, lo que significa que no se crearán sesiones HTTP, 
  ya que la autenticación se basa en JWT y no en sesiones de servidor.

* addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class): 
  Añade el filtro de JWT (JwtAuthFilter) antes del filtro de autenticación de Spring 
  (UsernamePasswordAuthenticationFilter). 
  Esto asegura que el token JWT se valide antes de intentar la autenticación basada en nombre de usuario y contraseña.


  */

@Configuration
@EnableWebSecurity
@AllArgsConstructor
@EnableMethodSecurity
public class WebSecurity {

        @Autowired
        private UserDetailServiceImpl userDetailServiceImpl;

        // Inyectar PasswordEncoder
        @Autowired
        private PasswordEncoder passwordEncoder;

        @Autowired
        private JwtAuthFilter jwtAuthFilter;

        @Bean
        public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {

                http
                                .csrf(csrf -> csrf.disable())
                                .authorizeHttpRequests(auth -> auth
                                                .requestMatchers("/auth/register").permitAll()
                                                .requestMatchers("/auth/login").permitAll()
                                                .requestMatchers("/public/**").permitAll()
                                                .requestMatchers("/home/**")
                                                .hasAnyAuthority(Role.ROLE_USER.name(), Role.ROLE_ADMIN.name())
                                                .requestMatchers("/dashboard/**").hasAuthority(Role.ROLE_ADMIN.name())
                                                .anyRequest().authenticated()

                                )

                                // .httpBasic(Customizer.withDefaults())
                                .sessionManagement(session -> session
                                                .sessionCreationPolicy(SessionCreationPolicy.STATELESS));
                // Añadir el filtro de JWT antes del filtro de autenticación de Spring
                http.addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class); // de que
                // estás
                // usando
                // sesiones

                return http.build();

        }

        // Configuración del AuthenticationManager para usar UserDetailService y
        // PasswordEncoder
        @Bean
        public AuthenticationManager authenticationManager(HttpSecurity http) throws Exception {
                AuthenticationManagerBuilder authenticationManagerBuilder = http
                                .getSharedObject(AuthenticationManagerBuilder.class);

                authenticationManagerBuilder
                                .userDetailsService(userDetailServiceImpl)
                                .passwordEncoder(passwordEncoder);

                return authenticationManagerBuilder.build();

        }

}

/*
Logout desde el cliente: Lo más común en sistemas JWT es que el cliente elimine el token almacenado.
Logout en el servidor: No es necesario en un sistema sin estado basado en JWT, 
 pero podrías implementar una ruta para invalidar tokens si decides hacerlo.
 */