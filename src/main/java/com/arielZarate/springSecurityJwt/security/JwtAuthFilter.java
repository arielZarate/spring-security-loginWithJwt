package com.arielZarate.springSecurityJwt.security;

import java.io.IOException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import com.arielZarate.springSecurityJwt.services.UserDetailServiceImpl;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

@Component
public class JwtAuthFilter extends OncePerRequestFilter {

    @Autowired
    private JwtTokenUtil jwtTokenUtil;

    @Autowired
    private UserDetailServiceImpl userDetailServiceImpl;


    /*Para mejorar la depuración y el monitoreo, puedes añadir logs en puntos clave, 
     como al extraer el token, al validar el token y al autenticar al usuario, 
     usando algún framework como SLF4J o Log4j */
    Logger logger = LoggerFactory.getLogger(JwtAuthFilter.class);

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        final String authorizationHeader = request.getHeader("Authorization");

        String username = null;
        String jwt = null;

        if (authorizationHeader != null && authorizationHeader.startsWith("Bearer")) {
            jwt = authorizationHeader.substring(7);
            username = jwtTokenUtil.extractEmail(jwt);
            logger.info("JWT Token recibido para el usuario: {}", username);
        }

        // Validar el token y autenticar el usuario
        if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {
            UserDetails userDetails = this.userDetailServiceImpl.loadUserByUsername(username);

            if (jwtTokenUtil.validateToken(jwt, userDetails.getUsername())) {
                UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken = new UsernamePasswordAuthenticationToken(
                        userDetails, null, userDetails.getAuthorities());
                usernamePasswordAuthenticationToken
                        .setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                SecurityContextHolder.getContext().setAuthentication(usernamePasswordAuthenticationToken);
            }
        }

        filterChain.doFilter(request, response);
    }

}



/*  
 
Funcionamiento del JwtAuthFilter
Interceptar solicitudes:

El filtro extiende de OncePerRequestFilter, lo que significa que se ejecuta una sola vez por cada solicitud HTTP.
Dentro del método doFilterInternal(), intercepta todas las solicitudes entrantes.
Extraer el token del encabezado:

La línea final String authorizationHeader = request.getHeader("Authorization"); obtiene el valor del header Authorization que proviene de las solicitudes del frontend.
Si el encabezado Authorization existe y comienza con "Bearer", extrae el token JWT. Esto es lo que haces con jwt = authorizationHeader.substring(7);, ya que el token viene precedido por el texto "Bearer ".
Extraer el nombre de usuario del token:

Utilizando tu componente JwtTokenUtil, extraes el email del usuario (username) contenido dentro del token JWT mediante el método extractEmail(jwt).
Verificación del token y autenticación:

Si el usuario no está ya autenticado en el contexto de seguridad (SecurityContextHolder.getContext().getAuthentication() == null), carga los detalles del usuario desde la base de datos con userDetailServiceImpl.loadUserByUsername(username).
Luego valida que el token sea correcto para ese usuario con jwtTokenUtil.validateToken(jwt, userDetails.getUsername()).
Si la validación es correcta, se crea un UsernamePasswordAuthenticationToken y se lo pasa al contexto de seguridad (SecurityContextHolder.getContext().setAuthentication(...)) para autenticar al usuario.
Continuación de la cadena de filtros:

Después de autenticar al usuario, el método filterChain.doFilter(request, response); asegura que la solicitud continúe su curso hacia el controlador correspondiente
 */