package com.arielZarate.springSecurityJwt.security;

import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;



@Configuration
public class CorsConfig implements WebMvcConfigurer {
    
    @Override
    public void addCorsMappings(CorsRegistry registry) {
        registry.addMapping("/**")
            .allowedOrigins("*")  // Cambia esto según tu necesidad
           // .allowCredentials(true)
            .allowedMethods("GET", "POST", "PUT", "DELETE", "OPTIONS")
            .allowedHeaders("Authorization", "Content-Type")  // Solo las cabeceras que usas
            .maxAge(3600);  // Tiempo máximo en cache para las opciones pre-flight
    }
}




/*
 Explicación de las Mejoras
allowedOrigins("https://tudominio.com", "https://otrotudominio.com"):

En lugar de permitir todos los orígenes, restringe el acceso a tu API solo desde dominios conocidos y de confianza.
allowedMethods("GET", "POST", "PUT", "DELETE", "OPTIONS"):

Solo permite los métodos que necesitas. Si tu API no usa DELETE, por ejemplo, puedes eliminarlo de la lista.
allowedHeaders("Authorization", "Content-Type"):

Especifica solo las cabeceras que necesitas, como Authorization para tokens JWT y Content-Type para datos JSON. Esto limita el acceso solo a los encabezados esenciales.
allowCredentials(true):

Si tu aplicación necesita compartir cookies o credenciales de sesión (aunque en un sistema basado en JWT esto es poco común), deberías permitirlas explícitamente. Esto es útil si tienes un sistema híbrido que aún utiliza autenticación basada en sesiones o cookies.
maxAge(3600):

Define el tiempo (en segundos) que las solicitudes preflight (OPTIONS) pueden almacenarse en caché por el navegador. Esto mejora el rendimiento al reducir la cantidad de solicitudes OPTIONS.
 */