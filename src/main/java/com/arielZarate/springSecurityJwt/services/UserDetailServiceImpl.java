package com.arielZarate.springSecurityJwt.services;

import java.util.Optional;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import com.arielZarate.springSecurityJwt.entity.AuthDetailModel;
import com.arielZarate.springSecurityJwt.entity.User;
import com.arielZarate.springSecurityJwt.repository.UserRepository;

/*Resumen del flujo:
# Cuando un usuario intenta autenticarse, Spring Security delega a UserDetailsService 
  la tarea de buscar al usuario en la base de datos.

  #UserDetailServiceImpl busca al usuario por su correo electrónico utilizando el UserRepository.
  Si se encuentra el usuario, se crea un objeto AuthDetailModel que representa los detalles del 
  usuario que se usará en el proceso de autenticación y autorización.

  Si no se encuentra, se lanza una excepción que indica que el usuario no existe.

Esta implementación es fundamental para cualquier sistema que gestione usuarios autenticados y roles, 
en este caso utilizando JWT para la autenticación en una arquitectura basada en toke 

*/

@Service
public class UserDetailServiceImpl implements UserDetailsService {

  @Autowired
  private UserRepository userRepository;

  @Override
  public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
    Optional<User> user = this.userRepository.findByEmail(email);
    // return new AuthDetailModel(user);
    AuthDetailModel authDetail = user.map(AuthDetailModel::new)
        .orElseThrow(() -> new UsernameNotFoundException("Usuario no encontrado con email: " + email));

    return authDetail;
  }

}
