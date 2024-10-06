package com.arielZarate.springSecurityJwt.utils;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class ValidateAuth {
      // Regex para validar el formato del correo electrónico
      private static final String EMAIL_REGEX = "^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$";
    
      // Método para validar el formato del correo electrónico
      public static boolean isValidEmail(String email) {
          if (email == null || email.isEmpty()) {
              return false;
          }
          Pattern pattern = Pattern.compile(EMAIL_REGEX);
          Matcher matcher = pattern.matcher(email);
          return matcher.matches();
      }
  
      // Método para validar la longitud de la contraseña
      public static boolean isStrongPassword(String password) {
          if (password == null) {
              return false;
          }


          //esto esta basico se puede mejorar solo que yo para que no me de errores 
          //cuando los cree el password con 12345 no quieor que ahora me de error si la pongo mas extricta
          return password.length() >= 5; // Al menos 5 caracteres
      }
}
