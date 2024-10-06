# Proyecto Spring Security con JWT

Este proyecto implementa un sistema de autenticación y autorización utilizando Spring Security y JWT (JSON Web Token). Permite el registro de usuarios, inicio de sesión, y el acceso a recursos protegidos basados en roles (usuario y administrador).

## Características

- Registro de usuarios con validación de correos electrónicos únicos.
- Autenticación de usuarios mediante credenciales (correo y contraseña).
- Generación de tokens JWT para el acceso a recursos protegidos.
- Protección de rutas según roles (usuario y administrador).
- Uso de BCrypt para el cifrado de contraseñas.

## Tecnologías Utilizadas

- Java 17
- Spring Boot
- Spring Security
- JWT (JSON Web Token)
- Lombok
- H2 Database (o MySQL)
- Maven

## Estructura del Proyecto

```bash
com.arielZarate.springSecurityJwt ├── config │ ├── JwtTokenUtil.java │ ├── PasswordConfig.java │ └── WebSecurity.java ├── controllers │ └── AuthController.java ├── entity │ ├── AuthDetailModel.java │ ├── Role.java │ └── User.java ├── repository │ └── UserRepository.java └── services ├── AuthService.java └── UserDetailServiceImpl.java
```

## Instalación

1. **Clonar el repositorio:**
   ```bash
   git clone https://github.com/tu_usuario/springSecurityJwt.git
   cd springSecurityJwt


2. Configurar la base de datos: Modifica la configuración de tu base de datos en src/main/resources/application.properties o application.yml.


3. construir el proyecto
`mvn clean install`
4. Ejecutar el proyecto
`mvn spring-boot:run`



## Registro de Usuario
Para registrar un nuevo usuario, realiza una solicitud POST a /auth/register con el siguiente cuerpo en formato JSON:

```json
{
    "email": "usuario@ejemplo.com",
    "password": "tu_contraseña",
    "role": "ROLE_USER" // o ROLE_ADMIN
}

```

## Inicio de Sesión
Para iniciar sesión, realiza una solicitud POST a /auth/login con el siguiente cuerpo en formato JSON:


````json
{
    "email": "usuario@ejemplo.com",
    "password": "tu_contraseña"
}

````


## Acceso a Recursos Protegidos
- Ruta pública: /public - Acceso sin autenticación.
- Ruta para usuarios: /home - Requiere autenticación para usuarios y administradores.
- Ruta para administradores: /dashboard - Requiere autenticación solo para  
   administradores.



## Ejemplo de uso de JWT
Después de iniciar sesión, recibirás un token JWT que debes incluir en el encabezado Authorization de tus solicitudes a recursos protegidos:  
`Authorization: Bearer <tu_token_jwt>`



## API

## Endpoints
![endpoint](./images/endpoints.png)

## Configuración
### Configuración de Seguridad
El sistema utiliza Spring Security para manejar la autenticación y autorización. El filtro de JWT es añadido a la cadena de filtros de seguridad de Spring.

### Cifrado de Contraseñas
Las contraseñas se cifran utilizando BCrypt para mejorar la seguridad.

## Contribuciones
Las contribuciones son bienvenidas. Por favor, abre un issue o un pull request si deseas aportar.

## Licencia

```bash

### Notas
- Asegúrate de reemplazar `https://github.com/tu_usuario/springSecurityJwt.git` con la URL correcta de tu repositorio.
- Completa y ajusta los ejemplos de uso y configuraciones según tu implementación específica.
- Si usas una base de datos diferente a H2, actualiza las instrucciones de instalación y configuración de la base de datos.
  
Con este `README.md`, tu proyecto será más accesible y fácil de entender para otros desarrolladores. ¡Espero que te sirva!

```