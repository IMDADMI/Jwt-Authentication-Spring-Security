
# Stateless authentication system using JWT and spring security

This is the backend part of the jwt security method you can view the front part in the Jwt-Authentication repository in admi branch
### You can view the backend part in the repository **Jwt-Authentication-Spring-Security** 
**please make sure to add the roles (USER,ADMIN) and the admin user manually using the api**
***please make sure to add your database configuration in the Application.properties file ***


## Demo
this app is bootstrapped by https://start.spring.io/ 
To start the application go to the app root and run 
```bash
  ./mvnw install
```  
then run the api using you favorit ide


# Documentation

## JWT Introduction
JSON Web Tokens (JWT) are a compact and self-contained way to represent information between two parties. In our case, JWTs will be used to securely transmit authentication details between the client and the server. The token contains claims (data) that are digitally signed, ensuring their authenticity and integrity.
## how the authentication flow works in this system
### User Authentication:
When a user attempts to log in with their username and password, Spring Security's authentication process comes into play. The user's credentials are verified against the stored credentials (e.g., in a database) to ensure they are valid.
### JWT Generation and Sending:
Upon successful authentication, the server generates a JWT containing relevant user information (e.g., username, roles), signs it with **HMAC 256**, and sends it back to the client in the response headers or as part of the response body.

### Subsequent Requests
For subsequent requests to secured API endpoints, the client must include the JWT in the request headers. The server verifies the token's signature and extracts the user information from the token's claims. If the token is valid and not expired, the user is considered authenticated, and the request proceeds
### Securing Controller Methods:
To secure specific API endpoints, i use the @Secure annotation provided by Spring Security. This annotation ensures that only authenticated users with the necessary roles (specified in the annotation) can access the protected resources.
