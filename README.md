In Spring Security 6.x and Spring Framework 3.x, the @EnableMethodSecurity annotation replaces @EnableGlobalMethodSecurity to enable role-based access control at the method level. Here’s a breakdown of what each of the parameters does:
---

@EnableMethodSecurity
The @EnableMethodSecurity annotation allows you to use annotations such as @Secured, @PreAuthorize, and @PostAuthorize to enforce access control on specific methods in your application.

Parameters
securedEnabled = true:

Enabling this allows the use of @Secured annotations in your code.
With @Secured, you can specify required roles directly on methods,
for example
---

@Secured("ROLE_ADMIN")
public String message() {
    return "Hello";
}

---

prePostEnabled = true:

This enables @PreAuthorize and @PostAuthorize annotations.
@PreAuthorize allows more complex security expressions using Spring Expression Language (SpEL) to control access based on roles or custom logic.

---

@PreAuthorize("hasRole('ADMIN')")
public String message() {
    return "Hello";
}

---

@PostAuthorize works similarly but runs security checks after the method execution, which can be useful for verifying returned data based on security rules.

---

Summary of Use Cases
Use securedEnabled = true if you need @Secured annotations for straightforward role-based access control.
Use prePostEnabled = true if you need more flexibility with complex access rules or want to use @PreAuthorize and @PostAuthorize.
By setting these to true, you enable fine-grained access control across your application.


---
In Spring Security, you cannot define multiple users with the same spring.security.user.name in application.properties, which causes the "duplicate entry" error you're seeing. This is because the spring.security.user.* properties only support a single user.

To create different users with distinct passwords for each role, you need to configure multiple users manually in your Java configuration class using in-memory authentication.

Solution: Java Configuration with In-Memory Authentication
Instead of defining users in application.properties, you can use Spring Security’s InMemoryAuthentication in a Java configuration class. Here’s how to set up multiple users with different passwords for different roles:

1. Java Configuration Example:
You can define different users with distinct passwords and roles in your custom security configuration class:
```
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {
    // Define password encoder
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        // In-memory authentication with different roles and passwords
        auth.inMemoryAuthentication()
            .passwordEncoder(passwordEncoder())
            .withUser("admin")
            .password(passwordEncoder().encode("adminpassword"))  // Admin's password
            .roles("ADMIN")
            .and()
            .withUser("user")
            .password(passwordEncoder().encode("userpassword"))  // User's password
            .roles("USER");
    }
    // Configure HTTP security (e.g., which roles can access which endpoints)
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
            .authorizeRequests()
                .antMatchers("/admin/**").hasRole("ADMIN")
                .antMatchers("/user/**").hasRole("USER")
                .anyRequest().authenticated()
            .and()
            .formLogin();  // Enable form login
    }
    // Define the password encoder (e.g., BCrypt)
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}
```
---

Explanation:

Authentication Configuration:

withUser("admin"): Defines a user with the username admin.
.password(passwordEncoder().encode("adminpassword")): Defines the password for the admin user (encoded using BCrypt).
.roles("ADMIN"): Assigns the role ADMIN to this user.
Similarly, you define the user user with a different password and role USER.

Password Encoder:

We use BCryptPasswordEncoder to encode the passwords securely. It's a recommended practice to never store passwords in plain text.
Authorization Configuration:

antMatchers("/admin/**").hasRole("ADMIN"): Only users with the ADMIN role can access URLs starting with /admin/.

antMatchers("/user/**").hasRole("USER"): Only users with the USER role can access URLs starting with /user/.

### Login Configuration:

The .formLogin() method enables a basic login form for the application.

2. Test the Configuration:
For Admin: You should be able to log in with admin and the password adminpassword, and access /admin/** URLs.

For User: You should be able to log in with user and the password userpassword, and access /user/** URLs.

5. Using Application Properties:
   
If you really want to use application.properties for users, you'll need to configure them in a different way. But the above Java configuration is the best approach for defining multiple users with different roles and passwords.

