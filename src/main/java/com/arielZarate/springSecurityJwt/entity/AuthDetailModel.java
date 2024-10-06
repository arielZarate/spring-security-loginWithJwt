package com.arielZarate.springSecurityJwt.entity;

import java.util.Collection;
import java.util.Collections;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;



@Data
@AllArgsConstructor
@NoArgsConstructor

public class AuthDetailModel implements UserDetails {

private User user;


@Override
public Collection<? extends GrantedAuthority> getAuthorities() {
    return Collections.singletonList(new SimpleGrantedAuthority(user.getRole().name()));
}

@Override
public String getPassword() {
    return user.getPassword();
}

@Override
public String getUsername() {
    return user.getEmail();
}

@Override
public boolean isAccountNonExpired() {
    return true;
}

@Override
public boolean isAccountNonLocked() {
    return true;
}

@Override
public boolean isCredentialsNonExpired() {
    return true;
}

@Override
public boolean isEnabled() {
    return true;
}


@Override
public String toString() {
    return "AuthDetailModel{" +
            "id=" + user.getId() + 
            ", email='" + user.getEmail() + '\'' +
            ", roles=" + getAuthorities() + '\'' +
            ", password=" + getPassword() +
            '}';
}

}
