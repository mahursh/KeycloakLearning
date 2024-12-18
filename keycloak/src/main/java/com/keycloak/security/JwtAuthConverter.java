package com.keycloak.security;

import org.springframework.core.convert.converter.Converter;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;
import org.springframework.stereotype.Component;

import java.util.Collection;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

@Component
public class JwtAuthConverter implements Converter<Jwt, AbstractAuthenticationToken> {

    private final JwtGrantedAuthoritiesConverter jwtGrantedAuthoritiesConverter =
            new JwtGrantedAuthoritiesConverter();

    @Override
    public AbstractAuthenticationToken convert(@NonNull Jwt jwt) {

        Collection<GrantedAuthority> authorities = Stream.concat(
                jwtGrantedAuthoritiesConverter.convert(jwt).stream(),
                extractClientRoles(jwt).stream()
        ).collect(Collectors.toSet());

        return new JwtAuthenticationToken(
                jwt,
                authorities
        );
    }

    @SuppressWarnings("unchecked")
    private Collection<? extends GrantedAuthority> extractClientRoles(Jwt jwt){
        Map<String , Object> resourceAccess;
        Map<String , Object> clientConfig;
        Collection<String> clientRoles;

        Object rawResourceAccess = jwt.getClaim("resource_access");

        if(!(rawResourceAccess instanceof Map)){
            return Set.of();
        }
        resourceAccess = (Map<String, Object>) rawResourceAccess;

        Object rawClientConfig = resourceAccess.get("news_app_client");

        if(!(rawClientConfig instanceof Map)){
            return Set.of();
        }
        clientConfig = (Map<String, Object>) rawClientConfig;

        Object rawClientRoles = clientConfig.get("roles");
        if(!(rawClientRoles instanceof Collection)){
            return Set.of();
        }

        clientRoles = (Collection<String>) rawClientRoles;

        return clientRoles
                .stream()
                .map(role ->new SimpleGrantedAuthority("ROLE_"+ role))
                .collect(Collectors.toSet());

    }
}
