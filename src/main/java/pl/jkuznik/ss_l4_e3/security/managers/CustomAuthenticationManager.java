package pl.jkuznik.ss_l4_e3.security.managers;

import lombok.AllArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import pl.jkuznik.ss_l4_e3.security.providers.ApiKeyProvider;

@AllArgsConstructor
public class CustomAuthenticationManager implements AuthenticationManager {


    private final String key;

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {

        ApiKeyProvider apiKeyProvider = new ApiKeyProvider(key);

        if ( apiKeyProvider.supports(authentication.getClass())){
            return apiKeyProvider.authenticate(authentication);
        }
        return authentication;
    }
}
