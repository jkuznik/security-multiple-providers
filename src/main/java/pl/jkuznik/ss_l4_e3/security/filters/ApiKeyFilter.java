package pl.jkuznik.ss_l4_e3.security.filters;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.AllArgsConstructor;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;
import pl.jkuznik.ss_l4_e3.security.authentications.ApiKeyAuthentication;
import pl.jkuznik.ss_l4_e3.security.managers.CustomAuthenticationManager;

import java.io.IOException;


@AllArgsConstructor
public class ApiKeyFilter extends OncePerRequestFilter {

    private final String apiKey;

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {

        CustomAuthenticationManager manager = new CustomAuthenticationManager(apiKey);

        String requestKey = request.getHeader("x-api-key");

        if ( "null".equals(requestKey) || requestKey == null) {

            filterChain.doFilter(request, response);
        }

        var auth = new ApiKeyAuthentication(requestKey);

        try {
            var authenticate = manager.authenticate(auth);

            if (authenticate.isAuthenticated()) {
                SecurityContextHolder.getContext().setAuthentication(authenticate);
                filterChain.doFilter(request, response);
            }
        }catch (AuthenticationException e) {
            System.out.println(e.getMessage());
        }
    }
}
