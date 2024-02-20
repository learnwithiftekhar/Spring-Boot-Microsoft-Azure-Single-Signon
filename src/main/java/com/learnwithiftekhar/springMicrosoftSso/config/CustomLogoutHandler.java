package com.learnwithiftekhar.springMicrosoftSso.config;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.stereotype.Component;
import org.springframework.web.util.UriComponentsBuilder;

import java.io.IOException;

@Component
public class CustomLogoutHandler extends SecurityContextLogoutHandler {


    private final ClientRegistrationRepository clientRegistrationRepository;

    public CustomLogoutHandler(ClientRegistrationRepository clientRegistrationRepository) {
        this.clientRegistrationRepository = clientRegistrationRepository;
    }

    @Override
    public void logout(HttpServletRequest request,
                       HttpServletResponse response,
                       Authentication authentication) {
        super.logout(request, response, authentication);

        // We need to create logout url
        // 1. get logout endpoint
        String logoutendPoint = (String) clientRegistrationRepository
                .findByRegistrationId("azure-dev")
                .getProviderDetails()
                .getConfigurationMetadata()
                .get("end_session_endpoint");


        // 2. generate the logout url
        String logoutUri = UriComponentsBuilder
                .fromHttpUrl(logoutendPoint)
                .encode()
                .toUriString();

        // 3. send the request to logout url
        try {
            response.sendRedirect(logoutUri);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }
}
