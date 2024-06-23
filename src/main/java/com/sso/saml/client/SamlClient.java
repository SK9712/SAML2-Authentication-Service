package com.sso.saml.client;

import com.sso.saml.builder.SamlUserCredential;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.springframework.http.*;

import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;

import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;

public class SamlClient {
    private RestTemplate restTemplate = new RestTemplate();

    /**
     * Sends a SAML authentication request to the specified identity provider URL and returns the response.
     *
     * @param base64EncodedRequest The SAML request encoded in Base64.
     * @param idProviderUrl        The URL of the identity provider to which the SAML request is sent.
     * @return ResponseEntity<String> The response from the identity provider.
     * @throws RuntimeException If an error occurs while sending the SAML request.
     */
    public ResponseEntity<String> getIdentityProviderAuthPortal(String base64EncodedRequest, String idProviderUrl) {
        try {
            MultiValueMap<String, String> map = new LinkedMultiValueMap<>();
            map.add("SAMLRequest", base64EncodedRequest);

            HttpHeaders requestHeaders = new HttpHeaders();

            requestHeaders.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

            HttpEntity<MultiValueMap<String, String>> requestEntity = new HttpEntity<>(map, requestHeaders);

            return restTemplate.exchange(idProviderUrl, HttpMethod.POST,
                    requestEntity, String.class);
        } catch (Exception ex) {
            ex.printStackTrace();
            throw new RuntimeException("Exception while sending SAML Request to identity provider", ex);
        }
    }

    /**
     * Redirects to the authentication portal using the provided headers.
     *
     * @param portalHeaders The headers received from a previous authentication step, containing cookies and location URL.
     * @return ResponseEntity<String> The response from the identity provider portal.
     * @throws RuntimeException If an error occurs while redirecting to the identity provider portal.
     */
    public ResponseEntity<String> redirectToAuthPortal(HttpHeaders portalHeaders) {
        try {
            HttpHeaders requestHeaders = new HttpHeaders();

            portalHeaders.get("Set-Cookie").forEach(cookie -> requestHeaders.add("cookie", cookie));

            HttpEntity<MultiValueMap<String, String>> requestEntity = new HttpEntity<>(null, requestHeaders);

            return restTemplate.exchange(URLDecoder.decode(portalHeaders.get("Location").get(0), StandardCharsets.UTF_8.name()),
                    HttpMethod.POST, requestEntity, String.class);
        } catch (Exception ex) {
            ex.printStackTrace();
            throw new RuntimeException("Exception while redirecting to identity provider portal...", ex);
        }
    }

    /**
     * Authenticates a user through the identity provider using the provided credentials.
     *
     * @param authPortal The HTML content of the authentication portal where the user is redirected.
     * @param portalHeaders The HTTP headers received from the authentication portal.
     * @param samlUserCredential The SAML user credentials containing username and password.
     * @return Document The HTML document containing the authentication response from the identity provider.
     * @throws RuntimeException If an error occurs during the authentication process.
     */
    public Document authenticateUser(String authPortal, HttpHeaders portalHeaders,
                                     SamlUserCredential samlUserCredential) {
        try {
            HttpHeaders requestHeaders = new HttpHeaders();
            requestHeaders.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

            portalHeaders.get("Set-Cookie").forEach(cookie -> requestHeaders.add("cookie", cookie));

            MultiValueMap<String, String> map = new LinkedMultiValueMap<>();
            map.add("username", samlUserCredential.getUsername());
            map.add("password", samlUserCredential.getPassword());

            HttpEntity<MultiValueMap<String, String>> requestEntity = new HttpEntity<>(map, requestHeaders);

            Document htmlcode = Jsoup.parse(authPortal);
            String postLink = htmlcode.forms().get(0).attr("action");

            ResponseEntity<String> authResponse = restTemplate.exchange(URLDecoder.decode(postLink, StandardCharsets.UTF_8.name()),
                    HttpMethod.POST,
                    requestEntity, String.class);

            return Jsoup.parse(authResponse.getBody());
        } catch (Exception ex) {
            ex.printStackTrace();
            throw new RuntimeException("Exception while authenticating user through identity provider...", ex);
        }
    }
}
