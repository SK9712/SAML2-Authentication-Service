package com.sso.saml.client;

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

    public Document authenticateUser(String authPortal, HttpHeaders portalHeaders, String username, String password) {
        try {
            HttpHeaders requestHeaders = new HttpHeaders();
            requestHeaders.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

            portalHeaders.get("Set-Cookie").forEach(cookie -> requestHeaders.add("cookie", cookie));

            MultiValueMap<String, String> map = new LinkedMultiValueMap<>();
            map.add("username", username);
            map.add("password", password);

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
