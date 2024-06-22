package com.test.poc;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.xml.XmlMapper;

import com.google.gson.Gson;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;

import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;

import org.opensaml.DefaultBootstrap;
import org.opensaml.common.SAMLVersion;
import org.opensaml.common.impl.SAMLObjectContentReference;
import org.opensaml.saml2.core.AuthnRequest;
import org.opensaml.saml2.core.Issuer;
import org.opensaml.saml2.core.impl.AuthnRequestBuilder;
import org.opensaml.saml2.core.impl.IssuerBuilder;
import org.opensaml.xml.Configuration;
import org.opensaml.xml.encryption.EncryptionConstants;
import org.opensaml.xml.io.Marshaller;
import org.opensaml.xml.io.MarshallerFactory;
import org.opensaml.xml.security.credential.BasicCredential;
import org.opensaml.xml.signature.Signature;
import org.opensaml.xml.signature.SignatureConstants;
import org.opensaml.xml.signature.Signer;
import org.opensaml.xml.signature.impl.SignatureBuilder;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.env.Environment;
import org.springframework.http.*;
import org.springframework.stereotype.Component;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;

import org.w3c.dom.Element;

import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import java.io.FileInputStream;
import java.io.StringWriter;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.util.Base64;
import java.util.UUID;


@Component
public class SamlExecutor {

    private RestTemplate restTemplate = new RestTemplate();

    @Autowired
    private Environment environment;

    public JsonObject processApiRequest(JsonObject request) {
        String username = request.get("username").getAsString();
        String password = request.get("password").getAsString();

        JsonObject result = new JsonObject();

        try {
            DefaultBootstrap.bootstrap();
            AuthnRequest samlAuthnRequest = getSamlAuthnRequest();

            /* Setting jsonRequestString as StringEntity */
            String base64EncodedRequest = base64EncodeXMLObject(samlAuthnRequest);

            /* Getting SAML identity provider meta-info */
            ResponseEntity<String> idProviderMetaResp = getIdentityProviderAuthPortal(base64EncodedRequest,
                    environment.getProperty("saml.identity.provider.url", "http://127.0.0.1:8080/auth/realms/identityprovider/protocol/saml"));

            /* Redirecting to identity provider authentication portal */
            ResponseEntity<String> authPortalResp = redirectToAuthPortal(idProviderMetaResp.getHeaders());

            /* Authenticating user with identity provider and getting SAML Response */
            Document samlAuthResponse = authenticateUser(authPortalResp.getBody(), idProviderMetaResp.getHeaders(), username, password);

            if (samlAuthResponse.getElementsByAttributeValue("name", "SAMLResponse").size() > 0) {
                String base64DecodedSamlResp = base64Decode(samlAuthResponse.getElementsByAttributeValue("name", "SAMLResponse")
                        .get(0).attr("value"));

                System.out.println("XML: " + base64DecodedSamlResp);

                XmlMapper xmlMapper = new XmlMapper();
                JsonNode jsonNode = xmlMapper.readTree(base64DecodedSamlResp.getBytes());
                ObjectMapper objectMapper = new ObjectMapper();
                String samlJsonStr = objectMapper.writeValueAsString(jsonNode);

                System.out.println("Json: " + samlJsonStr);

                result.addProperty("Status", "Success");
                result.add("SAMLResponse", new Gson().fromJson(samlJsonStr, JsonElement.class));

                if (Boolean.parseBoolean(environment.getProperty("saml.processing.enable", "false")))
                    samlAuthResponse.forms().get(0).submit();
            } else {
                result.addProperty("Status", "Failure");
                result.addProperty("Reason", "invalid username or password");
            }
        } catch (Exception ex) {
            ex.printStackTrace();
            throw new RuntimeException("Exception occurred while processing SAML flow...", ex);
        }

        return result;
    }

    private AuthnRequest getSamlAuthnRequest() throws Exception {
        AuthnRequest authnRequest = ((AuthnRequestBuilder) Configuration.getBuilderFactory().getBuilder(
                AuthnRequest.DEFAULT_ELEMENT_NAME)).buildObject();

        authnRequest.setDestination(environment.getProperty("saml.identity.provider.url", "http://127.0.0.1:8080/auth/realms/identityprovider/protocol/saml"));

        /* Your consumer URL (where you want to receive SAML response) */
        authnRequest.setAssertionConsumerServiceURL(environment.getProperty("saml.response.consumer.url", "http://127.0.0.1:8010/realms/serviceprovider/broker/SAML-IDP/endpoint"));

        /* Unique request ID */
        authnRequest.setID("_" + UUID.randomUUID());
        authnRequest.setVersion(SAMLVersion.VERSION_20);
        authnRequest.setIssueInstant(new org.joda.time.DateTime());
        authnRequest.setProtocolBinding("urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST");

        if (Boolean.parseBoolean(environment.getProperty("saml.service.provider.signature.enable", "false")))
            setAuthnSignature(authnRequest);

        /* Your issuer URL */
        authnRequest.setIssuer(buildIssuer(environment.getProperty("saml.service.provider.url",
                "http://127.0.0.1:8010/realms/serviceprovider")));

        return authnRequest;
    }

    private void setAuthnSignature(AuthnRequest authnRequest) throws Exception {
        BasicCredential basicCredential = new BasicCredential();
        basicCredential.setPrivateKey(loadPrivateKey(environment.getProperty("saml.service.provider.keystore.path")));

        SignatureBuilder signatureBuilder = new SignatureBuilder();
        Signature signature = signatureBuilder.buildObject();
        signature.setSignatureAlgorithm(SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA256);
        signature.setCanonicalizationAlgorithm(SignatureConstants.ALGO_ID_C14N_OMIT_COMMENTS);
        signature.setSigningCredential(basicCredential);

        authnRequest.setSignature(signature);
        ((SAMLObjectContentReference) signature.getContentReferences().get(0))
                .setDigestAlgorithm(EncryptionConstants.ALGO_ID_DIGEST_SHA256);
    }

    private ResponseEntity<String> getIdentityProviderAuthPortal(String base64EncodedRequest, String idProviderUrl) {
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

    private ResponseEntity<String> redirectToAuthPortal(HttpHeaders portalHeaders) {
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

    private Document authenticateUser(String authPortal, HttpHeaders portalHeaders, String username, String password) {
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

    private Issuer buildIssuer(String issuerValue) {
        Issuer issuer = ((IssuerBuilder) Configuration.getBuilderFactory().getBuilder(
                Issuer.DEFAULT_ELEMENT_NAME)).buildObject();
        issuer.setValue(issuerValue);
        return issuer;
    }

    private String base64EncodeXMLObject(AuthnRequest xmlObject) throws Exception {
        MarshallerFactory marshallerFactory = Configuration.getMarshallerFactory();
        Marshaller marshaller = marshallerFactory.getMarshaller(xmlObject);
        Element samlObjectElement = marshaller.marshall(xmlObject);

        if (Boolean.parseBoolean(environment.getProperty("saml.service.provider.signature.enable", "false")))
            Signer.signObject(xmlObject.getSignature());

        // Transforming Element into String
        Transformer transformer = TransformerFactory.newInstance().newTransformer();
        transformer.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "yes");

        StreamResult result = new StreamResult(new StringWriter());
        DOMSource source = new DOMSource(samlObjectElement);
        transformer.transform(source, result);
        String xmlString = result.getWriter().toString();

        // next, base64 encode it
        String base64EncodedMessage = Base64.getEncoder().encodeToString(xmlString.getBytes("UTF-8"));

        return base64EncodedMessage;
    }

    private String base64Decode(String base64Message) {
        byte[] xmlByteData = Base64.getDecoder().decode(base64Message);

        return new String(xmlByteData, StandardCharsets.UTF_8);
    }

    private PrivateKey loadPrivateKey(String filePath) throws Exception {
        KeyStore keyStore = KeyStore.getInstance("JKS");
        keyStore.load(new FileInputStream(filePath),
                environment.getProperty("saml.service.provider.keystore.password", "ted").toCharArray());

        return (PrivateKey) keyStore.getKey(environment.getProperty("saml.service.provider.url",
                "http://127.0.0.1:8010/realms/serviceprovider"),
                environment.getProperty("saml.service.provider.keystore.key.password", "ted").toCharArray());
    }
}
