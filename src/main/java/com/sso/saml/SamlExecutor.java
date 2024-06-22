package com.sso.saml;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.xml.XmlMapper;

import com.sso.saml.builder.SamlRequestBuilder;
import com.sso.saml.client.SamlClient;
import com.sso.saml.util.SamlUtil;
import org.jsoup.nodes.Document;

import org.opensaml.saml2.core.AuthnRequest;
import org.springframework.core.io.ClassPathResource;
import org.springframework.http.ResponseEntity;

import java.util.HashMap;
import java.util.Map;
import java.util.Properties;


public class SamlExecutor {

    private SamlClient samlClient = new SamlClient();

    private SamlRequestBuilder samlRequestBuilder = new SamlRequestBuilder();

    public Map<String, Object> authenticate(String username, String password) {
        Map<String, Object> result = new HashMap<>();

        try {
            Properties samlProperties = new Properties();
            samlProperties.load(new ClassPathResource("samlclient.properties").getInputStream());

            AuthnRequest samlAuthnRequest = samlRequestBuilder.getSamlAuthnRequest(samlProperties);

            /* Setting jsonRequestString as StringEntity */
            String base64EncodedRequest = SamlUtil.base64EncodeXMLObject(samlAuthnRequest,
                    Boolean.parseBoolean(SamlUtil.getSamlProperty(samlProperties, "saml.service.provider.signature.enable", "false")));

            /* Getting SAML identity provider meta-info */
            ResponseEntity<String> idProviderMetaResp = samlClient.getIdentityProviderAuthPortal(base64EncodedRequest,
                    SamlUtil.getSamlProperty(samlProperties, "saml.identity.provider.url",
                            "http://127.0.0.1:8080/auth/realms/identityprovider/protocol/saml"));

            /* Redirecting to identity provider authentication portal */
            ResponseEntity<String> authPortalResp = samlClient.redirectToAuthPortal(idProviderMetaResp.getHeaders());

            /* Authenticating user with identity provider and getting SAML Response */
            Document samlAuthResponse = samlClient.authenticateUser(authPortalResp.getBody(),
                    idProviderMetaResp.getHeaders(), username, password);

            if (samlAuthResponse.getElementsByAttributeValue("name", "SAMLResponse").size() > 0) {
                String samlResponseData = decodeSamlResponse(samlProperties, samlAuthResponse);

                result.put("Status", "Success");
                result.put("SAMLResponse", samlResponseData);

                if (Boolean.parseBoolean(SamlUtil.getSamlProperty(samlProperties,
                        "saml.processing.enable", "false")))
                    samlAuthResponse.forms().get(0).submit();
            } else {
                result.put("Status", "Failure");
                result.put("Reason", "invalid username or password");
            }
        } catch (Exception ex) {
            ex.printStackTrace();
            throw new RuntimeException("Exception occurred while processing SAML flow...", ex);
        }

        return result;
    }

    private String decodeSamlResponse(Properties samlProperties, Document samlAuthResponse) throws Exception {
        String base64DecodedSamlResp = SamlUtil.base64Decode(samlAuthResponse.getElementsByAttributeValue("name", "SAMLResponse")
                .get(0).attr("value"));

        if (samlProperties.getProperty("saml.response.type", "xml")
                .equalsIgnoreCase("json")) {
            XmlMapper xmlMapper = new XmlMapper();
            JsonNode jsonNode = xmlMapper.readTree(base64DecodedSamlResp.getBytes());
            ObjectMapper objectMapper = new ObjectMapper();
            return objectMapper.writeValueAsString(jsonNode);
        }

        return base64DecodedSamlResp;
    }
}
