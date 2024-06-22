package com.sso.saml.builder;

import com.sso.saml.util.SamlUtil;

import org.opensaml.DefaultBootstrap;
import org.opensaml.common.SAMLVersion;
import org.opensaml.common.impl.SAMLObjectContentReference;
import org.opensaml.saml2.core.AuthnRequest;
import org.opensaml.saml2.core.Issuer;
import org.opensaml.saml2.core.impl.AuthnRequestBuilder;
import org.opensaml.saml2.core.impl.IssuerBuilder;
import org.opensaml.xml.Configuration;
import org.opensaml.xml.encryption.EncryptionConstants;
import org.opensaml.xml.security.credential.BasicCredential;
import org.opensaml.xml.signature.Signature;
import org.opensaml.xml.signature.SignatureConstants;
import org.opensaml.xml.signature.impl.SignatureBuilder;

import java.util.Properties;
import java.util.UUID;


public class SamlRequestBuilder {

    public AuthnRequest getSamlAuthnRequest(Properties samlProperties) throws Exception {
        DefaultBootstrap.bootstrap();

        AuthnRequest authnRequest = ((AuthnRequestBuilder) Configuration.getBuilderFactory().getBuilder(
                AuthnRequest.DEFAULT_ELEMENT_NAME)).buildObject();

        authnRequest.setDestination(SamlUtil.getSamlProperty(samlProperties, "saml.identity.provider.url",
                "http://127.0.0.1:8080/auth/realms/identityprovider/protocol/saml"));

        /* Your consumer URL (where you want to receive SAML response) */
        authnRequest.setAssertionConsumerServiceURL(SamlUtil.getSamlProperty(samlProperties, "saml.response.consumer.url",
                "http://127.0.0.1:8010/realms/serviceprovider/broker/SAML-IDP/endpoint"));

        /* Unique request ID */
        authnRequest.setID("_" + UUID.randomUUID());
        authnRequest.setVersion(SAMLVersion.VERSION_20);
        authnRequest.setIssueInstant(new org.joda.time.DateTime());
        authnRequest.setProtocolBinding("urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST");

        if (Boolean.parseBoolean(SamlUtil.getSamlProperty(samlProperties, "saml.service.provider.signature.enable", "false")))
            setAuthnSignature(samlProperties, authnRequest);

        /* Your issuer URL */
        authnRequest.setIssuer(buildIssuer(SamlUtil.getSamlProperty(samlProperties, "saml.service.provider.url",
                "http://127.0.0.1:8010/realms/serviceprovider")));

        return authnRequest;
    }

    private void setAuthnSignature(Properties samlProperties, AuthnRequest authnRequest) throws Exception {
        BasicCredential basicCredential = new BasicCredential();
        basicCredential.setPrivateKey(SamlUtil.loadPrivateKey(SamlUtil.getSamlProperty(samlProperties,"saml.service.provider.keystore.path", System.getProperty("user.dir")),
                SamlUtil.getSamlProperty(samlProperties, "saml.service.provider.url", "http://127.0.0.1:8010/realms/serviceprovider"),
                SamlUtil.getSamlProperty(samlProperties, "saml.service.provider.keystore.password", "password"),
                SamlUtil.getSamlProperty(samlProperties, "saml.service.provider.keystore.key.password", "password")));

        SignatureBuilder signatureBuilder = new SignatureBuilder();
        Signature signature = signatureBuilder.buildObject();
        signature.setSignatureAlgorithm(SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA256);
        signature.setCanonicalizationAlgorithm(SignatureConstants.ALGO_ID_C14N_OMIT_COMMENTS);
        signature.setSigningCredential(basicCredential);

        authnRequest.setSignature(signature);
        ((SAMLObjectContentReference) signature.getContentReferences().get(0))
                .setDigestAlgorithm(EncryptionConstants.ALGO_ID_DIGEST_SHA256);
    }

    private Issuer buildIssuer(String issuerValue) {
        Issuer issuer = ((IssuerBuilder) Configuration.getBuilderFactory().getBuilder(
                Issuer.DEFAULT_ELEMENT_NAME)).buildObject();
        issuer.setValue(issuerValue);
        return issuer;
    }
}
