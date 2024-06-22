package com.sso.saml.util;

import org.opensaml.saml2.core.AuthnRequest;
import org.opensaml.xml.Configuration;
import org.opensaml.xml.io.Marshaller;
import org.opensaml.xml.io.MarshallerFactory;
import org.opensaml.xml.signature.Signer;
import org.w3c.dom.Element;

import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import java.io.FileInputStream;
import java.io.StringWriter;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.util.Base64;
import java.util.Properties;

public class SamlUtil {

    public static String base64Decode(String base64Message) {
        byte[] xmlByteData = Base64.getDecoder().decode(base64Message);

        return new String(xmlByteData, StandardCharsets.UTF_8);
    }

    public static String base64EncodeXMLObject(AuthnRequest xmlObject, boolean samlSignature) throws Exception {
        MarshallerFactory marshallerFactory = Configuration.getMarshallerFactory();
        Marshaller marshaller = marshallerFactory.getMarshaller(xmlObject);
        Element samlObjectElement = marshaller.marshall(xmlObject);

        if (samlSignature)
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

    public static PrivateKey loadPrivateKey(String filePath, String serviceProviderUrl,
                                            String keyStorePassword, String privateKeyPassword) throws Exception {
        KeyStore keyStore = KeyStore.getInstance("JKS");
        keyStore.load(new FileInputStream(filePath), keyStorePassword.toCharArray());

        return (PrivateKey) keyStore.getKey(serviceProviderUrl, privateKeyPassword.toCharArray());
    }

    public static String getSamlProperty(Properties properties, String propertyName, String defaultValue) {
        if (properties.containsKey(propertyName) && !properties.getProperty(propertyName).isEmpty())
            return properties.getProperty(propertyName);
        return defaultValue;
    }
}
