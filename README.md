# Introduction

This is a SAML2 based Authentication service for applications that are using keycloak as their identity provider.

# Configuration

The SAML client can be configured in samlclient.properties.

# # SAML Configuration Properties

saml.identity.provider.url = <identityProviderURL> //Here keycloak is the identity provider

saml.response.consumer.url = <consumerUrl> //here, we specify consumer url where SAMLResponse need to be recieved

saml.service.provider.url = <serviceProvider> //here, we specify the application which has been registered in identityProvider

saml.service.provider.signature.enable = <BooleanValue> //here we set whether the SAMLRequest need to have client digital signature

saml.service.provider.keystore.path = <KeyStoreFilePath> //here, we specify the absolute path of the keystore file in JKS format containing the privateKey information

saml.service.provider.keystore.password = <KeyStorePassword> //here, we specify the keyStore password

saml.service.provider.keystore.key.password = password //here, we specify the privateKey password 

saml.processing.enable = <BooleanValue> //here, we set whether the SAMLResponse need to be submitted to consumer url by identity provider

saml.response.type = <xml/json> //here, we whether the reponse needs to be in xml or json format
