/*
 * Copyright (c) 2017, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.wso2.carbon.identity.sso.agent.bean;

import org.apache.commons.lang.ArrayUtils;
import org.apache.commons.lang.StringUtils;
import org.opensaml.common.xml.SAMLConstants;
import org.wso2.carbon.identity.sso.agent.AESDecryptor;
import org.wso2.carbon.identity.sso.agent.util.SSOAgentConstants;
import org.wso2.carbon.identity.sso.agent.exception.SSOAgentException;
import org.wso2.carbon.identity.sso.agent.openid.AttributesRequestor;
import org.wso2.carbon.identity.sso.agent.security.SSOAgentCarbonX509Credential;
import org.wso2.carbon.identity.sso.agent.security.SSOAgentX509Credential;

import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyStore;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;

public class SSOAgentConfig {

    private static final Logger LOGGER = Logger.getLogger(SSOAgentConstants.LOGGER_NAME);
    private static final String ARGUMENT = "sun.java.command";

    private Boolean isSAML2SSOLoginEnabled = false;
    private Boolean isOpenIdLoginEnabled = false;
    private Boolean isOAuth2SAML2GrantEnabled = false;
    private Boolean isDynamicAppRegistrationEnabled = false;
    private Boolean isDynamicSAMLConfigEnabled = false;

    private String saml2SSOURL = null;
    private String openIdURL = null;
    private String oauth2SAML2GrantURL = null;
    private Set<String> skipURIs = new HashSet<String>();

    private Map<String, String[]> queryParams = new HashMap<String, String[]>();

    private SAML2 saml2 = new SAML2();
    private OpenID openId = new OpenID();
    private OAuth2 oauth2 = new OAuth2();
    private String requestQueryParameters;
    private Boolean enableHostNameVerification = false;
    private Boolean enableSSLVerification = false;
    private InputStream keyStoreStream;
    private String keyStorePassword;
    private KeyStore keyStore;
    private String privateKeyPassword;
    private String privateKeyAlias;
    private String idpPublicCertAlias;

    public SSOAgentConfig(Properties ssoProperties) {
        try {
            initConfig(ssoProperties);
        } catch (SSOAgentException e) {
            LOGGER.log(Level.INFO, "Error occurred during Agent configuration. Cannot proceed Further ");
        }
    }

    public SSOAgentConfig() {

    }

    public Boolean getEnableHostNameVerification() {
        return enableHostNameVerification;
    }

    public void setEnableHostNameVerification(String enableHostNameVerificationString) {
        if (enableHostNameVerificationString != null) {
            enableHostNameVerification =
                    Boolean.parseBoolean(enableHostNameVerificationString);
        }
    }

    public Boolean getEnableSSLVerification() {
        return enableSSLVerification;
    }

    public void setEnableSSLVerification(String enableSSLVerificationString) {
        if (enableSSLVerificationString != null) {
            this.enableSSLVerification = Boolean.parseBoolean(enableSSLVerificationString);
        }
    }


    public String getRequestQueryParameters() {
        return requestQueryParameters;
    }

    public void setRequestQueryParameters(String requestQueryParameters) {
        this.requestQueryParameters = requestQueryParameters;
    }

    public Boolean isSAML2SSOLoginEnabled() {
        return isSAML2SSOLoginEnabled;
    }

    public Boolean isOpenIdLoginEnabled() {
        return isOpenIdLoginEnabled;
    }

    public Boolean isDynamicAppRegistrationEnabled() {
        return isDynamicAppRegistrationEnabled;
    }

    public void setDynamicAppRegistrationEnabled(String isDynamicAppRegistrationEnabledString) {
        if (isDynamicAppRegistrationEnabledString != null) {
            this.isDynamicAppRegistrationEnabled = Boolean.parseBoolean(isDynamicAppRegistrationEnabledString);
        } else {
            LOGGER.log(Level.FINE, SSOAgentConstants.SSOAgentConfig.ENABLE_DYNAMIC_APP_REGISTRATION +
                    " not configured. Defaulting to \'false\'");
            this.isDynamicAppRegistrationEnabled = false;
        }
    }

    public Boolean isDynamicSAMLConfigEnabled() {
        return isDynamicSAMLConfigEnabled;
    }

    public void setIsDynamicSAMLConfigEnabled(String isDynamicSAMLConfigEnabledString) {
        if (isDynamicSAMLConfigEnabledString != null) {
            isDynamicSAMLConfigEnabled = Boolean.parseBoolean(isDynamicSAMLConfigEnabledString);
        } else {
            LOGGER.log(Level.FINE, SSOAgentConstants.SSOAgentConfig.ENABLE_DYNAMIC_SAML_CONFIGURATION +
                    " not configured. Defaulting to \'false\'");
            isDynamicSAMLConfigEnabled = false;
        }
    }

    public Boolean isOAuth2SAML2GrantEnabled() {
        return isOAuth2SAML2GrantEnabled;
    }

    public String getSAML2SSOURL() {
        return saml2SSOURL;
    }

    public void setSAML2SSOURL(String saml2SSOURL) {
        this.saml2SSOURL = saml2SSOURL;
    }

    public String getOpenIdURL() {
        return openIdURL;
    }

    public void setOpenIdURL(String openIdURL) {
        this.openIdURL = openIdURL;
    }

    public String getOAuth2SAML2GrantURL() {
        return oauth2SAML2GrantURL;
    }

    public void setOAuth2SAML2GrantURL(String oauth2SAML2GrantURL) {
        this.oauth2SAML2GrantURL = oauth2SAML2GrantURL;
    }

    public Set<String> getSkipURIs() {
        return skipURIs;
    }

    public void setSkipURIs(String skipURIsString) {
        if (!StringUtils.isBlank(skipURIsString)) {
            String[] skipURIArray = skipURIsString.split(",");
            for (String skipURI : skipURIArray) {
                skipURIs.add(skipURI);
            }
        }
    }

    public Map<String, String[]> getQueryParams() {
        return queryParams;
    }

    public void setQueryParams(String queryParamsString) {
        if (!StringUtils.isBlank(queryParamsString)) {
            String[] queryParamsArray = queryParamsString.split("&");
            Map<String, List<String>> queryParamMap = new HashMap<String, List<String>>();
            if (queryParamsArray.length > 0) {
                for (String queryParam : queryParamsArray) {
                    String[] splitParam = queryParam.split("=");
                    if (splitParam.length == 2) {
                        if (queryParamMap.get(splitParam[0]) != null) {
                            queryParamMap.get(splitParam[0]).add(splitParam[1]);
                        } else {
                            List<String> newList = new ArrayList<String>();
                            newList.add(splitParam[1]);
                            queryParamMap.put(splitParam[0], newList);
                        }
                    }

                }
                for (Map.Entry<String, List<String>> entry : queryParamMap.entrySet()) {
                    String[] valueArray = entry.getValue().toArray(new String[entry.getValue().size()]);
                    queryParams.put(entry.getKey(), valueArray);
                }
            }
        }
    }

    public SAML2 getSAML2() {
        return saml2;
    }

    public OAuth2 getOAuth2() {
        return oauth2;
    }

    public OpenID getOpenId() {
        return openId;
    }

    public void setSAML2SSOLoginEnabled(String isSAML2SSOLoginEnabledString) {
        if (isSAML2SSOLoginEnabledString != null) {
            isSAML2SSOLoginEnabled = Boolean.parseBoolean(isSAML2SSOLoginEnabledString);
        } else {
            LOGGER.log(Level.FINE, SSOAgentConstants.SSOAgentConfig.ENABLE_SAML2_SSO_LOGIN +
                    " not configured. Defaulting to \'false\'");
            isSAML2SSOLoginEnabled = false;
        }
    }

    public void setOpenIdLoginEnabled(String isOpenIdLoginEnabledString) {
        if (isOpenIdLoginEnabledString != null) {
            isOpenIdLoginEnabled = Boolean.parseBoolean(isOpenIdLoginEnabledString);
        } else {
            LOGGER.log(Level.FINE, SSOAgentConstants.SSOAgentConfig.ENABLE_OPENID_SSO_LOGIN +
                    " not configured. Defaulting to \'false\'");
            isOpenIdLoginEnabled = false;
        }
    }

    public void setOAuth2SAML2GrantEnabled(String isSAML2OAuth2GrantEnabledString) {
        if (isSAML2OAuth2GrantEnabledString != null) {
            this.isOAuth2SAML2GrantEnabled = Boolean.parseBoolean(isSAML2OAuth2GrantEnabledString);
        } else {
            LOGGER.log(Level.FINE, SSOAgentConstants.SSOAgentConfig.ENABLE_OAUTH2_SAML2_OAUTH2_GRANT +
                    " not configured. Defaulting to \'false\'");
            this.isOAuth2SAML2GrantEnabled = false;
        }
    }

    private InputStream getKeyStoreStream() {
        return keyStoreStream;
    }

    public void setKeyStoreStream(String keyStoreString) throws SSOAgentException {
        if (keyStoreString != null) {
            try {
                this.keyStoreStream = new FileInputStream(keyStoreString);
            } catch (FileNotFoundException e) {
                throw new SSOAgentException("Cannot find file " + keyStoreString, e);
            }
        }
    }

    public String getPrivateKeyPassword() {
        return privateKeyPassword;
    }

    public String getPrivateKeyAlias() {
        return privateKeyAlias;
    }

    public String getIdPPublicCertAlias() {
        return idpPublicCertAlias;
    }

    public void setPrivateKeyPassword(String privateKeyPassword) {
        this.privateKeyPassword = privateKeyPassword;
    }

    public void setPrivateKeyAlias(String privateKeyAlias) {
        this.privateKeyAlias = privateKeyAlias;
    }

    public void setIdpPublicCertAlias(String idpPublicCertAlias) {
        this.idpPublicCertAlias = idpPublicCertAlias;
    }

    public String getKeyStorePassword() {
        return keyStorePassword;
    }

    public void setKeyStorePassword(String keyStorePassword) {
        this.keyStorePassword = keyStorePassword;
    }

    public KeyStore getKeyStore() throws org.wso2.carbon.identity.sso.agent.exception.SSOAgentException {
        if (keyStore == null) {
            setKeyStore(readKeyStore(getKeyStoreStream(), getKeyStorePassword()));
        }
        return keyStore;
    }

    public void setKeyStore(KeyStore keyStore) {
        this.keyStore = keyStore;
    }

    private void initConfig(Properties properties) throws SSOAgentException {

        decryptEncryptedProperties(properties);

        setPrivateKeyPassword(properties.getProperty(SSOAgentConstants.PRIVATE_KEY_PASSWORD));
        setPrivateKeyAlias(properties.getProperty(SSOAgentConstants.PRIVATE_KEY_ALIAS));
        setIdpPublicCertAlias(properties.getProperty(SSOAgentConstants.IDP_PUBLIC_CERT_ALIAS));
        setEnableSSLVerification(properties.getProperty(SSOAgentConstants.SSL.ENABLE_SSL_VERIFICATION));
        setEnableHostNameVerification(properties.getProperty(SSOAgentConstants.SSL.ENABLE_SSL_HOST_NAME_VERIFICATION));
        setRequestQueryParameters(properties.getProperty(SSOAgentConstants.SSOAgentConfig.SAML_REQUEST_QUERY_PARAM));

        setSAML2SSOLoginEnabled(properties.getProperty(SSOAgentConstants.SSOAgentConfig.ENABLE_SAML2_SSO_LOGIN));
        setOpenIdLoginEnabled(properties.getProperty(SSOAgentConstants.SSOAgentConfig.ENABLE_OPENID_SSO_LOGIN));
        setOAuth2SAML2GrantEnabled(properties.getProperty(
                SSOAgentConstants.SSOAgentConfig.ENABLE_OAUTH2_SAML2_OAUTH2_GRANT));

        setDynamicAppRegistrationEnabled(properties.getProperty(
                SSOAgentConstants.SSOAgentConfig.ENABLE_DYNAMIC_APP_REGISTRATION));
        setIsDynamicSAMLConfigEnabled(properties.getProperty(
                SSOAgentConstants.SSOAgentConfig.ENABLE_DYNAMIC_SAML_CONFIGURATION));

        setSAML2SSOURL(properties.getProperty(SSOAgentConstants.SSOAgentConfig.SAML2_SSO_URL));
        setOpenIdURL(properties.getProperty(SSOAgentConstants.SSOAgentConfig.OPENID_URL));
        setOAuth2SAML2GrantURL(properties.getProperty(SSOAgentConstants.SSOAgentConfig.OAUTH2_SAML2_GRANT_URL));
        setSkipURIs(properties.getProperty(SSOAgentConstants.SSOAgentConfig.SKIP_URIS));
        setQueryParams(properties.getProperty(SSOAgentConstants.SSOAgentConfig.QUERY_PARAMS));

        performSAMLSpecificConfigurations(properties,saml2);
        performOAUTH2SpecificConfigurations(properties,oauth2);
        performOpenIDSpecificConfigurations(properties,openId);

        setKeyStoreStream(properties.getProperty("KeyStore"));
        setKeyStorePassword(properties.getProperty("KeyStorePassword"));

        initializeSSLContext();
    }

    private void performOpenIDSpecificConfigurations(Properties properties, OpenID openId) {
        openId.setProviderURL(properties.getProperty(SSOAgentConstants.SSOAgentConfig.OpenID.PROVIDER_URL));
        openId.setReturnToURL(properties.getProperty(SSOAgentConstants.SSOAgentConfig.OpenID.RETURN_TO_URL));
        openId.setAttributeExchangeEnabled(properties.getProperty(
                SSOAgentConstants.SSOAgentConfig.OpenID.ENABLE_ATTRIBUTE_EXCHANGE));
        openId.setDumbModeEnabled(properties.getProperty(
                SSOAgentConstants.SSOAgentConfig.OpenID.ENABLE_DUMB_MODE));
    }

    private void performOAUTH2SpecificConfigurations(Properties properties, OAuth2 oauth2) {
        oauth2.setTokenURL(properties.getProperty(SSOAgentConstants.SSOAgentConfig.OAuth2.TOKEN_URL));
        oauth2.setClientId(properties.getProperty(SSOAgentConstants.SSOAgentConfig.OAuth2.CLIENT_ID));
        oauth2.setClientSecret(properties.getProperty(SSOAgentConstants.SSOAgentConfig.OAuth2.CLIENT_SECRET));
    }

    private void performSAMLSpecificConfigurations(Properties properties, SAML2 saml2) throws SSOAgentException {
        saml2.setHttpBinding(properties.getProperty(SSOAgentConstants.SSOAgentConfig.SAML2.HTTP_BINDING));
        saml2.setSPEntityId(properties.getProperty(SSOAgentConstants.SSOAgentConfig.SAML2.SP_ENTITY_ID));
        saml2.setACSURL(properties.getProperty(SSOAgentConstants.SSOAgentConfig.SAML2.ACS_URL));
        saml2.setIdPEntityId(properties.getProperty(SSOAgentConstants.SSOAgentConfig.SAML2.IDP_ENTITY_ID));
        saml2.setIdPURL(properties.getProperty(SSOAgentConstants.SSOAgentConfig.SAML2.IDP_URL));
        saml2.setAttributeConsumingServiceIndex(properties.getProperty(
                SSOAgentConstants.SSOAgentConfig.SAML2.ATTRIBUTE_CONSUMING_SERVICE_INDEX));
        saml2.setSLOEnabled(properties.getProperty(
                SSOAgentConstants.SSOAgentConfig.SAML2.ENABLE_SLO));
        saml2.setSLOURL(properties.getProperty(SSOAgentConstants.SSOAgentConfig.SAML2.SLO_URL));

        saml2.setAssertionSigned(properties.getProperty(
                SSOAgentConstants.SSOAgentConfig.SAML2.ENABLE_ASSERTION_SIGNING));
        saml2.setAssertionEncrypted(properties.getProperty(
                SSOAgentConstants.SSOAgentConfig.SAML2.ENABLE_ASSERTION_ENCRYPTION));
        saml2.setResponseSigned(properties.getProperty(SSOAgentConstants.SSOAgentConfig.SAML2.ENABLE_RESPONSE_SIGNING));
        saml2.setSignatureValidatorImplClass(properties.getProperty(
                SSOAgentConstants.SSOAgentConfig.SAML2.SIGNATURE_VALIDATOR));

        saml2.setRequestSigned(properties.getProperty(SSOAgentConstants.SSOAgentConfig.SAML2.ENABLE_REQUEST_SIGNING));
        saml2.setPassiveAuthn(properties.getProperty(SSOAgentConstants.SSOAgentConfig.SAML2.IS_PASSIVE_AUTHN));
        saml2.setForceAuthn(properties.getProperty(SSOAgentConstants.SSOAgentConfig.SAML2.IS_FORCE_AUTHN));
        saml2.setRelayState(properties.getProperty(SSOAgentConstants.SSOAgentConfig.SAML2.RELAY_STATE));
        saml2.setPostBindingRequestHTMLPayload(properties.getProperty(
                SSOAgentConstants.SSOAgentConfig.SAML2.POST_BINDING_REQUEST_HTML_PAYLOAD));
        saml2.setTimeStampSkewInSeconds(properties.getProperty(SSOAgentConstants.SSOAgentConfig.SAML2.TIME_STAMP_SKEW));
    }

    private void initializeSSLContext() throws SSOAgentException {
        SSLContext sc;
        try {
            // Get SSL context

            sc = SSLContext.getInstance("SSL");
            doHostNameVerification();
            TrustManager[] trustManagers = doSSLVerification();

            sc.init(null, trustManagers, new java.security.SecureRandom());
            SSLSocketFactory sslSocketFactory = sc.getSocketFactory();
            HttpsURLConnection.setDefaultSSLSocketFactory(sslSocketFactory);

        } catch (Exception e) {
            throw new SSOAgentException("An error occurred while initializing SSL Context");
        }
    }

    private void decryptEncryptedProperties(Properties properties) throws SSOAgentException {
        String decodedPassword;
        boolean isReadpassword = false;
        char[] password = null;

        // Get copy of properties for looping in order to avoid ConcurrentModificationException.
        Properties copyOfProperties = new Properties();
        copyOfProperties.putAll(properties);

        // Path of the password file.
        String filePath = System.getProperty("catalina.home") + SSOAgentConstants.SSOAgentConfig.PASSWORD_FILEPATH;

        // Looping through properties to check the encrypted property value by checking the prefix Enc:.
        for (Map.Entry<Object, Object> entry : copyOfProperties.entrySet()) {
            if (String.valueOf(entry.getValue()).startsWith("Enc:")) {
                if (!System.getProperty(ARGUMENT).contains("password")) {

                    // Check whether the password has been already read.
                    if (!isReadpassword) {
                        Path path = Paths.get(filePath);
                        try (BufferedReader reader = Files.newBufferedReader(path, Charset.forName("UTF-8"))) {
                            StringBuilder currentLine = new StringBuilder();

                            // Read the password from the password file.
                            currentLine.append(reader.readLine());
                            if (currentLine.length() > 0) {
                                password = new char[currentLine.length()];
                                currentLine.getChars(0, currentLine.length(), password, 0);
                                currentLine = null;
                            }
                            isReadpassword = true;
                            if (Files.deleteIfExists(path)) {
                                LOGGER.info("Deleted the temporary password file at " + path);
                            }
                        } catch (IOException ex) {
                            throw new SSOAgentException("Error while reading the file ", ex);
                        }
                    }
                } else if (!isReadpassword) {

                    // Read password from the console.
                    System.out.print("Enter password for decryption:");
                    password = System.console().readPassword();
                    isReadpassword = true;
                }
                if (ArrayUtils.isEmpty(password)) {
                    LOGGER.log(Level.SEVERE, "Can't find the password to decrypt the encrypted values.");
                    return;
                }

                // Get the encrypted property value.
                String encryptedValue = String.valueOf(entry.getValue());

                // Remove the Enc: prefix and get the actual encrypted value.
                if (encryptedValue.split(":").length > 1) {
                    decodedPassword = AESDecryptor.decrypt(String.valueOf(entry.getValue()).split
                            (":")[1].trim(), password);

                    // Remove the encrypted property value and replace with decrypted property value (plain text)
                    properties.remove(String.valueOf(entry.getKey()));
                    properties.setProperty(String.valueOf(entry.getKey()), decodedPassword);
                } else {
                    LOGGER.log(Level.SEVERE, "Encrypted value is not in the correct format. Encrypted value " +
                            "must contain the encrypted value with Enc: as prefix.");
                    return;
                }
            }
        }

        // Delete the stored password from memory by filling with zeros.
        if (password != null) {
            Arrays.fill(password, (char) 0);
        }
    }

    public void verifyConfig() throws SSOAgentException {

        if (isSAML2SSOLoginEnabled && saml2SSOURL == null) {
            throw new SSOAgentException("\'" +
                    SSOAgentConstants.SSOAgentConfig.SAML2_SSO_URL + "\' not configured");
        }

        if (isOpenIdLoginEnabled && openIdURL == null) {
            throw new SSOAgentException("\'" +
                    SSOAgentConstants.SSOAgentConfig.OPENID_URL + "\' not configured");
        }

        if (!isSAML2SSOLoginEnabled && isOAuth2SAML2GrantEnabled) {
            throw new SSOAgentException(
                    "SAML2 SSO Login is disabled. Cannot use SAML2 Bearer Grant type for OAuth2");
        }

        if (isSAML2SSOLoginEnabled && isOAuth2SAML2GrantEnabled && oauth2SAML2GrantURL == null) {
            throw new SSOAgentException("\'" +
                    SSOAgentConstants.SSOAgentConfig.OAUTH2_SAML2_GRANT_URL + "\' not configured");
        }

        if (isSAML2SSOLoginEnabled && saml2.spEntityId == null) {
            throw new SSOAgentException("\'" +
                    SSOAgentConstants.SSOAgentConfig.SAML2.SP_ENTITY_ID + "\' not configured");
        }

        if (isSAML2SSOLoginEnabled && saml2.acsURL == null) {
            throw new SSOAgentException("\'" +
                    SSOAgentConstants.SSOAgentConfig.SAML2.ACS_URL + "\' not configured");
        }

        if (isSAML2SSOLoginEnabled && saml2.idPEntityId == null) {
            throw new SSOAgentException("\'" +
                    SSOAgentConstants.SSOAgentConfig.SAML2.IDP_ENTITY_ID + "\' not configured");
        }

        if (isSAML2SSOLoginEnabled && saml2.idPURL == null) {
            throw new SSOAgentException("\'" +
                    SSOAgentConstants.SSOAgentConfig.SAML2.IDP_URL + "\' not configured");
        }

        if (isSAML2SSOLoginEnabled && saml2.attributeConsumingServiceIndex == null) {
            LOGGER.log(Level.FINE,
                    "\'" + SSOAgentConstants.SSOAgentConfig.SAML2.ATTRIBUTE_CONSUMING_SERVICE_INDEX +
                            "\' not configured. " + "No attributes of the Subject will be requested");
        }

        if (isSAML2SSOLoginEnabled && saml2.isSLOEnabled && saml2.sloURL == null) {
            throw new SSOAgentException("Single Logout enabled, but SLO URL not configured");
        }

        if (isSAML2SSOLoginEnabled &&
                (saml2.isAssertionSigned || saml2.isAssertionEncrypted || saml2.isResponseSigned ||
                        saml2.isRequestSigned) && saml2.ssoAgentX509Credential == null) {
            LOGGER.log(Level.FINE,
                    "\'SSOAgentX509Credential\' not configured. Defaulting to " +
                            SSOAgentCarbonX509Credential.class.getName());
        }

        if (isSAML2SSOLoginEnabled &&
                (saml2.isAssertionSigned || saml2.isResponseSigned) &&
                saml2.ssoAgentX509Credential.getEntityCertificate() == null) {
            throw new SSOAgentException("Public certificate of IdP not configured");
        }

        if (isSAML2SSOLoginEnabled &&
                (saml2.isRequestSigned || saml2.isAssertionEncrypted) &&
                saml2.ssoAgentX509Credential.getPrivateKey() == null) {
            throw new SSOAgentException("Private key of SP not configured");
        }

        if (isOpenIdLoginEnabled && openId.providerURL == null) {
            throw new SSOAgentException("\'" +
                    SSOAgentConstants.SSOAgentConfig.OpenID.PROVIDER_URL + "\' not configured");
        }

        if (isOpenIdLoginEnabled && openId.returnToURL == null) {
            throw new SSOAgentException("\'" +
                    SSOAgentConstants.SSOAgentConfig.OpenID.RETURN_TO_URL + "\' not configured");
        }

        if (isOpenIdLoginEnabled && openId.attributesRequestor == null) {
            LOGGER.log(Level.FINE, "\'" +
                    SSOAgentConstants.SSOAgentConfig.OpenID.PROVIDER_URL +
                    "\' not configured. " + "No attributes of the Subject will be fetched");
        }

        if (isSAML2SSOLoginEnabled && isOAuth2SAML2GrantEnabled && oauth2.tokenURL == null) {
            throw new SSOAgentException("OAuth2 Token endpoint not configured");
        }

        if (isSAML2SSOLoginEnabled && isOAuth2SAML2GrantEnabled && oauth2.clientId == null) {
            throw new SSOAgentException("OAuth2 Client Id not configured");
        }

        if (isSAML2SSOLoginEnabled && isOAuth2SAML2GrantEnabled && oauth2.clientSecret == null) {
            throw new SSOAgentException("OAuth2 Client Secret not configured");
        }

    }

    /**
     * get the key store instance
     *
     * @param is            KeyStore InputStream
     * @param storePassword password of key store
     * @return KeyStore instant
     * @throws org.wso2.carbon.identity.sso.agent.exception.SSOAgentException if fails to load key store
     */
    private KeyStore readKeyStore(InputStream is, String storePassword) throws
            org.wso2.carbon.identity.sso.agent.exception.SSOAgentException {

        if (storePassword == null) {
            throw new org.wso2.carbon.identity.sso.agent.exception.SSOAgentException("KeyStore password can not be null");
        }

        try {
            KeyStore keyStore = KeyStore.getInstance("JKS");
            keyStore.load(is, storePassword.toCharArray());
            return keyStore;
        } catch (Exception e) {

            throw new org.wso2.carbon.identity.sso.agent.exception.SSOAgentException("Error while loading key store file", e);
        } finally {
            if (is != null) {
                try {
                    is.close();
                } catch (IOException ignored) {

                    throw new org.wso2.carbon.identity.sso.agent.exception.SSOAgentException("Error while closing input stream of key store", ignored);
                }
            }
        }
    }

    private void doHostNameVerification() {
        if (!this.getEnableHostNameVerification()) {
            // Create empty HostnameVerifier
            HostnameVerifier hv = new HostnameVerifier() {
                public boolean verify(String urlHostName, SSLSession session) {
                    return true;
                }
            };
            HttpsURLConnection.setDefaultHostnameVerifier(hv);
        }
    }

    private TrustManager[] doSSLVerification() throws Exception {
        TrustManager[] trustManagers = null;
        if (this.getEnableSSLVerification()) {
            TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            tmf.init(this.getKeyStore());
            trustManagers = tmf.getTrustManagers();
        } else {
            // Create a trust manager that does not validate certificate chains
            trustManagers = new TrustManager[]{new X509TrustManager() {
                public java.security.cert.X509Certificate[] getAcceptedIssuers() {
                    return null;
                }

                public void checkClientTrusted(java.security.cert.X509Certificate[] certs,
                                               String authType) {
                }

                public void checkServerTrusted(java.security.cert.X509Certificate[] certs,
                                               String authType) {
                }
            }};
        }
        return trustManagers;
    }

    public class SAML2 {

        private String httpBinding = null;
        private String spEntityId = null;
        private String acsURL = null;
        private String idPEntityId = null;
        private String idPURL = null;
        private Boolean isSLOEnabled = false;
        private String sloURL = null;
        private String attributeConsumingServiceIndex = null;
        private SSOAgentX509Credential ssoAgentX509Credential = null;
        private Boolean isAssertionSigned = false;
        private Boolean isAssertionEncrypted = false;
        private Boolean isResponseSigned = false;
        private Boolean isRequestSigned = false;
        private Boolean isPassiveAuthn = false;
        private Boolean isForceAuthn = false;
        private String relayState = null;
        private String signatureValidatorImplClass = null;
        private int timeStampSkewInSeconds = 300;
        /**
         * The html page that will auto-submit the SAML2 to the IdP.
         * This should be in valid HTML syntax, with following section within the
         * auto-submit form.
         * "&lt;!--$saml_params--&gt;"
         * This section will be replaced by the SAML2 parameters.
         * <p/>
         * If the parameter value is empty, null or doesn't have the above
         * section, the default page will be shown
         */
        private String postBindingRequestHTMLPayload = null;

        public String getHttpBinding() {
            return httpBinding;
        }

        public void setHttpBinding(String httpBinding) {
            if (httpBinding == null || httpBinding.isEmpty()) {
                LOGGER.log(Level.FINE, SSOAgentConstants.SSOAgentConfig.SAML2.HTTP_BINDING +
                        " not configured. Defaulting to \'" + SAMLConstants.SAML2_POST_BINDING_URI + "\'");
                this.httpBinding = SAMLConstants.SAML2_POST_BINDING_URI;
            } else {
                this.httpBinding = httpBinding;
            }
        }

        public String getSPEntityId() {
            return spEntityId;
        }

        public void setSPEntityId(String spEntityId) throws SSOAgentException {
            if (StringUtils.isBlank(spEntityId)) {
                throw new SSOAgentException(SSOAgentConstants.SSOAgentConfig.SAML2.SP_ENTITY_ID
                        + " context-param is not specified in the web.xml. Cannot proceed Further.");
            } else {
                this.spEntityId = spEntityId;
            }
        }

        public String getACSURL() {
            return acsURL;
        }

        public void setACSURL(String acsURL) throws SSOAgentException {
            if (StringUtils.isBlank(acsURL)) {
                throw new SSOAgentException(SSOAgentConstants.SSOAgentConfig.SAML2.ACS_URL
                        + " context-param is not specified in the web.xml. Cannot proceed Further.");
            } else {
                this.acsURL = acsURL;
            }
        }

        public String getIdPEntityId() {
            return idPEntityId;
        }

        public void setIdPEntityId(String idPEntityId) throws SSOAgentException {
            if (StringUtils.isBlank(idPEntityId)) {
                throw new SSOAgentException(SSOAgentConstants.SSOAgentConfig.SAML2.IDP_ENTITY_ID
                        + " context-param is not specified in the web.xml. Cannot proceed Further.");
            } else {
                this.idPEntityId = idPEntityId;
            }
        }

        public String getIdPURL() {
            return idPURL;
        }

        public void setIdPURL(String idPURL) throws SSOAgentException {
            if (StringUtils.isBlank(idPURL)) {
                throw new SSOAgentException(SSOAgentConstants.SSOAgentConfig.SAML2.IDP_URL
                        + " context-param is not specified in the web.xml. Cannot proceed Further.");
            } else {
                this.idPURL = idPURL;
            }
        }

        public Boolean isSLOEnabled() {
            return isSLOEnabled;
        }

        public String getSLOURL() {
            return sloURL;
        }

        public void setSLOURL(String sloURL) {
            this.sloURL = sloURL;
        }

        public String getAttributeConsumingServiceIndex() {
            return attributeConsumingServiceIndex;
        }

        public void setAttributeConsumingServiceIndex(String attributeConsumingServiceIndex) {
            if (StringUtils.isBlank(attributeConsumingServiceIndex)) {
                LOGGER.log(Level.INFO, "Attribute Consuming Service index is not specified.IDP configuration is " +
                        "required to get user attributes.");
            } else {
                this.attributeConsumingServiceIndex = attributeConsumingServiceIndex;
            }
        }

        public SSOAgentX509Credential getSSOAgentX509Credential() {
            return ssoAgentX509Credential;
        }

        public void setSSOAgentX509Credential(SSOAgentX509Credential ssoAgentX509Credential) {
            this.ssoAgentX509Credential = ssoAgentX509Credential;
        }

        public Boolean isAssertionSigned() {
            return isAssertionSigned;
        }

        public Boolean isAssertionEncrypted() {
            return isAssertionEncrypted;
        }

        public Boolean isResponseSigned() {
            return isResponseSigned;
        }

        public Boolean isRequestSigned() {
            return isRequestSigned;
        }

        public Boolean isPassiveAuthn() {
            return isPassiveAuthn;
        }

        public Boolean isForceAuthn() {
            return isForceAuthn;
        }

        public String getRelayState() {
            return relayState;
        }

        public void setRelayState(String relayState) {
            this.relayState = relayState;
        }

        public String getPostBindingRequestHTMLPayload() {
            return postBindingRequestHTMLPayload;
        }

        public void setPostBindingRequestHTMLPayload(String postBindingRequestHTMLPayload) {
            this.postBindingRequestHTMLPayload = postBindingRequestHTMLPayload;
        }

        public void setSLOEnabled(String isSLOEnabledString) {
            if (isSLOEnabledString != null) {
                this.isSLOEnabled = Boolean.parseBoolean(isSLOEnabledString);
            } else {
                LOGGER.info("\'" + SSOAgentConstants.SSOAgentConfig.SAML2.ENABLE_SLO +
                        "\' not configured properly. Defaulting to \'false\'");
                this.isSLOEnabled = false;
            }
        }

        public void setAssertionSigned(String isAssertionSignedString) {
            if (isAssertionSignedString != null) {
                this.isAssertionSigned = Boolean.parseBoolean(isAssertionSignedString);
            } else {
                LOGGER.log(Level.FINE, SSOAgentConstants.SSOAgentConfig.SAML2.ENABLE_ASSERTION_SIGNING +
                        " not configured properly. Defaulting to \'false\'");
                this.isAssertionSigned = false;
            }
        }

        public void setAssertionEncrypted(String isAssertionEncryptedString) {
            if (isAssertionEncryptedString != null) {
                this.isAssertionEncrypted = Boolean.parseBoolean(isAssertionEncryptedString);
            } else {
                LOGGER.log(Level.FINE, SSOAgentConstants.SSOAgentConfig.SAML2.ENABLE_ASSERTION_ENCRYPTION +
                        " not configured properly. Defaulting to \'false\'");
                this.isAssertionEncrypted = false;
            }
        }

        public void setResponseSigned(String isResponseSignedString) {
            if (isResponseSignedString != null) {
                this.isResponseSigned = Boolean.parseBoolean(isResponseSignedString);
            } else {
                LOGGER.log(Level.FINE, SSOAgentConstants.SSOAgentConfig.SAML2.ENABLE_RESPONSE_SIGNING +
                        " not configured properly. Defaulting to \'false\'");
                this.isResponseSigned = false;
            }
        }

        public void setRequestSigned(String isRequestSignedString) {
            if (isRequestSignedString != null) {
                this.isRequestSigned = Boolean.parseBoolean(isRequestSignedString);
            } else {
                LOGGER.log(Level.FINE, SSOAgentConstants.SSOAgentConfig.SAML2.ENABLE_REQUEST_SIGNING +
                        " not configured. Defaulting to \'false\'");
                this.isRequestSigned = false;
            }
        }

        public void setPassiveAuthn(String isPassiveAuthnString) {
            if (isPassiveAuthnString != null) {
                this.isPassiveAuthn = Boolean.parseBoolean(isPassiveAuthnString);
            } else {
                LOGGER.log(Level.FINE, "\'" + SSOAgentConstants.SSOAgentConfig.SAML2.IS_PASSIVE_AUTHN +
                        "\' not configured. Defaulting to \'false\'");
                this.isPassiveAuthn = false;
            }
        }

        public void setPassiveAuthn(Boolean isPassiveAuthn){
            this.isPassiveAuthn = isPassiveAuthn;
        }

        public void setForceAuthn(String isForceAuthnString) {
            if (isForceAuthnString != null) {
                this.isForceAuthn = Boolean.parseBoolean(isForceAuthnString);
            } else {
                LOGGER.log(Level.FINE, "\'" + SSOAgentConstants.SSOAgentConfig.SAML2.IS_FORCE_AUTHN +
                        "\' not configured. Defaulting to \'false\'");
                this.isForceAuthn = false;
            }
        }

        public String getSignatureValidatorImplClass() {
            return signatureValidatorImplClass;
        }

        public void setSignatureValidatorImplClass(String signatureValidatorImplClass) {
            if (this.isResponseSigned() || this.isAssertionSigned()) {
                if (signatureValidatorImplClass != null) {
                    this.signatureValidatorImplClass = signatureValidatorImplClass;
                } else {
                    LOGGER.log(Level.FINE, SSOAgentConstants.SSOAgentConfig.SAML2.SIGNATURE_VALIDATOR +
                            " not configured.");
                }
            }
        }

        public int getTimeStampSkewInSeconds() {
            return timeStampSkewInSeconds;
        }

        public void setTimeStampSkewInSeconds(String timeStampSkewInSecondsString) {
            if (timeStampSkewInSecondsString != null) {
                this.timeStampSkewInSeconds = Integer.parseInt(timeStampSkewInSecondsString);
            } else {
                LOGGER.log(Level.FINE, SSOAgentConstants.SSOAgentConfig.SAML2.TIME_STAMP_SKEW +
                        " not configured. Defaulting to 300s");
            }
        }

    }

    public class OpenID {

        private String mode = null;
        private String providerURL = null;
        private String returnToURL = null;
        private String claimedId = null;
        private AttributesRequestor attributesRequestor = null;
        private boolean isAttributeExchangeEnabled = false;
        private boolean isDumbModeEnabled = false;

        public String getMode() {
            return mode;
        }

        public void setMode(String mode) {
            this.mode = mode;
        }

        public String getProviderURL() {
            return providerURL;
        }

        public void setProviderURL(String providerURL) {
            this.providerURL = providerURL;
        }

        public String getReturnToURL() {
            return returnToURL;
        }

        public void setReturnToURL(String returnToURL) {
            this.returnToURL = returnToURL;
        }

        public String getClaimedId() {
            return claimedId;
        }

        public void setClaimedId(String claimedId) {
            this.claimedId = claimedId;
        }

        public AttributesRequestor getAttributesRequestor() {
            return attributesRequestor;
        }

        public void setAttributesRequestor(AttributesRequestor attributesRequestor) {
            this.attributesRequestor = attributesRequestor;
        }

        public boolean isAttributeExchangeEnabled() {
            return isAttributeExchangeEnabled;
        }

        public void setAttributeExchangeEnabled(String isAttributeExchangeEnabledString) {
            if (isAttributeExchangeEnabledString != null) {
                this.isAttributeExchangeEnabled = Boolean.parseBoolean(isAttributeExchangeEnabledString);
            } else {
                LOGGER.log(Level.FINE, "\'" + SSOAgentConstants.SSOAgentConfig.OpenID.ENABLE_ATTRIBUTE_EXCHANGE +
                        "\' not configured. Defaulting to \'true\'");
                this.isAttributeExchangeEnabled = true;
            }
        }

        public boolean isDumbModeEnabled() {
            return isDumbModeEnabled;
        }

        public void setDumbModeEnabled(String isDumbModeEnabledString) {
            if (isDumbModeEnabledString != null) {
                this.isDumbModeEnabled = Boolean.parseBoolean(isDumbModeEnabledString);
            } else {
                LOGGER.log(Level.FINE, "\'" + SSOAgentConstants.SSOAgentConfig.OpenID.ENABLE_DUMB_MODE +
                        "\' not configured. Defaulting to \'false\'");
                this.isDumbModeEnabled = false;
            }
        }
    }

    public class OAuth2 {

        private String tokenURL = null;
        private String clientId = null;
        private String clientSecret = null;

        public String getClientSecret() {
            return clientSecret;
        }

        public void setClientSecret(String clientSecret) {
            this.clientSecret = clientSecret;
        }

        public String getTokenURL() {
            return tokenURL;
        }

        public void setTokenURL(String tokenURL) {
            this.tokenURL = tokenURL;
        }

        public String getClientId() {
            return clientId;
        }

        public void setClientId(String clientId) {
            this.clientId = clientId;
        }
    }
}
