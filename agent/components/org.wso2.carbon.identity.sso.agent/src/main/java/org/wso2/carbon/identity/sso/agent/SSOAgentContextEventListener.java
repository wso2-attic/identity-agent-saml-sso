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
package org.wso2.carbon.identity.sso.agent;

import org.apache.commons.lang.StringUtils;
import org.wso2.carbon.identity.sso.agent.bean.SSOAgentConfig;
import org.wso2.carbon.identity.sso.agent.exception.SSOAgentException;
import org.wso2.carbon.identity.sso.agent.security.SSOAgentX509Credential;
import org.wso2.carbon.identity.sso.agent.security.SSOAgentX509KeyStoreCredential;
import org.wso2.carbon.identity.sso.agent.util.SSOAgentConstants;

import java.io.IOException;
import java.io.InputStream;
import java.util.Enumeration;
import java.util.Properties;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.servlet.ServletContext;
import javax.servlet.ServletContextEvent;
import javax.servlet.ServletContextListener;

/**
 * Context Event Listener Class for SAML SSO. This class is used to perform saml configurations.
 * Initialization is performed in the following order.
 * 1. assignment of default values
 * 2. fetch values from context-params defined in web.xml
 * 3. read properties from sso.properties file.
 */
public class SSOAgentContextEventListener implements ServletContextListener {

    public static final String DEFAULT_SSO_PROPERTIES_FILE_NAME = "sso.properties";
    private static Logger logger = Logger.getLogger(SSOAgentContextEventListener.class.getName());

    @Override
    public void contextInitialized(ServletContextEvent servletContextEvent) {
        Properties ssoProperties = new Properties();
        try {
            ServletContext servletContext = servletContextEvent.getServletContext();

            String propertyFileName = getPropertyFileName(servletContext);
            loadSSOProperties(ssoProperties,servletContextEvent,propertyFileName);

            // Load the client security certificate, if not specified throw SSOAgentException.
            String certificateFileName = servletContext.getInitParameter(SSOAgentConstants
                    .CERTIFICATE_FILE_PARAMETER_NAME);
            InputStream keyStoreInputStream;
            if (StringUtils.isNotBlank(certificateFileName)) {
                keyStoreInputStream = servletContext.getResourceAsStream("/WEB-INF/classes/"
                        + certificateFileName);
            } else {
                throw new SSOAgentException(SSOAgentConstants.CERTIFICATE_FILE_PARAMETER_NAME
                        + " context-param is not specified in the web.xml");
            }

            SSOAgentX509Credential credential = new SSOAgentX509KeyStoreCredential(keyStoreInputStream,
                        ssoProperties.getProperty(SSOAgentConstants.KEY_STORE_PASSWORD).toCharArray(),
                        ssoProperties.getProperty(SSOAgentConstants.IDP_PUBLIC_CERT_ALIAS),
                        ssoProperties.getProperty(SSOAgentConstants.PRIVATE_KEY_ALIAS),
                        ssoProperties.getProperty(SSOAgentConstants.PRIVATE_KEY_PASSWORD).toCharArray());

            SSOAgentConfig config = new SSOAgentConfig();
            config.initConfig(ssoProperties);
            config.getSAML2().setSSOAgentX509Credential(credential);
            servletContext.setAttribute(SSOAgentConstants.CONFIG_BEAN_NAME, config);
        } catch (SSOAgentException e) {
            logger.log(Level.SEVERE,"An error occurred while trying to load sso properties: SSOAgentException: " +
                    e.getMessage(), e);
        }
    }

    private void loadSSOProperties(Properties ssoProperties, ServletContextEvent servletContextEvent,
                                   String propertyFileName) {
        loadDefaultValues(ssoProperties);
        readPropertiesFromContextParams(ssoProperties,servletContextEvent);
        readPropertiesFromPropertyFile(ssoProperties,servletContextEvent,propertyFileName);

        Enumeration effectivePropertyNames = ssoProperties.propertyNames();
        String effectivePropertiesString = "Final(Effective) Properties: ";
        String propertyName;
        while(effectivePropertyNames.hasMoreElements()){
            propertyName = effectivePropertyNames.nextElement().toString();
            effectivePropertiesString += propertyName + " = "+ssoProperties.getProperty(propertyName)+", ";
        }
        logger.log(Level.INFO,effectivePropertiesString);
    }

    private void readPropertiesFromPropertyFile(Properties ssoProperties, ServletContextEvent servletContextEvent,
                                                String propertyFileName) {
        Properties propertiesInPropertyFile = new Properties();

        try {
            propertiesInPropertyFile.load(servletContextEvent.getServletContext().
                    getResourceAsStream("/WEB-INF/classes/" + propertyFileName));
        } catch (IOException e) {
            logger.log(Level.INFO, String.format(" Error occurred while trying to load property file: %s",
                    propertyFileName));
        }

        Enumeration propertyFilePropertyNames = propertiesInPropertyFile.propertyNames();
        String propertyFilePropertyName;
        while(propertyFilePropertyNames.hasMoreElements()){
            propertyFilePropertyName = propertyFilePropertyNames.nextElement().toString();
            if(ssoProperties.getProperty(propertyFilePropertyName) == null){
                ssoProperties.setProperty(propertyFilePropertyName,propertiesInPropertyFile.
                        getProperty(propertyFilePropertyName));
            }else if(ssoProperties.getProperty(propertyFilePropertyName) != null){
                ssoProperties.replace(propertyFilePropertyName,propertiesInPropertyFile.
                        getProperty(propertyFilePropertyName));
            }
        }
    }


    private void readPropertiesFromContextParams(Properties ssoProperties, ServletContextEvent servletContextEvent) {
        ServletContext servletContext = servletContextEvent.getServletContext();
        Enumeration parameterNames = servletContext.getInitParameterNames();
        String contextParamName;

        while(parameterNames.hasMoreElements()){
            contextParamName = parameterNames.nextElement().toString();
            if(ssoProperties.getProperty(contextParamName) == null){
                ssoProperties.setProperty(contextParamName,servletContext.getInitParameter(contextParamName));
            }else if(ssoProperties.getProperty(contextParamName) != null){
                ssoProperties.replace(contextParamName,servletContext.getInitParameter(contextParamName));
            }
        }
    }

    private void loadDefaultValues(Properties ssoProperties) {
        ssoProperties.setProperty(SSOAgentConstants.SSOAgentConfig.ENABLE_SAML2_SSO_LOGIN, "true");
        ssoProperties.setProperty(SSOAgentConstants.SSOAgentConfig.SAML2_SSO_URL, "samlsso");
        ssoProperties.setProperty(SSOAgentConstants.SSOAgentConfig.SAML2.IDP_ENTITY_ID, "localhost");
        ssoProperties.setProperty(SSOAgentConstants.SSOAgentConfig.SAML2.IDP_URL,
                "https://localhost:9443/samlsso");
        ssoProperties.setProperty(SSOAgentConstants.SSOAgentConfig.SAML2.ENABLE_REQUEST_SIGNING, "true");

        ssoProperties.setProperty(SSOAgentConstants.SSOAgentConfig.SAML2.ENABLE_SLO, "true");
        ssoProperties.setProperty(SSOAgentConstants.SSOAgentConfig.SAML2.SLO_URL, "samllogout");

        ssoProperties.setProperty(SSOAgentConstants.KEY_STORE_PASSWORD, "wso2carbon");
        ssoProperties.setProperty(SSOAgentConstants.IDP_PUBLIC_CERT_ALIAS, "wso2carbon");
        ssoProperties.setProperty(SSOAgentConstants.PRIVATE_KEY_ALIAS, "wso2carbon");
        ssoProperties.setProperty("PrivateKeyPassword", "wso2carbon");
    }

    private String getPropertyFileName(ServletContext servletContext) {
        if(servletContext.getInitParameter(SSOAgentConstants.PROPERTY_FILE_PARAMETER_NAME) != null){
            return servletContext.getInitParameter(SSOAgentConstants.PROPERTY_FILE_PARAMETER_NAME);
        }
        return DEFAULT_SSO_PROPERTIES_FILE_NAME;
    }

    @Override
    public void contextDestroyed(ServletContextEvent servletContextEvent) {
    }

}
