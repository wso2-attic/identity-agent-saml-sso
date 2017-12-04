/*
 * Copyright 2017 WSO2.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.wso2.carbon.identity.sso.agent.bean;

import java.net.MalformedURLException;
import java.net.URL;
import java.rmi.RemoteException;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.apache.axis2.AxisFault;
import org.apache.axis2.client.Options;
import org.apache.axis2.client.ServiceClient;
import org.apache.axis2.context.ServiceContext;
import org.apache.axis2.transport.http.HTTPConstants;
import org.wso2.carbon.authenticator.stub.AuthenticationAdminStub;
import org.wso2.carbon.authenticator.stub.LoginAuthenticationExceptionException;
import org.wso2.carbon.identity.application.common.model.xsd.ApplicationBasicInfo;
import org.wso2.carbon.identity.application.common.model.xsd.InboundAuthenticationConfig;
import org.wso2.carbon.identity.application.common.model.xsd.InboundAuthenticationRequestConfig;
import org.wso2.carbon.identity.application.common.model.xsd.ServiceProvider;
import org.wso2.carbon.identity.application.mgt.stub.IdentityApplicationManagementServiceIdentityApplicationManagementException;
import org.wso2.carbon.identity.application.mgt.stub.IdentityApplicationManagementServiceStub;
import org.wso2.carbon.identity.sso.agent.exception.SSOAgentException;
import org.wso2.carbon.identity.sso.saml.stub.IdentitySAMLSSOConfigServiceIdentityException;
import org.wso2.carbon.identity.sso.saml.stub.IdentitySAMLSSOConfigServiceStub;
import org.wso2.carbon.identity.sso.saml.stub.types.SAMLSSOServiceProviderDTO;

/**
 * This class is used to check the application registration status in the IDP.
 * Further, this class provides the capability of dynamic app registration and saml configuration.
 */
public class AppRegistrationAndConfigBean {

    private static final Logger LOGGER = Logger.getLogger("logger");

    private String sessionCookie = "";
    private IdentityApplicationManagementServiceStub applicationMgtStub;
    private String appMgtEndPoint = "https://localhost:9443/services/IdentityApplicationManagementService";

    public AppRegistrationAndConfigBean() throws AxisFault, RemoteException, MalformedURLException, SSOAgentException {
        applicationMgtStub = new IdentityApplicationManagementServiceStub(appMgtEndPoint);
        authenticate();
    }

    private void authenticate() throws RemoteException, MalformedURLException, SSOAgentException {
        try {
            AuthenticationAdminStub authenticationStub = new AuthenticationAdminStub("https://localhost:9443/services/AuthenticationAdmin?wsdl");
            authenticationStub.login("admin", "admin", (new URL("https://localhost:9443/services/")).getHost());

            ServiceContext serviceContext = authenticationStub._getServiceClient()
                    .getLastOperationContext().getServiceContext();

            sessionCookie = (String) serviceContext.getProperty(HTTPConstants.COOKIE_STRING);

            ServiceClient client2 = applicationMgtStub._getServiceClient();
            Options option2 = client2.getOptions();
            option2.setManageSession(true);

            // set the session cookie of the previous call to AuthenticationAdmin service
            option2.setProperty(org.apache.axis2.transport.http.HTTPConstants.COOKIE_STRING, sessionCookie);
        } catch (LoginAuthenticationExceptionException e) {
            throw new SSOAgentException("Error occured while trying to invoke login function with AuthenticationAdminStub!",e);
        }

    }

    public boolean checkAppRegistrationStatus(String spName) throws RemoteException, MalformedURLException, SSOAgentException {
        try {

            ApplicationBasicInfo[] appInfoArray = applicationMgtStub.getAllApplicationBasicInfo();
            for (ApplicationBasicInfo abf : appInfoArray) {
                if (spName.equals(abf.getApplicationName())) {
                    return true;
                }
            }
        } catch (IdentityApplicationManagementServiceIdentityApplicationManagementException e) {
            throw new SSOAgentException("Error in invoking IdentityApplicationManagementService"
                    + " while checking Application registration status for the provider :" + spName, e);
        }
        return false;
    }

    public boolean checkSAMLconfigurationStatus(String spName) throws RemoteException, SSOAgentException {
        try {
            ServiceProvider sp = applicationMgtStub.getApplication(spName);
            InboundAuthenticationConfig iac = sp.getInboundAuthenticationConfig();
            InboundAuthenticationRequestConfig[] iarc = iac.getInboundAuthenticationRequestConfigs();
            String inboundConfigs = "";

            for (InboundAuthenticationRequestConfig elem : iarc) {
                inboundConfigs += elem.getInboundAuthType() + " , ";
                if ("samlsso".equals(elem.getInboundAuthType())) {
                    return true;
                }
            }
            LOGGER.log(Level.INFO, inboundConfigs + " Configured for the provider:" + spName);
        } catch (IdentityApplicationManagementServiceIdentityApplicationManagementException e) {
            throw new SSOAgentException("Error in invoking IdentityApplicationManagementService"
                    + " while checking SAML configuration status for the provider :" + spName, e);
        }
        return false;
    }

    public void performDynamicAppRegistration(String spName) throws MalformedURLException, RemoteException, SSOAgentException {
        try {
            ServiceProvider sp = new ServiceProvider();
            sp.setApplicationName(spName);
            sp.setDescription("Application was created in IDP via SSO Agent.");
            applicationMgtStub.createApplication(sp);
        } catch (IdentityApplicationManagementServiceIdentityApplicationManagementException e) {
            throw new SSOAgentException("Error occured while performing dynamic registration for application '"
                    + spName + "':", e);
        }
    }

    public String performDynamicSAMLConfiguration(SSOAgentConfig ssoAgentConfig) throws RemoteException, SSOAgentException {

        String spName = ssoAgentConfig.getSAML2().getSPEntityId();
        try {
            ServiceProvider sp = applicationMgtStub.getApplication(spName);

            InboundAuthenticationConfig inboundAuthnConfig = new InboundAuthenticationConfig();
            InboundAuthenticationRequestConfig inAuthnReqConfig = new InboundAuthenticationRequestConfig();
            
              if (sp.isInboundAuthenticationConfigSpecified()) {
                InboundAuthenticationConfig iac = sp.getInboundAuthenticationConfig();
                InboundAuthenticationRequestConfig[] iarc = iac.getInboundAuthenticationRequestConfigs();
                for (InboundAuthenticationRequestConfig i : iarc) {
                    if ("oauth2".equals(i.getInboundAuthType())) {
                        return "oauth/openID connect configuration is already Done for " + spName
                                + ".Simultaneous SAML and oauth/openID connect configurations are not recommended.";
                    }
                }
            }
              
            inAuthnReqConfig.setInboundAuthKey(spName);
            inAuthnReqConfig.setInboundAuthType("samlsso");
            inboundAuthnConfig.addInboundAuthenticationRequestConfigs(inAuthnReqConfig);

            SAMLSSOServiceProviderDTO dto = new SAMLSSOServiceProviderDTO();
            dto.addAssertionConsumerUrls("https://localhost:8080/demo-test-agents/callback");
            dto.setDoSignResponse(true);
            dto.setDoValidateSignatureInRequests(true);
            dto.setDoSingleLogout(true);
            dto.setEnableAttributeProfile(true);
            dto.setCertAlias("wso2carbon");
            dto.setIssuer(spName);

            IdentitySAMLSSOConfigServiceStub samlStub = new IdentitySAMLSSOConfigServiceStub();
            ServiceClient client3 = samlStub._getServiceClient();
            Options option3 = client3.getOptions();
            option3.setManageSession(true);
            option3.setProperty(org.apache.axis2.transport.http.HTTPConstants.COOKIE_STRING, sessionCookie);

            samlStub.removeServiceProvider(spName);
            samlStub.addRPServiceProvider(dto);

            sp.setInboundAuthenticationConfig(inboundAuthnConfig);
//        sp.setDescription(sp.getDescription()+". SAML Configured dynamically!");
            applicationMgtStub.updateApplication(sp);

        } catch (IdentityApplicationManagementServiceIdentityApplicationManagementException e) {
            throw new SSOAgentException("Error in invoking IdentityApplicationManagementService"
                    + " while performing dynamic SAML configuration for the provider :" + spName, e);
        } catch (IdentitySAMLSSOConfigServiceIdentityException e) {
            throw new SSOAgentException("Error in invoking IdentitySAMLSSOConfigService"
                    + " while performing dynamic SAML configuration for the provider :" + spName, e);
        }
        return "updated";
    }

}
