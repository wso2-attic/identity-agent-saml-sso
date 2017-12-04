# identity-agent-saml-sso

Identity-agent-saml-sso provides the capability to communicate with your IDP(i.e. WSO2 Identity Server) in a really 
easy manner. You do not have to write any new java code to use this agent in your web application. All the mandatory 
functionality is included alread. Further, this agent resides in this repository as module 'agent' you can build the agent as a 
 single jar. 

## How to use Agent for a given web application.
Process of including SAML SSO Agent to your web application can be described in three main steps.

First Step: You have to provide the proeprties that you wish to use. For that you can add the .properties file to your 
web application under the directory: src/main/resources. This properties
 file should include the relevant properties that are required to perform communication with wso2 identity server via
 SAML flow.(NOTE: you can use properties as con)  
 
 ```
 NOTE: You can define properties as context-params in the web.xml too. However the effective set of properties have 
 the following priority. 
 Highest -> properties defined in .properties file
 Mid     -> properties defined as context-params
 lowest  -> default values assumed for properties
 
 Thus, higer priority will override the redundant occurrences.
 ``` 
 ```
 The list of properties and their default values assumed by the agent are as follows:

 ```
 Second Step: Next step is adding the agent to your web application. If you web applicaiton is a Maven web project 
 then add the below dependency. Or else you can add the jar you get after building the module agent.
 
 ```
 DEPENDECY GROUPID:ARTIFACTID
 ```

Third Step: Then you have to add the SAMLSSO Filter to your web application's web.xml file as shown below.
 ```
  <filter>
        <filter-name>SAML2SSOAgentFilter</filter-name>
        <filter-class>org.wso2.carbon.identity.sso.agent.SAML2SSOAgentFilter</filter-class>
  </filter>
  <filter-mapping>
          <filter-name>SAML2SSOAgentFilter</filter-name>
          <url-pattern>/samlsso</url-pattern>
      </filter-mapping>
      <filter-mapping>
          <filter-name>SAML2SSOAgentFilter</filter-name>
          <url-pattern>/samlcallback</url-pattern>
      </filter-mapping>
      <filter-mapping>
          <filter-name>SAML2SSOAgentFilter</filter-name>
          <url-pattern>/samllogout</url-pattern>
      </filter-mapping>
 ```
 In the above code sample, we can see that three url patterns are mapped to this filter.
 The pattern [/samlsso]() is used to initiate SAML flow with the agent. Then the [/samlcallback]() is used to map the 
 callback from the IDP( WSO2 Identity Server). [/samllogout]() is used to map the SAML logout request.
 
 TIP: these patterns([/samlsso](),[/samlcallback]() and [/samllogout]()) are assumed default values by the agent. If 
 you prefer to change those values you can easily do so by using either your .properties file or else use context-params in your web.xml.
 
 
## Sample web application with SAML Agent

This repository contains a module called 'sample' which contains a simple sample web application the usage of SAML 
SSO 
Agent.
