# PeopleSoft OIDC / OAuth SSO Integration

This project demonstrates how to enable OpenID Connect (OIDC) based Single Sign-On for PeopleSoft without modifying delivered login code.

The solution uses a Java servlet filter deployed in the PeopleSoft WebLogic web tier to authenticate users via an Identity Provider and pass the authenticated identity to PeopleSoft through Signon PeopleCode.

Architecture Overview

Browser
   ↓
OIDC Identity Provider
   ↓
Java Filter (WebLogic)
   ↓
PeopleSoft Portal
   ↓
Signon PeopleCode
   ↓
PS_TOKEN Session

Key Features

• No modification to delivered PeopleSoft login framework  
• Uses Signon PeopleCode extension point  
• Compatible with modern Identity Providers (Azure AD, Okta, Keycloak)  
• Lightweight and upgrade safe  

Repository Contents

/oidc-filter      → Java filter source code  
/config-example   → Example OIDC configuration  
/docs             → Implementation documentation  
/jar              → Compiled filter JAR  

Supported Identity Providers

• Azure Active Directory  
• Okta  
• Keycloak  

Disclaimer

This project is not affiliated with or endorsed by Oracle.



# Architecture Overview

This solution introduces modern OpenID Connect authentication to PeopleSoft using a servlet filter.

The filter intercepts requests before they reach the PeopleSoft portal.

Authentication Flow

1. User accesses PeopleSoft URL
2. Filter checks authentication status
3. If not authenticated, user is redirected to Identity Provider
4. Identity Provider authenticates the user
5. ID token is returned to the filter
6. Filter validates the token
7. Email claim is extracted
8. Email is injected into HTTP header
9. Signon PeopleCode maps email to OPRID
10. PeopleSoft issues PS_TOKEN session

Advantages

• No changes to delivered authentication code  
• Identity handled by external provider  
• PeopleSoft retains authorization and session control


# Installation Guide

Step 1: Deploy Filter JAR

Copy the filter jar into the PeopleSoft portal library directory:

/home/psadm2/psft/pt/8.61/webserv/peoplesoft/applications/peoplesoft/PORTAL.war/WEB-INF/lib

Example directory:


oidc-filter.jar

Step 2: Create OIDC Configuration File

Create:

/home/psadm2/psft/pt/8.61/webserv/peoplesoft/config/oidc.properties

Example:

client.id=xxxxx
client.secret=xxxxx
issuer=https://login.microsoftonline.com/tenant/v2.0
redirect.uri=https://ps.company.com/oidc/callback
scope=openid email profile

Step 3: Update WebLogic Startup Options

Add the following system property:

JAVA_OPTIONS_LINUX="-server -Xms512m -Xmx512m \
-Dtoplink.xml.platform=oracle.toplink.platform.xml.jaxp.JAXPPlatform \
-Dcom.sun.xml.namespace.QName.useCompatibleSerialVersionUID=1.0 \
-DTM_ALLOW_NOTLS=Y \
-DTM_MIN_PUB_KEY_LENGTH=1024 \
-Doidc.config=/home/psadm2/psft/pt/8.61/webserv/peoplesoft/config/oidc.properties"

Step 4: Restart WebLogic

Restart the PeopleSoft web server domain.


# Security Considerations

The authentication header should only be injected by the servlet filter.

Security Recommendations

• Ensure all requests pass through the filter
• Restrict direct access to backend WebLogic ports
• Do not expose internal admin ports
• Validate ID token signature and issuer
• Ensure token expiration checks are enabled

Because the filter handles authentication, PeopleSoft should trust the injected header only when requests pass through the filter.
