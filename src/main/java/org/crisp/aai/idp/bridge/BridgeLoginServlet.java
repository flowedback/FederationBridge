/*
 * Copyright [2012] [SWITCH]
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.crisp.aai.idp.bridge;

import java.security.Principal;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.List;
import java.util.Set;

import javax.security.auth.Subject;
import javax.security.auth.x500.X500Principal;
import javax.servlet.ServletConfig;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.opensaml.saml2.core.AuthnContext;
import org.opensaml.xml.util.DatatypeHelper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import edu.internet2.middleware.shibboleth.idp.authn.AuthenticationEngine;
import edu.internet2.middleware.shibboleth.idp.authn.LoginHandler;
import edu.internet2.middleware.shibboleth.idp.authn.UsernamePrincipal;


public class BridgeLoginServlet extends HttpServlet {

	/** Serial version UID. */
	private static final long serialVersionUID = -4431927396568561030L;
	
	/** Class logger. */
	private final Logger log = LoggerFactory.getLogger(BridgeLoginServlet.class);
	
    //private static final String GETPAR_PASSTHROUGH = "x509-pass-through";
	private java.util.Map<String, String> lookupTable = new HashMap<String, String>();
	 
	/** The authentication method returned to the authentication engine. */
    private String authenticationMethod;
    
    
    public void init(ServletConfig config) {
        log.trace("servlet initialization");
        lookupTable.put("amontiel","flowback");
        String method =
                DatatypeHelper.safeTrimOrNullString(config.getInitParameter(LoginHandler.AUTHENTICATION_METHOD_KEY));
        if (method != null) {
            authenticationMethod = method;
        } else {
            authenticationMethod = AuthnContext.PPT_AUTHN_CTX;
        }
    }

    protected void service(HttpServletRequest request, HttpServletResponse response) {
        log.trace("servlet service");
        String principalName = DatatypeHelper.safeTrimOrNullString(request.getRemoteUser());
    	//String principalName = httpRequest.getRemoteUser();
    	//principalName = "luis";
        if (principalName != null) {
        	principalName= lookupTable.get(principalName);
        	

            log.debug("Remote user identified as {} returning control back to authentication engine", principalName);
            request.setAttribute(LoginHandler.PRINCIPAL_KEY, new UsernamePrincipal(principalName));
            request.setAttribute(LoginHandler.AUTHENTICATION_METHOD_KEY, authenticationMethod);
        } else {
            log.debug("No remote user information was present in the request");
        }

        AuthenticationEngine.returnToAuthenticationEngine(request, response);
    }

}
