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

import java.io.IOException;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.opensaml.util.URLBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import edu.internet2.middleware.shibboleth.idp.authn.provider.AbstractLoginHandler;
import edu.internet2.middleware.shibboleth.idp.util.HttpServletHelper;


public class BridgeLoginHandler extends AbstractLoginHandler {
	
	//The class logger
    private final Logger log = LoggerFactory.getLogger(BridgeLoginHandler.class);
 
   
    /** The URL of the SSO-protected servlet. */
    private  String servletURL;
  
    public String getServletURL() {
		return servletURL;
	}

	public void setServletURL(String servletURL) {
		servletURL = servletURL;
	}

	public BridgeLoginHandler(
            String authenticationServletURL
            ) {
        super();

        setSupportsPassive(false);
        setSupportsForceAuthentication(false);

    
        servletURL = authenticationServletURL;
       
    }

    /**
     * Perform login with X509LoginHandler
     *
     * @param  request  HTTPServletRequest
     * @param  response HTTPServletResponse
     */
    public void login(final HttpServletRequest request,
            final HttpServletResponse response) {
    	 // forward control to the servlet.
        try {
            String profileUrl = HttpServletHelper.getContextRelativeUrl(request, servletURL).buildURL();

            log.debug("Redirecting to {}", profileUrl);
            response.sendRedirect(profileUrl);
            return;
        } catch (IOException ex) {
            log.error("Unable to redirect to remote user authentication servlet.", ex);
        }
    }

    
  

  
}
