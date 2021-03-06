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


import edu.internet2.middleware.shibboleth.idp.authn.provider.RemoteUserLoginHandler;
import edu.internet2.middleware.shibboleth.idp.config.profile.authn.AbstractLoginHandlerFactoryBean;

public class BridgeLoginHandlerFactoryBean extends AbstractLoginHandlerFactoryBean{
	 /** Path to protected servlet. */
    private String bridgingServletPath;

    /** {@inheritDoc} */
    public Class getObjectType() {
        return RemoteUserLoginHandler.class;
    }

    /**
     * Gets the path to protected servlet.
     * 
     * @return path to protected servlet
     */
    public String getProtectedServletPath() {
        return bridgingServletPath;
    }

    /**
     * Sets the path to protected servlet.
     * 
     * @param path Tpath to protected servlet
     */
    public void setProtectedServletPath(String path) {
        this.bridgingServletPath = path;
    }

    /** {@inheritDoc} */
    protected Object createInstance() throws Exception {
        RemoteUserLoginHandler handler = new RemoteUserLoginHandler();
        handler.setServletURL(getProtectedServletPath());
        populateHandler(handler);
        return handler;
    }
}
