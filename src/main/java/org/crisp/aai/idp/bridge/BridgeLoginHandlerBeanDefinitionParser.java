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
import javax.xml.namespace.QName;

import org.opensaml.xml.util.DatatypeHelper;
import org.springframework.beans.factory.support.BeanDefinitionBuilder;
import org.w3c.dom.Element;

import edu.internet2.middleware.shibboleth.idp.config.profile.authn.AbstractLoginHandlerBeanDefinitionParser;

public class BridgeLoginHandlerBeanDefinitionParser extends AbstractLoginHandlerBeanDefinitionParser {

    /** Schema type. */
    public static final QName SCHEMA_TYPE = new QName(BridgeNamespaceHandler.NAMESPACE, "bridge");

    /** {@inheritDoc} */
    protected Class getBeanClass(Element element) {
        return BridgeLoginHandlerFactoryBean.class;
    }
    protected void doParse(Element config, BeanDefinitionBuilder builder) {
        super.doParse(config, builder);

        if (config.hasAttributeNS(null, "protectedServletPath")) {
            builder.addPropertyValue("protectedServletPath", 
            		DatatypeHelper.safeTrimOrNullString(config.getAttributeNS(null, "protectedServletPath")));
        } else {
            builder.addPropertyValue("protectedServletPath", "/Authn/Bridge");
        }
    }
   
}
