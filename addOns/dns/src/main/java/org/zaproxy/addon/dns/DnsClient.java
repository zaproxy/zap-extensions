/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2023 The ZAP Development Team
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.zaproxy.addon.dns;

import java.util.ArrayList;
import java.util.Hashtable;
import java.util.List;
import java.util.Map;
import javax.naming.NamingEnumeration;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class DnsClient {
    private static final Logger LOGGER = LogManager.getLogger(DnsClient.class);
    private static final String TXT = "TXT";

    public List<String> getTxtRecord(String host) {
        Hashtable<String, String> env =
                new Hashtable<>(
                        Map.of(
                                "java.naming.factory.initial",
                                "com.sun.jndi.dns.DnsContextFactory"));
        List<String> result = new ArrayList<>();
        try {
            DirContext dirContext = new InitialDirContext(env);
            Attributes attrs = dirContext.getAttributes(host, new String[] {TXT});
            Attribute attr = attrs.get(TXT);

            if (attr != null) {
                NamingEnumeration<?> attrenum = attr.getAll();
                while (attrenum.hasMore()) {
                    result.add(attrenum.next().toString());
                }
            }
        } catch (javax.naming.NamingException e) {
            LOGGER.debug("There was a problem getting the TXT record: ", e);
        }
        return result;
    }
}
