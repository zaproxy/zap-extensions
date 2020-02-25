/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2014 The ZAP Development Team
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
package org.zaproxy.zap.extension.soap;

import static org.junit.Assert.*;

import com.predic8.wsdl.BindingOperation;
import com.predic8.wsdl.Definitions;
import com.predic8.wsdl.Port;
import java.util.HashMap;
import org.apache.commons.httpclient.URI;
import org.apache.commons.httpclient.URIException;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpRequestHeader;
import org.zaproxy.zap.network.HttpRequestBody;

public class ImportWSDLTestCase {

    private final int WSDL_KEY = 0;
    private final String TEST_OP = "testOp";
    private final String TEST_URI = "http://test.com";

    private ImportWSDL singleton;
    private HttpMessage testRequest;
    private SOAPMsgConfig soapConfig;

    @Before
    public void setUp() throws URIException, NullPointerException {
        ImportWSDL.destroy();
        /* Retrieves singleton instance. */
        singleton = ImportWSDL.getInstance();

        /* Makes test request. */
        testRequest = new HttpMessage();
        HttpRequestHeader header = new HttpRequestHeader();
        header.setURI(new URI(TEST_URI, true));
        testRequest.setRequestHeader(header);
        HttpRequestBody body = new HttpRequestBody();
        body.append("test");
        body.setLength(4);
        testRequest.setRequestBody(body);

        /* Empty configuration object. */
        soapConfig = new SOAPMsgConfig();
        soapConfig.setWsdl(new Definitions());
        soapConfig.setSoapVersion(1);
        soapConfig.setParams(new HashMap<String, String>());
        soapConfig.setPort(new Port());
        soapConfig.setBindOp(new BindingOperation());
    }

    @After
    public void teardown() {
        ImportWSDL.destroy();
    }

    @Test
    public void singletonInstanceShouldNeverBeNull() {
        assertNotNull(singleton);
    }

    @Test
    public void getSoapActionsTest() {
        ImportWSDL singleton = ImportWSDL.getInstance();
        /* Must return null if no action has been inserted before. */
        String[][] soapActions = singleton.getSoapActions();
        assertNull(soapActions);
        /* Checks that action has been inserted. */
        singleton.putAction(WSDL_KEY, TEST_OP);
        soapActions = singleton.getSoapActions();
        String[][] expectedActions = {{TEST_OP}};
        assertArrayEquals(soapActions, expectedActions);
    }

    @Test
    public void getSourceSoapActionsTest() {
        HttpMessage request = new HttpMessage();
        String[] result = singleton.getSourceSoapActions(request);
        /* There are no requests in singleton's list. Response should be null. */
        assertNull(result);

        singleton.putAction(WSDL_KEY, TEST_OP);
        /* Test request. */
        singleton.putRequest(WSDL_KEY, testRequest);
        result = singleton.getSourceSoapActions(testRequest);
        assertNotNull(result);
    }

    @Test
    public void getSoapConfigTest() {
        /* Must be null since the new HttpMessage does not exist in the list. */
        SOAPMsgConfig receivedConfig = singleton.getSoapConfig(new HttpMessage());
        assertNull(receivedConfig);

        singleton.putConfiguration(testRequest, soapConfig);
        receivedConfig = singleton.getSoapConfig(testRequest);
        assertNotNull(receivedConfig);
        assertTrue(soapConfig.equals(receivedConfig));
    }

    @Test
    public void getSoapConfigByBodyTest() {
        /* Must be null since the new HttpMessage does not exist in the list. */
        SOAPMsgConfig receivedConfig = singleton.getSoapConfig(new HttpMessage());
        assertNull(receivedConfig);

        /* Puts a config and tries to retrieve it from singleton instance. */
        singleton.putConfiguration(testRequest, soapConfig);
        receivedConfig = singleton.getSoapConfigByBody(testRequest);
        assertNotNull(receivedConfig);
        assertTrue(soapConfig.equals(receivedConfig));
    }
}
