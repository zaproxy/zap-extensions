package org.zaproxy.zap.extension.soap;

import static org.junit.Assert.*;

import java.util.HashMap;

import org.apache.commons.httpclient.URI;
import org.apache.commons.httpclient.URIException;
import org.junit.Before;
import org.junit.Test;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpRequestHeader;
import org.zaproxy.zap.network.HttpRequestBody;

import com.predic8.wsdl.BindingOperation;
import com.predic8.wsdl.Definitions;
import com.predic8.wsdl.Port;

public class ImportWSDLTestCase {

	private final int WSDL_KEY = 0;
	private final String TEST_OP = "testOp";
	private final String TEST_URI = "http://test.com";
	
	private ImportWSDL singleton;
	private HttpMessage testRequest;
	private SOAPMsgConfig soapConfig;
	
	@Before
	public void setUp() throws URIException, NullPointerException{
		/* Retrieves singleton instance. */
		singleton = ImportWSDL.getInstance();
		
		/* Makes test request. */
		testRequest = new HttpMessage();
		HttpRequestHeader header = new HttpRequestHeader();
		header.setURI(new URI(TEST_URI,true));
		testRequest.setRequestHeader(header);
		HttpRequestBody body = new HttpRequestBody();
		body.append("test");
		body.setLength(4);
		testRequest.setRequestBody(body);
		
		/* Empty configuration object. */
		soapConfig = new SOAPMsgConfig();
		soapConfig.setWsdl(new Definitions());
		soapConfig.setSoapVersion(1);
		soapConfig.setParams(new HashMap<String,String>());
		soapConfig.setPort(new Port());
		soapConfig.setBindOp(new BindingOperation());
	}
	
	@Test
	public void singletonInstanceShouldNeverBeNull() {
		assertNotNull(singleton);
	}

	@Test
	public void getSoapActionsTest(){
		ImportWSDL singleton = ImportWSDL.getInstance();
		/* Must return null if no action has been inserted before. */
		String[][] soapActions = singleton.getSoapActions();
		assertNull(soapActions);
		/* Checks that action has been inserted. */
		singleton.putAction(WSDL_KEY, TEST_OP);
		soapActions = singleton.getSoapActions();
		String[][] expectedActions = {{TEST_OP}};
		assertArrayEquals(soapActions,expectedActions);
	}
	
	@Test
	public void getSourceSoapActionsTest(){
		HttpMessage request = new HttpMessage();
		String[] result = singleton.getSourceSoapActions(request);
		/* There are no requests in singleton's list. Response should be null. */
		assertNull(result);
		
		/* Test request. */
		singleton.putRequest(WSDL_KEY, testRequest);
		result = singleton.getSourceSoapActions(testRequest);
		assertNotNull(result);
	}
	
	@Test
	public void getSoapConfigTest(){
		/* Must be null since the new HttpMessage does not exist in the list. */
		SOAPMsgConfig receivedConfig = singleton.getSoapConfig(new HttpMessage());
		assertNull(receivedConfig);
			
		singleton.putConfiguration(testRequest, soapConfig);
		receivedConfig = singleton.getSoapConfig(testRequest);
		assertNotNull(receivedConfig);
		assertTrue(soapConfig.equals(receivedConfig));
	}
	
	@Test
	public void getSoapConfigByBodyTest(){
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
