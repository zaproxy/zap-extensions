package org.zaproxy.zap.extension.soap;

import static org.junit.Assert.*;

import java.util.HashMap;

import org.junit.Before;
import org.junit.Test;

import com.predic8.wsdl.BindingOperation;
import com.predic8.wsdl.Definitions;
import com.predic8.wsdl.Port;

public class SOAPMsgConfigTestCase {

	private static final String KEY_PREFIX = "xpath:/";
	private static final String KEY_NAME = "testkey";
	private static final String KEY_VALUE = "testvalue";
	private static final String KEY_VALUE2 = "testvalue2";
	
	private SOAPMsgConfig soapConfig;
	
	@Before
	public void setUp(){
		/* Empty configuration object. */
		soapConfig = new SOAPMsgConfig();
		soapConfig.setWsdl(new Definitions());
		soapConfig.setSoapVersion(1);
		soapConfig.setParams(new HashMap<String,String>());
		soapConfig.setPort(new Port());
		soapConfig.setBindOp(new BindingOperation());
	}
	
	@Test
	public void isCompleteTest() {
		/* Positive case. */
		assertTrue(soapConfig.isComplete());
		
		/* Negative cases. */
		soapConfig.setWsdl(null);
		assertFalse(soapConfig.isComplete()); // Null WSDL.
		soapConfig.setWsdl(new Definitions());
		
		soapConfig.setSoapVersion(0);
		assertFalse(soapConfig.isComplete()); // SOAP version < 1
		soapConfig.setSoapVersion(3);
		assertFalse(soapConfig.isComplete()); // SOAP version > 2
		soapConfig.setSoapVersion(1);
		
		soapConfig.setParams(null);
		assertFalse(soapConfig.isComplete()); // Null params.
		soapConfig.setParams(new HashMap<String,String>());
		
		soapConfig.setPort(null);
		assertFalse(soapConfig.isComplete()); // Null port.
		soapConfig.setPort(new Port());
		
		soapConfig.setBindOp(null);
		assertFalse(soapConfig.isComplete()); // Null binding operation.
		soapConfig.setBindOp(new BindingOperation());
	}
	
	@Test
	public void changeParamTest(){
		/* Configuration. */
		HashMap<String,String> map = new HashMap<String,String>();
		map.put(KEY_PREFIX + KEY_NAME, KEY_VALUE);
		soapConfig.setParams(map);
		
		/* Checks that configuration has been processed correctly. */
		map = soapConfig.getParams();
		String value = map.get(KEY_PREFIX + KEY_NAME);
		assertTrue(value.equals(KEY_VALUE));
		
		/* Positive case. */
		soapConfig.changeParam(KEY_NAME, KEY_VALUE2);
		map = soapConfig.getParams();
		value = map.get(KEY_PREFIX + KEY_NAME);
		assertTrue(value.equals(KEY_VALUE2)); // Parameter value has been changed.
		
		/* Negative cases. */
		soapConfig.changeParam(KEY_NAME, null); // Null value.
		map = soapConfig.getParams();
		value = map.get(KEY_PREFIX + KEY_NAME);
		assertTrue(value.equals(KEY_VALUE2)); // Parameter value has NOT been changed.
		
		soapConfig.changeParam(null, KEY_VALUE); // Null key.
		map = soapConfig.getParams();
		value = map.get(KEY_PREFIX + KEY_NAME);
		assertTrue(value.equals(KEY_VALUE2)); // Parameter value has NOT been changed.
	}

}
