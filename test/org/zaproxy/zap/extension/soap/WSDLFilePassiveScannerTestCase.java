package org.zaproxy.zap.extension.soap;

import static org.junit.Assert.*;

import java.lang.reflect.InvocationTargetException;

import org.junit.Before;
import org.junit.Test;
import org.parosproxy.paros.network.HttpMessage;

public class WSDLFilePassiveScannerTestCase {
	private HttpMessage wsdlMsg = new HttpMessage();
	
	@Before
	public void setUp(){
		try {
			wsdlMsg = Sample.setRequestHeaderContent(wsdlMsg);
			wsdlMsg = Sample.setResponseHeaderContent(wsdlMsg);
			wsdlMsg = Sample.setResponseBodyContent(wsdlMsg);
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
	
	@Test
	public void isWsdlTest() throws NoSuchMethodException, SecurityException, IllegalAccessException, IllegalArgumentException, InvocationTargetException{
		WSDLFilePassiveScanner scanner = new WSDLFilePassiveScanner();
		/* Positive case. */
		boolean result = scanner.isWsdl(wsdlMsg);
		assertTrue(result);
		
		/* Negative cases. */		
		result = scanner.isWsdl(null); /* Null response. */
		assertFalse(result);		
		
		result = scanner.isWsdl(new HttpMessage()); /* Empty response. */
		assertFalse(result);
	}

}
