package org.zaproxy.zap.extension.soap;

import static org.junit.Assert.*;

import java.lang.reflect.InvocationTargetException;

import org.junit.Before;
import org.junit.Test;
import org.parosproxy.paros.network.HttpMessage;

public class WSDLSpiderTestCase {

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
	public void parseResourceTest() throws NoSuchMethodException, SecurityException, IllegalAccessException, IllegalArgumentException, InvocationTargetException {
		WSDLSpider spider = new WSDLSpider();
		
		/* Positive case. */
		boolean result = spider.parseResourceWSDL(wsdlMsg, null, 0, false);
		assertTrue(result);
		
		/* Negative cases. */		
		result = spider.parseResourceWSDL(null, null, 0, false); /* Null response. */
		assertFalse(result);		
		
		result = spider.parseResourceWSDL(new HttpMessage(), null, 0, false); /* Empty response. */
		assertFalse(result);
			
		wsdlMsg.setResponseBody("test");
		result = spider.parseResourceWSDL(wsdlMsg, null, 0, false); /* Response with no-wsdl content. */
		assertFalse(result);
	}

}
