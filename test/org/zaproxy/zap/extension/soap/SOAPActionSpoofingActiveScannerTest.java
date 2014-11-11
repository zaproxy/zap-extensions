package org.zaproxy.zap.extension.soap;

import static org.junit.Assert.*;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;

import org.junit.Before;
import org.junit.Test;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.parosproxy.paros.network.HttpMessage;

public class SOAPActionSpoofingActiveScannerTest {

	private HttpMessage originalMsg = new HttpMessage();
	private HttpMessage modifiedMsg = new HttpMessage();
	
	@Before
	public void setUp() throws HttpMalformedHeaderException{
		/* Original. */
		Sample.setOriginalRequest(originalMsg);
		Sample.setOriginalResponse(originalMsg);
		/* Modified. */
		Sample.setOriginalRequest(modifiedMsg);
		Sample.setByeActionRequest(modifiedMsg);
		Sample.setByeResponse(modifiedMsg);
	}
	

	
	@Test
	public void scanResponseTest() throws IllegalAccessException, IllegalArgumentException, InvocationTargetException, NoSuchMethodException, SecurityException, HttpMalformedHeaderException {
		SOAPActionSpoofingActiveScanner scanner = new SOAPActionSpoofingActiveScanner();
		Method method = scanner.getClass().getDeclaredMethod("scanResponse", HttpMessage.class, HttpMessage.class);
		method.setAccessible(true);
		
		/* Positive cases. */	
		int result = (Integer) method.invoke(scanner, modifiedMsg, originalMsg);
		assertTrue(result == SOAPActionSpoofingActiveScanner.SOAPACTION_EXECUTED);
		
		Sample.setOriginalResponse(modifiedMsg);
		result = (Integer) method.invoke(scanner, modifiedMsg, originalMsg);
		assertTrue(result == SOAPActionSpoofingActiveScanner.SOAPACTION_IGNORED);
		
		/* Negative cases. */
		result = (Integer) method.invoke(scanner, new HttpMessage(), originalMsg);
		assertTrue(result == SOAPActionSpoofingActiveScanner.EMPTY_RESPONSE);
		
		Sample.setEmptyBodyResponse(modifiedMsg);
		result = (Integer) method.invoke(scanner, modifiedMsg, originalMsg);
		assertTrue(result == SOAPActionSpoofingActiveScanner.EMPTY_RESPONSE);
		
		Sample.setInvalidFormatResponse(modifiedMsg);
		result = (Integer) method.invoke(scanner, modifiedMsg, originalMsg);
		assertTrue(result == SOAPActionSpoofingActiveScanner.INVALID_FORMAT);
	}

}
