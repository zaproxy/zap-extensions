package org.zaproxy.zap.extension.soap;

import static org.junit.Assert.*;

import org.junit.Before;
import org.junit.Test;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.parosproxy.paros.network.HttpMessage;

public class SOAPActionSpoofingActiveScannerTestCase {

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
	public void scanResponseTest() throws Exception {
		SOAPActionSpoofingActiveScanner scanner = new SOAPActionSpoofingActiveScanner();
		
		/* Positive cases. */	
		int result = scanner.scanResponse(modifiedMsg, originalMsg);
		assertTrue(result == SOAPActionSpoofingActiveScanner.SOAPACTION_EXECUTED);
		
		Sample.setOriginalResponse(modifiedMsg);
		result = scanner.scanResponse(modifiedMsg, originalMsg);
		assertTrue(result == SOAPActionSpoofingActiveScanner.SOAPACTION_IGNORED);
		
		/* Negative cases. */
		result = scanner.scanResponse(new HttpMessage(), originalMsg);
		assertTrue(result == SOAPActionSpoofingActiveScanner.EMPTY_RESPONSE);
		
		Sample.setEmptyBodyResponse(modifiedMsg);
		result = scanner.scanResponse(modifiedMsg, originalMsg);
		assertTrue(result == SOAPActionSpoofingActiveScanner.EMPTY_RESPONSE);
		
		Sample.setInvalidFormatResponse(modifiedMsg);
		result = scanner.scanResponse(modifiedMsg, originalMsg);
		assertTrue(result == SOAPActionSpoofingActiveScanner.INVALID_FORMAT);
	}

}
