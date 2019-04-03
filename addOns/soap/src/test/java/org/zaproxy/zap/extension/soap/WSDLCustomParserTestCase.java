package org.zaproxy.zap.extension.soap;

import static org.junit.Assert.*;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

import org.apache.log4j.BasicConfigurator;
import org.apache.log4j.Level;
import org.apache.log4j.Logger;
import org.junit.Before;
import org.junit.Test;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.testutils.TestUtils;

public class WSDLCustomParserTestCase extends TestUtils {

	private String wsdlContent;
	private WSDLCustomParser parser;
	
	@Before
	public void setUp() throws Exception {
		/* Simple log configuration to prevent Log4j malfunction. */
		BasicConfigurator.configure(); 
		Logger rootLogger = Logger.getRootLogger();
		rootLogger.setLevel(Level.OFF);
		
		/* Gets test wsdl file and retrieves its content as String. */
		Path wsdlPath = getResourcePath("resources/test.wsdl");
		wsdlContent = new String(Files.readAllBytes(wsdlPath), StandardCharsets.UTF_8);

		parser = new WSDLCustomParser();
	}
	
	@Test
	public void parseWSDLContentTest() {
		/* Positive case. Checks the method's return value. */
		boolean result = parser.extContentWSDLImport(wsdlContent, false);
		assertTrue(result);
		
		/* Negative cases. */
		result = parser.extContentWSDLImport("", false); //Empty content.
		assertFalse(result);
		
		result = parser.extContentWSDLImport("asdf", false); //Non-empty invalid content.
		assertFalse(result);
	}	
	
	@Test
	public void canBeWSDLparsedTest() {
		/* Positive case. */
		boolean result = parser.canBeWSDLparsed(wsdlContent);
		assertTrue(result);
		/* Negative cases. */
		result = parser.canBeWSDLparsed(""); //Empty content.
		assertFalse(result);
		result = parser.canBeWSDLparsed("asdf"); //Non-empty invalid content.
		assertFalse(result);
	}
	
	@Test
	public void createSoapRequestTest(){
		parser.extContentWSDLImport(wsdlContent, false);
		/* Positive case. */
		HttpMessage result = parser.createSoapRequest(parser.getLastConfig());
		assertNotNull(result);
		/* Negative case. */
		result = parser.createSoapRequest(new SOAPMsgConfig());
		assertNull(result);
	}

}
