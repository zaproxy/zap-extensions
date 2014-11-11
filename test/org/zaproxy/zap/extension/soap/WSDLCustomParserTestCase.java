package org.zaproxy.zap.extension.soap;

import static org.junit.Assert.*;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.Reader;
import java.lang.reflect.Method;

import org.apache.log4j.BasicConfigurator;
import org.apache.log4j.Level;
import org.apache.log4j.Logger;
import org.junit.Before;
import org.junit.Test;
import org.parosproxy.paros.network.HttpMessage;

public class WSDLCustomParserTestCase {

	private String wsdlContent;
	private WSDLCustomParser parser = new WSDLCustomParser();
	
	@Before
	public void setUp() throws NullPointerException, IOException{
		/* Simple log configuration to prevent Log4j malfunction. */
		BasicConfigurator.configure(); 
		Logger rootLogger = Logger.getRootLogger();
		rootLogger.setLevel(Level.OFF);
		
		/* Gets test wsdl file and retrieves its content as String. */
		InputStream in = getClass().getResourceAsStream("resources/test.wsdl");
		Reader fr = new InputStreamReader(in, "utf-8");
		BufferedReader br = new BufferedReader(fr);		
		StringBuilder sb = new StringBuilder();
		String line = "";
		line = br.readLine();	
		do{		
			sb.append(line+"\r\n");
		}while((line = br.readLine()) != null);
		wsdlContent = sb.toString();		
	}
	
	@Test
	public void parseWSDLContentTest() {	
		try{
			/* Positive case. Checks the method's return value. */
			Method method = parser.getClass().getDeclaredMethod("parseWSDLContent", String.class, boolean.class);
			method.setAccessible(true);
			boolean result = (Boolean) method.invoke(parser, wsdlContent, false);
			assertTrue(result);
			
			/* Negative cases. */
			result = (Boolean) method.invoke(parser, "", false); //Empty content.
			assertFalse(result);
			
			result = (Boolean) method.invoke(parser, "asdf", false); //Non-empty invalid content.
			assertFalse(result);
		}catch(Exception e){
			fail("Could not call parseWSDLContent() method.");
		}	
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
		if(WSDLCustomParser.getLastConfig() == null){
			fail ("parseWSDLContentTest has not been able to save a proper configuration object to perform this test.");
			return;
		}
		/* Positive case. */
		HttpMessage result = parser.createSoapRequest(WSDLCustomParser.getLastConfig());
		assertNotNull(result);
		/* Negative case. */
		result = parser.createSoapRequest(new SOAPMsgConfig());
		assertNull(result);
	}

}
