package org.zaproxy.zap.extension.soap;

import static org.junit.Assert.*;

import java.net.URL;

import org.junit.Before;
import org.junit.Test;

public class ExtensionImportWSDLTestCase {

	ExtensionImportWSDL extension;
	
	@Before
	public void setUp() {
		extension = new ExtensionImportWSDL();
	}
	
	@Test
	public void getAuthorTest(){
		try{
			String author = extension.getAuthor();
			assertNotNull(author);
		}catch(NullPointerException e){
			fail("Author could not be retrieved. If this parameter is set externally (e.g. messages.properties file), ignore this result.");
		}
	}
	
	@Test
	public void getDescriptionTest(){
		try{
			String description = extension.getDescription();
			assertNotNull(description);
		}catch(NullPointerException e){
			fail("Description could not be retrieved. If this parameter is set externally (e.g. messages.properties file), ignore this result.");
		}
		
	}
	
	@Test
	public void getURLTest(){
		try{
			URL url = extension.getURL();
			assertNotNull(url);
		}catch(NullPointerException e){
			fail("URL could not be retrieved. If this parameter is set externally (e.g. messages.properties file), ignore this result.");
		}
	}

}
