package org.zaproxy.zap.extension.soap;

import static org.junit.Assert.assertNotNull;

import org.junit.Before;
import org.junit.Test;
import org.zaproxy.zap.testutils.TestUtils;

public class ExtensionImportWSDLTestCase extends TestUtils {

	ExtensionImportWSDL extension;
	
	@Before
	public void setUp() {
		extension = new ExtensionImportWSDL();
		mockMessages(extension);
	}
	
	@Test
	public void getAuthorTest(){
		assertNotNull(extension.getAuthor());
	}
	
	@Test
	public void getDescriptionTest(){
		assertNotNull(extension.getDescription());
	}
	
	@Test
	public void getURLTest(){
		assertNotNull(extension.getURL());
	}

}
