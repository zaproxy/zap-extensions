package org.zaproxy.zap.extension.soap;

import static org.junit.Assert.assertNotNull;

import org.junit.Before;
import org.junit.Test;
import org.zaproxy.zap.extension.ScannerTestUtils;

public class ExtensionImportWSDLTestCase extends ScannerTestUtils {

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
