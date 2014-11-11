package org.zaproxy.zap.extension.soap;


import org.junit.runners.Suite;
import org.junit.runner.RunWith;

@RunWith(Suite.class)
@Suite.SuiteClasses({
	ExtensionImportWSDLTestCase.class, 
	ImportWSDLTestCase.class, 
	SOAPActionSpoofingActiveScannerTest.class,
	WSDLCustomParserTestCase.class, 
	WSDLFilePassiveScannerTestCase.class, 
	WSDLSpiderTestCase.class,
	SOAPMsgConfigTestCase.class})
public class SOAPTestSuite {

}
