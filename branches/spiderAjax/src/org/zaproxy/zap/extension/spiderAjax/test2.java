package org.zaproxy.zap.extension.spiderAjax;

import java.util.ArrayList;
import java.util.List;
import org.apache.log4j.Logger;
import com.crawljax.core.CandidateElement;
import com.crawljax.core.CrawlSession;
import com.crawljax.core.plugin.PreStateCrawlingPlugin;

public class test2 implements PreStateCrawlingPlugin {
	private static final Logger logger = Logger.getLogger(ExtensionAjax.class);
	ArrayList<String> urls;
	boolean replaceInput = false;

	public test2() {

	}

	@Override
	public void preStateCrawling(CrawlSession arg0, List<CandidateElement> arg1) {

		for (CandidateElement a : arg1) {
			logger.info("\n\n" + a.getElement().getBaseURI() + "\n"
					+ a.getElement().getNodeName() + "\n"
					+ a.getElement().getTagName() + "\n"
					+ a.getElement().getNodeValue() + "\n"
					+ a.getElement().getNodeType() + "\n"
					+ a.getElement().getTextContent() + "\n"
					+ a.getElement().getBaseURI() + "\n"
					+ a.getElement().getNodeName() + "\n"
					+ a.getElement().getNodeValue() + "\n"
					+ a.getElement().getTextContent() + "\n"
					+ a.getElement().getTagName() + "\n\n");
		}
	}
}
