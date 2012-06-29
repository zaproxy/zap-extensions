package org.zaproxy.zap.extension.spiderAjax;

import java.util.ArrayList;
import org.apache.log4j.Logger;
import com.crawljax.core.CrawlSession;
import com.crawljax.core.plugin.OnNewStatePlugin;

public class test implements OnNewStatePlugin {
	private static final Logger logger = Logger.getLogger(ExtensionAjax.class);

	ArrayList<String> urls;
	boolean replaceInput = false;

	public test(boolean replaceInput) {
		this.replaceInput = replaceInput;
		this.urls = new ArrayList<String>();
	}

	public void onNewState(CrawlSession session) {

		logger.info("\n\n" +
				session.getCurrentState().getUrl() +
				session.getCurrentState().getName() +
				session.getCurrentState().toString() +
				session.getCurrentState().getStrippedDom() +
				session.getStateFlowGraph().toString() +
				session.getCrawlPaths().toString() +
				session.getBrowser().getCurrentUrl() +
				session.getBrowser().getDom() +
				session.getCurrentState().getUrl() +
				session.getCurrentState().getUrl() +
				session.getCurrentState().getUrl() +
				
 "\n\n");

	}


}
