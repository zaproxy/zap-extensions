package org.zaproxy.zap.extension.sse.ui.httppanel.views.large;

import org.zaproxy.zap.extension.httppanel.Message;
import org.zaproxy.zap.extension.httppanel.view.largeresponse.LargeResponseUtil;
import org.zaproxy.zap.extension.sse.ServerSentEvent;

public class EventStreamLargeEventUtil extends LargeResponseUtil {

	public static boolean isLargeEvent(Message aMessage) {
		if (aMessage instanceof ServerSentEvent) {
			ServerSentEvent message = (ServerSentEvent) aMessage;
			Long length = message.getRawEventLength();
			if (length == null) {
				return false;
			}
			return length > minContentLength;
		}

		return false;
	}
}