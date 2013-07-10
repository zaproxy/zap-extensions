package org.zaproxy.zap.extension.sse;

import java.io.BufferedReader;
import java.io.IOException;

import org.apache.log4j.Logger;

public class EventStreamListener implements Runnable {
    
	private static final Logger logger = Logger.getLogger(EventStreamListener.class);
	
	private EventStreamProxy proxy;
	private BufferedReader reader;

	public EventStreamListener(EventStreamProxy proxy, BufferedReader reader) {
		this.proxy = proxy;
		this.reader = reader;
	}

	@Override
	public void run() {				
		try {
			String firstEventLine;
			String line;
			while ((firstEventLine = reader.readLine()) != null) {
				if (firstEventLine.equals("")) {
					//TODO: should we really fire an empty event?
					proxy.processEvent("");
				}
				
				StringBuilder rawEvent = new StringBuilder(firstEventLine);
				while ((line = reader.readLine()) != null) {
					if (line.equals("")) {
						// event finishes on newline => trigger dispatch
						proxy.processEvent(rawEvent.toString());
						break;
					}
					rawEvent.append("\n");
					rawEvent.append(line);
				}
			}
		} catch (Exception e) {
			// includes SocketException
			// no more reading possible
			e.printStackTrace();
			logger.info("Server-Sent Events server produced exception: " + e.getMessage(), e);
		} finally {
			logger.info("Server-Sent Events server closed its connection - shutdown");
			this.proxy.stop();
		}
	}

	public void close() throws IOException {
		reader.close();
	}
}
