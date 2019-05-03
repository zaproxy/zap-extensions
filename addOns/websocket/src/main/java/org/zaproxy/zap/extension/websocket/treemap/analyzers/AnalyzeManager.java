package org.zaproxy.zap.extension.websocket.treemap.analyzers;

import org.zaproxy.zap.extension.websocket.WebSocketMessageDTO;

import java.util.ArrayList;
import java.util.List;

public class AnalyzeManager {
	
	private List<PayloadAnalyzer> analyzers;
	
	public AnalyzeManager(){
		analyzers = new ArrayList<>();
	}
	
	public PayloadAnalyzer recognizeMessage(WebSocketMessageDTO webSocketMessage, PayloadAnalyzer preferableAnalyzer){
		List<PayloadAnalyzer> validAnalyzers = new ArrayList<>();
		for(PayloadAnalyzer payloadAnalyzer : analyzers){
			if(payloadAnalyzer.recognizer(webSocketMessage)){
				validAnalyzers.add(payloadAnalyzer);
			}
		}
		if(validAnalyzers.size() > 1 && preferableAnalyzer != null
				&& validAnalyzers.contains(preferableAnalyzer)){
			return preferableAnalyzer;
		}else if (validAnalyzers.size() > 0) {
			return validAnalyzers.get(0);
		}
		return null;
	}
	
	public void addAnalyzer(PayloadAnalyzer payloadAnalyzer){
		analyzers.add(payloadAnalyzer);
	}
}
