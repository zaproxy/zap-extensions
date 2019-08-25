package org.zaproxy.zap.extension.websocket.treemap.analyzers;

import org.zaproxy.zap.extension.websocket.WebSocketMessageDTO;
import org.zaproxy.zap.extension.websocket.treemap.analyzers.structures.PayloadStructure;

public interface PayloadAnalyzer {
    PayloadStructure getPayloadStructure(WebSocketMessageDTO webSocketMessageDTO) throws Exception;
    boolean recognizer(WebSocketMessageDTO webSocketMessageDTO);
    String getName();
	String getLeafName(PayloadStructure payloadStructure);
}
