package org.zaproxy.zap.extension.websocket.scanner.ascan.plugin;

import org.zaproxy.zap.extension.websocket.treemap.analyzers.structures.PayloadStructure;
import org.zaproxy.zap.extension.websocket.treemap.analyzers.structures.utilities.ClassValuePair;
import org.zaproxy.zap.extension.websocket.treemap.nodes.WebSocketMessageNode;

import java.util.Iterator;
import java.util.List;
import java.util.Map;

public abstract class WebSocketMessageParamScan extends WebSocketMessageNodeScan {
	
	public abstract void scanMessageParam(String key, ClassValuePair valuePair);
	
	public abstract boolean applyScan(String key, ClassValuePair valuePair);
	
	@Override
	public boolean applyScan(WebSocketMessageNode messageNode) {
		return (messageNode.getPayloadAnalyzer() != null && messageNode.getPayloadStructure() != null);
	}
	
	@Override
	public void scanMessageNode(WebSocketMessageNode messageNode) {
		PayloadStructure payloadStructure = messageNode.getPayloadStructure();
		recursiveScan(payloadStructure);
	}
	
	private void recursiveScan(PayloadStructure payloadStructure){
		Iterator<Map.Entry<String,ClassValuePair>> iterator = payloadStructure.getMap().entrySet().iterator();
		while (iterator.hasNext()){
			Map.Entry<String,ClassValuePair> entry = iterator.next();
			if(entry.getValue().getaClass().isAssignableFrom(PayloadStructure.class) ){
				recursiveScan((PayloadStructure) entry.getValue());
			}else if (entry.getValue().getaClass().isAssignableFrom(List.class)){
				for(ClassValuePair value : entry.getValue().getValueList()){
					if(value.getaClass().isAssignableFrom(PayloadStructure.class)){
						recursiveScan((PayloadStructure) value.getValue());
					}else {
						if(applyScan(entry.getKey(), value)){
							scanMessageParam(entry.getKey(),value);
						}
						
					}
				}
			}else{
				if(applyScan(entry.getKey(), entry.getValue())) {
					scanMessageParam(entry.getKey(), entry.getValue());
				}
			}
		}
	}
}
