package org.zaproxy.zap.extension.websocket.treemap.nodes;

import org.zaproxy.zap.extension.websocket.WebSocketMessage;

public enum WebSocketNodeType {
    HANDSHAKE, MESSAGE_CLOSE, MESSAGE_PING, MESSAGE_PONG, MESSAGE_TEXT, MESSAGE_OBJECT, FOLDER_HOST,
    FOLDER_ROOT, FOLDER_HANDSHAKES, FOLDER_MESSAGES, FOLDER_HEARTBEATS, FOLDER_CLOSE;
    
    public static WebSocketNodeType getAppropriateType(int opcode, boolean isFolder){
        WebSocketNodeType result = null;
        switch (opcode){
            case WebSocketMessage.OPCODE_BINARY:
                if(isFolder){
                    result = FOLDER_MESSAGES;
                }else{
                    result = MESSAGE_OBJECT;
                }
                break;
            case WebSocketMessage.OPCODE_TEXT:
                if(isFolder){
                    result = FOLDER_MESSAGES;
                }else{
                    result = MESSAGE_TEXT;
                }
                break;
            case WebSocketMessage.OPCODE_PING:
                if(isFolder){
                    result = FOLDER_HEARTBEATS;
                }else{
                    result = MESSAGE_PING;
                }
                break;
            case WebSocketMessage.OPCODE_PONG:
                if(isFolder){
                    result = FOLDER_HEARTBEATS;
                }else{
                    result = MESSAGE_PONG;
                }
                break;
            case WebSocketMessage.OPCODE_CLOSE:
                if(isFolder){
                    result = FOLDER_CLOSE;
                }else{
                    result = MESSAGE_CLOSE;
                }
                break;
        }
        return result;
    }
}
