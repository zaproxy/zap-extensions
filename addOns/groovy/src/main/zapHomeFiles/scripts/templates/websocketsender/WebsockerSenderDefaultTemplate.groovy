import org.zaproxy.zap.extension.websocket.WebSocketMessage
import org.zaproxy.zap.extension.websocket.WebSocketSenderScriptHelper

// Note that new WebSocketSender scripts will initially be disabled
// Right click the script in the Scripts tree and select "enable"

/**
 * Called before forwarding the WebSocket message frame to the server or client.
 *
 * @param {WebSocketMessage} msg - The message frame being sent or received.
 * @param {WebSocketSenderScriptHelper} helper - Gives access to the websocket connection Initiator and the channelId.
 */
void onMessageFrame(WebSocketMessage msg, WebSocketSenderScriptHelper helper){
    println(msg.getReadablePayload())
}
