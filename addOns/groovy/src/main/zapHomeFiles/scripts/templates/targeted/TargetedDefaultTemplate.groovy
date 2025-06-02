/*
Targeted scripts can only be invoked by you, the user, e.g. via a right-click option on the Sites or History tabs
*/
import org.parosproxy.paros.network.HttpMessage

void invokeWith(HttpMessage msg){
  println('invokeWith called for url=' + msg.getRequestHeader().getURI().toString())
}

// Needed for debugging with the DebugWrapper script
// Returns the function, that will be executed by the DebugWrapper script
return [
    invokeWith :  { msg -> invokeWith(msg) }
]