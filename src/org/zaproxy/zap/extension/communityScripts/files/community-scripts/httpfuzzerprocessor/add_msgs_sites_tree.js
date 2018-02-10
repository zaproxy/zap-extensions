// A Fuzzer HTTP Processor script that allows to populate the Sites tree
// with messages sent by the fuzzer (by default the fuzz result/messages
// are not shown in the Fuzzer tab).

var session = org.parosproxy.paros.model.Model.getSingleton().getSession();

function processMessage(utils, message) {}

function processResult(utils, fuzzResult){
    var msg = fuzzResult.getHttpMessage();
    // The type 15 indicates that the message was sent by the user.
    // Refer to the HistoryReference for more details on the available types.
    // Persist the message to the session.
    var ref = new org.parosproxy.paros.model.HistoryReference(session, 15, msg);
    // Add the message to Sites tree.
    java.awt.EventQueue.invokeLater(function() session.getSiteTree().addPath(ref, msg));

    // Do not show the result/messages in the Fuzzer tab.
    return false;
}
