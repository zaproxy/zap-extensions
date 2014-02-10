function makeProxyFrame(ifr) {
  var enc = 'data:text/html;charset=US-ASCII,';
  var preSrc = atob('PCFET0NUWVBFIGh0bWw+PGh0bWw+PGhlYWQ+PG1ldGEgY29udGVudD0idGV4dC9odG1sO2NoYXJzZXQ9dXRmLTgiIGh0dHAtZXF1aXY9IkNvbnRlbnQtVHlwZSI+PG1ldGEgY29udGVudD0idXRmLTgiIGh0dHAtZXF1aXY9ImVuY29kaW5nIj48dGl0bGU+TWlkZGxlPC90aXRsZT48L2hlYWQ+PHNjcmlwdD4Kd2luZG93LmFkZEV2ZW50TGlzdGVuZXIoIm1lc3NhZ2UiLGZ1bmN0aW9uKGUpewp2YXIgZGVzdCA9IHdpbmRvdy5wYXJlbnQ7CmlmKGUuc291cmNlID09PSB3aW5kb3cucGFyZW50KSB7CmRlc3QgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgiaW5uZXIiKS5jb250ZW50V2luZG93Owp9CmRlc3QucG9zdE1lc3NhZ2UoZS5kYXRhLCIqIik7Cn0sdHJ1ZSk7Cjwvc2NyaXB0PjxzdHlsZT4KYm9keSwgaHRtbCB7IHdpZHRoOjEwMCUgOwpoZWlnaHQ6MTAwJSA7Cm92ZXJmbG93OmhpZGRlbiA7Cn0KaWZyYW1lIHsgd2lkdGg6MTAwJSA7CmhlaWdodDoxMDAlIDsKYm9yZGVyOm5vbmUgOwp9Cjwvc3R5bGU+PGJvZHk+PGlmcmFtZSBpZD0iaW5uZXIiIG5hbWU9ImlubmVyV2luZG93IiBzcmM9Ig==');
  var postSrc = atob('IiBoZWlnaHQ9IjEwMCUiPjwvaWZyYW1lPjwvYm9keT48L2h0bWw+');
  ifr.src = enc+preSrc+ifr.src+postSrc;
}
/*
 * Makes a listener that directs messages to the appropriate actor based on
 * the message type.
 */
function getActorsListener(messagePeer, getEndpointName) {
  // TODO: replace with something that actually makes something globally
  // unique (this is what ZAP uses currently)
  function zapS4() {
    return (((1+Math.random())*0x10000)|0).toString(16).substring(1);
  }
  function zapGuidGen() {
    return zapS4()+zapS4()+"-"+zapS4()+"-"+zapS4()+"-"+zapS4()+"-"+zapS4()+zapS4()+zapS4();
  }

  // Actors which receieve messages from the tool
  var actors = {
    /*
     * set the location of the current window. Useful for, e.g. forcing the
     * browser to make a request.
     */
    'setLocation' : function(message) {
      if(message.URL) {
        // navigate to the specified URL
        window.location = message.URL;
      }
    },

    /*
     * cause the browser to make a request with a given method. Useful for,
     * e.g. resending forms for replaying a POST.
     */
    'makeRequest' : function(message) {
      if(message.URL && message.method) {
        // inject a form into the document
        var form = document.createElement('form');
        form.method = message.method;
        form.action = message.URL;
        // TODO: set form parameters would be nice
        document.body.appendChild(form);

        // submit the form
        form.submit();
      }
    }
  };

  // hook in things from the DOM
  // postMessage Proxy stuff
  var awaitingResponses = [];
  var endpoints = [];
  var forEach = Array.prototype.forEach;

  function hookWindow(win) {
    if(!win.postMessage.isPnHProbe){
      try{
        var endpointId = zapGuidGen();
        win.origPostMessage = win.postMessage;
        endpoints[endpointId] = function(response) {
          win.origPostMessage(response.data, '*');
        }
        win.postMessage = function(message, targetOrigin, transfer){
          var pMsg = {
            to:getEndpointName(),
            type:'interceptPostMessage',
            from:'TODO: we need a from',
            target:'someTarget',
            data:message,
            messageId:zapGuidGen(),
            endpointId:endpointId
          };
          messagePeer.sendMessage(pMsg);
          awaitingResponses[pMsg.messageId] = function(response){
            if(transfer) {
              //win.origPostMessage(response.data, targetOrigin, transfer);
              win.origPostMessage(response.data, '*', transfer);
            } else {
              //win.origPostMessage(response.data, targetOrigin);
              win.origPostMessage(response.data, '*');
            }
          };
          // TODO: setTimeout for no response
        }
        win.postMessage.isPnHProbe = true;
        console.log('hooked');
        return true;
      } catch (e) {
        console.log('conventional hook failed');
        return false;
      }
    } else {
      return true;
      console.log('pnh hook postMessage hook already in place');
    }
  }

  function makeProxy(fn, pre, post) {
    if(fn.isPnHProbeProxy) return fn;
    console.log('make proxy... '+fn);
    newFn = function(){
      var newArgs = pre ? pre(this,arguments) : arguments;
      var ret = fn.apply(this, newArgs);
      return post ? post(ret) : ret;
    }
    newFn.isPnHProbeProxy = true;
    return newFn;
  }

  function addEventListenerProxy(obj, args) {
    var type = args[0];
    var onEventProxy = makeProxy(args[1], function() {
      //TODO: replace with an actual implementation
      var evt = arguments[1][0];
      var endpointId = zapGuidGen();
      var message = 'a '+type+' event happened!';
      var pMsg = {
        to:getEndpointName(),
        type:'eventInfoMessage',
        from:'TODO: we need a from',
        target:'someTarget',
        data:message,
        evt:evt,
        messageId:zapGuidGen(),
        endpointId:endpointId
      };
      messagePeer.sendMessage(pMsg);
      return arguments[1];
    });
    return[args[0], onEventProxy, args[2]];
  }

  function proxyAddEventListener(node) {
    node.addEventListener = makeProxy(node.addEventListener, addEventListenerProxy);
  }

  var observer = new MutationObserver(function(mutations) {
    function hookNode(node) {
      if(node.contentWindow && node.contentWindow.postMessage) {
        node.addEventListener('load', function() {
          console.log("MODIFY TEH "+node.nodeName+"!!!");
          if(!hookWindow(node.contentWindow)) {
            makeProxyFrame(node);
            hookWindow(node.contentWindow);
            console.log('tried alternative postMessage hook');
          }
        }, false);
      }
      forEach.call(node.childNodes, function(child){
        hookNode(child);
      });
    };

    mutations.forEach(function(mutation) {
      forEach.call(mutation.addedNodes, function(node){
        hookNode(node);
      });
    });
  });

  // configuration of the observer:
  var config = { attributes: true, childList: true, characterData: true, subtree: true };

  // pass in the target node, as well as the observer options
  observer.observe(document, config);

  hookWindow(window);
  proxyAddEventListener(window);
  proxyAddEventListener(Node.prototype);

  /*
   * The actual listener that's returned for adding to a receiver.
   */
  return function(message) {
    if(message && message.type) {
      if(actors[message.type]) {
        actors[message.type](message);
      } else {
        // if we're awaiting a response with this ID, call the handler
        if(message.responseTo) {
          if(awaitingResponses[message.responseTo]){
            console.log('awaiting response: '+message.responseTo+' - handling');
            var handleFunc = awaitingResponses[message.responseTo];
            delete awaitingResponses[message.responseTo];
            handleFunc(message);
          } else {
            if(endpoints[message.responseTo]){
              console.log('known endpoint: '+message.responseTo+' - handling');
              endpoints[message.responseTo](message);
            } else {
              console.log('no endpoint or awaited response for message '+message.responseTo);
            }
          }
        }
      }
    } else {
      console.log('no message data or missing type information');
    }
  };
}
function Receiver(name, remote){
  this.remote = !!remote;
  this.name = name;
  this.listeners = [];

  // TODO use emit / proper custom events
  this.addListener = function(listener){
    this.listeners[this.listeners.length] = listener;
  };

  this.forward = function(message) {
    for(i in this.listeners){
      var listener = this.listeners[i];
      listener(message);
    }
  };
}

var messageClient = function () {
  var receivers = [];
  var messagePeer = {
    sendMessage:function(message){
      var dest = message.to;
      var receiver = this.getReceiver(dest);
      receiver.forward(message);
    },

    getReceiver:function(name) {
      if(!receivers[name]) {
        receivers[name] = new Receiver(name);
      }
      return receivers[name];
    },

    getLocalReceivers:function() {
      var localReceivers = [];
      for(var idx=0; idx < receivers.length; idx++) {
        var receiver = receivers[idx];
        if(!receiver.remote) {
          localReceivers[localReceivers.length] = receiver;
        }
      }
      return localReceivers;
    }
  };
  return messagePeer;
}();

function Heartbeat(interval, heartbeatID, destination) {
  this.interval = 1000;
  if(interval) {
    this.interval = interval;
  }
  this.heartbeatID = heartbeatID;
  this.destination = destination;
}

Heartbeat.prototype.beat = function() {
  messageClient.sendMessage({type:'heartbeat', time:new Date().getTime(), to:this.destination, from:this.heartbeatID});
}

Heartbeat.prototype.stop = function() {
  if(this.handle) {
    clearInterval(this.handle);
    this.handle = false;
  }
}

Heartbeat.prototype.start = function() {
  if(this.handle) {
    this.stop();
  }
  this.handle = setInterval(this.beat.bind(this),this.interval);
}
// TODO: Configure the messagetransport from the probe config section
function HTTPMessageTransport(name, receiver, config) {
  this.name = name;
  this.receiver = receiver;
  this.config = config;
}

HTTPMessageTransport.prototype.makeURL = function(message) {
  var unencoded = JSON.stringify(message);
  var encoded = encodeURI ? encodeURI(unencoded) : escape(unencoded);
  // TODO local ZAP edit
  var URL = this.config.endpoint+"message="+encoded+'&id='+this.name;
  return URL;
}

HTTPMessageTransport.prototype.send = function(message) {
  var xhr = new XMLHttpRequest();
  var URL = this.makeURL(message);
  xhr.open("GET", URL, true);
  xhr.onload = function(aEvt){
    if (xhr.readyState == 4) {
      if(xhr.status == 200) {
        var messages = JSON.parse(xhr.responseText).messages;
        for(var idx = 0; idx < messages.length; idx++) {
          if(this.receiver) {
            this.receiver.forward(messages[idx]);
          }
        }
      }
      else {
        console.log("Error loading page\n");
      }
    }
  }.bind(this);

  xhr.onerror = function(e) {
    console.log('Request to transport endpoint failed');
    console.log(e.target.status);
  };
  xhr.send();
}
const transports = {HTTPMessageTransport:HTTPMessageTransport};

function Probe(url, id) {
  // TODO: create the transport name from a GUID or something (perhaps the
  // injector can get something sensible).
  this.transportName = id;
  this.receiver = messageClient.getReceiver(this.transportName);

  this.getEndpointName = function(){
    return this.endpointName;
  }

  this.receiver.addListener(getActorsListener(messageClient, this.getEndpointName.bind(this)));
  // TODO: wrap with promise pixie dust
  var xhr = new XMLHttpRequest();
  xhr.open("GET", url, true);
  xhr.onload = function(aEvt) {
    if (xhr.readyState == 4) {
      if (xhr.status == 200) {
        var json = xhr.responseText;
        var manifest = JSON.parse(json);
        this.configure(manifest);
      }
    }
  }.bind(this);
  xhr.send();
}

Probe.prototype.configure = function(manifest) {
  if(manifest && manifest.features && manifest.features.probe) {
    var probeSection = manifest.features.probe;

    // get the remote endpoint ID
    this.endpointName = probeSection.endpointName;

    // find a suitable transport
    this.transport = new transports[probeSection.transport](this.transportName,
        this.receiver, probeSection);

    // Wire the transport to receive messages to the remote endpoint
    var remoteReceiver = messageClient.getReceiver(this.endpointName);
    remoteReceiver.addListener(function(message){
      this.transport.send(message);
    }.bind(this));

    // create a heartbeat
    // now create the heartbeat
    // TODO: Configure the heartbeat interval from the manifest
    this.heartbeat = new Heartbeat(1000, this.transportName, this.endpointName);
    this.heartbeat.start();

    // make XSS oracle
    if(probeSection.oracle) {
      window.xss = function(arg) {
        var child = document.createElement('img');
        function cleanup(){
          console.log('cleaning up');
          document.body.removeChild(child);
        }
        child.src = probeSection.oracle+arg;
        child.addEventListener('load',cleanup,false);
        child.addEventListener('error',cleanup,false);
        document.body.appendChild(child);
      };
    }
  }
}
