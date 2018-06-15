"""
This script export WebSocket communication to Emacs Org File.
Script require the external Module PyOrgMode (https://github.com/bjonnh/PyOrgMode)
To add an external module: Tools -> Options -> Jython 

Export Format:

* (#<ChannelID>)<WebSocket Channel host name>
** Summary [Optional]
	 - Host: <host>
	 - URI: <URI>
	 - Port: <port>
	 - Websocket Port: <WebSocket Port>
	 - Websocket URL: <WebSocket URL>
	 - Messages Opcodes: 
	 - Outgoing Messages format: 
	 - Incoming Messages format: 
	 - Input Messages encryption: 
	 - Output Messages encryption: 
	 - Ping/Pong: 
	 - Close message: Opcode= , Text= 
** Switching Protocol
*** Handshake Request
	#+BEGIN_SRC html
	<Http Handshake Request>
	#+END_SRC
*** Handshake Respone
	#+BEGIN_SRC html
	<Http Handshake Request>
	#+END_SRC
** Messages
*** (#<ChannelID>.<MessageID) <Direction> <Opcode> <Date Time> <Byte Lenght>
	- Text
	<Text Payload>
	- Hex
	<Hex Payload>
"""

from org.parosproxy.paros.control import Control
from org.parosproxy.paros.extension.history import ExtensionHistory
from org.zaproxy.zap.extension.websocket import ExtensionWebSocket
from org.zaproxy.zap.extension.websocket import WebSocketChannelDTO
from org.zaproxy.zap.extension.websocket import WebSocketMessageDTO
from org.zaproxy.zap.extension.websocket.utility import InvalidUtf8Exception

import PyOrgMode
import sys
import binascii

reload(sys)
sys.setdefaultencoding('utf-8')

extWebSocket = Control.getSingleton().getExtensionLoader().getExtension(ExtensionWebSocket.NAME)
pathToOrgFile = "/path/to/file.org"
printSummary = True
base = PyOrgMode.OrgDataStructure()
channelsList = extWebSocket.getStorage().getTable().getChannelItems()

# Loop through the Channel List
for channel in channelsList:
  hr = channel.getHandshakeReference()
  newChannelElement = PyOrgMode.OrgNode.Element()
  newChannelElement.level = 1
  newChannelElement.heading = "(#"+str(channel.id)+"): "
  if(hr != None):
    handshakeMessage = hr.getHttpMessage()    
    newChannelElement.heading =  newChannelElement.heading + handshakeMessage.getRequestHeader().getHostName() + "\n"
    #Print Summary
    if(printSummary):
      newSummary = PyOrgMode.OrgNode.Element() 
      newSummary.heading = "Summary"
      newSummary.level = 2
      newSummary.append("\t - Host: " + handshakeMessage.getRequestHeader().getHostName() + "\n")
      newSummary.append("\t - URI: " + handshakeMessage.getRequestHeader().getMethod() + " " + handshakeMessage.getRequestHeader().getURI().toString() + "\n")
      newSummary.append("\t - Port: " + str(handshakeMessage.getRequestHeader().getURI().getPort()) + "\n")
      newSummary.append("\t - Websocket Port: " + str(channel.port) +"\n")
      newSummary.append("\t - Websocket Url: " + str(channel.url) + "\n")
      newSummary.append("\t - Messages Opcodes: \n")
      newSummary.append("\t - Outgoing Messages format: \n")
      newSummary.append("\t - Incoming Messages format: \n")
      newSummary.append("\t - Input Messages encryption: \n")
      newSummary.append("\t - Output Messages encryption: \n")
      newSummary.append("\t - Ping/Pong: \n")
      newSummary.append("\t - Close message: Opcode= , Text= \n")
      newChannelElement.append_clean(newSummary);
    
    # Print handshake request
    newHandShake = PyOrgMode.OrgNode.Element()
    newHandShake.heading = "Switching Protocol"
    newHandShake.level = 2

    # Print Request Header 
    newHandShakeRequest = PyOrgMode.OrgNode.Element()
    newHandShakeRequest.heading = "Handshake Request"
    newHandShakeRequest.append("\t#+BEGIN_SRC html \n" + handshakeMessage.getRequestHeader().toString() + "\t#+END_SRC \n") 
    newHandShake.append_clean(newHandShakeRequest)

    # Print Response Header 
    newHandShakeResponse = PyOrgMode.OrgNode.Element()
    newHandShakeResponse.heading = "Handshake Response"
    newHandShakeResponse.append("\t#+BEGIN_SRC html \n" + handshakeMessage.getResponseHeader().toString() + "\t#+END_SRC \n") 
    newHandShake.append_clean(newHandShakeResponse)

    newChannelElement.append_clean(newHandShake)
    
  print("Processing Channel ID: #" + str(channel.id))
  
  #Get Messages  
  messageCriteria = WebSocketMessageDTO(channel)

  messagesList = extWebSocket.getWebsocketMessages(messageCriteria, None,None,0,0,10000)

  newMessages = PyOrgMode.OrgNode.Element()
  newMessages.level = 2
  newMessages.heading = "Messages"

  for message in messagesList:
    if(message.isOutgoing):
      direction = "OUTGOING"
    else:
      direction = "INCOMING"

    newMessage = PyOrgMode.OrgNode.Element()
    newMessage.level = 3
    newMessage.heading = "(#" + str(channel.id) + "." + str(message.id) +") "+ direction + " " + message.readableOpcode +" "+ message.dateTime +" "+ str(message.payloadLength) 

    try:
      messageUTF8 = message.getReadablePayload()
    except InvalidUtf8Exception, e:
      messageUTF8 = "<unreadable binary payload>"
    messageHex = message.payload

    newMessage.append("\t - TEXT\n \t #+BEGIN_SRC\n " + messageUTF8 + "\n\t #+END_SRC\n\n")
    newMessage.append("\t - HEX\n \t #+BEGIN_SRC\n " + binascii.hexlify(messageHex) + "\n\t #+END_SRC\n\n")
    newMessages.append_clean(newMessage)

  newChannelElement.append_clean(newMessages)
  base.root.append_clean(newChannelElement)
    
base.save_to_file(pathToOrgFile)
print("\nWebSocket Communication exported in: " + pathToOrgFile)
