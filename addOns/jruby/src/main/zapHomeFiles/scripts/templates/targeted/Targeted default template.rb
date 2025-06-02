# Targeted scripts can only be invoked by you, the user, e.g. via a right-click option on the Sites or History tabs

def invokeWith(msg)
  # Debugging can be done using puts like this
  puts('invokeWith called for url=' + msg.getRequestHeader().getURI().toString()); 
end