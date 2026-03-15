// Adds an example MCP resource that returns sample data.
//
// Extender scripts allow you to add completely new functionality to ZAP.
// The install function is called when the script is enabled and the uninstall
// function when it is disabled. Any functionality added in the install function
// should be removed in the uninstall method.
//
// This script demonstrates how to register a custom MCP resource with the ZAP
// MCP Server. The MCP add-on must be installed for this to work.

var Control = Java.type("org.parosproxy.paros.control.Control");
var ExtensionMcp = Java.type("org.zaproxy.addon.mcp.ExtensionMcp");
var McpResource = Java.type("org.zaproxy.addon.mcp.McpResource");

const NAME = "example-resource";

function newResource() {
  return new (Java.extend(McpResource)) {
    getUri: function() {
      return "zap://example-resource";
    },

    getName: function() {
      return NAME;
    },

    getDescription: function() {
      return "An example MCP resource that returns sample data. Use this as a template for custom resources.";
    },

    getMimeType: function() {
      return "application/json";
    },

    toListEntry: function() {
      var node = McpResource.OBJECT_MAPPER.createObjectNode();
      node.put("uri", this.getUri());
      node.put("name", this.getName());
      node.put("description", this.getDescription());
      node.put("mimeType", this.getMimeType());
      return node;
    },

    readContent: function(uri) {
      var content = McpResource.OBJECT_MAPPER.createObjectNode();
      content.put("message", "This is an example MCP resource");
      content.put("uri", uri || this.getUri());
      content.put("timestamp", new Date().toISOString());
      return content.toString();
    }
  };
}

/**
 * This function is called when the script is enabled.
 *
 * @param helper - a helper class which provides the methods:
 *   getView() - returns a View object (null in daemon mode)
 *   getApi() - returns an API object for adding API calls
 */
function install(helper) {
  var extMcp = control.getExtensionLoader().getExtension(ExtensionMcp);
  if (extMcp === null) {
    print("MCP add-on is not installed. Cannot register example resource.");
    return;
  }
  extMcp.getResourceRegistry().registerResource(newResource());
}

/**
 * This function is called when the script is disabled.
 *
 * @param helper - a helper class which provides the methods:
 *   getView() - returns a View object (null in daemon mode)
 *   getApi() - returns an API object for adding API calls
 */
function uninstall(helper) {
  var extMcp = control.getExtensionLoader().getExtension(ExtensionMcp);
  if (extMcp !== null) {
    extMcp.getResourceRegistry().unregisterResource(NAME);
  }
}
