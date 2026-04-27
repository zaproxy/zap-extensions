// Adds an example MCP resource that returns sample data.
//
// Extender scripts allow you to add completely new functionality to ZAP.
// The install function is called when the script is enabled and the uninstall
// function when it is disabled. Any functionality added in the install function
// should be removed in the uninstall method.
//
// This script demonstrates how to register a custom MCP resource with the ZAP
// MCP Server. The MCP add-on must be installed for this to work.

const ExtensionMcp = Java.type("org.zaproxy.addon.mcp.ExtensionMcp");
const McpResource = Java.type("org.zaproxy.addon.mcp.McpResource");

const RESOURCE_URI = "zap://example-resource";
const NAME = "example-resource";

function newResource() {
  return new (Java.extend(McpResource))({
    getUri: function () {
      return RESOURCE_URI;
    },

    getName: function () {
      return NAME;
    },

    getDescription: function () {
      return "An example MCP resource that returns sample data. Use this as a template for custom resources.";
    },

    readContent: function () {
      var content = McpResource.OBJECT_MAPPER.createObjectNode();
      content.put("message", "This is an example MCP resource");
      content.put("uri", this.getUri());
      content.put("name", this.getName());
      content.put("description", this.getDescription());
      content.put("timestamp", new Date().toISOString());
      return content.toString();
    },
  });
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
    extMcp.getResourceRegistry().unregisterResource(RESOURCE_URI);
  }
}
