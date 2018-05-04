//@zaproxy-standalone

org.zaproxy.zap.extension.script.ScriptVars.setGlobalVar('LIST', JSON.stringify(['Zaproxy', 'Zap', 'Simon', 'Mozilla']))

var list = JSON.parse(org.zaproxy.zap.extension.script.ScriptVars.getGlobalVar('LIST'))

list.forEach(function(item) {
	print(item)
})
