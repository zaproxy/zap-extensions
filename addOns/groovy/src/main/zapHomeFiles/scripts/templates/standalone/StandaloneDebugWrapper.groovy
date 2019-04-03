import org.parosproxy.paros.Constant
import org.zaproxy.zap.extension.script.ExtensionScript

import java.nio.file.Paths

println("Start Debugging...")
def relativeScriptFilePath = "scripts/standalone/StandaloneDefaultTemplate.groovy"

def scriptFilePath = Paths
        .get(Constant.getZapHome(), ExtensionScript.SCRIPTS_DIR, relativeScriptFilePath)
        .toAbsolutePath()
        .toString()

def script = new File(scriptFilePath)
evaluate(script)
println("End Debugging...")