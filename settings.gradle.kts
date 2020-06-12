rootProject.name = "zap-extensions"

val addOnsProjectName = "addOns"
include(addOnsProjectName)
include("testutils")

// Keep the add-ons in alphabetic order.
var addOns = listOf(
    "accessControl",
    "alertFilters",
    "alertReport",
    "allinonenotes",
    "amf",
    "ascanrules",
    "ascanrulesAlpha",
    "ascanrulesBeta",
    "authstats",
    "beanshell",
    "birtreports",
    "browserView",
    "bruteforce",
    "bugtracker",
    "callgraph",
    "cmss",
    "codedx",
    "commonlib",
    "coreLang",
    "custompayloads",
    "customreport",
    "diff",
    "directorylistv1",
    "directorylistv2_3",
    "directorylistv2_3_lc",
    "domxss",
    "encoder",
    "exportreport",
    "formhandler",
    "frontendscanner",
    "fuzz",
    "fuzzdb",
    "gettingStarted",
    "graaljs",
    "graphql",
    "groovy",
    "highlighter",
    "httpsInfo",
    "imagelocationscanner",
    "importLogFiles",
    "importurls",
    "invoke",
    "jruby",
    "jsonview",
    "jython",
    "kotlin",
    "onlineMenu",
    "openapi",
    "plugnhack",
    "portscan",
    "pscanrules",
    "pscanrulesAlpha",
    "pscanrulesBeta",
    "quickstart",
    "regextester",
    "replacer",
    "requester",
    "retire",
    "reveal",
    "revisit",
    "saml",
    "saverawmessage",
    "savexmlmessage",
    "scripts",
    "selenium",
    "sequence",
    "simpleexample",
    "soap",
    "spiderAjax",
    "sqliplugin",
    "sse",
    "svndigger",
    "tips",
    "tlsdebug",
    "todo",
    "tokengen",
    "treetools",
    "viewstate",
    "vulncheck",
    "wappalyzer",
    "wavsepRpt",
    "webdrivers",
    "webdrivers:webdriverlinux",
    "webdrivers:webdrivermacos",
    "webdrivers:webdriverwindows",
    "websocket",
    "zest"
)

addOns.forEach { include("$addOnsProjectName:$it") }

rootProject.children.forEach { project -> setUpProject(settingsDir, project) }

fun setUpProject(parentDir: File, project: ProjectDescriptor) {
    project.projectDir = File(parentDir, project.name)
    project.buildFileName = "${project.name}.gradle.kts"

    if (!project.projectDir.isDirectory) {
        throw AssertionError("Project ${project.name} has no directory: ${project.projectDir}")
    }
    if (!project.buildFile.isFile) {
        throw AssertionError("Project ${project.name} has no build file: ${project.buildFile}")
    }
    project.children.forEach { project -> setUpProject(project.parent!!.projectDir, project) }
}
