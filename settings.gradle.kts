rootProject.name = "zap-extensions"

val addOnsProjectName = "addOns"
include(addOnsProjectName)
include("testutils")

// Keep the add-ons in alphabetic order.
var addOns = listOf(
    "accessControl",
    "alertFilters",
    "allinonenotes",
    "amf",
    "ascanrules",
    "ascanrulesAlpha",
    "ascanrulesBeta",
    "authstats",
    "automation",
    "beanshell",
    "browserView",
    "bruteforce",
    "bugtracker",
    "callgraph",
    "callhome",
    "codedx",
    "commonlib",
    "coreLang",
    "custompayloads",
    "diff",
    "directorylistv1",
    "directorylistv2_3",
    "directorylistv2_3_lc",
    "domxss",
    "encoder",
    "evalvillain",
    "exim",
    "formhandler",
    "frontendscanner",
    "fuzz",
    "fuzzdb",
    "gettingStarted",
    "graaljs",
    "graphql",
    "groovy",
    "highlighter",
    "imagelocationscanner",
    "invoke",
    "jruby",
    "jsonview",
    "jython",
    "kotlin",
    "network",
    "oast",
    "onlineMenu",
    "openapi",
    "packpentester",
    "packscanrules",
    "paramdigger",
    "plugnhack",
    "portscan",
    "pscanrules",
    "pscanrulesAlpha",
    "pscanrulesBeta",
    "quickstart",
    "regextester",
    "replacer",
    "reports",
    "requester",
    "retest",
    "retire",
    "reveal",
    "revisit",
    "saml",
    "scripts",
    "selenium",
    "sequence",
    "simpleexample",
    "soap",
    "spider",
    "spiderAjax",
    "sqliplugin",
    "sse",
    "svndigger",
    "tips",
    "todo",
    "tokengen",
    "treetools",
    "viewstate",
    "wappalyzer",
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
