rootProject.name = "zap-extensions"

val addOnsProjectName = "addOns"
include(addOnsProjectName)
include("testutils")

// Keep the add-ons in alphabetic order.
var addOns = listOf(
    "alertFilters",
    "alertReport",
    "ascanrules",
    "ascanrulesBeta",
    "beanshell",
    "bruteforce",
    "coreLang",
    "diff",
    "directorylistv1",
    "directorylistv2_3",
    "directorylistv2_3_lc",
    "frontendscanner",
    "fuzz",
    "fuzzdb",
    "gettingStarted",
    "groovy",
    "importurls",
    "invoke",
    "jruby",
    "jython",
    "onlineMenu",
    "plugnhack",
    "portscan",
    "pscanrules",
    "pscanrulesBeta",
    "quickstart",
    "replacer",
    "reveal",
    "saverawmessage",
    "savexmlmessage",
    "scripts",
    "selenium",
    "spiderAjax",
    "sqliplugin",
    "svndigger",
    "tips",
    "todo",
    "tokengen",
    "treetools",
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
