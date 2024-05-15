
pluginManagement {
    repositories {
        mavenCentral()
        gradlePluginPortal()
    }
}

dependencyResolutionManagement {
    versionCatalogs {
        create("libs") {
            version("log4j", "2.20.0")
            library("log4j-core", "org.apache.logging.log4j", "log4j-core").versionRef("log4j")
            library("log4j-slf4j", "org.apache.logging.log4j", "log4j-slf4j-impl").versionRef("log4j")
            library("log4j-slf4j2", "org.apache.logging.log4j", "log4j-slf4j2-impl").versionRef("log4j")
        }
    }
}

rootProject.name = "zap-extensions"

val addOnsProjectName = "addOns"
include(addOnsProjectName)
include("testutils")

// Keep the add-ons in alphabetic order.
var addOns = listOf(
    "accessControl",
    "alertFilters",
    "allinonenotes",
    "ascanrules",
    "ascanrulesAlpha",
    "ascanrulesBeta",
    "authhelper",
    "authstats",
    "automation",
    "beanshell",
    "browserView",
    "bruteforce",
    "bugtracker",
    "callgraph",
    "callhome",
    "client",
    "commonlib",
    "coreLang",
    "custompayloads",
    "database",
    "dev",
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
    "grpc",
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
    "postman",
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
    "webuipoc",
    "zest",
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
    project.children.forEach { it -> setUpProject(it.parent!!.projectDir, it) }
}
