rootProject.name = "zap-extensions"

val addOnsProjectName = "addOns"
include(addOnsProjectName)
include("testutils")

// Keep the add-ons in alphabetic order.
var addOns = listOf(
    "ascanrules",
    "coreLang",
    "directorylistv1",
    "directorylistv2_3",
    "directorylistv2_3_lc",
    "frontendscanner",
    "fuzzdb",
    "gettingStarted",
    "onlineMenu",
    "pscanrules",
    "quickstart",
    "reveal",
    "saverawmessage",
    "savexmlmessage",
    "selenium",
    "spiderAjax",
    "todo",
    "websocket"
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
