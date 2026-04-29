import com.diffplug.gradle.spotless.JavaExtension
import com.diffplug.gradle.spotless.SpotlessExtension
import org.gradle.api.Project
import org.gradle.api.artifacts.dsl.DependencyHandler
import org.gradle.api.internal.provider.TransformBackedProvider

/**
 * Configures the java extension with all Java files except the given ones and configures
 * a format with Google Java Format (AOSP) for the given files.
 *
 * <p>It also allows to exclude additional files from both formatting and license checks.
 */
fun SpotlessExtension.javaWith3rdPartyFormatted(project: Project, files: List<String>, excluded: List<String> = listOf()) {
    java {
        target(
            project.fileTree(project.projectDir) {
                include("src/**/*.java")
                exclude(files)
                exclude(excluded)
            },
        )
    }

    format("3rdParty", JavaExtension::class.java, {
        target(
            project.fileTree(project.projectDir) {
                include(files)
            },
        )

        googleJavaFormatAosp()
    })
}

/**
 * Configures the Google Java Format (AOSP).
 */
fun JavaExtension.googleJavaFormatAosp() =
    googleJavaFormat("1.17.0").aosp()

/**
 * Adds an add-on project as a dependency.
 */
fun DependencyHandler.zapAddOn(addOnId: String) {
    add("zapAddOn", project(mapOf("path" to ":addOns:$addOnId")))

    add("testRuntimeOnly", project(mapOf("path" to ":addOns:$addOnId", "configuration" to "zapAddOn")))
}

/**
 * Opt-in Prettier (Spotless) for this add-on only, using the root project's Node/npm.
 * Registers format [formatId] (default `js`) with tasks `:addOns:<id>:spotlessJs`, `spotlessJsCheck`,
 * and `spotlessJsApply` (distinct from root `spotlessJavascript*`).
 */
fun SpotlessExtension.configureZapAddOnSpotlessJs(
    project: Project,
    prettierVersion: String,
    formatId: String = "js",
) {
    format(formatId) {
        target(
            project.fileTree(project.projectDir) {
                include("src/**/*.js", "src/**/*.mjs", "src/**/*.cjs")
            },
        )
        targetExclude(
            "**/*.min.js",
        )
        val npmDir =
            (project.rootProject.tasks.named("npmSetup").get().property("npmDir") as TransformBackedProvider<*, *>)
                .get()
                .toString()
        val npmExecutable =
            if (System.getProperty("os.name").lowercase().contains("windows")) {
                "/npm.cmd"
            } else {
                "/bin/npm"
            }
        prettier(prettierVersion).npmExecutable(npmDir.plus(npmExecutable))
    }

    val implTaskName =
        "spotless" + formatId.replaceFirstChar { if (it.isLowerCase()) it.titlecase() else it.toString() }
    project.tasks.named(implTaskName).configure {
        dependsOn(project.rootProject.tasks.named("nodeSetup"), project.rootProject.tasks.named("npmSetup"))
    }
}
