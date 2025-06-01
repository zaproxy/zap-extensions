import com.diffplug.gradle.spotless.JavaExtension
import com.diffplug.gradle.spotless.SpotlessExtension
import org.gradle.api.Project
import org.gradle.api.artifacts.dsl.DependencyHandler

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
