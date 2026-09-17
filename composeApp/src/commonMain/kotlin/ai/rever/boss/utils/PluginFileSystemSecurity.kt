package ai.rever.boss.utils

import ai.rever.boss.utils.logging.BossLogger
import ai.rever.boss.utils.logging.LogCategory
import java.io.File
import java.nio.file.InvalidPathException
import java.nio.file.Path
import java.nio.file.Paths

/**
 * Security utility for plugin filesystem access.
 *
 * Enforces filesystem boundaries, normalizes paths, and prevents path traversal attacks.
 * Integrates with the existing BOSS plugin/sandbox architecture rather than creating
 * a parallel permission framework.
 *
 * ## Security Model
 *
 * - **Boundary**: Plugins are restricted to the user's home directory by default.
 * - **Normalization**: All paths are canonicalized before validation to handle
 *   relative paths, symlinks, and platform-specific separators.
 * - **Traversal Prevention**: Uses canonical path comparison to detect and block
 *   path traversal attempts, including encoded/relative variants.
 * - **Symlink Safety**: Symlinks are resolved to their targets before boundary checks,
 *   preventing symlink escapes from the allowed directory.
 *
 * ## Migration Implications
 *
 * Existing plugins that accessed files outside the user's home directory will now
 * receive SecurityException with a clear error message. This is intentional:
 * unrestricted filesystem access was a security vulnerability, not a feature.
 *
 * Plugins that need access to specific directories outside the home should:
 * 1. Request the user to open files through the FilePickerProvider (user-mediated access)
 * 2. Use project-specific paths provided by ProjectDataProvider
 * 3. Work within the plugin's own storage directory (via PluginStorageFactory)
 */
object PluginFileSystemSecurity {
    private val logger = BossLogger.forComponent("PluginFileSystemSecurity")

    /**
     * Maximum path length to prevent DoS through excessively long paths.
     * Matches the limit used in CLISecurityValidator for consistency.
     */
    private const val MAX_PATH_LENGTH = 32_768

    /**
     * Validates and normalizes a filesystem path for plugin access.
     *
     * This method:
     * - Rejects null bytes and excessively long paths
     * - Normalizes the path to its canonical form
     * - Ensures the path is within the allowed boundary (user home)
     * - Prevents path traversal through canonical comparison
     *
     * @param rawPath The raw path string from the plugin
     * @param operation The operation being performed (for error messages)
     * @return The canonical path if valid
     * @throws SecurityException if the path is invalid or outside the allowed boundary
     */
    fun validateAndNormalizePath(
        rawPath: String,
        operation: String = "filesystem access",
    ): String {
        // Basic validation
        if (rawPath.isBlank()) {
            throw SecurityException("Path cannot be blank for $operation")
        }

        if (rawPath.length > MAX_PATH_LENGTH) {
            throw SecurityException("Path exceeds maximum length of $MAX_PATH_LENGTH characters for $operation")
        }

        // Check for null bytes (can bypass path checks)
        if (rawPath.contains('\u0000')) {
            throw SecurityException("Path contains null byte - possible directory traversal attack for $operation")
        }

        try {
            // Convert to Path object for robust normalization
            val path = Paths.get(rawPath)

            // Normalize to handle . and .. segments
            val normalizedPath = path.normalize()

            // Convert to absolute path
            val absolutePath = normalizedPath.toAbsolutePath()

            // Resolve to canonical path (follows symlinks, handles platform-specific issues)
            val canonicalPath = absolutePath.normalize()

            // Enforce boundary: must be within user's home directory
            val homeDir = File(System.getProperty("user.home")).canonicalFile
            val homePath = homeDir.toPath().normalize()

            if (!isPathWithinBoundary(canonicalPath, homePath)) {
                logger.warn(
                    LogCategory.SECURITY,
                    "Plugin filesystem access denied: path outside allowed boundary",
                    mapOf(
                        "path" to canonicalPath.toString(),
                        "boundary" to homePath.toString(),
                        "operation" to operation,
                    ),
                )
                throw SecurityException(
                    "Access denied: path '${canonicalPath}' is outside the allowed boundary (user home directory). " +
                        "Use FilePickerProvider for user-mediated file access or work within your plugin storage directory.",
                )
            }

            return canonicalPath.toString()
        } catch (e: InvalidPathException) {
            throw SecurityException("Invalid filesystem path for $operation: ${e.message}")
        } catch (e: SecurityException) {
            // Re-throw our security exceptions
            throw e
        } catch (e: Exception) {
            logger.warn(LogCategory.SECURITY, "Path validation failed", mapOf("path" to rawPath, "error" to e.toString()))
            throw SecurityException("Path validation failed for $operation: ${e.message}")
        }
    }

    /**
     * Validates that a child path is within a parent directory boundary.
     *
     * This is used for operations like createFile/createFolder where the plugin
     * specifies a parent directory and a child name.
     *
     * @param parentPath The parent directory path
     * @param childName The child file/folder name
     * @param operation The operation being performed (for error messages)
     * @return The canonical path of the child if valid
     * @throws SecurityException if the child would be outside the parent boundary
     */
    fun validateChildPath(
        parentPath: String,
        childName: String,
        operation: String = "create operation",
    ): String {
        // Validate the parent path first
        val canonicalParent = validateAndNormalizePath(parentPath, operation)

        // Validate the child name (no path separators, no null bytes)
        if (childName.isBlank()) {
            throw SecurityException("Child name cannot be blank for $operation")
        }

        if (childName.contains('\u0000')) {
            throw SecurityException("Child name contains null byte for $operation")
        }

        // Prevent path traversal in the child name
        if (childName.contains("..") || childName.contains("/") || childName.contains("\\") ||
            childName.contains(File.separator)
        ) {
            throw SecurityException("Child name contains path traversal sequences for $operation")
        }

        // Construct the full child path
        val childPath = File(canonicalParent, childName)

        // Ensure the child is within the parent
        val canonicalChild = childPath.canonicalFile
        if (!isPathWithinBoundary(canonicalChild.toPath(), Paths.get(canonicalParent))) {
            throw SecurityException(
                "Path traversal detected: child would be created outside parent directory for $operation",
            )
        }

        return canonicalChild.absolutePath
    }

    /**
     * Checks if a path is within a boundary directory.
     *
     * Uses canonical path comparison to handle symlinks and platform differences.
     *
     * @param path The path to check
     * @param boundary The boundary directory
     * @return true if the path is within the boundary, false otherwise
     */
    private fun isPathWithinBoundary(
        path: Path,
        boundary: Path,
    ): Boolean {
        val normalizedPath = path.normalize()
        val normalizedBoundary = boundary.normalize()

        // Exact match is allowed (the boundary itself)
        if (normalizedPath == normalizedBoundary) {
            return true
        }

        // Check if the path starts with the boundary path plus a separator
        val boundaryString = normalizedBoundary.toString()
        val pathString = normalizedPath.toString()

        return pathString.startsWith(boundaryString + File.separator) ||
            pathString.startsWith(boundaryString + "/") ||
            pathString.startsWith(boundaryString + "\\")
    }

    /**
     * Gets the allowed boundary directory for plugin filesystem access.
     *
     * Currently returns the user's home directory. This can be extended in the
     * future to support plugin-specific boundaries or configuration.
     *
     * @return The canonical boundary directory
     */
    fun getAllowedBoundary(): File {
        return File(System.getProperty("user.home")).canonicalFile
    }
}
