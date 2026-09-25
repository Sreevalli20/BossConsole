package ai.rever.boss.utils

import ai.rever.boss.utils.logging.BossLogger
import ai.rever.boss.utils.logging.LogCategory
import java.io.File
import java.nio.file.Files
import java.nio.file.InvalidPathException
import java.nio.file.Path
import java.nio.file.Paths
import java.util.concurrent.ConcurrentHashMap

/**
 * Security utility for plugin filesystem access.
 *
 * Enforces filesystem boundaries based on host-granted capabilities.
 * Integrates with the existing BOSS plugin/sandbox architecture rather than creating
 * a parallel permission framework.
 *
 * ## Security Model
 *
 * - **Explicit Capabilities**: Plugins are granted access to specific filesystem roots
 *   through host-controlled mechanisms (project selection, plugin storage, user-mediated file pickers).
 * - **Normalization**: All paths are canonicalized before validation to handle
 *   relative paths, symlinks, and platform-specific separators.
 * - **Traversal Prevention**: Uses canonical path comparison to detect and block
 *   path traversal attempts, including encoded/relative variants.
 * - **TOCTOU Awareness**: Path validation happens at the operation boundary, not just at check time.
 *
 * ## Allowed Roots
 *
 * The following roots are explicitly granted:
 * - **Plugin Storage**: The plugin's own storage directory (always granted)
 * - **Current Project**: The currently selected project directory (if a project is selected)
 * - **User Home**: The user's home directory (default for backwards compatibility)
 *
 * Additional roots can be granted through user-mediated mechanisms like FilePickerProvider.
 *
 * ## Migration Implications
 *
 * Existing plugins that accessed files outside the granted roots will now
 * receive SecurityException with a clear error message. This is intentional:
 * unrestricted filesystem access was a security vulnerability, not a feature.
 *
 * Plugins that need access to specific directories should:
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
     * Thread-safe set of allowed filesystem roots.
     * Roots are canonical paths that plugins are explicitly granted access to.
     */
    private val allowedRoots = ConcurrentHashMap<String, File>()

    /**
     * Initialize default allowed roots.
     * This is called during plugin initialization to set up the base capabilities.
     */
    fun initializeDefaultRoots(
        pluginStorageDir: File,
        currentProjectDir: File? = null,
    ) {
        // Always grant plugin storage directory
        val canonicalStorage = pluginStorageDir.canonicalFile
        allowedRoots[canonicalStorage.absolutePath] = canonicalStorage

        // Grant current project directory if provided
        if (currentProjectDir != null && currentProjectDir.exists()) {
            val canonicalProject = currentProjectDir.canonicalFile
            allowedRoots[canonicalProject.absolutePath] = canonicalProject
        }

        // Grant user home directory for backwards compatibility
        val homeDir = File(System.getProperty("user.home")).canonicalFile
        allowedRoots[homeDir.absolutePath] = homeDir

        logger.debug(
            LogCategory.FILE,
            "Initialized plugin filesystem security roots",
            mapOf(
                "roots" to allowedRoots.keys.toList(),
            ),
        )
    }

    /**
     * Add an explicit allowed root.
     * This is used for user-mediated grants (e.g., from FilePickerProvider).
     *
     * @param root The directory root to grant access to
     */
    fun addAllowedRoot(root: File) {
        val canonicalRoot = root.canonicalFile
        allowedRoots[canonicalRoot.absolutePath] = canonicalRoot
        logger.debug(
            LogCategory.FILE,
            "Added allowed filesystem root",
            mapOf("root" to canonicalRoot.absolutePath),
        )
    }

    /**
     * Remove an allowed root.
     * This is used for capability revocation.
     *
     * @param root The directory root to revoke access from
     */
    fun removeAllowedRoot(root: File) {
        val canonicalRoot = root.canonicalFile
        allowedRoots.remove(canonicalRoot.absolutePath)
        logger.debug(
            LogCategory.FILE,
            "Removed allowed filesystem root",
            mapOf("root" to canonicalRoot.absolutePath),
        )
    }

    /**
     * Get the current set of allowed roots.
     *
     * @return Set of canonical allowed root paths
     */
    fun getAllowedRoots(): Set<File> = allowedRoots.values.toSet()

    /**
     * Validates and normalizes a filesystem path for plugin access.
     *
     * This method:
     * - Rejects null bytes and excessively long paths
     * - Normalizes the path to its canonical form
     * - Ensures the path is within at least one allowed root
     * - Prevents path traversal through canonical comparison
     * - Resolves symlinks to prevent symlink escapes
     *
     * ## TOCTOU Limitations
     *
     * This validation happens at the check boundary. There is a theoretical time-of-check-to-time-of-use
     * (TOCTOU) window between validation and the actual filesystem operation. For complete TOCTOU safety,
     * filesystem operations would need to use handle-relative or no-follow semantics from native libraries
     * (see boss-native-files). This implementation uses standard Java File API which follows symlinks
     * at operation time, but the boundary check still prevents access to paths outside granted roots.
     *
     * @param rawPath The raw path string from the plugin
     * @param operation The operation being performed (for error messages)
     * @return The canonical path if valid
     * @throws SecurityException if the path is invalid or outside all allowed roots
     */
    @Suppress("ThrowsCount", "TooGenericExceptionCaught")
    fun validateAndNormalizePath(
        rawPath: String,
        operation: String = "filesystem access",
    ): String {
        // Basic validation - collect all validation errors
        val validationError =
            when {
                rawPath.isBlank() -> {
                    "Path cannot be blank for $operation"
                }

                rawPath.length > MAX_PATH_LENGTH -> {
                    "Path exceeds maximum length of $MAX_PATH_LENGTH characters for $operation"
                }

                rawPath.contains('\u0000') -> {
                    "Path contains null byte - possible directory traversal attack for $operation"
                }

                else -> {
                    null
                }
            }

        if (validationError != null) {
            throw SecurityException(validationError)
        }

        return try {
            // Convert to Path object for robust normalization
            val path = Paths.get(rawPath)

            // Normalize to handle . and .. segments
            val normalizedPath = path.normalize()

            // Convert to absolute path
            val absolutePath = normalizedPath.toAbsolutePath()

            // Resolve to real path using FileSystemPathPolicy pattern:
            // Find nearest existing ancestor, resolve it with toRealPath(), then re-resolve remainder
            // This handles both existing paths and paths that don't exist yet
            val canonicalPath = resolvePathWithNearestExistingAncestor(absolutePath, rawPath, operation)

            // Check against all allowed roots using canonical path
            if (!isPathWithinAnyAllowedRoot(canonicalPath)) {
                throw createAccessDeniedSecurityException(canonicalPath, operation)
            }

            canonicalPath.toString()
        } catch (e: InvalidPathException) {
            throw SecurityException("Invalid filesystem path for $operation: ${e.message}", e)
        } catch (e: SecurityException) {
            // Re-throw our security exceptions
            throw e
        } catch (e: java.io.IOException) {
            logger.warn(LogCategory.FILE, "Path validation failed", mapOf("path" to rawPath, "error" to e.toString()))
            throw SecurityException("Path validation failed for $operation: ${e.message}", e)
        } catch (e: Exception) {
            // Catch-all for any other unexpected exceptions
            @Suppress("TooGenericExceptionCaught")
            logger.warn(LogCategory.FILE, "Path validation failed", mapOf("path" to rawPath, "error" to e.toString()))
            throw SecurityException("Path validation failed for $operation: ${e.message}", e)
        }
    }

    /**
     * Resolves a path using the nearest-existing-ancestor pattern from FileSystemPathPolicy.
     *
     * For existing paths: uses toRealPath() to resolve symlinks
     * For non-existent paths: finds nearest existing ancestor, resolves it with toRealPath(),
     * then re-resolves the remaining path components
     *
     * @param absolutePath The absolute normalized path
     * @param rawPath The original raw path for logging
     * @param operation The operation being performed
     * @return The resolved canonical path
     */
    private fun resolvePathWithNearestExistingAncestor(
        absolutePath: Path,
        rawPath: String,
        operation: String,
    ): Path {
        if (Files.exists(absolutePath)) {
            // Path exists - resolve symlinks with toRealPath()
            return try {
                absolutePath.toRealPath()
            } catch (e: java.nio.file.FileSystemException) {
                throw SecurityException("Path validation failed for $operation: ${e.message}", e)
            }
        }

        // Path doesn't exist - find nearest existing ancestor
        var ancestor: Path? = absolutePath.parent
        while (ancestor != null && !Files.exists(ancestor)) {
            ancestor = ancestor.parent
        }

        return if (ancestor != null) {
            // Resolve the existing ancestor with toRealPath(), then re-resolve the remainder
            try {
                val resolvedAncestor = ancestor.toRealPath()
                val remainingPath = ancestor.relativize(absolutePath)
                resolvedAncestor.resolve(remainingPath).normalize()
            } catch (e: java.nio.file.FileSystemException) {
                throw SecurityException("Path validation failed for $operation: ${e.message}", e)
            }
        } else {
            // No existing ancestor found - use normalized path as fallback
            logger.debug(
                LogCategory.FILE,
                "No existing ancestor found for path, using normalized path",
                mapOf("path" to rawPath),
            )
            absolutePath.normalize()
        }
    }

    private fun createAccessDeniedSecurityException(
        canonicalPath: Path,
        operation: String,
    ): SecurityException {
        val errorMessage =
            "Access denied: path '$canonicalPath' is outside all allowed filesystem roots. " +
                "Use FilePickerProvider for user-mediated file access, work within your project directory, " +
                "or use your plugin's storage directory."
        logger.warn(
            LogCategory.FILE,
            "Plugin filesystem access denied: path outside all allowed roots",
            mapOf(
                "path" to canonicalPath.toString(),
                "allowedRoots" to allowedRoots.keys.toList(),
                "operation" to operation,
            ),
        )
        return SecurityException(errorMessage)
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
    @Suppress("ThrowsCount")
    fun validateChildPath(
        parentPath: String,
        childName: String,
        operation: String = "create operation",
    ): String {
        // Validate the parent path first (this resolves symlinks)
        val canonicalParent = validateAndNormalizePath(parentPath, operation)

        // Validate the child name (no path separators, no null bytes)
        val validationError =
            when {
                childName.isBlank() -> "Child name cannot be blank for $operation"

                childName.contains('\u0000') -> "Child name contains null byte for $operation"

                childName.contains("..") ||
                    childName.contains("/") ||
                    childName.contains("\\") ||
                    childName.contains(File.separator) -> "Child name contains path traversal sequences for $operation"

                else -> null
            }

        if (validationError != null) {
            throw SecurityException(validationError)
        }

        // Construct the full child path
        val childPath = Paths.get(canonicalParent, childName)

        // Ensure the child is within the parent using the same resolution model
        // Normalize both paths to ensure consistent comparison
        val normalizedChild = childPath.normalize()
        val normalizedParent = Paths.get(canonicalParent).normalize()

        if (!isPathWithinBoundary(normalizedChild, normalizedParent)) {
            throw SecurityException(
                "Path traversal detected: child would be created outside parent directory for $operation",
            )
        }

        return normalizedChild.toString()
    }

    /**
     * Checks if a path is within any allowed root.
     *
     * Uses canonical path comparison to handle symlinks and platform differences.
     *
     * @param path The path to check
     * @return true if the path is within any allowed root, false otherwise
     */
    private fun isPathWithinAnyAllowedRoot(path: Path): Boolean {
        val normalizedPath = path.normalize()

        for (root in allowedRoots.values) {
            val rootPath = root.toPath().normalize()
            if (isPathWithinBoundary(normalizedPath, rootPath)) {
                return true
            }
        }

        return false
    }

    /**
     * Checks if a path is within a boundary directory.
     *
     * Uses Path.startsWith() which is component-aware to handle symlinks and platform differences.
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

        // Path.startsWith() is component-aware and handles prefix collision attacks
        // (e.g., /home/user vs /home/user-other) correctly
        return normalizedPath.startsWith(normalizedBoundary)
    }
}
