# Plugin Filesystem Access Security Hardening

## Overview

This document describes the security hardening implemented for plugin filesystem access in BOSS. The changes enforce a clear filesystem boundary for plugins, normalize and validate paths before access, and prevent path traversal attacks including equivalent/encoded/relative traversal cases.

## Security Model

### Boundary Enforcement

Plugins are restricted to the user's home directory by default. This boundary is enforced through:

- **Canonical Path Validation**: All paths are resolved to their canonical form before validation
- **Boundary Checks**: Paths must be within the user's home directory
- **Symlink Resolution**: Symlinks are resolved to their targets before boundary checks

### Path Normalization

The security utility performs comprehensive path normalization:

1. **Basic Validation**: Rejects null bytes, blank paths, and excessively long paths (>32KB)
2. **Path Normalization**: Uses `Path.normalize()` to handle `.` and `..` segments
3. **Absolute Path Conversion**: Converts relative paths to absolute paths
4. **Canonical Resolution**: Resolves symlinks and platform-specific path issues

### Traversal Prevention

Path traversal attacks are prevented through:

- **Canonical Comparison**: Uses canonical paths for boundary checks (not string comparison)
- **Segment Validation**: Validates child names don't contain path separators or traversal sequences
- **Symlink Safety**: Resolves symlinks before boundary checks to prevent symlink escapes

## Implementation

### PluginFileSystemSecurity Utility

The `PluginFileSystemSecurity` object provides centralized security validation:

```kotlin
// Validate and normalize a path for filesystem access
val validatedPath = PluginFileSystemSecurity.validateAndNormalizePath(
    rawPath = "/home/user/file.txt",
    operation = "readFile"
)

// Validate a child path (for create operations)
val validatedChildPath = PluginFileSystemSecurity.validateChildPath(
    parentPath = "/home/user/documents",
    childName = "newfile.txt",
    operation = "createFile"
)
```

### Integration Points

Security checks are integrated into:

1. **FileSystemDataProviderImpl**: All filesystem operations now validate paths
   - `scanDirectory` / `scanDirectoryWithDepth`
   - `directoryHasChildren`
   - `openFile`
   - `createFile` / `createFolder`
   - `delete`
   - `rename`
   - `readFile` / `writeFile`
   - `revealInFileManager`

2. **RevealInFileManager**: The reveal utility now validates paths before OS operations

## Migration Implications

### Breaking Changes

Plugins that previously accessed files outside the user's home directory will now receive `SecurityException` with a clear error message. This is intentional: unrestricted filesystem access was a security vulnerability, not a feature.

### Error Messages

When access is denied, plugins receive a clear error message:

```
Access denied: path '/etc/passwd' is outside the allowed boundary (user home directory).
Use FilePickerProvider for user-mediated file access or work within your plugin storage directory.
```

### Recommended Migration Paths

Plugins that need access to specific directories outside the home should:

1. **Use FilePickerProvider**: Request the user to open files through the file picker
   ```kotlin
   val filePicker = pluginContext.filePickerProvider
   val selectedFile = filePicker?.pickFile()
   ```

2. **Use ProjectDataProvider**: Access project-specific paths
   ```kotlin
   val projectPath = pluginContext.projectPath
   // Work within the project directory
   ```

3. **Use PluginStorageFactory**: Store plugin data in the plugin's storage directory
   ```kotlin
   val storageFactory = pluginContext.pluginStorageFactory
   val pluginStorage = storageFactory?.getStorage(pluginId)
   ```

### Testing Recommendations

Plugin developers should:

1. Test all filesystem operations with paths within the user home directory
2. Verify error handling for denied access attempts
3. Use the recommended migration paths for any out-of-bounds access
4. Test with various path formats (relative, absolute, with symlinks)

## Security Benefits

### Prevented Attack Vectors

1. **Path Traversal**: Blocks `../`, encoded variants, and relative traversal
2. **Symlink Escapes**: Resolves symlinks before boundary checks
3. **Null Byte Injection**: Rejects paths with null bytes
4. **Excessive Path Length**: Prevents DoS through long paths
5. **System Directory Access**: Blocks access to sensitive system directories

### Backward Compatibility

The changes preserve legitimate plugin behavior for:

- Plugins that already work within the user home directory
- Standard file operations on user files
- Project-specific workflows
- Plugin storage operations

## Limitations

### Scope

This security hardening is scoped to the `FileSystemDataProvider` interface and does not:

- Provide a full sandbox against concurrent filesystem mutation
- Replace the need for user-mediated access for sensitive operations
- Protect against vulnerabilities in plugin code itself
- Apply to other plugin interfaces (e.g., terminal, network)

### Platform Considerations

- **Windows**: Handles both forward slashes and backslashes correctly
- **macOS**: Resolves case-insensitive filesystem issues
- **Linux**: Standard Unix path handling

### Future Enhancements

Potential future improvements could include:

- Plugin-specific boundary configuration
- Granular permission system for different directories
- User-configurable directory grants
- Integration with RBAC for filesystem permissions

## Testing

### Security Test Coverage

Comprehensive tests cover:

- Path traversal attacks (../, encoded variants)
- Path normalization and canonicalization
- Boundary enforcement (user home directory)
- Symlink escape prevention
- Allowed and denied paths
- Edge cases (null bytes, excessive length, etc.)
- Platform-specific path handling
- Unicode character handling

### Running Tests

```bash
# Run the filesystem security tests
./gradlew :composeApp:test --tests PluginFileSystemSecurityTest

# Run all composeApp tests
./gradlew :composeApp:test
```

## References

- [AGENTS.md](../AGENTS.md) - Project architecture and workflow rules
- [FileSystemPathPolicy](../modules/boss-service-filesystem/src/main/kotlin/ai/rever/boss/service/filesystem/FileSystemPathPolicy.kt) - System path validation for RPC services
- [CLISecurityValidator](../composeApp/src/desktopMain/kotlin/ai/rever/boss/cli/CLISecurityValidator.kt) - CLI security validation patterns

## Conclusion

This security hardening significantly improves the security posture of plugin filesystem access in BOSS while maintaining backward compatibility for legitimate use cases. The clear error messages and recommended migration paths help plugin developers adapt to the new security boundaries.
