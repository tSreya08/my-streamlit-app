import os
import io
import stat
import zipfile
from typing import List, Dict, Any, Optional, Union
from core.sandbox_runner import safe_cleanup

# Resource Limits to Prevent ZIP Bombs & Resource Exhaustion
MAX_COMPRESSED_SIZE_BYTES = 25 * 1024 * 1024       # 25 MB
MAX_UNCOMPRESSED_SIZE_BYTES = 100 * 1024 * 1024     # 100 MB
MAX_FILE_COUNT = 1000                               # Max files allowed in zip
MAX_SINGLE_FILE_SIZE_BYTES = 10 * 1024 * 1024       # 10 MB per file

# Directory names to ignore during extraction and scanning
IGNORED_DIRS = {
    ".venv", "venv", "__pycache__", "node_modules",
    ".pytest_cache", ".mypy_cache", ".tox", ".eggs",
    "dist", "build", ".idea", ".vscode"
}

DEPENDENCY_FILENAMES = {
    "requirements.txt", "pyproject.toml", "Pipfile", "setup.py"
}


class IngestionError(Exception):
    """Custom exception raised when project ingestion or zip validation fails."""
    pass


class IngestedProject:
    """
    Represents an extracted, validated Python project ready for investigation.
    """
    def __init__(
        self,
        project_dir: str,
        python_files: List[str],
        dependency_files: Dict[str, Any],
        file_tree: List[str],
        has_git: bool,
        git_message: str
    ):
        self.project_dir = project_dir
        self.python_files = sorted(python_files)
        self.dependency_files = dependency_files
        self.file_tree = sorted(file_tree)
        self.has_git = has_git
        self.git_message = git_message

    def cleanup(self):
        """Safely cleans up the temporary project directory."""
        if self.project_dir and os.path.exists(self.project_dir):
            safe_cleanup(self.project_dir)

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.cleanup()


def is_path_safe(base_dir: str, rel_path: str) -> bool:
    """
    Ensures the target extraction path does not escape base_dir.
    """
    base_abs = os.path.abspath(base_dir)
    target_abs = os.path.abspath(os.path.join(base_dir, rel_path))
    return target_abs == base_abs or target_abs.startswith(base_abs + os.sep)


def should_ignore_entry(filename: str) -> bool:
    """
    Checks if a zip entry belongs to an ignored directory.
    Note: .git is NOT ignored here; it is handled separately to preserve history.
    """
    parts = filename.replace("\\", "/").split("/")
    for part in parts:
        if part in IGNORED_DIRS:
            return True
    return False


def validate_zip_safety(zf: zipfile.ZipFile, compressed_size: Optional[int] = None):
    """
    Validates ZIP file safety constraints:
    - Path traversal attempts (.. or absolute paths)
    - Symlinks / special files
    - Resource limits (file count, single file size, total uncompressed size, compressed size)
    """
    if compressed_size is not None and compressed_size > MAX_COMPRESSED_SIZE_BYTES:
        raise IngestionError(
            f"Archive compressed size ({compressed_size / (1024 * 1024):.1f} MB) exceeds "
            f"the maximum allowed limit of {MAX_COMPRESSED_SIZE_BYTES / (1024 * 1024):.0f} MB."
        )

    entries = zf.infolist()
    if len(entries) > MAX_FILE_COUNT:
        raise IngestionError(
            f"Archive contains {len(entries)} files, exceeding the limit of {MAX_FILE_COUNT} files."
        )

    total_uncompressed = 0
    for info in entries:
        # Check path traversal
        norm_name = os.path.normpath(info.filename).replace("\\", "/")
        if norm_name.startswith(("/", "\\")) or info.filename.startswith(("/", "\\")):
            raise IngestionError(f"Security error: Absolute path detected in ZIP: '{info.filename}'")
        
        parts = [p for p in norm_name.split("/") if p]
        if ".." in parts:
            raise IngestionError(f"Security error: Path traversal ('..') detected in ZIP: '{info.filename}'")

        # Check for symlinks
        is_symlink = ((info.external_attr >> 16) & 0o170000) == 0o120000
        if is_symlink:
            raise IngestionError(f"Security error: Symlink entry detected in ZIP: '{info.filename}'")

        # Check single file size
        if info.file_size > MAX_SINGLE_FILE_SIZE_BYTES:
            raise IngestionError(
                f"File '{info.filename}' ({info.file_size / (1024 * 1024):.1f} MB) exceeds "
                f"single file limit of {MAX_SINGLE_FILE_SIZE_BYTES / (1024 * 1024):.0f} MB."
            )

        total_uncompressed += info.file_size
        if total_uncompressed > MAX_UNCOMPRESSED_SIZE_BYTES:
            raise IngestionError(
                f"Total uncompressed archive size exceeds limit of "
                f"{MAX_UNCOMPRESSED_SIZE_BYTES / (1024 * 1024):.0f} MB (ZIP bomb protection)."
            )


def extract_project_zip(
    zip_source: Union[str, bytes, io.BytesIO],
    target_base_dir: Optional[str] = None
) -> IngestedProject:
    """
    Safely ingests and extracts a Python project ZIP file.
    
    1. Validates zip integrity and safety limits.
    2. Extracts into a temporary sandbox directory.
    3. Ignores unnecessary folders (.venv, __pycache__, node_modules).
    4. Preserves .git metadata read-only while neutralizing any executable git hooks.
    5. Discovers Python files, dependency declarations, and builds project tree.
    6. Verifies that at least one Python file is present.
    """
    import tempfile

    temp_dir = tempfile.mkdtemp(prefix="phantom_ingest_", dir=target_base_dir)

    try:
        # 1. Open zip archive
        compressed_size = None
        if isinstance(zip_source, str):
            if not os.path.isfile(zip_source):
                raise IngestionError(f"File not found: '{zip_source}'")
            compressed_size = os.path.getsize(zip_source)
            if not zipfile.is_zipfile(zip_source):
                raise IngestionError("The provided file is not a valid ZIP archive.")
            zf = zipfile.ZipFile(zip_source, "r")
        elif isinstance(zip_source, bytes):
            compressed_size = len(zip_source)
            byte_stream = io.BytesIO(zip_source)
            if not zipfile.is_zipfile(byte_stream):
                raise IngestionError("The uploaded file is not a valid ZIP archive.")
            byte_stream.seek(0)
            zf = zipfile.ZipFile(byte_stream, "r")
        else:
            # Handle UploadedFile or BytesIO
            if hasattr(zip_source, "size"):
                compressed_size = zip_source.size
            elif hasattr(zip_source, "getbuffer"):
                compressed_size = zip_source.getbuffer().nbytes
            
            # Reset seek position if available
            if hasattr(zip_source, "seek"):
                zip_source.seek(0)

            if not zipfile.is_zipfile(zip_source):
                raise IngestionError("The uploaded file is not a valid ZIP archive.")
            if hasattr(zip_source, "seek"):
                zip_source.seek(0)
            zf = zipfile.ZipFile(zip_source, "r")

        # 2. Validate zip safety & limits
        with zf:
            validate_zip_safety(zf, compressed_size)

            # 3. Extract safe entries
            for member in zf.infolist():
                filename = member.filename

                # Disallow origin manifest spoofing from untrusted archives
                if ".phantom_origin" in filename:
                    continue

                # Skip ignored directories
                if should_ignore_entry(filename):
                    continue

                # Path safety check
                if not is_path_safe(temp_dir, filename):
                    raise IngestionError(f"Security error: Path traversal detected: '{filename}'")

                # Neutralize untrusted git hooks: do not extract executable hook scripts
                clean_path = filename.replace("\\", "/").strip("/")
                if clean_path.startswith(".git/hooks/") and not member.is_dir():
                    continue

                # Extract safely
                zf.extract(member, temp_dir)

        # 4. Neutralize git hooks directory if .git was extracted
        git_dir = os.path.join(temp_dir, ".git")
        hooks_dir = os.path.join(git_dir, "hooks")
        if os.path.isdir(hooks_dir):
            try:
                safe_cleanup(hooks_dir)
                os.makedirs(hooks_dir, exist_ok=True)
            except Exception:
                pass

        # 5. Scan extracted project files
        python_files = []
        dependency_files = {}
        file_tree = []

        for root, dirs, files in os.walk(temp_dir):
            # Prune ignored directories in-place during walk
            dirs[:] = [d for d in dirs if d not in IGNORED_DIRS and (d != ".git")]

            rel_root = os.path.relpath(root, temp_dir)

            for file in files:
                rel_file = os.path.normpath(os.path.join(rel_root, file)).replace("\\", "/")
                if rel_file.startswith("./"):
                    rel_file = rel_file[2:]

                # Check if ignored
                if should_ignore_entry(rel_file):
                    continue

                file_tree.append(rel_file)

                if file.endswith(".py"):
                    python_files.append(rel_file)

                if file in DEPENDENCY_FILENAMES:
                    full_dep_path = os.path.join(root, file)
                    try:
                        with open(full_dep_path, "r", encoding="utf-8", errors="replace") as f:
                            lines = [line.strip() for line in f if line.strip() and not line.startswith("#")]
                        dependency_files[rel_file] = lines[:50]  # Store first 50 lines
                    except Exception as e:
                        dependency_files[rel_file] = [f"Error reading {file}: {e}"]

        # 6. Check that project contains at least one Python file
        if not python_files:
            raise IngestionError("No Python source files (.py) found in the project archive.")

        # 7. Check Git repository availability
        has_git = False
        git_message = "No Git repository found in project (.git is missing)."
        if os.path.isdir(git_dir):
            try:
                import git
                repo = git.Repo(temp_dir)
                has_git = True
                branch = repo.active_branch.name if not repo.head.is_detached else "detached"
                commit_count = sum(1 for _ in repo.iter_commits(max_count=10))
                git_message = f"Git repository active (Branch: {branch}, {commit_count}+ recent commits available)."
            except Exception as e:
                has_git = False
                git_message = f"Git directory detected, but history is unreadable: {e}"

        return IngestedProject(
            project_dir=temp_dir,
            python_files=python_files,
            dependency_files=dependency_files,
            file_tree=file_tree,
            has_git=has_git,
            git_message=git_message
        )

    except Exception:
        # Reliable cleanup on failure
        safe_cleanup(temp_dir)
        raise
