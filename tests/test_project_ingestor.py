import os
import io
import zipfile
import shutil
import pytest
from core.project_ingestor import (
    extract_project_zip,
    IngestionError,
    IngestedProject,
    MAX_FILE_COUNT,
    MAX_UNCOMPRESSED_SIZE_BYTES
)


def create_zip_bytes(file_dict: dict) -> bytes:
    """Helper to create an in-memory zip archive from a dict of {relpath: content}."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for path, content in file_dict.items():
            if isinstance(content, str):
                zf.writestr(path, content.encode("utf-8"))
            else:
                zf.writestr(path, content)
    buf.seek(0)
    return buf.getvalue()


def test_valid_python_project_zip():
    files = {
        "main.py": "print('hello world')",
        "utils/helpers.py": "def add(a, b): return a + b",
        "requirements.txt": "requests>=2.28.0\npytest>=8.0.0",
        "README.md": "# Sample Project"
    }
    zip_bytes = create_zip_bytes(files)

    with extract_project_zip(zip_bytes) as project:
        assert os.path.isdir(project.project_dir)
        assert len(project.python_files) == 2
        assert "main.py" in project.python_files
        assert "utils/helpers.py" in project.python_files
        assert "requirements.txt" in project.dependency_files
        assert "requests>=2.28.0" in project.dependency_files["requirements.txt"]
        assert "README.md" in project.file_tree
        assert project.has_git is False
        temp_dir = project.project_dir

    # Verify context manager cleanup
    assert not os.path.exists(temp_dir)


def test_zip_path_traversal_attack_rejected():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        # Create an entry with relative traversal
        zf.writestr("../../evil.py", "malicious_code = True")
        zf.writestr("app.py", "print('normal')")
    buf.seek(0)

    with pytest.raises(IngestionError) as exc_info:
        extract_project_zip(buf.getvalue())
    assert "Path traversal" in str(exc_info.value) or "Security error" in str(exc_info.value)


def test_malformed_zip_rejected():
    corrupt_bytes = b"PK\x03\x04This is corrupt junk data"
    with pytest.raises(IngestionError) as exc_info:
        extract_project_zip(corrupt_bytes)
    assert "not a valid ZIP archive" in str(exc_info.value)


def test_zip_with_no_python_files_rejected():
    files = {
        "README.md": "# No Python here",
        "package.json": "{}",
        "styles.css": "body { color: red; }"
    }
    zip_bytes = create_zip_bytes(files)

    with pytest.raises(IngestionError) as exc_info:
        extract_project_zip(zip_bytes)
    assert "No Python source files" in str(exc_info.value)


def test_zip_with_git_history():
    # Package our sample shop_cart (which has a real 4-commit .git) into a zip
    buf = io.BytesIO()
    sample_dir = os.path.abspath("samples/shop_cart")
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for root, _, files in os.walk(sample_dir):
            for file in files:
                full_path = os.path.join(root, file)
                rel_path = os.path.relpath(full_path, sample_dir)
                zf.write(full_path, rel_path)
    buf.seek(0)

    with extract_project_zip(buf.getvalue()) as project:
        assert project.has_git is True
        assert "Git repository active" in project.git_message
        assert "cart.py" in project.python_files
        assert os.path.isdir(os.path.join(project.project_dir, ".git"))


def test_ignored_directories_filtered_out():
    files = {
        "app.py": "import os",
        ".venv/lib/site-packages/evil.py": "bad = 1",
        "venv/bin/activate.py": "bad = 2",
        "__pycache__/app.cpython-314.pyc": b"\x00\x00\x00\x00",
        "node_modules/package/index.js": "console.log('js')",
        "subfolder/worker.py": "worker = True"
    }
    zip_bytes = create_zip_bytes(files)

    with extract_project_zip(zip_bytes) as project:
        # Only app.py and subfolder/worker.py should be ingested
        assert len(project.python_files) == 2
        assert "app.py" in project.python_files
        assert "subfolder/worker.py" in project.python_files
        assert not any(".venv" in f for f in project.file_tree)
        assert not any("__pycache__" in f for f in project.file_tree)
        assert not any("node_modules" in f for f in project.file_tree)


def test_oversized_file_count_rejected(monkeypatch):
    import core.project_ingestor
    monkeypatch.setattr(core.project_ingestor, "MAX_FILE_COUNT", 5)

    files = {f"file_{i}.py": "x = 1" for i in range(10)}
    zip_bytes = create_zip_bytes(files)

    with pytest.raises(IngestionError) as exc_info:
        extract_project_zip(zip_bytes)
    assert "exceeding the limit" in str(exc_info.value)


def test_oversized_uncompressed_bytes_rejected(monkeypatch):
    import core.project_ingestor
    # Limit to 500 bytes
    monkeypatch.setattr(core.project_ingestor, "MAX_UNCOMPRESSED_SIZE_BYTES", 500)

    files = {
        "big_file.py": "a" * 1000
    }
    zip_bytes = create_zip_bytes(files)

    with pytest.raises(IngestionError) as exc_info:
        extract_project_zip(zip_bytes)
    assert "uncompressed archive size exceeds limit" in str(exc_info.value)


def test_temporary_directory_cleanup_on_failure():
    import tempfile
    
    # We will trigger a failure after directory creation by providing a zip with no python files
    files = {"info.txt": "just text"}
    zip_bytes = create_zip_bytes(files)

    # Capture temp dirs before
    temp_root = tempfile.gettempdir()
    before_dirs = set(os.listdir(temp_root))

    with pytest.raises(IngestionError):
        extract_project_zip(zip_bytes)

    # After failure, no new phantom_ingest_ directory should linger
    after_dirs = set(os.listdir(temp_root))
    new_dirs = [d for d in (after_dirs - before_dirs) if d.startswith("phantom_ingest_")]
    assert len(new_dirs) == 0
