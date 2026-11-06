import os
import shutil

# Ensure Git executable is located (check MinGit in LocalAppData or system PATH)
mingit_cmd = os.path.expandvars(r"%LOCALAPPDATA%\Programs\MinGit\cmd")
mingit_exe = os.path.join(mingit_cmd, "git.exe")

if "GIT_PYTHON_GIT_EXECUTABLE" not in os.environ:
    if shutil.which("git"):
        os.environ["GIT_PYTHON_GIT_EXECUTABLE"] = shutil.which("git")
    elif os.path.exists(mingit_exe):
        os.environ["GIT_PYTHON_GIT_EXECUTABLE"] = mingit_exe
        if mingit_cmd not in os.environ.get("PATH", ""):
            os.environ["PATH"] = mingit_cmd + os.pathsep + os.environ.get("PATH", "")
