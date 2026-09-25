"""Subprocess management with process-group isolation and signal escalation cascades."""

import asyncio
import os
import signal
import sys
from pathlib import Path
from typing import Optional


class ProcessExecutionError(Exception):
    """Raised when an external tool execution fails."""
    def __init__(self, message: str, exit_code: Optional[int] = None, stderr: str = ""):
        super().__init__(message)
        self.exit_code = exit_code
        self.stderr = stderr


class ProcessRunner:
    """Spawns and manages CLI tool processes in isolated process groups."""

    @staticmethod
    async def run_command_stream(
        cmd_args: list[str],
        stdout_path: Path,
        stderr_path: Path,
        cwd: Optional[Path] = None,
        env: Optional[dict[str, str]] = None,
        timeout_seconds: Optional[int] = None,
    ) -> int:
        """Executes a command vector streaming directly to disk with process group isolation.
        
        Uses asyncio.create_subprocess_exec (NEVER shell=True).
        """
        # Ensure parent directories exist
        stdout_path.parent.mkdir(parents=True, exist_ok=True)
        stderr_path.parent.mkdir(parents=True, exist_ok=True)

        merged_env = os.environ.copy()
        if env:
            merged_env.update(env)

        # Prepend ~/.astrarecon/bin and ~/go/bin to PATH for child processes
        managed_bin = str(Path.home() / ".astrarecon" / "bin")
        go_bin = str(Path.home() / "go" / "bin")
        current_path = merged_env.get("PATH", "")
        extra_paths = [p for p in (managed_bin, go_bin) if p not in current_path and Path(p).is_dir()]
        if extra_paths:
            merged_env["PATH"] = os.pathsep.join(extra_paths) + os.pathsep + current_path

        # On Linux/Unix, preexec_fn=os.setsid creates a new process group.
        # On Windows, we use creationflags for process isolation.
        preexec_fn = None
        creationflags = 0

        if sys.platform != "win32":
            preexec_fn = os.setsid
        else:
            # CREATE_NEW_PROCESS_GROUP on Windows
            creationflags = 0x00000200  # subprocess.CREATE_NEW_PROCESS_GROUP

        with open(stdout_path, "wb") as out_f, open(stderr_path, "wb") as err_f:
            if sys.platform != "win32":
                proc = await asyncio.create_subprocess_exec(
                    *cmd_args,
                    stdin=asyncio.subprocess.DEVNULL,
                    stdout=out_f,
                    stderr=err_f,
                    cwd=str(cwd) if cwd else None,
                    env=merged_env,
                    preexec_fn=preexec_fn,
                )
            else:
                proc = await asyncio.create_subprocess_exec(
                    *cmd_args,
                    stdin=asyncio.subprocess.DEVNULL,
                    stdout=out_f,
                    stderr=err_f,
                    cwd=str(cwd) if cwd else None,
                    env=merged_env,
                    creationflags=creationflags,
                )

            try:
                if timeout_seconds:
                    await asyncio.wait_for(proc.wait(), timeout=float(timeout_seconds))
                else:
                    await proc.wait()
            except asyncio.TimeoutError:
                await ProcessRunner.terminate_process_tree(proc, timeout_grace_period=3.0)
                raise ProcessExecutionError(
                    f"Command '{cmd_args[0]}' timed out after {timeout_seconds}s",
                    exit_code=-1,
                )
            except asyncio.CancelledError:
                await ProcessRunner.terminate_process_tree(proc, timeout_grace_period=2.0)
                raise

            return proc.returncode or 0

    @staticmethod
    async def terminate_process_tree(proc: asyncio.subprocess.Process, timeout_grace_period: float = 3.0) -> None:
        """Terminates an entire process tree using graceful escalation: SIGINT -> SIGTERM -> SIGKILL."""
        if proc.returncode is not None:
            return  # Already terminated

        pid = proc.pid
        if sys.platform != "win32":
            try:
                # Send SIGINT to process group
                os.killpg(pid, signal.SIGINT)
                try:
                    await asyncio.wait_for(proc.wait(), timeout=timeout_grace_period)
                    return
                except asyncio.TimeoutError:
                    pass

                # Escalate to SIGTERM
                os.killpg(pid, signal.SIGTERM)
                try:
                    await asyncio.wait_for(proc.wait(), timeout=1.5)
                    return
                except asyncio.TimeoutError:
                    pass

                # Final force-kill
                os.killpg(pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        else:
            # Windows process tree termination
            try:
                proc.terminate()
                try:
                    await asyncio.wait_for(proc.wait(), timeout=timeout_grace_period)
                    return
                except asyncio.TimeoutError:
                    pass

                # Force kill process tree using taskkill
                import subprocess
                subprocess.run(
                    ["taskkill", "/F", "/T", "/PID", str(pid)],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    check=False,
                )
                try:
                    await asyncio.wait_for(proc.wait(), timeout=1.0)
                except asyncio.TimeoutError:
                    proc.kill()
            except Exception:
                pass
