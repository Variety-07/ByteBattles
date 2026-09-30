import io
import socket
import tarfile
import docker
from docker.utils.socket import frames_iter

MAX_OUTPUT_BYTES = 10 * 1024 * 1024  # 10 MB

# send stdin

from config import (
    WORKSPACE_DIR,
)
from shared.models import Language, FILENAME, Verdict
from .types import CompileResult, RunResult

class JudgeExecutor:
    def __init__(self):
        self.workspace_dir = WORKSPACE_DIR
        self.client = docker.from_env()

    def _container_exec(self, container, cmd: list[str], workdir: str = WORKSPACE_DIR):
        return container.exec_run(cmd, workdir=workdir, tty=False, demux=True)
    
    def compile_c(self, container) -> CompileResult:
        cmd = [
            "/bin/sh",
            "-lc",
            f"timeout -s KILL 10s gcc -O2 -pipe -static -s -o {WORKSPACE_DIR}/main.out {WORKSPACE_DIR}/main.c 2>&1", 
        ] #Basically to stop malicious programs from running infinitely
        result = self._container_exec(container, cmd)
        exit_code = int(result.exit_code)

        stdout_b, stderr_b = result.output if isinstance(result.output, tuple) else (b"", b"")
        out = (stdout_b or b"").decode(errors="replace") + (stderr_b or b"").decode(errors="replace")

        return CompileResult(
            ok=exit_code == 0,
            output=out,
            exit_code=exit_code,
        )

    def compile_cpp(self, container) -> CompileResult:
        cmd = [
            "/bin/sh",
            "-lc",
            f"timeout -s KILL 10s g++ -O2 -std=c++17 -pipe -static -s -o {WORKSPACE_DIR}/main.out {WORKSPACE_DIR}/main.cpp 2>&1",
        ]
        result = self._container_exec(container, cmd)
        exit_code = int(result.exit_code)

        stdout_b, stderr_b = result.output if isinstance(result.output, tuple) else (b"", b"")
        out = (stdout_b or b"").decode(errors="replace") + (stderr_b or b"").decode(errors="replace")

        return CompileResult(
            ok=exit_code == 0,
            output=out,
            exit_code=exit_code,
        )

    def run_program(
        self,
        container,
        language: Language,
        executable_path: str,
        input_data: str,
        expected_output: str,
        time_limit_sec: int,
        memory_limit_kb: int,
    ) -> RunResult:
        
        # Build command
        if language == Language.C:
            inner_cmd = f"{executable_path}"
        elif language == Language.CPP:
            inner_cmd = f"{executable_path}"
        elif language == Language.PYTHON:
            inner_cmd = f"python3 {executable_path}"
        else:
            raise ValueError(f"Unsupported language: {language}")

        cmd = [
            "/bin/sh",
            "-lc",
            f"/usr/bin/time -f \'%e %M\' timeout -s KILL {time_limit_sec}s sh -c \"{inner_cmd} 2>/dev/null\""
        ]

        exec_id = self.client.api.exec_create(
            container.id,
            cmd=cmd,
            # stdin=False,
            stdin=True,
            tty=False,
            user='run'
        )["Id"]

        sock = self.client.api.exec_start(
            exec_id,
            socket=True,
            tty=False,
        )

        sock._sock.sendall(input_data.encode())
        sock._sock.shutdown(socket.SHUT_WR)

        stdout_chunks = []   #Changed code to ensure infinite loops dont eat up memory. 
        stderr_chunks = []
        stdout_size = 0
        output_limit_hit = False

        for stream_id, payload in frames_iter(socket=sock, tty=False):
            if stream_id == 1:
                stdout_size += len(payload)
                if stdout_size > MAX_OUTPUT_BYTES:
                    output_limit_hit = True
                    break
                stdout_chunks.append(payload)
            elif stream_id == 2:
                stderr_chunks.append(payload)  # only the tiny `time` line

        sock.close()

        if output_limit_hit:
            partial = b"".join(stdout_chunks).decode("utf-8", errors="replace")
            return RunResult(
                ok=False,
                verdict=Verdict.WRONG_ANSWER,
                output=partial[:8192],
                exit_code=-1,
                runtime_ms=0,
                memory_kb=0,
            )

        inspect = self.client.api.exec_inspect(exec_id)
        exit_code = inspect["ExitCode"]

        stdout_output = b"".join(stdout_chunks).decode("utf-8", errors="replace")
        stderr_output = b"".join(stderr_chunks).decode("utf-8", errors="replace")

        try:
            stats = stderr_output.strip().splitlines()[-1].split()
            time_elapsed = min(int(float(stats[0]) * 1000), time_limit_sec * 1000)
            #fix: like if we solved a prob in a few ms, it would be shown as 0ms 
            memory_kb_used = min(int(stats[1]), memory_limit_kb)
        except (IndexError, ValueError):
            time_elapsed, memory_kb_used = 0, 0

        if memory_kb_used == memory_limit_kb: #fix
            verdict = Verdict.MEMORY_LIMIT_EXCEEDED
        elif exit_code == 137 and time_elapsed < time_limit_sec * 1000 * 0.9:
            verdict = Verdict.MEMORY_LIMIT_EXCEEDED
        elif exit_code in (124, 137):
            verdict = Verdict.TIME_LIMIT_EXCEEDED
        elif exit_code != 0:
            verdict = Verdict.RUNTIME_ERROR
        else:
            # compare output
            def norm(s: str) -> str:
                return "\n".join(s.strip().split())            
            verdict = Verdict.ACCEPTED if norm(stdout_output) == norm(expected_output) else Verdict.WRONG_ANSWER

        return RunResult(
            ok=(verdict == Verdict.ACCEPTED),
            verdict=verdict,
            output=stdout_output,
            exit_code=exit_code,
            runtime_ms = time_elapsed,
            memory_kb = memory_kb_used
        )

    def copy_code_to_container(self, container, language: Language, code: bytes) -> None:
        tar_stream = io.BytesIO()

        with tarfile.open(fileobj=tar_stream, mode="w") as tar:
            file_data = io.BytesIO(code)

            tar_info = tarfile.TarInfo(name=FILENAME[language])
            tar_info.size = len(code)

            tar.addfile(tar_info, file_data)

        tar_stream.seek(0)

        container.put_archive(
            path=WORKSPACE_DIR,
            data=tar_stream.getvalue(),
        )