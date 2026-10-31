
import math
import socket
import time
from concurrent.futures import ThreadPoolExecutor, wait, FIRST_COMPLETED


def scan_port(target: str, port: int, timeout: float = 0.5) -> bool:
    if (
        isinstance(port, bool)
        or not isinstance(port, int)
        or not 1 <= port <= 65535
    ):
        raise ValueError(
            f"Invalid port: {port}. Must be between 1 and 65535."
        )

    if (
        isinstance(timeout, bool)
        or not isinstance(timeout, (int, float))
        or not math.isfinite(timeout)
        or timeout <= 0
    ):
        raise ValueError("Timeout must be a finite positive number.")

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            return sock.connect_ex((target, port)) == 0
    except socket.error:
        return False


def scan_ports(
    target: str,
    ports: list[int],
    workers: int = 100,
    timeout: float = 0.5,
) -> list[int]:
    for port in ports:
        if (
            isinstance(port, bool)
            or not isinstance(port, int)
            or not 1 <= port <= 65535
        ):
            raise ValueError(
                f"Invalid port: {port}. Must be between 1 and 65535."
            )

    if isinstance(workers, bool) or not isinstance(workers, int) or workers < 1:
        raise ValueError("Workers must be a positive integer.")

    if (
        isinstance(timeout, bool)
        or not isinstance(timeout, (int, float))
        or not math.isfinite(timeout)
        or timeout <= 0
    ):
        raise ValueError("Timeout must be a finite positive number.")

    total = len(ports)
    open_ports = []
    start_time = time.monotonic()

    print(f"Starting TCP scan against {target}")
    print(f"Ports to scan: {total}")
    print(f"Concurrent workers: {workers}")

    if total == 0:
        print("No ports specified.")
        return open_ports

    iterator = iter(ports)
    pending = {}
    completed = 0

    try:
        with ThreadPoolExecutor(max_workers=workers) as executor:
            limit = min(total, workers * 2)

            for _ in range(limit):
                port = next(iterator, None)
                if port is None:
                    break
                pending[executor.submit(scan_port, target, port, timeout)] = port

            while pending:
                finished, _ = wait(
                    pending,
                    return_when=FIRST_COMPLETED,
                )

                for future in finished:
                    port = pending.pop(future)
                    completed += 1

                    if future.result():
                        open_ports.append(port)
                        print(f"\n{port}/tcp open", flush=True)

                    next_port = next(iterator, None)
                    if next_port is not None:
                        pending[
                            executor.submit(
                                scan_port, target, next_port, timeout
                            )
                        ] = next_port

                percent = completed * 100 // total
                elapsed = time.monotonic() - start_time

                if completed == total or completed % 100 == 0:
                    print(
                        f"\rProgress: {completed}/{total} ports "
                        f"({percent}%) | Open: {len(open_ports)} | "
                        f"Elapsed: {elapsed:.1f}s",
                        end="\n" if completed == total else "",
                        flush=True,
                    )

    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user.")
        raise

    open_ports.sort()
    elapsed = time.monotonic() - start_time
    print(f"\nScan completed in {elapsed:.1f}s.")
    print(f"Open TCP ports: {len(open_ports)}")

    return open_ports
