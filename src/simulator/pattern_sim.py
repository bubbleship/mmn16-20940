import itertools
import time
from typing import Any, Generator


def brute_force(alphabet: str, length: int, max_attempts: int | None = None, timeout: int | None = None) -> Generator[
    str, Any, None]:
    """
    Simulates a brute-force attack on the given password pattern.
    If timeout is specified, the generator will stop after the specified number of seconds.
    """
    t0 = time.time()
    attempt_count = 0
    for combination in itertools.product(alphabet, repeat=length):
        if timeout is not None and time.time() - t0 > timeout:
            break
        if max_attempts is not None and attempt_count >= max_attempts:
            break
        attempt_count += 1
        yield ''.join(combination)
