import time
import itertools
from typing import Any, Generator


def brute_force(alphabet: str, length: int, timeout: int | None = None) -> Generator[str, Any, None]:
    """
    Simulates a brute-force attack on the given password pattern.
    If timeout is specified, the generator will stop after the specified number of seconds.
    """
    t0 = time.time()
    for combination in itertools.product(alphabet, repeat=length):
        if timeout is not None and time.time() - t0 > timeout:
            break
        yield ''.join(combination)
