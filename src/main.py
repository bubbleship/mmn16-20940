import asyncio

from src.simulator.experiment import run_experiment


def main() -> None:
    asyncio.run(run_experiment())


if __name__ == "__main__":
    main()
