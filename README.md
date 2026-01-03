# Assignment 16 - 20940

A systematic evaluation of password-based authentication mechanisms comparing the effectiveness of various cryptographic
hashing algorithms and defensive strategies against brute force and password spray attacks.

## Overview

This research project evaluates the effectiveness of different password authentication defense mechanisms
through controlled attack simulations. The experiment compares baseline cryptographic approaches (PlainText, BCrypt,
Argon2ID) with various defense strategies including Multi-Factor Authentication (MFA), rate limiting, account lockout,
CAPTCHA, and their combinations.

The simulation measures attack success rates, execution times, and defensive effectiveness across multiple scenarios to
provide quantitative security assessments for the study.

## Requirements

- Python 3.13+ or [UV package manager](https://docs.astral.sh/uv/getting-started/installation/) (recommended)

## Setup and Execution

Clone the repository:
```bash
git clone https://github.com/bubbleship/mmn16-20940.git
```
```bash
cd mmn16-20940
```

### Method 1: UV (Recommended)

Install dependencies:

```bash
uv sync
```

Run experiment:

```bash
uv run run-experiment
```

### Method 2: Standard Python

```bash
# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: powershell -ExecutionPolicy ByPass -c "venv\Scripts\activate"

# Install dependencies
pip install -e .

# Run the experiment
run-experiment
```

## Output

The experiment generates comprehensive results in the `results/` directory, including:

- Attack success rate statistics
- Defense mechanism effectiveness metrics
- Execution time measurements
- Visualization plots

Results are automatically processed and saved in JSON format for further analysis.

### Troubleshoot

On Windows:
```bash
Set-ExecutionPolicy RemoteSigned
```
```bash
Set-ExecutionPolicy Restricted  # To restore the default setting later
```


GROUP SEED: 511584106
