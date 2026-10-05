# CSCE 465 Project

## Environment Setup

This project uses Python and the `cryptography` library.

### 1. Install Python

Make sure Python 3 is installed.

Check your version with:

```bash
python --version
```

or:

```bash
python3 --version
```

### 2. Create a Virtual Environment

From the project folder, run:

```bash
python -m venv venv
```

Activate the virtual environment.

**Windows:**

```bash
venv\Scripts\activate
```

**macOS/Linux:**

```bash
source venv/bin/activate
```

### 3. Install Required Packages

Install the required Python packages:

```bash
pip install cryptography pytest
```

If the project includes a `requirements.txt` file, you can instead run:

```bash
pip install -r requirements.txt
```

## Running the Programs

Run each Python file from the project directory using:

```bash
python filename.py
```

For example:

```bash
python baseline_ctr.py
```

Replace `filename.py` with the file you want to run.

## Running the Tests

If the project uses `pytest`, run all tests with:

```bash
pytest
```

For more detailed output, run:

```bash
pytest -v
```

To run a specific test file:

```bash
pytest test_filename.py
```

## Notes

Make sure the virtual environment is activated before running the programs or tests. If Python cannot find the `cryptography` package, reinstall the dependencies with:

```bash
pip install cryptography pytest
```