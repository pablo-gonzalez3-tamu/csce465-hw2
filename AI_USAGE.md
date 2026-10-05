# AI_USAGE.md

## Tool/model and date
- ChatGPT, GPT-5.6 Sol — October 2, 2026

## Purpose
I used AI as a learning, debugging, and writing-support tool while working on the project. I used it to understand why my code behaved a certain way, troubleshoot errors, connect files together correctly, run tests, and review my writing for grammar and clarity. I reviewed the responses and tested the code myself before using any suggestions.

## AI Conversation Log files Summaries

### Log 1

**My prompt:**
> why does it not output anything when i run it

**AI response:**
> The response explained that the file may only be defining functions without actually calling them. It suggested checking whether the program had a main block or whether the function that performs the experiment was being executed.

**What I used:**
I used this to troubleshoot why the program ran without printing the expected output.

---

### Log 2

**My prompt:**
> can you explain the cod

**AI response:**
> The response walked through the code and explained what the main sections were doing, including encryption, byte operations, record handling, and how the program flow worked.

**What I used:**
I used the explanation to better understand code that I had already been working with.

---

### Log 3

**My prompt:**
> why are the numbers the same everytime, should they be different

**AI response:**
> The response explained that some values are expected to stay the same when the same plaintext, byte positions, or fixed inputs are being used. It also explained that not every number in the output is supposed to be random.

**What I used:**
I used this to understand why certain byte values repeated between runs.

---

### Log 4

**My prompt:**
> how to run test

**AI response:**
> The response explained how to run the test suite with `pytest`, how to run a specific test file, and how to use verbose output to see more information about which tests passed or failed.

**What I used:**
I used this to run and check the automated tests for the project.

---

### Log 5

**My prompt:**
> It keeps giving me this error, are the variables not correct

**AI response:**
> The response helped compare the variable names, expected arguments, and values being passed between parts of the program. It pointed out possible mismatches and suggested checking that the same names and types were being used consistently.

**What I used:**
I used this to troubleshoot variable-name and parameter mismatches.

---

### Log 6

**My prompt:**
> this is handshake.py’s variables, so can you fix it to where it imports correctly

**AI response:**
> The response helped align the imported names with the variables and functions that were actually defined in `handshake.py`. It also explained that import errors can happen when the requested name does not exactly match what the other file exports.

**What I used:**
I used this to fix import mismatches between project files.

---

### Log 7

**My prompt:**
> Can you read through this, and tell me any grammatical errors I may have made

**AI response:**
> The response reviewed the writing for grammar, sentence structure, wording, and clarity. It pointed out awkward phrasing and suggested cleaner wording while keeping the original meaning.

**What I used:**
I used this to proofread and improve the written parts of the report.

---

## What I used

I used AI assistance for:

- Debugging code that produced no output
- Understanding code behavior
- Understanding repeated byte values
- Learning how to run tests with `pytest`
- Fixing variable and parameter mismatches
- Fixing imports between project files
- Reviewing grammar and clarity in the report
- Explaining cryptography concepts when I did not fully understand what the code was doing

## What I changed

I changed code, variable names, imports, comments, and wording based on what matched my own project. I did not use every suggestion exactly as written.

For writing-related help, I kept the main ideas but changed wording so the final report reflected my own understanding and writing style.

## How I tested it

I ran the Python files locally and checked their output. I also ran the automated tests with `pytest`.

I checked that:

- The programs produced the expected output.
- Imports worked between files.
- Variables and function arguments matched correctly.
- Valid cases passed.
- Invalid or modified inputs were rejected when expected.
- The final written report still accurately described what my code actually did.

## One error, limitation, or rejected suggestion

One limitation was that AI sometimes guessed the wrong variable name, file structure, or function name when it did not have the complete project context. I had to compare the suggestions against my actual files and change them when they did not match.

I also did not automatically accept grammar or code changes. I reviewed each suggestion and kept only the changes that fit my project and my own understanding.
