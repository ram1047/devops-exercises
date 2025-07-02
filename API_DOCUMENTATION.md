# DevOps Exercises - API and Component Documentation

This document provides comprehensive documentation for all public APIs, functions, and components in the DevOps Exercises repository.

## Table of Contents

1. [Utility Scripts](#utility-scripts)
2. [Flask Web Applications](#flask-web-applications)
3. [Coding Examples](#coding-examples)
4. [Testing Utilities](#testing-utilities)
5. [Shell Scripts](#shell-scripts)

---

## Utility Scripts

### Question Utils (`scripts/question_utils.py`)

A collection of utility functions for parsing and managing DevOps interview questions from the repository's README.md file.

#### Functions

##### `get_file_list() -> str`

Reads the main README.md file and returns its content as a string.

**Returns:**
- `str`: Complete content of README.md file

**Example:**
```python
from scripts.question_utils import get_file_list

content = get_file_list()
print(len(content))  # Prints the length of README content
```

##### `get_question_list(file_list: List[str]) -> list`

Extracts all questions from the provided file content using regex pattern matching.

**Parameters:**
- `file_list` (List[str]): Content of the markdown file

**Returns:**
- `list`: List of question summaries

**Example:**
```python
from scripts.question_utils import get_file_list, get_question_list

content = get_file_list()
questions = get_question_list(content)
print(f"Total questions: {len(questions)}")
```

##### `get_answered_questions(question_list: List[str]) -> list`

Filters and returns only questions that have answers (non-empty content between `<b>` tags).

**Parameters:**
- `question_list` (List[str]): Content of the markdown file

**Returns:**
- `list`: List of questions that have answers

**Example:**
```python
from scripts.question_utils import get_file_list, get_answered_questions

content = get_file_list()
answered = get_answered_questions(content)
print(f"Answered questions: {len(answered)}")
```

##### `get_answers_count() -> List[int]`

Returns count statistics for answered vs total questions.

**Returns:**
- `List[int]`: [number_of_answered_questions, total_number_of_questions]

**Example:**
```python
from scripts.question_utils import get_answers_count

stats = get_answers_count()
print(f"Progress: {stats[0]}/{stats[1]} questions answered")
```

##### `get_challenges_count() -> int`

Counts the number of challenge files in the exercises directory.

**Returns:**
- `int`: Number of .md files in the exercises directory

**Example:**
```python
from scripts.question_utils import get_challenges_count

challenges = get_challenges_count()
print(f"Available challenges: {challenges}")
```

##### `get_random_question(question_list: List[str], with_answer: bool = False) -> str`

Selects a random question from the available questions.

**Parameters:**
- `question_list` (List[str]): Content of the markdown file
- `with_answer` (bool): If True, only returns questions with answers

**Returns:**
- `str`: Random question text

**Example:**
```python
from scripts.question_utils import get_file_list, get_random_question

content = get_file_list()
random_q = get_random_question(content, with_answer=True)
print(f"Random question: {random_q}")
```

### Random Question CLI (`scripts/random_question.py`)

Interactive command-line tool for quiz-style learning with random questions.

#### Functions

##### `main()`

Main entry point for the interactive quiz application.

**Features:**
- Parses README.md for question/answer pairs
- Supports skipping questions without answers (`-s` flag)
- Interactive quiz mode with answer reveals
- Keyboard interrupt handling for clean exit

**Usage:**
```bash
# Run with all questions
python scripts/random_question.py

# Skip questions without answers
python scripts/random_question.py -s
```

**Command Line Options:**
- `-s, --skip`: Skip questions without documented answers

### Update Question Numbers (`scripts/update_question_number.py`)

Utility script to automatically update the question count in README.md.

**Features:**
- Counts total questions from README.md
- Counts challenge exercises from exercises directory
- Updates the question count badge in README.md

**Usage:**
```bash
python scripts/update_question_number.py
```

---

## Flask Web Applications

### User Management API (`topics/flask_container_ci/app/main.py`)

A Flask REST API for managing user data with CSRF protection.

#### Endpoints

##### `GET /`

Returns available API resources and current URI information.

**Response:**
```json
{
    "resources": {
        "users": "/users",
        "user": "/users/<username>"
    },
    "current_uri": "/"
}
```

**Example:**
```bash
curl http://localhost:5000/
```

##### `GET /users`

Returns all users from the users.json file.

**Response:**
```json
{
    "user1": { "data": "..." },
    "user2": { "data": "..." }
}
```

**Example:**
```bash
curl http://localhost:5000/users
```

##### `GET /users/<username>`

Returns specific user data by username.

**Parameters:**
- `username` (str): Username to retrieve

**Response:**
```json
{
    "user_data": "specific user information"
}
```

**Errors:**
- `404 Not Found`: If username doesn't exist

**Example:**
```bash
curl http://localhost:5000/users/john_doe
```

##### `GET /users/<username>/something`

Placeholder endpoint (raises NotImplementedError).

**Parameters:**
- `username` (str): Username

**Response:**
- `NotImplementedError`: Always raised

#### Utility Functions

##### `pretty_json(arg: dict) -> Response`

Formats JSON responses with proper headers and indentation.

**Parameters:**
- `arg` (dict): Data to format as JSON

**Returns:**
- `Response`: Flask response with formatted JSON

##### `create_test_app() -> Flask`

Creates a Flask application instance for testing purposes.

**Returns:**
- `Flask`: Configured Flask application with CSRF protection

**Usage:**
```python
from topics.flask_container_ci.app.main import create_test_app

app = create_test_app()
# Use for testing
```

### Matrix Operations API (`topics/flask_container_ci2/app/main.py`)

A Flask REST API for matrix operations (implementation incomplete).

#### Endpoints

##### `GET /`

Returns available matrix API resources.

**Response:**
```json
{
    "resources": {
        "matrix": "/matrix/<matrix>",
        "column": "/columns/<matrix>/<column_number>",
        "row": "/rows/<matrix>/<row_number>"
    },
    "current_uri": "/",
    "example": "/matrix/'123n456n789'"
}
```

##### `GET /matrix/<matrix>`

Processes matrix data (TODO: implementation needed).

**Parameters:**
- `matrix` (str): Matrix data in string format

**Status:** Not implemented (contains `pass`)

##### `GET /matrix/<matrix>/<column_number>`

Extracts specific column from matrix (TODO: implementation needed).

**Parameters:**
- `matrix` (str): Matrix data
- `column_number` (str): Column index to extract

**Status:** Not implemented (contains `pass`)

##### `GET /matrix/<matrix>/<row_number>`

Extracts specific row from matrix (TODO: implementation needed).

**Parameters:**
- `matrix` (str): Matrix data
- `row_number` (str): Row index to extract

**Status:** Not implemented (contains `pass`)

#### Utility Functions

##### `pretty_json(arg: dict) -> Response`

Same functionality as the user management API - formats JSON responses.

---

## Coding Examples

### Binary Search Algorithm (`coding/python/binary_search.py`)

Implementation of the binary search algorithm with O(log n) time complexity.

#### Functions

##### `binary_search(arr: List[int], lb: int, ub: int, target: int) -> int`

Performs binary search on a sorted array to find the target value.

**Parameters:**
- `arr` (List[int]): Sorted array to search in
- `lb` (int): Lower bound index
- `ub` (int): Upper bound index  
- `target` (int): Value to search for

**Returns:**
- `int`: Index of target if found, -1 if not found

**Time Complexity:** O(log n)

**Example:**
```python
from coding.python.binary_search import binary_search

sorted_array = [1, 3, 5, 7, 9, 11, 13, 15]
target = 7
result = binary_search(sorted_array, 0, len(sorted_array) - 1, target)
print(f"Index of {target}: {result}")  # Output: Index of 7: 3
```

**Usage in Script:**
The script includes a demonstration that:
1. Creates a random sorted list of 10 integers (1-50)
2. Selects a random target
3. Performs binary search
4. Displays results

```bash
python coding/python/binary_search.py
```

---

## Testing Utilities

### Syntax Linting (`tests/syntax_lint.py`)

Comprehensive testing suite for validating markdown syntax in the repository.

#### Functions

##### `count_details(file_list: List[bytes]) -> bool`

Debug utility to count and validate `<details>` tag pairs.

**Parameters:**
- `file_list` (List[bytes]): List of file lines as bytes

**Returns:**
- `bool`: True if opening and closing tags match

##### `count_summary(file_list: List[bytes]) -> bool`

Debug utility to count and validate `<summary>` tag pairs.

**Parameters:**
- `file_list` (List[bytes]): List of file lines as bytes

**Returns:**
- `bool`: True if opening and closing tags match

##### `check_details_tag(file_list: List[bytes]) -> None`

Validates proper structure of `<details>` blocks and reports errors.

**Parameters:**
- `file_list` (List[bytes]): List of file lines as bytes

**Side Effects:**
- Appends error messages to global `errors` list

**Validation Rules:**
- Each `<details>` must have corresponding `</details>`
- No nested unclosed detail blocks
- Proper opening/closing order

##### `check_summary_tag(file_list: List[bytes]) -> None`

Validates proper structure of `<summary>` blocks and reports errors.

**Parameters:**
- `file_list` (List[bytes]): List of file lines as bytes

**Side Effects:**
- Appends error messages to global `errors` list

**Validation Rules:**
- Each `<summary>` must have corresponding `</summary>`
- No nested unclosed summary blocks
- Proper opening/closing order

##### `check_md_file(file_name: str) -> None`

Main validation function that checks both details and summary tags.

**Parameters:**
- `file_name` (str): Path to markdown file to validate

**Usage:**
```bash
python tests/syntax_lint.py path/to/file.md
```

**Exit Codes:**
- `0`: All tests passed
- `1`: Validation errors found

---

## Shell Scripts

### Question Counter (`scripts/count_questions.sh`)

Shell script for counting questions in the repository.

**Usage:**
```bash
bash scripts/count_questions.sh
```

### CI Runner (`scripts/run_ci.sh`)

Continuous Integration script for repository validation.

**Usage:**
```bash
bash scripts/run_ci.sh
```

---

## Installation and Setup

### Prerequisites

- Python 3.7+
- Flask
- Flask-WTF (for CSRF protection)

### Installation

1. Clone the repository:
```bash
git clone https://github.com/bregman-arie/devops-exercises.git
cd devops-exercises
```

2. Install Python dependencies:
```bash
pip install flask flask-wtf
```

3. For Flask applications, ensure you have the required data files:
   - `users.json` for the user management API

### Running Flask Applications

#### User Management API:
```bash
cd topics/flask_container_ci/app
python main.py
# Access at http://localhost:5000
```

#### Matrix Operations API:
```bash
cd topics/flask_container_ci2/app
python main.py
# Access at http://localhost:5000
```

---

## Testing

### Running Syntax Tests

```bash
python tests/syntax_lint.py README.md
```

### Running Unit Tests

```bash
python -m pytest tests/
```

### Testing Flask Applications

Both Flask applications include test files that can be run with standard Python testing frameworks.

---

## Contributing

When adding new functions or APIs:

1. Follow the existing code style and documentation format
2. Add comprehensive docstrings to all public functions
3. Include usage examples in docstrings
4. Update this documentation file
5. Add appropriate tests

---

## API Summary

| Component | Purpose | Key Functions |
|-----------|---------|---------------|
| `question_utils.py` | Question management utilities | `get_question_list()`, `get_answers_count()` |
| `random_question.py` | Interactive quiz tool | `main()` |
| Flask User API | User data management | GET `/users`, GET `/users/<username>` |
| Flask Matrix API | Matrix operations | GET `/matrix/<matrix>` (incomplete) |
| `binary_search.py` | Search algorithm example | `binary_search()` |
| `syntax_lint.py` | Markdown validation | `check_details_tag()`, `check_summary_tag()` |

For questions or issues with these APIs, please refer to the repository's issue tracker or contribution guidelines.