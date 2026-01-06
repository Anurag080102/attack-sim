# Agent Workflow Guide

This document outlines the standard workflow for making changes to the codebase.

## Post-Change Workflow

After making changes to the codebase, follow these steps to ensure code quality and proper version control:

### Step 0: Code Quality Checks

Run ruff format and lint commands to ensure code quality:

```bash
ruff format .
ruff check .
```

Iterate on these commands until all errors are fixed and the code passes all checks.

### Step 1: Review Git Status

Check which files have been modified or added:

```bash
git status
```

This gives you an overview of all changes in your working directory.

### Step 2: Review File Contents

Examine the content of each modified or added file to understand the changes:

```bash
git diff
```

Or for specific files:

```bash
git diff <file_path>
```

Review staged changes:

```bash
git diff --staged
```

### Step 3: Group Changes into Atomic Commits

Organize your changes into logical, atomic commits. Each commit should represent a single, coherent change.

Group related files together based on:
- Feature additions
- Bug fixes
- Refactoring
- Documentation updates
- Configuration changes

Stage files for each atomic commit:

```bash
git add <file1> <file2> ...
```

### Step 4: Commit with Proper Format

Follow this commit message format:

```
<type>(<operational scope>): <title>.

<bullet point>
<bullet point>
<bullet point>
.
.
.

Refs: #<local branch name>
```

#### Commit Message Components:

**Type**: The category of change
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation changes
- `refactor`: Code refactoring
- `test`: Adding or updating tests
- `chore`: Maintenance tasks
- `style`: Code style changes (formatting, etc.)
- `perf`: Performance improvements

**Operational Scope**: The area of the codebase affected (e.g., `crawler`, `xss-detector`, `sql-injector`, `config`)

**Title**: Brief description of the change (use imperative mood, capitalize first letter, end with period)

**Bullet Points**: Detailed list of changes made
- Use present tense
- Be specific and clear
- Each point should describe a distinct change

**Refs**: Reference to the local branch name (without the `#` symbol if it's a branch name)

#### Example Commit:

```
feat(crawler): Add depth limit parameter to crawling function.

- Implement max_depth parameter in crawl() method
- Add depth tracking to prevent infinite recursion
- Update documentation to reflect new parameter
- Add unit tests for depth limiting functionality

Refs: #feature/crawler-depth-limit
```

### Step 5: Verify Commit

After committing, verify your commit:

```bash
git log -1
git show HEAD
```

## Best Practices

- **Keep commits atomic**: Each commit should represent one logical change
- **Write clear messages**: Future you (and others) should understand the change
- **Test before committing**: Ensure all tests pass and code quality checks succeed
- **Review your diff**: Always review what you're committing to avoid accidental changes
- **Commit frequently**: Small, frequent commits are easier to understand and revert if needed
