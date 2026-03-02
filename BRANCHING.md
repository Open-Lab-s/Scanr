# 🌿 Scanr Branching Strategy

This document defines the official Git branching model for Scanr.

The objective is to ensure:

-   Production stability
-   Clean and traceable history
-   Enforced CI validation
-   Predictable releases
-   Scalable open-source collaboration

## Development Model

Scanr follows a Trunk-Based Development approach with a protected `main`
branch.

All changes must go through Pull Requests.

## Branch Structure

    main
    feature/*
    fix/*
    hotfix/*
    release/* (optional)

## 🔒 1. main Branch

### Purpose

-   Always production-ready
-   Stable and releasable at any time

### Protection Rules

-   No direct pushes
-   Pull Request required
-   Minimum 1 approval
-   All CI checks must pass
-   Conversations must be resolved
-   Branch must be up to date before merging
-   Squash merge only

## 🚀 2. Feature Branches

### Naming Convention

    feature/<short-description>

### Examples

    feature/sbom-diff
    feature/osv-investigation
    feature/dependency-check-cli

### Workflow

    main → feature/* → Pull Request → main

Feature branches must: - Be small and focused - Address one logical
change - Include tests if applicable - Pass all CI checks

## 3. Fix Branches

### Naming Convention

    fix/<short-description>

### Examples

    fix/osv-timeout
    fix/cli-crash

Used for: - Bug fixes - Non-breaking corrections - Stability
improvements

## 4. Hotfix Branches

### Naming Convention

    hotfix/<short-description>

Used when: - A critical issue is found in production - Immediate fix is
required

### Flow

    main → hotfix/* → Pull Request → main

## 5. Release Branches (Optional)

### Naming Convention

    release/vX.Y.Z

Example:

    release/v0.2.0

## 🧾 Commit Message Convention

Scanr follows Conventional Commits.

### Format

    type: short description

### Allowed Types

    feat      → new feature
    fix       → bug fix
    refactor  → code restructuring
    docs      → documentation changes
    test      → test updates
    chore     → maintenance
    ci        → CI/CD changes

### Examples

    feat: add SBOM diff command
    fix: handle OSV rate limiting
    docs: update CLI usage section
    refactor: optimize dependency resolver

## Pull Request Requirements

Every Pull Request must:

-   Clearly describe the change
-   Reference related issue (if applicable)
-   Pass all CI checks
-   Receive at least 1 approval
-   Use squash merge

## Versioning Strategy

Scanr follows Semantic Versioning (SemVer):

    MAJOR.MINOR.PATCH

Examples:

    v0.1.0
    v0.2.0
    v1.0.0

## CI Requirements

Before merging into `main`, the following checks must pass:

-   Build
-   Lint
-   Unit tests
-   Dependency audit
-   CLI smoke test

## Guiding Principles

Scanr is a security-focused CLI tool.

-   Stability over speed
-   Traceability over convenience
-   Reproducibility over shortcuts

Every merge should increase reliability.
