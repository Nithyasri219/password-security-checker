# Password Security Checker

A simple Python CLI that checks password strength and optionally estimates whether a password appears in known data breaches using **Have I Been Pwned's k-anonymity API**.

The complete password is never sent to the API. Only the first five characters of a SHA-1 hash are transmitted.

## Features

- Checks password length and character variety
- Penalizes common passwords and repeated/sequential patterns
- Estimates strength and provides improvement tips
- Performs a privacy-preserving breach check
- Uses `getpass` so the password is not echoed in the terminal

## Run

```bash
python password_checker.py
```

For a non-interactive test with the included unit tests:

```bash
python -m unittest -v
```

## Security notes

- Do not use real passwords on untrusted systems or enter production credentials into examples.
- The breach check only reports whether a hash suffix was found in HIBP's database; absence is not proof that a password is safe.
- Python's standard library is used, so no third-party package installation is required.
