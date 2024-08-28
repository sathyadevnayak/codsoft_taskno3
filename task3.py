import random
import string

password_history = []

def generate_password(length, include_lowercase=True, include_uppercase=True, include_digits=True, include_special_chars=True):
  """Generates a random password based on specified criteria.

  Args:
    length: The desired length of the password.
    include_lowercase: Whether to include lowercase letters.
    include_uppercase: Whether to include uppercase letters.
    include_digits: Whether to include digits.
    include_special_chars: Whether to include special characters.

  Returns:
    The generated password as a string.
  """

  characters = ""
  if include_lowercase:
    characters += string.ascii_lowercase
  if include_uppercase:
    characters += string.ascii_uppercase
  if include_digits:
    characters += string.digits
  if include_special_chars:
    characters += string.punctuation

  if not characters:
    return "No character types selected."

  password = ''.join(random.choice(characters) for _ in range(length))

  while password in password_history:
    password = ''.join(random.choice(characters) for _ in range(length))

  password_history.append(password)
  return password

def password_strength_meter(password):
  """Evaluates password strength and returns a descriptive message."""
  length = len(password)
  has_lowercase = any(char.islower() for char in password)
  has_uppercase = any(char.isupper() for char in password)
  has_digits = any(char.isdigit() for char in password)
  has_special_chars = any(not char.isalnum() for char in password)

  strength = 0
  if length >= 8:
    strength += 1
  if has_lowercase:
    strength += 1
  if has_uppercase:
    strength += 1
  if has_digits:
    strength += 1
  if has_special_chars:
    strength += 1

  if strength == 5:
    return "Very strong password"
  elif strength >= 3:
    return "Strong password"
  elif strength >= 2:
    return "Medium strength password"
  else:
    return "Weak password"

def main():
  while True:
    try:
      password_length = int(input("Enter desired password length (minimum 8 characters): "))
      if password_length < 8:
        print("Password length must be at least 8 characters.")
        continue

      use_lowercase = input("Include lowercase letters? (y/n): ").lower() == "y"
      use_uppercase = input("Include uppercase letters? (y/n): ").lower() == "y"
      use_digits = input("Include digits? (y/n): ").lower() == "y"
      use_special_chars = input("Include special characters? (y/n): ").lower() == "y"

      password = generate_password(password_length, use_lowercase, use_uppercase, use_digits, use_special_chars)
      if not password:
        print("At least one character type must be selected.")
        continue

      strength = password_strength_meter(password)
      print("Generated password:", password)
      if password!="No character types selected.":
          print("Password strength:", strength)

      break
    except ValueError:
      print("Invalid input. Please enter a number.")

if __name__ == "__main__":
  main()
