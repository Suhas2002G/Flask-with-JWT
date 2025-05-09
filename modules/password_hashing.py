import bcrypt

class Authentication:
    # Function to hash the password
    def hash_password(self,password: str) -> bytes:
        salt = bcrypt.gensalt()  # Generate a salt
        hashed = bcrypt.hashpw(password.encode('utf-8'), salt)  # Hash the password
        return hashed

    # Function to check if the entered password matches the stored hash
    def check_password(self,stored_hash: bytes, password: str) -> bool:
        return bcrypt.checkpw(password.encode('utf-8'), stored_hash)
