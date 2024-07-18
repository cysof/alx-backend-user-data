#!/usr/bin/env python3
"""defining an authentication method"""

import bcrypt
from sqlalchemy.orm.exc import NoResultFound
from db import DB
from user import User
import bcrypt
from uuid import uuid4
#!/usr/bin/env python3
"""defining an authentication method"""

import bcrypt
from sqlalchemy.orm.exc import NoResultFound
from db import DB
from user import User
import bcrypt
from uuid import uuid4


def _hash_password(password: str) -> str:
    """takes in a password string
    argument and returns a bytes"""

    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())


def _generate_uuid() -> str:
    """ _generate_uuid."""

    return str(uuid4())


class Auth:
    """Auth class to interact with the authentication database.
    """

    def __init__(self):
        self._db = DB()

    def register_user(self, email: str, password: str) -> User:
        """register user"""
        try:
            self._db.find_user_by(email=email)
            raise ValueError(f"User {email} already exists")
        except NoResultFound:
            return self._db.add_user(email, _hash_password(password))

    def valid_login(self, email: str, password: str) -> bool:
        """valid_login"""
        try:
            user = self._db.find_user_by(email=email)
        except NoResultFound:
            return False
        return bcrypt.checkpw(password.encode('utf-8'), user.hashed_password)

    def create_session(self, email: str) -> str:
        """create _session"""
        try:
            user = self._db.find_user_by(email=email)
            sess_id = _generate_uuid()
            self._db.update_user(user.id, session_id=sess_id)
            return sess_id
        except NoResultFound:
            return

def _hash_password(password: str) -> bytes:
    """Hashes a password using the bcrypt algorithm.
    Arguments:
      password(str) -- a string to be hashed
    Returns:
      A byte string.
    """
    hashed_pwd = password.encode('utf-8')  # Convert the password to bytes
    # Generate a salt and hash the password
    salted_hash = bcrypt.hashpw(hashed_pwd, bcrypt.gensalt())
    return salted_hash

def _generate_uuid() -> str:
    """ _generate_uuid."""

    return str(uuid4())

class Auth:
    """Auth class to interact with the authentication database.
    """

    def __init__(self):
        """
        Initializes the Auth class.

        Creates a new instance of the Auth class.

        Parameters:
            None

        Returns:
            None
        """
        self._db = DB()


    
    def register_user(self, email: str, password: str) -> User:
        """
        Registers a new user in the database.

        Creates a new user object and adds it to the database.

        Parameters:
            email (str): The email of the user.
            password (str): The password of the user.

        Returns:
            User: The new user object. Returns None if an error occurs.
        """
        try:
            self._db.find_user_by(email=email)
            raise ValueError(f"User {email} already exists")
        except NoResultFound:
            return self._db.add_user(email, _hash_password(password))
        

    def valid_login(self, email: str, password: str) -> bool:
        """
        Validates a user's login credentials.

        Parameters:
            email (str): The email of the user.
            password (str): The password of the user.

        Returns:
            bool: True if the user is valid, False otherwise.
        """
        try:
            user = self._db.find_user_by(email=email)
            if bcrypt.checkpw(password.encode('utf-8'), user.hashed_password):
                return True
            return False
        except NoResultFound:
            return False

    def create_session(self, email: str) -> str:
        """
        Creates a new session for a user.

        Parameters:
            email (str): The email of the user.

        Returns:
            str: The session ID.
        """
        try:
            user = self._db.find_user_by(email=email)
            session_id = _generate_uuid()
            self._db.update_user(user.id, session_id=session_id)
            return session_id
        except NoResultFound:
            return None
        

    def get_user_from_session_id(self, session_id: str) -> User:
        """
        Retrieves a user from a session ID.

        Parameters:
            session_id (str): The session ID.

        Returns:
            User: The user object.
        """
        if session_id is None:
            return None
        try:
            user = self._db.find_user_by(session_id=session_id)
            return user
        except NoResultFound:
            return None
