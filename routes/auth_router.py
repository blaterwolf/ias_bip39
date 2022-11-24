from fastapi import APIRouter, Depends, Response
from sqlalchemy.orm import Session
from database import get_db
from models.user_model import User
from schemas.auth_schema import TokenData, AuthForm, ResetPasswordForm
from schemas.user_schema import CreateUser
from jose import jwt
from passlib.context import CryptContext
from bip39 import BIP39

# using: openssl rand -hex 32
AUTH_SECRET = '07774dad34fe4a073e7e978751fba97632bea34dc004328f8306249c0128e42e'
pwd_context = CryptContext(schemes=['bcrypt'], deprecated='auto')


def password_verify(plain, hashed):
    return pwd_context.verify(plain, hashed)


def password_hash(password):
    return pwd_context.hash(password)


router = APIRouter(
    prefix='/auth',
    tags=['auth']
)


@router.post('/signup')
def signup(request: CreateUser, db: Session = Depends(get_db)):
    """Signs Up user to the system and insert it to the database.

    Args:
        request (CreateUser): gets the Request data from the client.
        db: Session object where cinacall niya yung database.

    Returns:
        json['message']: Sign Up Successful
    """
    try:
        # Turn regular string password to Hashed Password version.
        request.password = password_hash(request.password)
        entropy = BIP39.generate_entropy()
        hashed_entropy = password_hash(entropy)
        seed = " ".join(BIP39.generate_phrase(entropy))
        # bind the request data to the User model.
        user = User(
            user_name=request.user_name,
            password=request.password,
            entropy=hashed_entropy
        )
        # send the model to the database
        db.add(user)
        db.commit()
        return {
            'message': f'Sign Up Successful! Please remember this 12-word seed phrase:',
            'seed': seed
        }
    except Exception as e:
        print(e)


@router.post('/reset-password')
def verify_reset_password(form: ResetPasswordForm, db: Session = Depends(get_db)):
    try:
        user = db.query(User).filter(User.user_name == form.user_name).first()
        hashed_entropy = user.entropy
        user_seed = form.seed
        result = BIP39().verify_entropy_and_seed(user_seed, hashed_entropy)
        if (result):
            # * Generate new Entropy
            entropy = BIP39.generate_entropy()
            hashed_entropy = password_hash(entropy)
            new_seed = " ".join(BIP39.generate_phrase(entropy))
            # * Update the user's password
            form.new_password = password_hash(form.new_password)
            # * Update entropy and password of user
            db.query(User).filter(User.user_name == form.user_name).update({
                'entropy': hashed_entropy,
                'password': form.new_password
            })
            db.commit()
            user = db.query(User).filter(
                User.user_name == form.user_name).first()
            return {
                'message': 'Successfully reset the password! Please remember this 12-word seed phrase:',
                'previous_seed': user_seed,
                'new_seed': new_seed,
                'verify_entropy_and_seed() result': result,
                'user': user,
            }
        else:
            return {
                'message': 'Seed phrase is invalid.',
                'verify_entropy_and_seed() result': result,
                'seed': user_seed,
            }
        return {
            'user': user,
            'result': result,
            'seed': user_seed,
            'message': 'Ongoing Password Reset Algorithm!',
        }
    except Exception as e:
        print(e)


@router.post('/login')
def login(form: AuthForm, response: Response, db: Session = Depends(get_db)):
    """Login the user to the network.

    Args:
        form (AuthForm): Request body: gets the user_name and password
        response (Response): To be used for setting cookies in the browswer.
        db: Session object where cinacall niya yung database.

    Returns:
        json['message']: Login Success.
    """
    try:
        # Get the user from the database.
        user = db.query(User).filter(User.user_name == form.user_name).first()
        if user:
            match = password_verify(form.password, user.password)
            if match:
                data = TokenData(author_id=user.user_id,
                                 user_name=user.user_name)
                token = jwt.encode(dict(data), AUTH_SECRET)
                response.set_cookie('token', token, httponly=True)
                return {'message': 'Login Success!'}

        return {'message': 'User not found. Please Sign Up first.'}
    except Exception as e:
        print(e)


@router.post('/logout')
def logout(response: Response):
    response.delete_cookie('token')
    return {'message': 'Logout Success!'}
