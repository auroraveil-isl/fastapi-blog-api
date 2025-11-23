from fastapi import FastAPI, HTTPException, status, Depends
from fastapi.security import OAuth2PasswordRequestForm
from pydantic import BaseModel, EmailStr
from typing import Optional, List
from sqlalchemy.orm import Session
from datetime import timedelta
from database import get_db, BlogPostDB
from auth import (
    UserDB, get_password_hash, authenticate_user, 
    create_access_token, get_current_user, 
    get_user_by_username, get_user_by_email,
    ACCESS_TOKEN_EXPIRE_MINUTES
)

app = FastAPI(title="Blog API with Authentication", version="3.0.0")

# Pydantic models
class BlogPost(BaseModel):
    title: str
    content: str
    author: str
    published: bool = True

class BlogPostUpdate(BaseModel):
    title: Optional[str] = None
    content: Optional[str] = None
    published: Optional[bool] = None

class BlogPostResponse(BlogPost):
    id: int

    class Config:
        from_attributes = True

class UserCreate(BaseModel):
    username: str
    email: EmailStr
    password: str

class UserResponse(BaseModel):
    id: int
    username: str
    email: str

    class Config:
        from_attributes = True

class Token(BaseModel):
    access_token: str
    token_type: str

# Root endpoint
@app.get("/")
def read_root():
    return {"message": "Welcome to the Blog API with Authentication! Visit /docs"}

# ===== AUTHENTICATION ENDPOINTS =====

@app.post("/register", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
def register(user: UserCreate, db: Session = Depends(get_db)):
    print(f"Register attempt - Username: {user.username}, Email: {user.email}")
    
    try:
        # Check if username exists
        db_user = get_user_by_username(db, user.username)
        print(f"Username check: {db_user}")
        if db_user:
            raise HTTPException(status_code=400, detail="Username already registered")
        
        # Check if email exists
        db_user = get_user_by_email(db, user.email)
        print(f"Email check: {db_user}")
        if db_user:
            raise HTTPException(status_code=400, detail="Email already registered")
        
        # Create new user
        print("Hashing password...")
        hashed_password = get_password_hash(user.password)
        print(f"Password hashed successfully")
        
        new_user = UserDB(
            username=user.username,
            email=user.email,
            hashed_password=hashed_password
        )
        print("Adding user to database...")
        db.add(new_user)
        db.commit()
        db.refresh(new_user)
        print(f"User created successfully with ID: {new_user.id}")
        return new_user
    except Exception as e:
        print(f"ERROR in register: {type(e).__name__}: {str(e)}")
        raise

@app.post("/login", response_model=Token)
def login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = authenticate_user(db, form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}

@app.get("/users/me", response_model=UserResponse)
def read_users_me(current_user: UserDB = Depends(get_current_user)):
    return current_user

# ===== BLOG POST ENDPOINTS (NOW WITH AUTH) =====

@app.post("/posts", response_model=BlogPostResponse, status_code=status.HTTP_201_CREATED)
def create_post(
    post: BlogPost, 
    current_user: UserDB = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    # Automatically set author to current user
    db_post = BlogPostDB(
        title=post.title,
        content=post.content,
        author=current_user.username,
        published=post.published
    )
    db.add(db_post)
    db.commit()
    db.refresh(db_post)
    return db_post

@app.get("/posts", response_model=List[BlogPostResponse])
def get_all_posts(published: Optional[bool] = None, limit: int = 10, db: Session = Depends(get_db)):
    query = db.query(BlogPostDB)
    if published is not None:
        query = query.filter(BlogPostDB.published == published)
    posts = query.limit(limit).all()
    return posts

@app.get("/posts/{post_id}", response_model=BlogPostResponse)
def get_post(post_id: int, db: Session = Depends(get_db)):
    post = db.query(BlogPostDB).filter(BlogPostDB.id == post_id).first()
    if not post:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Post with id {post_id} not found")
    return post

@app.put("/posts/{post_id}", response_model=BlogPostResponse)
def update_post(
    post_id: int, 
    updated_post: BlogPostUpdate,
    current_user: UserDB = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    post = db.query(BlogPostDB).filter(BlogPostDB.id == post_id).first()
    if not post:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Post with id {post_id} not found")
    
    # Check if user is the author
    if post.author != current_user.username:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not authorized to update this post")
    
    update_data = updated_post.model_dump(exclude_unset=True)
    for key, value in update_data.items():
        setattr(post, key, value)
    db.commit()
    db.refresh(post)
    return post

@app.delete("/posts/{post_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_post(
    post_id: int,
    current_user: UserDB = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    post = db.query(BlogPostDB).filter(BlogPostDB.id == post_id).first()
    if not post:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Post with id {post_id} not found")
    
    # Check if user is the author
    if post.author != current_user.username:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not authorized to delete this post")
    
    db.delete(post)
    db.commit()
    return