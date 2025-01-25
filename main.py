from fastapi import FastAPI, HTTPException, Depends
from pydantic import BaseModel, EmailStr, validator
from sqlalchemy import create_engine, Column, Integer, String, ForeignKey
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session, relationship
import redis
import json
from passlib.context import CryptContext

DATABASE_URL = "mysql+pymysql://root:db2025@localhost:3307/kino"
engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

redis_client = redis.Redis(host='localhost', port=6379, db=0, decode_responses=True)
password_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Models
class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    email = Column(String(100), unique=True, nullable=False)
    hashed_password = Column(String(255), nullable=False)

class Movie(Base):
    __tablename__ = "movies"
    id = Column(Integer, primary_key=True, index=True)
    title = Column(String(100), nullable=False)
    description = Column(String(255))

class Hall(Base):
    __tablename__ = "halls"
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(100), nullable=False)
    capacity = Column(Integer, nullable=False)

class Projection(Base):
    __tablename__ = "projections"
    id = Column(Integer, primary_key=True, index=True)
    movie_id = Column(Integer, ForeignKey("movies.id"), nullable=False)
    hall_id = Column(Integer, ForeignKey("halls.id"), nullable=False)
    time = Column(String(100), nullable=False)

    movie = relationship("Movie")
    hall = relationship("Hall")

class Reservation(Base):
    __tablename__ = "reservations"
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    projection_id = Column(Integer, ForeignKey("projections.id"), nullable=False)
    seats_reserved = Column(Integer, nullable=False)

    user = relationship("User")
    projection = relationship("Projection")

Base.metadata.create_all(bind=engine)

# Schemas
class UserCreate(BaseModel):
    email: EmailStr
    password: str

    @validator("password")
    def validate_password(cls, password):
        if len(password) < 6:
            raise ValueError("Password must be at least 6 characters long.")
        return password

class UserResponse(BaseModel):
    id: int
    email: str

    class Config:
        orm_mode = True

class MovieCreate(BaseModel):
    title: str
    description: str | None = None

class MovieResponse(BaseModel):
    id: int
    title: str
    description: str | None

    class Config:
        orm_mode = True

class HallCreate(BaseModel):
    name: str
    capacity: int

class HallResponse(BaseModel):
    id: int
    name: str
    capacity: int

    class Config:
        orm_mode = True

class ProjectionCreate(BaseModel):
    movie_id: int
    hall_id: int
    time: str

class ProjectionResponse(BaseModel):
    id: int
    movie_id: int
    hall_id: int
    time: str

    class Config:
        orm_mode = True

class ReservationCreate(BaseModel):
    projection_id: int
    seats_reserved: int

class ReservationResponse(BaseModel):
    id: int
    user_id: int
    projection_id: int
    seats_reserved: int

    class Config:
        orm_mode = True

# Utility functions
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def hash_password(password: str) -> str:
    return password_context.hash(password)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return password_context.verify(plain_password, hashed_password)

# FastAPI instance
app = FastAPI()

# User routes
@app.post("/register", response_model=UserResponse)
def register_user(user: UserCreate, db: Session = Depends(get_db)):
    existing_user = db.query(User).filter(User.email == user.email).first()
    if existing_user:
        raise HTTPException(status_code=400, detail="Email already registered.")

    hashed_password = hash_password(user.password)
    db_user = User(email=user.email, hashed_password=hashed_password)
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return db_user

@app.post("/login")
def login_user(user: UserCreate, db: Session = Depends(get_db)):
    db_user = db.query(User).filter(User.email == user.email).first()
    if not db_user or not verify_password(user.password, db_user.hashed_password):
        raise HTTPException(status_code=400, detail="Invalid credentials.")
    return {"message": "Login successful"}

# Movie routes
@app.post("/movies/", response_model=MovieResponse)
def create_movie(movie: MovieCreate, db: Session = Depends(get_db)):
    db_movie = Movie(title=movie.title, description=movie.description)
    db.add(db_movie)
    db.commit()
    db.refresh(db_movie)
    redis_client.delete("movies_cache")  # Clear movie cache
    return db_movie

@app.get("/movies/", response_model=list[MovieResponse])
def list_movies(db: Session = Depends(get_db)):
    cached_movies = redis_client.get("movies_cache")
    if cached_movies:
        return json.loads(cached_movies)

    db_movies = db.query(Movie).all()
    movies = [{"id": movie.id, "title": movie.title, "description": movie.description} for movie in db_movies]
    redis_client.set("movies_cache", json.dumps(movies), ex=3600)
    return movies

@app.get("/movies/{movie_id}", response_model=MovieResponse)
def get_movie(movie_id: int, db: Session = Depends(get_db)):
    db_movie = db.query(Movie).filter(Movie.id == movie_id).first()
    if not db_movie:
        raise HTTPException(status_code=404, detail="Movie not found")
    return db_movie

@app.put("/movies/{movie_id}", response_model=MovieResponse)
def update_movie(movie_id: int, movie: MovieCreate, db: Session = Depends(get_db)):
    db_movie = db.query(Movie).filter(Movie.id == movie_id).first()
    if not db_movie:
        raise HTTPException(status_code=404, detail="Movie not found")

    db_movie.title = movie.title
    db_movie.description = movie.description
    db.commit()
    db.refresh(db_movie)
    redis_client.delete("movies_cache")
    return db_movie

@app.delete("/movies/{movie_id}")
def delete_movie(movie_id: int, db: Session = Depends(get_db)):
    db_movie = db.query(Movie).filter(Movie.id == movie_id).first()
    if not db_movie:
        raise HTTPException(status_code=404, detail="Movie not found")

    db.delete(db_movie)
    db.commit()
    redis_client.delete("movies_cache")
    return {"message": "Movie deleted successfully"}

# Hall routes
@app.post("/halls/", response_model=HallResponse)
def create_hall(hall: HallCreate, db: Session = Depends(get_db)):
    db_hall = Hall(name=hall.name, capacity=hall.capacity)
    db.add(db_hall)
    db.commit()
    db.refresh(db_hall)
    return db_hall

@app.get("/halls/", response_model=list[HallResponse])
def list_halls(db: Session = Depends(get_db)):
    db_halls = db.query(Hall).all()
    return db_halls

@app.get("/halls/{hall_id}", response_model=HallResponse)
def get_hall(hall_id: int, db: Session = Depends(get_db)):
    db_hall = db.query(Hall).filter(Hall.id == hall_id).first()
    if not db_hall:
        raise HTTPException(status_code=404, detail="Hall not found")
    return db_hall

@app.put("/halls/{hall_id}", response_model=HallResponse)
def update_hall(hall_id: int, hall: HallCreate, db: Session = Depends(get_db)):
    db_hall = db.query(Hall).filter(Hall.id == hall_id).first()
    if not db_hall:
        raise HTTPException(status_code=404, detail="Hall not found")

    db_hall.name = hall.name
    db_hall.capacity = hall.capacity
    db.commit()
    db.refresh(db_hall)
    return db_hall

@app.delete("/halls/{hall_id}")
def delete_hall(hall_id: int, db: Session = Depends(get_db)):
    db_hall = db.query(Hall).filter(Hall.id == hall_id).first()
    if not db_hall:
        raise HTTPException(status_code=404, detail="Hall not found")

    db.delete(db_hall)
    db.commit()
    return {"message": "Hall deleted successfully"}

# Projection routes
@app.post("/projections/", response_model=ProjectionResponse)
def create_projection(projection: ProjectionCreate, db: Session = Depends(get_db)):
    db_projection = Projection(movie_id=projection.movie_id, hall_id=projection.hall_id, time=projection.time)
    db.add(db_projection)
    db.commit()
    db.refresh(db_projection)
    return db_projection

@app.get("/projections/", response_model=list[ProjectionResponse])
def list_projections(db: Session = Depends(get_db)):
    db_projections = db.query(Projection).all()
    return db_projections

@app.get("/projections/{projection_id}", response_model=ProjectionResponse)
def get_projection(projection_id: int, db: Session = Depends(get_db)):
    db_projection = db.query(Projection).filter(Projection.id == projection_id).first()
    if not db_projection:
        raise HTTPException(status_code=404, detail="Projection not found")
    return db_projection

@app.put("/projections/{projection_id}", response_model=ProjectionResponse)
def update_projection(projection_id: int, projection: ProjectionCreate, db: Session = Depends(get_db)):
    db_projection = db.query(Projection).filter(Projection.id == projection_id).first()
    if not db_projection:
        raise HTTPException(status_code=404, detail="Projection not found")

    db_projection.movie_id = projection.movie_id
    db_projection.hall_id = projection.hall_id
    db_projection.time = projection.time
    db.commit()
    db.refresh(db_projection)
    return db_projection

@app.delete("/projections/{projection_id}")
def delete_projection(projection_id: int, db: Session = Depends(get_db)):
    db_projection = db.query(Projection).filter(Projection.id == projection_id).first()
    if not db_projection:
        raise HTTPException(status_code=404, detail="Projection not found")

    db.delete(db_projection)
    db.commit()
    return {"message": "Projection deleted successfully"}

# Reservation routes
@app.post("/reservations/", response_model=ReservationResponse)
def create_reservation(reservation: ReservationCreate, user_id: int = 1, db: Session = Depends(get_db)):
    # Dohvat projekcije
    db_projection = db.query(Projection).filter(Projection.id == reservation.projection_id).first()
    if not db_projection:
        raise HTTPException(status_code=404, detail="Projection not found.")

    # Dohvat dvorane povezane s projekcijom
    hall_capacity = db_projection.hall.capacity

    # Dohvat ukupno rezerviranih sjedala za tu projekciju
    total_reserved_seats = db.query(Reservation).filter(
        Reservation.projection_id == reservation.projection_id
    ).with_entities(db.func.sum(Reservation.seats_reserved)).scalar() or 0

    # Provjera dostupnosti sjedala
    if total_reserved_seats + reservation.seats_reserved > hall_capacity:
        raise HTTPException(status_code=400, detail="Not enough seats available.")

    # Kreiranje rezervacije
    db_reservation = Reservation(
        user_id=user_id,
        projection_id=reservation.projection_id,
        seats_reserved=reservation.seats_reserved
    )
    db.add(db_reservation)
    db.commit()
    db.refresh(db_reservation)
    return db_reservation


@app.get("/reservations/", response_model=list[ReservationResponse])
def list_reservations(db: Session = Depends(get_db)):
    db_reservations = db.query(Reservation).all()
    return db_reservations

@app.get("/reservations/{reservation_id}", response_model=ReservationResponse)
def get_reservation(reservation_id: int, db: Session = Depends(get_db)):
    db_reservation = db.query(Reservation).filter(Reservation.id == reservation_id).first()
    if not db_reservation:
        raise HTTPException(status_code=404, detail="Reservation not found")
    return db_reservation

@app.put("/reservations/{reservation_id}", response_model=ReservationResponse)
def update_reservation(
    reservation_id: int, 
    reservation: ReservationCreate, 
    user_id: int = 1, 
    db: Session = Depends(get_db)
):
    db_reservation = db.query(Reservation).filter(Reservation.id == reservation_id).first()
    if not db_reservation:
        raise HTTPException(status_code=404, detail="Reservation not found.")

    db_projection = db.query(Projection).filter(Projection.id == reservation.projection_id).first()
    if not db_projection:
        raise HTTPException(status_code=404, detail="Projection not found.")

    db_reservation.projection_id = reservation.projection_id
    db_reservation.seats_reserved = reservation.seats_reserved
    db.commit()
    db.refresh(db_reservation)
    return db_reservation

@app.delete("/reservations/{reservation_id}")
def delete_reservation(reservation_id: int, db: Session = Depends(get_db)):
    db_reservation = db.query(Reservation).filter(Reservation.id == reservation_id).first()
    if not db_reservation:
        raise HTTPException(status_code=404, detail="Reservation not found.")

    db.delete(db_reservation)
    db.commit()
    return {"message": "Reservation deleted successfully"}

