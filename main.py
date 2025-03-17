from fastapi import FastAPI, HTTPException, Depends
from pydantic import BaseModel
from sqlalchemy import create_engine, Column, Integer, String
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
import jwt
import datetime
import bcrypt
import requests  # Para comunicação com a IA LLaMA

# Configuração do Banco de Dados
DATABASE_URL = "sqlite:///./fluai.db" # conectar no banco de dados
engine = create_engine(DATABASE_URL) # Conexão com o banco de dados
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# Modelo de Usuário
class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    password = Column(String)
    level = Column(String, default="A1")  # Níveis: C2, C1, B2, B1, A2, A1, A, A+

Base.metadata.create_all(bind=engine)

# As Models
class UserCreate(BaseModel):
    username: str
    password: str

class UserLogin(BaseModel):
    username: str
    password: str

class LevelTestResponse(BaseModel):
    level: str

class LevelTestResult(BaseModel):
    answers: list  # Lista de respostas do usuário

# App FastAPI
app = FastAPI()
SECRET_KEY = "supersecretkey" #Chave da llama
LLAMA_API_URL = "http://localhost:8000/generate"  # URL da IA LLaMA

# Dependência para Sessão do DB
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# Endpoint: Cadastro de Usuário
@app.post("/register")
def register(user: UserCreate, db: Session = Depends(get_db)):
    hashed_pw = bcrypt.hashpw(user.password.encode(), bcrypt.gensalt())
    db_user = User(username=user.username, password=hashed_pw)
    db.add(db_user)
    db.commit()
    return {"message": "Usuário cadastrado com sucesso!"}

# Endpoint: Login
@app.post("/login")
def login(user: UserLogin, db: Session = Depends(get_db)):
    db_user = db.query(User).filter(User.username == user.username).first()
    if not db_user or not bcrypt.checkpw(user.password.encode(), db_user.password.encode()):
        raise HTTPException(status_code=400, detail="Credenciais inválidas")
    token = jwt.encode({"user": user.username, "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=2)}, SECRET_KEY)
    return {"token": token}

# Endpoint: Gerar Teste de Nivelamento
@app.get("/generate-level-test")
def generate_level_test():
    prompt = "Crie 10 questões de inglês com diferentes níveis de dificuldade (fácil, médio, difícil) e opções de resposta."
    response = requests.post(LLAMA_API_URL, json={"prompt": prompt})
    if response.status_code != 200:
        raise HTTPException(status_code=500, detail="Erro ao gerar teste com a IA.")
    questions = response.json()["questions"]
    return {"questions": questions}

# Endpoint: Avaliar Teste de Nivelamento
@app.post("/evaluate-level-test", response_model=LevelTestResponse)
def evaluate_level_test(result: LevelTestResult):
    prompt = {
        "prompt": "Corrija essas respostas e forneça um score baseado na precisão: ",
        "answers": result.answers
    }
    response = requests.post(LLAMA_API_URL, json=prompt)
    if response.status_code != 200:
        raise HTTPException(status_code=500, detail="Erro ao corrigir teste com a IA.")
    score = response.json()["score"]
    
    if score >= 90:
        level = "A+"
    elif score >= 80:
        level = "A"
    elif score >= 70:
        level = "A1"
    elif score >= 60:
        level = "A2"
    elif score >= 50:
        level = "B"
    elif score >= 40:
        level = "B1"
    elif score >= 30:
        level = "B2"
    elif score >= 20:
        level = "C1"
    else:
        level = "C2"
    
    return {"level": level}
# Endpoint: Gerar Atividades Baseadas no Nível do Usuário
@app.get("/generate-activities")
def generate_activities(token: str, db: Session = Depends(get_db)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        username = payload["user"]
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expirado")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Token inválido")
    
    db_user = db.query(User).filter(User.username == username).first()
    if not db_user:
        raise HTTPException(status_code=404, detail="Usuário não encontrado")
    
    prompt = f"Crie 5 atividades de inglês para um usuário de nível {db_user.level}, com questões e opções de resposta."
    response = requests.post(LLAMA_API_URL, json={"prompt": prompt})
    
    if response.status_code != 200:
        raise HTTPException(status_code=500, detail="Erro ao gerar atividades com a IA.")
    
    activities = response.json()["activities"]
    return {"activities": activities}
# Endpoint: Avaliar Atividades e Atualizar Nível do Usuário
@app.post("/evaluate-activities")
def evaluate_activities(token: str, result: LevelTestResult, db: Session = Depends(get_db)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        username = payload["user"]
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expirado")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Token inválido")
    
    db_user = db.query(User).filter(User.username == username).first()
    if not db_user:
        raise HTTPException(status_code=404, detail="Usuário não encontrado")
    
    prompt = {
        "prompt": "Corrija essas atividades e forneça um score baseado na precisão: ",
        "answers": result.answers
    }
    response = requests.post(LLAMA_API_URL, json=prompt)
    
    if response.status_code != 200:
        raise HTTPException(status_code=500, detail="Erro ao corrigir atividades com a IA.")
    
    score = response.json()["score"]
    
    if score >= 80:
        new_level = {
            "C2": "C1", "C1": "B2", "B2": "B1", "B1": "A2", "A2": "A1",
            "A1": "A", "A": "A+", "A+": "A+"
        }.get(db_user.level, db_user.level)
        db_user.level = new_level
        db.commit()
    
    return {"message": "Atividades corrigidas!", "new_level": db_user.level}

