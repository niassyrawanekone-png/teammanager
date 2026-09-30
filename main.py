from datetime import datetime, timedelta
from typing import List, Optional

from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr
from sqlalchemy.orm import Session
from jose import JWTError, jwt

from database import get_db, UtilisateurDB, ProjetDB
from security import hash_password, verify_password, create_access_token, SECRET_KEY, ALGORITHM

app = FastAPI(title="TeamManager API")

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

# --- SCHÉMAS PYDANTIC ---

class UserCreate(BaseModel):
    email: EmailStr
    password: Optional[str] = "123456"
    nom: str
    role: Optional[str] = "Membre"

class UserUpdate(BaseModel):
    nom: Optional[str] = None
    email: Optional[EmailStr] = None
    role: Optional[str] = None

class UserResponse(BaseModel):
    id: int
    nom: str
    email: str
    role: str

    class Config:
        from_attributes = True

class ProjetCreate(BaseModel):
    titre: str
    description: Optional[str] = ""
    statut: Optional[str] = "En cours"
    responsable: Optional[str] = "Non assigné"

class ProjetUpdate(BaseModel):
    titre: Optional[str] = None
    description: Optional[str] = None
    statut: Optional[str] = None
    responsable: Optional[str] = None

class ProjetResponse(BaseModel):
    id: int
    titre: str
    description: str
    statut: str
    responsable: str

    class Config:
        from_attributes = True

class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    email: Optional[str] = None

class ChangementNomSchema(BaseModel):
    nom: str

class ChangementMotDePasseSchema(BaseModel):
    ancien_mot_de_passe: str
    nouveau_mot_de_passe: str

# --- MIDDLEWARE CORS ---

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- DÉPENDANCE DE SÉCURITÉ ---

def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Impossible de valider les identifiants.",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        if email is None:
            raise credentials_exception
        token_data = TokenData(email=email)
    except JWTError:
        raise credentials_exception

    user = db.query(UtilisateurDB).filter(UtilisateurDB.email == token_data.email).first()
    if user is None:
        raise credentials_exception
    return user

# --- AUTHENTIFICATION ---

@app.post("/register", status_code=status.HTTP_201_CREATED)
def register(user: UserCreate, db: Session = Depends(get_db)):
    db_user = db.query(UtilisateurDB).filter(UtilisateurDB.email == user.email).first()
    if db_user:
        raise HTTPException(status_code=400, detail="Cet email est déjà utilisé.")
    
    hashed_pwd = hash_password(user.password or "123456")
    nouvel_utilisateur = UtilisateurDB(
        email=user.email,
        nom=user.nom,
        hashed_password=hashed_pwd,
        role=user.role
    )
    db.add(nouvel_utilisateur)
    db.commit()
    db.refresh(nouvel_utilisateur)
    return {"message": "Utilisateur créé avec succès !"}

@app.post("/login", response_model=Token)
def login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = db.query(UtilisateurDB).filter(UtilisateurDB.email == form_data.username).first()
    if not user or not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Email ou mot de passe incorrect.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    access_token = create_access_token(data={"sub": user.email})
    return {"access_token": access_token, "token_type": "bearer"}

# --- PROFIL DE L'UTILISATEUR CONNECTÉ ---

@app.get("/me", response_model=UserResponse)
def lire_mon_profil(current_user: UtilisateurDB = Depends(get_current_user)):
    return current_user

@app.put("/me/nom")
def modifier_nom(
    data: ChangementNomSchema, 
    db: Session = Depends(get_db), 
    current_user: UtilisateurDB = Depends(get_current_user)
):
    current_user.nom = data.nom
    db.commit()
    db.refresh(current_user)
    return {"message": "Nom mis à jour avec succès", "nom": current_user.nom}

@app.put("/me/mot-de-passe")
def modifier_mot_de_passe(
    data: ChangementMotDePasseSchema, 
    db: Session = Depends(get_db), 
    current_user: UtilisateurDB = Depends(get_current_user)
):
    if not verify_password(data.ancien_mot_de_passe, current_user.hashed_password):
        raise HTTPException(status_code=400, detail="L'actuel mot de passe est incorrect.")
    
    current_user.hashed_password = hash_password(data.nouveau_mot_de_passe)
    db.commit()
    return {"message": "Mot de passe modifié avec succès"}

# --- ENDPOINTS UTILISATEURS ---

@app.get("/utilisateurs/", response_model=List[UserResponse])
def lire_utilisateurs(db: Session = Depends(get_db)):
    return db.query(UtilisateurDB).all()

@app.get("/utilisateurs/{user_id}", response_model=UserResponse)
def lire_un_utilisateur(user_id: int, db: Session = Depends(get_db)):
    user_db = db.query(UtilisateurDB).filter(UtilisateurDB.id == user_id).first()
    if not user_db:
        raise HTTPException(status_code=404, detail="Utilisateur non trouvé")
    return user_db

@app.post("/utilisateurs/", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
def creer_utilisateur(
    donnees: UserCreate, 
    db: Session = Depends(get_db), 
    current_user: UtilisateurDB = Depends(get_current_user)
):
    utilisateur_existant = db.query(UtilisateurDB).filter(UtilisateurDB.email == donnees.email).first()
    if utilisateur_existant:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, 
            detail="Cet email est déjà attribué à un autre membre."
        )

    mot_de_passe_hache = hash_password(donnees.password or "123456")
    nouvel_utilisateur = UtilisateurDB(
        nom=donnees.nom,
        email=donnees.email,
        role=donnees.role,
        hashed_password=mot_de_passe_hache
    )
    db.add(nouvel_utilisateur)
    db.commit()
    db.refresh(nouvel_utilisateur)
    return nouvel_utilisateur

@app.put("/utilisateurs/{user_id}", response_model=UserResponse)
def modifier_utilisateur(
    user_id: int, 
    donnees: UserUpdate, 
    db: Session = Depends(get_db),
    current_user: UtilisateurDB = Depends(get_current_user)
):
    user_db = db.query(UtilisateurDB).filter(UtilisateurDB.id == user_id).first()
    if not user_db:
        raise HTTPException(status_code=404, detail="Utilisateur non trouvé")
    
    if donnees.role is not None:
        user_db.role = donnees.role
    if donnees.nom is not None:
        user_db.nom = donnees.nom
    if donnees.email is not None:
        user_db.email = donnees.email
        
    db.commit()
    db.refresh(user_db)
    return user_db

@app.delete("/utilisateurs/{user_id}")
def delete_utilisateur(
    user_id: int, 
    db: Session = Depends(get_db),
    current_user: UtilisateurDB = Depends(get_current_user)
):
    user_db = db.query(UtilisateurDB).filter(UtilisateurDB.id == user_id).first()
    if not user_db:
        raise HTTPException(status_code=404, detail="Utilisateur introuvable")
    db.delete(user_db)
    db.commit()
    return {"message": "Utilisateur supprimé"}

# --- ENDPOINTS PROJETS ---

@app.get("/projets/", response_model=List[ProjetResponse])
def lire_projets(db: Session = Depends(get_db)):
    return db.query(ProjetDB).all()

@app.post("/projets/", response_model=ProjetResponse, status_code=status.HTTP_201_CREATED)
def creer_projet(
    donnees: ProjetCreate, 
    db: Session = Depends(get_db),
    current_user: UtilisateurDB = Depends(get_current_user)
):
    nouveau_projet = ProjetDB(
        titre=donnees.titre,
        description=donnees.description,
        statut=donnees.statut,
        responsable=donnees.responsable
    )
    db.add(nouveau_projet)
    db.commit()
    db.refresh(nouveau_projet)
    return nouveau_projet

@app.put("/projets/{projet_id}", response_model=ProjetResponse)
def modifier_projet(
    projet_id: int, 
    donnees: ProjetUpdate, 
    db: Session = Depends(get_db),
    current_user: UtilisateurDB = Depends(get_current_user)
):
    projet_db = db.query(ProjetDB).filter(ProjetDB.id == projet_id).first()
    if not projet_db:
        raise HTTPException(status_code=404, detail="Projet non trouvé")
    
    if donnees.statut is not None:
        projet_db.statut = donnees.statut
    if donnees.titre is not None:
        projet_db.titre = donnees.titre
    if donnees.description is not None:
        projet_db.description = donnees.description
    if donnees.responsable is not None:
        projet_db.responsable = donnees.responsable
        
    db.commit()
    db.refresh(projet_db)
    return projet_db

@app.delete("/projets/{projet_id}")
def supprimer_projet(
    projet_id: int, 
    db: Session = Depends(get_db),
    current_user: UtilisateurDB = Depends(get_current_user)
):
    projet_db = db.query(ProjetDB).filter(ProjetDB.id == projet_id).first()
    if not projet_db:
        raise HTTPException(status_code=404, detail="Projet introuvable")
    db.delete(projet_db)
    db.commit()
    return {"message": "Projet supprimé"}