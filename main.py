from datetime import datetime
from typing import List, Optional
from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordRequestForm
from pydantic import BaseModel, EmailStr
from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, Text
from sqlalchemy.orm import Session, relationship

import database
import security
from database import engine, get_db

# Création des tables additionnelles (comme les messages de partage)
from sqlalchemy.ext.declarative import declarative_base
Base = database.Base

class MessagePartageDB(Base):
    __tablename__ = "messages_partage"

    id = Column(Integer, primary_key=True, index=True)
    contenu = Column(Text, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    user_id = Column(Integer, ForeignKey("utilisateurs.id"))

Base.metadata.create_all(bind=engine)

app = FastAPI(title="TeamManager API", version="1.0.0")

# ================= MIDDLEWARE CORS =================
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Autorise toutes les origines (Vercel, localhost, etc.)
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ================= SCHÉMAS PYDANTIC =================

class UtilisateurCreate(BaseModel):
    nom: Optional[str] = None
    email: EmailStr
    password: str

class UtilisateurOut(BaseModel):
    id: int
    nom: Optional[str] = None
    email: EmailStr
    role: str

    class Config:
        from_attributes = True

class NomUpdate(BaseModel):
    nom: str

class PasswordUpdate(BaseModel):
    ancien_mot_de_passe: str
    nouveau_mot_de_passe: str

class RoleUpdate(BaseModel):
    role: str

class ProjetCreate(BaseModel):
    titre: str
    description: Optional[str] = ""
    statut: Optional[str] = "En cours"
    responsable: Optional[str] = "Non assigné"

class ProjetOut(BaseModel):
    id: int
    titre: str
    description: Optional[str] = ""
    statut: str
    responsable: str

    class Config:
        from_attributes = True

class MessageCreate(BaseModel):
    contenu: str

class MessageOut(BaseModel):
    id: int
    contenu: str
    created_at: datetime
    auteur_nom: str

    class Config:
        from_attributes = True


# ================= ROUTES AUTHENTIFICATION =================

@app.post("/register", response_model=UtilisateurOut, status_code=status.HTTP_201_CREATED)
def inscrire(user: UtilisateurCreate, db: Session = Depends(get_db)):
    email_clean = user.email.lower().strip()
    db_user = db.query(database.UtilisateurDB).filter(database.UtilisateurDB.email == email_clean).first()
    if db_user:
        raise HTTPException(status_code=400, detail="Cet e-mail est déjà utilisé.")
    
    hashed = security.hash_password(user.password)
    
    # Rôle attribué automatiquement : SUPER_ADMIN si votre adresse email, sinon Membre
    role_initial = "SUPER_ADMIN" if email_clean == "niassyrawanekone@gmail.com" else "Membre"
    
    nouveau_user = database.UtilisateurDB(
        nom=user.nom, 
        email=email_clean, 
        hashed_password=hashed, 
        role=role_initial
    )
    db.add(nouveau_user)
    db.commit()
    db.refresh(nouveau_user)
    return nouveau_user


@app.post("/login")
def connecter(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    email_clean = form_data.username.lower().strip()
    
    # 1. Vérification spécifique du Super Admin
    if email_clean == "niassyrawanekone@gmail.com":
        if form_data.password != "niassy191006":
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="E-mail ou mot de passe incorrect.",
                headers={"WWW-Authenticate": "Bearer"},
            )
        
        # Vérifie si l'utilisateur existe déjà en BD, sinon on le crée / met à jour avec le rôle SUPER_ADMIN
        admin_user = db.query(database.UtilisateurDB).filter(database.UtilisateurDB.email == email_clean).first()
        if not admin_user:
            hashed = security.hash_password("niassy191006")
            admin_user = database.UtilisateurDB(
                nom="Rawane Koné Niassy", 
                email=email_clean, 
                hashed_password=hashed, 
                role="SUPER_ADMIN"
            )
            db.add(admin_user)
            db.commit()
            db.refresh(admin_user)
        elif admin_user.role != "SUPER_ADMIN":
            admin_user.role = "SUPER_ADMIN"
            db.commit()

        access_token = security.create_access_token(data={"sub": email_clean})
        return {"access_token": access_token, "token_type": "bearer"}

    # 2. Connexion classique pour les autres utilisateurs
    user = db.query(database.UtilisateurDB).filter(database.UtilisateurDB.email == email_clean).first()
    if not user or not security.verify_password(form_data.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="E-mail ou mot de passe incorrect.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token = security.create_access_token(data={"sub": user.email})
    return {"access_token": access_token, "token_type": "bearer"}


@app.get("/me", response_model=UtilisateurOut)
def obtenir_profil(current_user: database.UtilisateurDB = Depends(security.get_current_user)):
    return current_user


@app.put("/me/nom", response_model=UtilisateurOut)
def modifier_mon_nom(
    data: NomUpdate,
    db: Session = Depends(get_db),
    current_user: database.UtilisateurDB = Depends(security.get_current_user)
):
    current_user.nom = data.nom
    db.commit()
    db.refresh(current_user)
    return current_user


@app.put("/me/mot-de-passe")
def modifier_mon_mot_de_passe(
    data: PasswordUpdate,
    db: Session = Depends(get_db),
    current_user: database.UtilisateurDB = Depends(security.get_current_user)
):
    if not security.verify_password(data.ancien_mot_de_passe, current_user.hashed_password):
        raise HTTPException(status_code=400, detail="L'ancien mot de passe est incorrect.")
    
    current_user.hashed_password = security.hash_password(data.nouveau_mot_de_passe)
    db.commit()
    return {"message": "Mot de passe mis à jour avec succès."}


# ================= ROUTES UTILISATEURS =================

@app.get("/utilisateurs/", response_model=List[UtilisateurOut])
def lister_utilisateurs(
    db: Session = Depends(get_db),
    current_user: database.UtilisateurDB = Depends(security.get_current_user)
):
    return db.query(database.UtilisateurDB).all()


@app.post("/utilisateurs/", response_model=UtilisateurOut, status_code=status.HTTP_201_CREATED)
def ajouter_utilisateur(
    user: UtilisateurCreate,
    db: Session = Depends(get_db),
    current_user: database.UtilisateurDB = Depends(security.get_current_user)
):
    email_clean = user.email.lower().strip()
    db_user = db.query(database.UtilisateurDB).filter(database.UtilisateurDB.email == email_clean).first()
    if db_user:
        raise HTTPException(status_code=400, detail="Cet utilisateur existe déjà.")
    
    hashed = security.hash_password(user.password)
    nouveau_user = database.UtilisateurDB(nom=user.nom, email=email_clean, hashed_password=hashed, role="Membre")
    db.add(nouveau_user)
    db.commit()
    db.refresh(nouveau_user)
    return nouveau_user


@app.put("/utilisateurs/{user_id}", response_model=UtilisateurOut)
def modifier_role(
    user_id: int,
    data: RoleUpdate,
    db: Session = Depends(get_db),
    current_user: database.UtilisateurDB = Depends(security.get_current_user)
):
    target_user = db.query(database.UtilisateurDB).filter(database.UtilisateurDB.id == user_id).first()
    if not target_user:
        raise HTTPException(status_code=404, detail="Utilisateur non trouvé.")
    
    target_user.role = data.role
    db.commit()
    db.refresh(target_user)
    return target_user


@app.delete("/utilisateurs/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
def supprimer_utilisateur(
    user_id: int,
    db: Session = Depends(get_db),
    current_user: database.UtilisateurDB = Depends(security.get_current_user)
):
    target_user = db.query(database.UtilisateurDB).filter(database.UtilisateurDB.id == user_id).first()
    if not target_user:
        raise HTTPException(status_code=404, detail="Utilisateur non trouvé.")
    
    db.delete(target_user)
    db.commit()
    return None


# ================= ROUTES PROJETS =================

@app.get("/projets/", response_model=List[ProjetOut])
def lister_projets(
    db: Session = Depends(get_db),
    current_user: database.UtilisateurDB = Depends(security.get_current_user)
):
    return db.query(database.ProjetDB).all()


@app.post("/projets/", response_model=ProjetOut, status_code=status.HTTP_201_CREATED)
def ajouter_projet(
    projet: ProjetCreate,
    db: Session = Depends(get_db),
    current_user: database.UtilisateurDB = Depends(security.get_current_user)
):
    nouveau_projet = database.ProjetDB(
        titre=projet.titre, 
        description=projet.description, 
        statut=projet.statut,
        responsable=projet.responsable
    )
    db.add(nouveau_projet)
    db.commit()
    db.refresh(nouveau_projet)
    return nouveau_projet


@app.put("/projets/{projet_id}", response_model=ProjetOut)
def modifier_projet(
    projet_id: int,
    projet: ProjetCreate,
    db: Session = Depends(get_db),
    current_user: database.UtilisateurDB = Depends(security.get_current_user)
):
    p = db.query(database.ProjetDB).filter(database.ProjetDB.id == projet_id).first()
    if not p:
        raise HTTPException(status_code=404, detail="Projet non trouvé.")
    
    p.titre = projet.titre
    p.description = projet.description
    p.statut = projet.statut
    p.responsable = projet.responsable
    db.commit()
    db.refresh(p)
    return p


@app.delete("/projets/{projet_id}", status_code=status.HTTP_204_NO_CONTENT)
def supprimer_projet(
    projet_id: int,
    db: Session = Depends(get_db),
    current_user: database.UtilisateurDB = Depends(security.get_current_user)
):
    p = db.query(database.ProjetDB).filter(database.ProjetDB.id == projet_id).first()
    if not p:
        raise HTTPException(status_code=404, detail="Projet non trouvé.")
    
    db.delete(p)
    db.commit()
    return None


# ================= ROUTES ESPACE DE PARTAGE =================

@app.get("/partage/", response_model=List[MessageOut])
def lister_messages_partage(
    db: Session = Depends(get_db),
    current_user: database.UtilisateurDB = Depends(security.get_current_user)
):
    messages = db.query(MessagePartageDB).order_by(MessagePartageDB.created_at.desc()).all()
    resultat = []
    for msg in messages:
        auteur = db.query(database.UtilisateurDB).filter(database.UtilisateurDB.id == msg.user_id).first()
        nom_auteur = auteur.nom if (auteur and auteur.nom) else (auteur.email if auteur else "Inconnu")
        resultat.append({
            "id": msg.id,
            "contenu": msg.contenu,
            "created_at": msg.created_at,
            "auteur_nom": nom_auteur
        })
    return resultat


@app.post("/partage/", response_model=MessageOut, status_code=status.HTTP_201_CREATED)
def publier_message_partage(
    msg: MessageCreate,
    db: Session = Depends(get_db),
    current_user: database.UtilisateurDB = Depends(security.get_current_user)
):
    nouveau_msg = MessagePartageDB(contenu=msg.contenu, user_id=current_user.id)
    db.add(nouveau_msg)
    db.commit()
    db.refresh(nouveau_msg)

    nom_auteur = current_user.nom if current_user.nom else current_user.email
    return {
        "id": nouveau_msg.id,
        "contenu": nouveau_msg.contenu,
        "created_at": nouveau_msg.created_at,
        "auteur_nom": nom_auteur
    }


@app.delete("/partage/{message_id}", status_code=status.HTTP_204_NO_CONTENT)
def supprimer_message_partage(
    message_id: int,
    db: Session = Depends(get_db),
    current_user: database.UtilisateurDB = Depends(security.get_current_user)
):
    msg = db.query(MessagePartageDB).filter(MessagePartageDB.id == message_id).first()
    if not msg:
        raise HTTPException(status_code=404, detail="Message non trouvé.")
    
    if msg.user_id != current_user.id and current_user.role not in ["Admin", "SUPER_ADMIN"]:
        raise HTTPException(status_code=403, detail="Vous n'avez pas la permission de supprimer ce message.")
    
    db.delete(msg)
    db.commit()
    return None