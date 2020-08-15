#!/usr/bin/python3
# -*- coding: utf-8 -*-

#Configuraciones Básicas
#Flask
from flask import Flask
from flask import request
from flask import render_template
app = Flask(__name__)
#Librerías para Hashing
import hashlib

#Funciones de Hashing
#MD5
def calcular_md5(cadena,salt,pepper):
    if not salt:    #Si no hay una sal definida, la marcamos como "", para evitar que python ponga None, por ejemplo.
        salt = ""
    if not pepper:  #Mismo para Pepper.
        pepper = ""
    cadena_completa = cadena + salt + pepper
    hash_calculado = hashlib.md5(cadena_completa.encode('utf-8')).hexdigest()
    return hash_calculado

#FUNCION NUEVA
def calcular_sha1(cadena,salt,pepper):
    if not salt: #Chequea que no haya sal
        salt = ""
    if not pepper: #Chequea que no haya pepper
        pepper = ""
    cadena_completa = cadena + salt + pepper #Suma toda la cadena, a la sal y el pepper 
    hash_calculado = hashlib.sha1(cadena_completa.encode('utf-8')).hexdigest() #hashea, lo unico que cambia aca es hashlib.sha1 en vez de hashlib.md5
    return hash_calculado

def calcular_sha256(cadena,salt,pepper):
    if not salt: #Chequea que no haya sal
        salt = ""
    if not pepper: #Chequea que no haya pepper
        pepper = ""
    cadena_completa = cadena + salt + pepper #Suma toda la cadena, a la sal y el pepper 
    hash_calculado = hashlib.sha256(cadena_completa.encode('utf-8')).hexdigest() #hashea, lo unico que cambia aca es hashlib.sha1 en vez de hashlib.md5
    return hash_calculado

def calcular_sha512(cadena,salt,pepper):
    if not salt: #Chequea que no haya sal
        salt = ""
    if not pepper: #Chequea que no haya pepper
        pepper = ""
    cadena_completa = cadena + salt + pepper #Suma toda la cadena, a la sal y el pepper 
    hash_calculado = hashlib.sha512(cadena_completa.encode('utf-8')).hexdigest() #hashea, lo unico que cambia aca es hashlib.sha1 en vez de hashlib.md5
    return hash_calculado

def calcular_sha224(cadena,salt,pepper):
    if not salt: #Chequea que no haya sal
        salt = ""
    if not pepper: #Chequea que no haya pepper
        pepper = ""
    cadena_completa = cadena + salt + pepper #Suma toda la cadena, a la sal y el pepper 
    hash_calculado = hashlib.sha224(cadena_completa.encode('utf-8')).hexdigest() #hashea, lo unico que cambia aca es hashlib.sha1 en vez de hashlib.md5
    return hash_calculado

def calcular_sha384(cadena,salt,pepper):
    if not salt: #Chequea que no haya sal
        salt = ""
    if not pepper: #Chequea que no haya pepper
        pepper = ""
    cadena_completa = cadena + salt + pepper #Suma toda la cadena, a la sal y el pepper 
    hash_calculado = hashlib.sha384(cadena_completa.encode('utf-8')).hexdigest() #hashea, lo unico que cambia aca es hashlib.sha1 en vez de hashlib.md5
    return hash_calculado

def calcular_blake2b(cadena,salt,pepper):
    if not salt: #Chequea que no haya sal
        salt = ""
    if not pepper: #Chequea que no haya pepper
        pepper = ""
    cadena_completa = cadena + salt + pepper #Suma toda la cadena, a la sal y el pepper 
    hash_calculado = hashlib.blake2b(cadena_completa.encode('utf-8')).hexdigest() #hashea, lo unico que cambia aca es hashlib.sha1 en vez de hashlib.md5
    return hash_calculado

def calcular_blake2s(cadena,salt,pepper):
    if not salt: #Chequea que no haya sal
        salt = ""
    if not pepper: #Chequea que no haya pepper
        pepper = ""
    cadena_completa = cadena + salt + pepper #Suma toda la cadena, a la sal y el pepper 
    hash_calculado = hashlib.blake2s(cadena_completa.encode('utf-8')).hexdigest() #hashea, lo unico que cambia aca es hashlib.sha1 en vez de hashlib.md5
    return hash_calculado
#FIN DE FUNCION NUEVA

#Rutas
@app.route('/')
def index():
    return render_template("index.html", hash_output="Esperando...")

@app.route('/hash/')
def hash():
    cadena = request.args.get('inputCadena')
    salt = request.args.get('inputSalt')
    pepper = request.args.get('inputPepper')
    algoritmo = request.args.get('inputAlgoritmo')
    if algoritmo == "MD5":
        hash_calculado = calcular_md5(cadena,salt,pepper)
    #NUEVO IF ACA
    elif algoritmo == "SHA-1":
        hash_calculado = calcular_sha1(cadena,salt,pepper)
    elif algoritmo == "SHA-256":
        hash_calculado = calcular_sha256(cadena,salt,pepper)
    elif algoritmo == "SHA-512":
        hash_calculado = calcular_sha512(cadena,salt,pepper)
    elif algoritmo == "SHA-224":
        hash_calculado = calcular_sha224(cadena,salt,pepper)
    elif algoritmo == "SHA-384":
        hash_calculado = calcular_sha384(cadena,salt,pepper)
    elif algoritmo == "Blake-2B":
        hash_calculado = calcular_blake2b(cadena,salt,pepper)
    elif algoritmo == "Blake-2S":
        hash_calculado = calcular_blake2s(cadena,salt,pepper)

    #Agregar los demás algoritmos. Hashlib soporta aún más de los que yo puse en la caja de selección.
    return render_template("index.html", hash_output="Hash: " + hash_calculado)