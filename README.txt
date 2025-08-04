# 📘 Proyecto 2Bimestre: CI/CD para Core-BankEC

**Estudiantes:**  
- Sebastián Donoso  
- Ismael Toala  

**Fecha:** 03-08-2025  
**Proyecto:** Automatización de Integración y Despliegue para Aplicación Core-BankEC  

---

## 🔍 Introducción

Este proyecto implementa un pipeline de **Integración y Despliegue Continuo (CI/CD)** usando **GitHub Actions** para una aplicación backend en Python. La app, llamada `core-bankec-python`, maneja funciones bancarias como autenticación, validación y cifrado de datos sensibles.

Se aplicaron buenas prácticas de ingeniería de software como análisis estático con `flake8`, construcción de imágenes Docker, y manejo seguro de secrets.

---

## 🎯 Objetivos

- Diseñar y construir un pipeline CI/CD funcional.
- Aplicar herramientas de análisis estático (`flake8`).
- Automatizar la construcción de imágenes Docker.
- Ejecutar el pipeline en cada push a `main`.
- Consolidar buenas prácticas de desarrollo profesional.

---

## 📦 Entregables

| Entregable                    | Descripción                                                                 |
|------------------------------|-----------------------------------------------------------------------------|
| `app/`                        | Código fuente organizado por módulos                                        |
| `.github/workflows/ci.yml`   | Definición del pipeline en GitHub Actions                                   |
| `Dockerfile`                 | Instrucciones para construir la imagen Docker                              |
| `requirements.txt`          | Dependencias del proyecto                                                  |
| `.env` (generado con secrets) | Variables de entorno necesarias para la ejecución                          |
| `README.md`                 | Documentación técnica del proyecto                                          |

---

## ⚙️ Construcción del Pipeline

El archivo del pipeline (`ci.yml`) se encuentra en:

.github/workflows/ci.yml

Este se activa automáticamente con cualquier `push` o `pull request` en la rama `main`.

### 🔁 Flujo del pipeline

1. Checkout del código
2. Configuración de Python 3.10
3. Instalación de dependencias
4. Análisis estático con `flake8`
5. Generación del archivo `.env` desde secrets
6. Construcción de la imagen Docker

### 📝 Fragmento del pipeline

```yaml
name: CoreBankEC CI/CD

on:
  push:
    branches: [ main ]
  pull_request:
    branches: [ main ]

jobs:
  build-test-lint:
    runs-on: ubuntu-latest

    steps:
    - name: 🔄 Checkout del código
      uses: actions/checkout@v3

    - name: 🐍 Configurar Python 3.10
      uses: actions/setup-python@v4
      with:
        python-version: '3.10'

    - name: 📦 Instalar dependencias
      run: |
        python -m pip install --upgrade pip
        pip install -r requirements.txt
        pip install flake8

    - name: ✅ Análisis estático con flake8
      run: flake8 app/

    - name: 🔐 Crear archivo .env con secrets
      run: |
        echo "JWT_SECRET_KEY=${{ secrets.JWT_SECRET_KEY }}" >> .env
        echo "JWT_EXPIRATION_HOURS=${{ secrets.JWT_EXPIRATION_HOURS }}" >> .env
        echo "FERNET_KEY=${{ secrets.FERNET_KEY }}" >> .env

    - name: 🐳 Construir imagen Docker
      run: docker build -t core-bankec .
