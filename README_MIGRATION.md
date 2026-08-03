# Guía de Despliegue en Proxmox VE + Ubuntu Server 22.04 LTS + Docker

Esta guía describe los pasos exactos para desplegar el **LogDiagnostix Dashboard** en una máquina virtual o contenedor LXC con **Ubuntu Server 22.04 LTS** en **Proxmox VE** usando **Docker & Docker Compose**.

---

## 🚀 PASO 1: Instalar Docker en Ubuntu Server 22.04 LTS

En tu consola SSH de Ubuntu en Proxmox, ejecuta:

```bash
# 1. Actualizar paquetes del sistema
sudo apt update && sudo apt upgrade -y

# 2. Instalar Docker y Docker Compose
sudo apt install -y docker.io docker-compose-v2

# 3. Habilitar e iniciar el servicio Docker
sudo systemctl enable --now docker
sudo usermod -aG docker $USER
```

---

## 📦 PASO 2: Clonar el Repositorio de GitHub

```bash
# Clonar el proyecto en el servidor Ubuntu
git clone https://github.com/TU_USUARIO/log-diagnostic-dashboard.git
cd log-diagnostic-dashboard
```

---

## ⚡ PASO 3: Desplegar con Docker Compose (1 solo comando)

```bash
sudo docker compose up -d --build
```

¡Listo! La aplicación quedará disponible para toda la oficina en:
👉 `http://IP_DE_TU_UBUNTU_PROXMOX` (Puerto 80 por defecto).

---

## 🔄 Cómo actualizar la aplicación cuando hagas cambios locales:

Cada vez que hagas un ajuste en tu PC local y hagas `git push`:

En la máquina Ubuntu de Proxmox solo ejecutas:
```bash
git pull && sudo docker compose up -d --build
```
En 2 segundos el contenedor se reconstruirá con los nuevos cambios sin perder disponibilidad.
