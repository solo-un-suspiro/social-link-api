const express = require("express")
const mysql = require("mysql2")
const bcrypt = require("bcryptjs")
const jwt = require("jsonwebtoken")
const cors = require("cors")
const multer = require("multer")
const path = require("path")
require("dotenv").config()

const app = express()

// Middleware
app.use(cors())
app.use(express.json())
app.use("/uploads", express.static(path.join(__dirname, "uploads")))

// Conexión a MySQL
const pool = mysql.createPool({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: "GZ4E*g&#66i*",
  database: process.env.DB_NAME,
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0,
})

// Promisify para usar async/await
const promisePool = pool.promise()

// Middleware de autenticación
const auth = (req, res, next) => {
  try {
    const token = req.header("Authorization").replace("Bearer ", "")
    const decoded = jwt.verify(token, process.env.JWT_SECRET)
    req.userId = decoded.userId
    next()
  } catch (error) {
    res.status(401).json({ message: "Por favor autentícate" })
  }
}

// Configuración de multer para la carga de archivos
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, "uploads/") // Directorio de destino para las imágenes
  },
  filename: (req, file, cb) => {
    const ext = path.extname(file.originalname)
    cb(null, Date.now() + ext) // Nombre único para la imagen
  },
})

const upload = multer({ storage })

// Rutas
app.post("/api/register", async (req, res) => {
  try {
    const { username, email, password } = req.body

    // Verificar si el usuario o correo ya existen
    const [users] = await promisePool.query("SELECT username, email FROM users WHERE username = ? OR email = ?", [
      username,
      email,
    ])

    if (users.length > 0) {
      return res.status(400).json({ message: "El usuario o correo ya están en uso" })
    }

    // Hashear la contraseña solo si el usuario no existe
    const hashedPassword = await bcrypt.hash(password, 10)

    // Insertar el nuevo usuario
    await promisePool.query("INSERT INTO users (username, email, password) VALUES (?, ?, ?)", [
      username,
      email,
      hashedPassword,
    ])

    res.json({ message: "Usuario registrado correctamente" })
  } catch (error) {
    res.status(500).json({
      message: "Error al registrar el usuario",
      error: error.message,
    })
  }
})

app.post("/api/login", async (req, res) => {
  try {
    const { email, password } = req.body
    const [rows] = await promisePool.query("SELECT * FROM users WHERE email = ?", [email])
    if (rows.length === 0) {
      return res.status(400).json({ message: "Credenciales inválidas" })
    }
    const user = rows[0]
    const isMatch = await bcrypt.compare(password, user.password)
    if (!isMatch) {
      return res.status(400).json({ message: "Credenciales inválidas" })
    }
    const token = jwt.sign({ userId: user.id }, process.env.JWT_SECRET, { expiresIn: "1h" })
    res.json({ token })
  } catch (error) {
    res.status(500).json({ message: "Error en el inicio de sesión", error: error.message })
  }
})

app.get("/api/profile", auth, async (req, res) => {
  try {
    const [rows] = await promisePool.query("SELECT id, username, email, theme, profile_image FROM users WHERE id = ?", [
      req.userId,
    ])
    if (rows.length === 0) {
      return res.status(404).json({ message: "Usuario no encontrado" })
    }
    res.json(rows[0])
  } catch (error) {
    res.status(500).json({ message: "Error al obtener el perfil", error: error.message })
  }
})

app.put("/api/profile-image", auth, upload.single("profile_image"), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ message: "Por favor selecciona una imagen" })
    }
    const imageUrl = `/uploads/${req.file.filename}` // URL de la imagen subida
    // Actualizar la imagen de perfil en la base de datos
    await promisePool.query("UPDATE users SET profile_image = ? WHERE id = ?", [imageUrl, req.userId])
    res.json({ message: "Imagen de perfil actualizada exitosamente", imageUrl })
  } catch (error) {
    res.status(500).json({ message: "Error al actualizar la imagen de perfil", error: error.message })
  }
})

app.get("/api/links", auth, async (req, res) => {
  try {
    const [rows] = await promisePool.query("SELECT * FROM links WHERE user_id = ?", [req.userId])
    res.json(rows)
  } catch (error) {
    res.status(500).json({ message: "Error al obtener los enlaces", error: error.message })
  }
})

app.put("/api/links", auth, async (req, res) => {
  try {
    const { links } = req.body
    await promisePool.query("DELETE FROM links WHERE user_id = ?", [req.userId])
    for (const link of links) {
      await promisePool.query("INSERT INTO links (user_id, title, url) VALUES (?, ?, ?)", [
        req.userId,
        link.title,
        link.url,
      ])
    }
    res.json({ message: "Enlaces actualizados exitosamente" })
  } catch (error) {
    res.status(500).json({ message: "Error al actualizar los enlaces", error: error.message })
  }
})

app.put("/api/theme", auth, async (req, res) => {
  try {
    const { theme } = req.body
    await promisePool.query("UPDATE users SET theme = ? WHERE id = ?", [JSON.stringify(theme), req.userId])
    res.json({ message: "Tema actualizado exitosamente" })
  } catch (error) {
    res.status(500).json({ message: "Error al actualizar el tema", error: error.message })
  }
})

app.get("/u/:username", async (req, res) => {
  try {
    const [rows] = await promisePool.query("SELECT id, username, theme, profile_image FROM users WHERE username = ?", [
      req.params.username,
    ])
    if (rows.length === 0) {
      return res.status(404).json({ message: "Usuario no encontrado" })
    }
    const user = rows[0]
    const [links] = await promisePool.query("SELECT title, url FROM links WHERE user_id = ?", [user.id])
    res.json({ ...user, links })
  } catch (error) {
    res.status(500).json({ message: "Error al obtener los datos del usuario", error: error.message })
  }
})

const PORT = process.env.PORT || 10000
app.listen(PORT, () => console.log(`Servidor corriendo en el puerto ${PORT}`))

