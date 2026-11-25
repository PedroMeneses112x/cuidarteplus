const express = require("express");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const { pool } = require("../db");
const validate = require("../middleware/validate");
const { loginSchema, registerSchema } = require("../validations/auth");
const { normalizeRut } = require("../utils/rut");

const router = express.Router();

if (!process.env.JWT_SECRET) {
  throw new Error("FATAL: La variable de entorno JWT_SECRET no está definida.");
}
const JWT_SECRET = process.env.JWT_SECRET;

router.post("/login", validate(loginSchema), async (req, res) => {
  const { nombre_usuario, password } = req.body;
  try {
    const result = await pool.query(
      "SELECT id, nombre_usuario, contrasena, correo FROM usuarios WHERE nombre_usuario = $1",
      [nombre_usuario]
    );
    if (result.rows.length === 0) {
      return res.status(401).json({ error: "Credenciales inválidas" });
    }
    const user = result.rows[0];

    const isPasswordValid = user.contrasena.startsWith("$2")
      ? await bcrypt.compare(password, user.contrasena)
      : user.contrasena === password;

    if (!isPasswordValid) {
      return res.status(401).json({ error: "Credenciales inválidas" });
    }

    const rolesResult = await pool.query(
      `SELECT r.id, r.nombre 
       FROM usuario_roles ur
       JOIN roles r ON r.id = ur.rol_id
       WHERE ur.usuario_id = $1`,
      [user.id]
    );
    const roles = rolesResult.rows.map((r) => ({ id: r.id, nombre: r.nombre }));
    const rolNombre = roles.length > 0 ? roles[0].nombre : null;
    const rolId = roles.length > 0 ? roles[0].id : null;

    const pacienteResult = await pool.query(
      "SELECT id FROM pacientes WHERE usuario_id = $1",
      [user.id]
    );
    const pacienteId = pacienteResult.rows.length > 0 ? pacienteResult.rows[0].id : null;

    const token = jwt.sign(
      {
        usuarioId: user.id,
        nombreUsuario: user.nombre_usuario,
        rolId: rolId,
        rolNombre: rolNombre,
        pacienteId: pacienteId,
        roles: roles,
      },
      JWT_SECRET,
      { expiresIn: "2h" }
    );

    await pool.query(
      "INSERT INTO auditoria (usuario_id, accion) VALUES ($1, $2)",
      [user.id, "LOGIN: usuario inició sesión"]
    );

    res.json({ token });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Error interno al procesar inicio de sesión" });
  }
});

router.post("/registro", validate(registerSchema), async (req, res) => {
  const { nombre_usuario, password, correo, rut } = req.body;
  try {
    const normalizedRut = rut ? normalizeRut(rut) : null;

    let pacienteExistente = null;
    if (normalizedRut) {
      const rutCheck = await pool.query(
        "SELECT id, usuario_id FROM pacientes WHERE rut = $1",
        [normalizedRut]
      );
      if (rutCheck.rows.length > 0) {
        pacienteExistente = rutCheck.rows[0];
        if (pacienteExistente.usuario_id) {
          return res.status(400).json({
            error: "RUT ya registrado",
            glosa: "Este RUT ya tiene una cuenta de usuario asociada",
          });
        }
      }
    }

    const usuarioCheck = await pool.query(
      "SELECT id FROM usuarios WHERE nombre_usuario = $1 OR correo = $2",
      [nombre_usuario, correo]
    );
    if (usuarioCheck.rows.length > 0) {
      return res.status(400).json({
        error: "Usuario o correo duplicado",
        glosa: "El nombre de usuario o correo electrónico ya está en uso",
      });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const userResult = await pool.query(
      "INSERT INTO usuarios (nombre_usuario, contrasena, correo) VALUES ($1, $2, $3) RETURNING id, nombre_usuario, correo, created_at",
      [nombre_usuario, hashedPassword, correo]
    );
    const user = userResult.rows[0];

    const rolPacienteResult = await pool.query(
      "SELECT id FROM roles WHERE nombre = 'paciente'"
    );
    if (rolPacienteResult.rows.length > 0) {
      await pool.query(
        "INSERT INTO usuario_roles (usuario_id, rol_id) VALUES ($1, $2)",
        [user.id, rolPacienteResult.rows[0].id]
      );
    }

    if (normalizedRut) {
      if (pacienteExistente) {
        await pool.query(
          "UPDATE pacientes SET usuario_id = $1 WHERE rut = $2",
          [user.id, normalizedRut]
        );
      } else {
        await pool.query(
          `INSERT INTO pacientes (rut, primer_nombre, apellido_paterno, email, fecha_nacimiento, sexo, usuario_id)
           VALUES ($1, $2, $3, $4, '2000-01-01', 'M', $5)`,
          [normalizedRut, nombre_usuario, "", correo, user.id]
        );
      }
    }

    await pool.query(
      "INSERT INTO auditoria (usuario_id, accion) VALUES ($1, $2)",
      [user.id, "REGISTRO: nuevo usuario registrado"]
    );

    res.status(201).json({
      message: "Usuario registrado exitosamente",
      usuario: user,
    });
  } catch (err) {
    console.error(err);
    if (err.code === "23505") {
      return res.status(400).json({
        error: "Error al registrar",
        glosa: "El nombre de usuario o correo ya existe",
      });
    }
    res.status(500).json({
      error: "Error al registrar usuario",
    });
  }
});

module.exports = router;