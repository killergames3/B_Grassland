require('dotenv').config();
const express       = require('express');
const cors          = require('cors');
const helmet        = require('helmet');
const rateLimit     = require('express-rate-limit');
const mongoose      = require('mongoose');
const { body, param, validationResult } = require('express-validator');
const jwt           = require('jsonwebtoken');

const app   = express();
const port  = process.env.PORT || 3000;

// --- 1) Conexión MongoDB ---
mongoose.connect(process.env.MONGO_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true
})
.then(() => console.log('✔️ Conexión a MongoDB exitosa'))
.catch(err => console.error('❌ Error al conectar a MongoDB:', err));

// --- 2) Middlewares globales ---
app.use(helmet());
app.use(express.json());

// CORS solo para tu origen de cliente

const allowedOrigins = [
  'http://localhost:3000',
  'http://127.0.0.1:5501',
  'http://localhost:5501'
];

app.use(cors({
  origin: function (origin, callback) {
    if (!origin || allowedOrigins.includes(origin)) {
      callback(null, true); // Permitir
    } else {
      // No permitir, pero sin error
      callback(null, false); 
    }
  },
  optionsSuccessStatus: 200
}));


// Logger simple
app.use((req, res, next) => {
  console.log(`→ ${req.method} ${req.originalUrl}`);
  next();
});

// --- 3) Rate limiter ---
const apiLimiter = rateLimit({
  windowMs: (parseInt(process.env.RATE_LIMIT_WINDOW) || 60) * 60 * 1000, // e.g. 60 minutos
  max: parseInt(process.env.RATE_LIMIT_MAX) || 100,
  message: { error: 'Demasiadas peticiones, inténtalo más tarde.' }
});

// --- 4) Esquemas y modelos ---
const playerSchema = new mongoose.Schema({
  playerName:       { type: String, required: true, unique: true },
  posicionplayerx:  { type: Number, default: 2092 },
  posicionplayery:  { type: Number, default: 2126 },
  vidaPorcentaje:   { type: Number, default: 100 },
  aguaPorcentaje:   { type: Number, default: 100 },
  comidaPorcentaje: { type: Number, default: 100 },
  speed:            { type: Number, default: 2.7 },
  mundo:            { type: Number, default: 1 },
  moneda:           { type: Number, default: 0 },
  Username:         { type: String, default: '---' },
  nivel:            { type: Number, default: 0.0 },
  nivel_exp:        { type: Number, default: 0.0 },
  sabiduria:        { type: Number, default: 0.0 },
  sabiduria_exp:    { type: Number, default: 0.0 },
  fuerza:           { type: Number, default: 0.0 },
  fuerza_exp:       { type: Number, default: 0.0 },
  agricultura:      { type: Number, default: 0.0 },
  agricultura_exp:  { type: Number, default: 0.0 },
  misiones:         { type: Number, default: 0 },
  inventory:        { type: Array,  default: [] },
  chest:            { type: Array,  default: [] }
});
const Player = mongoose.model('Player', playerSchema);

const adminSchema = new mongoose.Schema({
  _id:       { type: String, default: 'config' },
  hora:      { type: String, default: '00:00' },
  dia_noche: { type: String, default: 'dia' }
});
const Admin = mongoose.model('Admin', adminSchema);

// --- 5) Middleware de autenticación JWT ---
function authenticateJWT(req, res, next) {
  const auth = req.header('Authorization') || '';
  const token = auth.startsWith('Bearer ') && auth.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Token no proporcionado' });

  jwt.verify(token, process.env.JWT_SECRET, (err, payload) => {
    if (err) return res.status(403).json({ error: 'Token inválido o expirado' });
    // Opcional: validar que payload.playerName === req.params.playerName
    req.user = payload;
    next();
  });
}

// --- 6) Ruta de emisión de token (login simulado) ---
app.post('/auth',
  body('playerName').isString().notEmpty(),
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

    const { playerName } = req.body;
    // Aquí podrías chequear en BD o firmar directamente:
    const token = jwt.sign({ playerName }, process.env.JWT_SECRET, {
      expiresIn: process.env.JWT_EXPIRES_IN || '1h'
    });
    res.json({ token });
  }
);

// --- 7) Rutas protegidas: save y load ---
app.post(
  '/save/:playerName',
  apiLimiter,
  authenticateJWT,
  [
    param('playerName').isString().notEmpty(),
    body('posicionplayerx').optional().isNumeric(),
    body('posicionplayery').optional().isNumeric(),
    body('vidaPorcentaje').optional().isNumeric(),
    body('aguaPorcentaje').optional().isNumeric(),
    body('comidaPorcentaje').optional().isNumeric(),
    body('speed').optional().isNumeric(),
    body('mundo').optional().isInt(),
    body('moneda').optional().isInt(),
    body('Username').optional().isString(),
    body('nivel').optional().isNumeric(),
    body('nivel_exp').optional().isNumeric(),
    body('sabiduria').optional().isNumeric(),
    body('sabiduria_exp').optional().isNumeric(),
    body('fuerza').optional().isNumeric(),
    body('fuerza_exp').optional().isNumeric(),
    body('agricultura').optional().isNumeric(),
    body('agricultura_exp').optional().isNumeric(),
    body('misiones').optional().isInt(),
    body('inventory').optional().isArray(),
    body('chest').optional().isArray()
  ],
  async (req, res) => {
    // Validación de express-validator
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(422).json({ errors: errors.array() });

    const { playerName } = req.params;
    const bodyData = req.body;

    // Sólo permitimos que el token coincida con el playerName
    if (req.user.playerName !== playerName) {
      return res.status(403).json({ error: 'No autorizado para ese jugador' });
    }

    // Construcción de updateData sin sobrescribir con undefined/null
    const updateData = {};
    Object.keys(bodyData).forEach(k => {
      if (bodyData[k] !== undefined && bodyData[k] !== null) {
        updateData[k] = bodyData[k];
      }
    });

    try {
      let player = await Player.findOne({ playerName });
      if (player) {
        Object.assign(player, updateData);
        await player.save();
      } else {
        player = new Player({ playerName, ...updateData });
        await player.save();
      }
      return res.json({ success: true });
    } catch (err) {
      console.error('Error en /save:', err);
      return res.status(500).json({ error: err.message });
    }
  }
);

app.get(
  '/load/:playerName',
  apiLimiter,
  authenticateJWT,
  param('playerName').isString().notEmpty(),
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(422).json({ errors: errors.array() });

    const { playerName } = req.params;
    if (req.user.playerName !== playerName) {
      return res.status(403).json({ error: 'No autorizado para ese jugador' });
    }

    try {
      let playerDoc = await Player.findOne({ playerName });
      if (!playerDoc) {
        playerDoc = new Player({ playerName });
        await playerDoc.save();
      }

      let admin = await Admin.findById('config');
      if (!admin) {
        admin = new Admin({ _id: 'config' });
        await admin.save();
      }

      return res.json({ ...playerDoc.toObject(), hora: admin.hora, dia_noche: admin.dia_noche });
    } catch (err) {
      console.error('Error en /load:', err);
      return res.status(500).json({ error: err.message });
    }
  }
);


// 8) 404 y arranque
app.use((req, res) => res.status(404).json({ error: `Ruta no encontrada: ${req.method} ${req.originalUrl}` }));

console.log('RUTAS DISPONIBLES:');
app._router.stack
  .filter(r => r.route && r.route.path)
  .forEach(r => {
    console.log(`  ${Object.keys(r.route.methods)[0].toUpperCase()} ${r.route.path}`);
  });

app.listen(port, '0.0.0.0', () => console.log(`Servidor escuchando en http://0.0.0.0:${port}`));
