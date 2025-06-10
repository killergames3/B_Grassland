require('dotenv').config();
const express       = require('express');
const cors          = require('cors');
const helmet        = require('helmet');
const rateLimit     = require('express-rate-limit');
const mongoose      = require('mongoose');
const cookieParser  = require('cookie-parser');
const { body, param, validationResult } = require('express-validator');
const jwt           = require('jsonwebtoken');

const app   = express();
const port  = process.env.PORT || 3000;

// 1) Conexión a MongoDB
mongoose.connect(process.env.MONGO_URI, { useNewUrlParser: true, useUnifiedTopology: true })
  .then(() => console.log('✔️ Conexión a MongoDB exitosa'))
  .catch(err => { console.error('❌ Error al conectar a MongoDB:', err); process.exit(1); });

// 2) Middlewares
app.use(helmet());
app.use(express.json());
app.use(cookieParser());

// ⚠️ CORS bien configurado
const allowedOrigins = [
  'http://localhost:5501',
  'http://localhost:3000',
  'http://127.0.0.1:5501',
  'http://127.0.0.1:3000',
  'http://192.168.100.221:5501',
  'http://192.168.100.221:3000',
  'https://grasslandforest.xyz',
  'https://effortless-profiterole-45a4cb.netlify.app'
];
app.use(cors({
  origin: (origin, cb) => {
    if (!origin || allowedOrigins.includes(origin)) cb(null, true);
    else cb(new Error('CORS no permitido'), false);
  },
  credentials: true
}));

app.use((req, res, next) => {
  console.log(`→ ${req.method} ${req.originalUrl}`);
  next();
});

const apiLimiter = rateLimit({
  windowMs: (parseInt(process.env.RATE_LIMIT_WINDOW) || 1) * 3600000,
  max: parseInt(process.env.RATE_LIMIT_MAX) || 100,
  message: { error: 'Demasiadas peticiones' }
});

// ─────────── SCHEMAS ───────────
const playerSchema = new mongoose.Schema({
  playerName: { type: String, required: true, unique: true },
  posicionplayerx: { type: Number, default: 2092 },
  posicionplayery: { type: Number, default: 2126 },
  vidaPorcentaje: { type: Number, default: 100 },
  aguaPorcentaje: { type: Number, default: 100 },
  comidaPorcentaje: { type: Number, default: 100 },
  speed: { type: Number, default: 2.7 },
  mundo: { type: Number, default: 1 },
  moneda: { type: Number, default: 0 },
  Username: { type: String, default: '---' },
  nivel: { type: Number, default: 0 },
  nivel_exp: { type: Number, default: 0 },
  sabiduria: { type: Number, default: 0 },
  sabiduria_exp: { type: Number, default: 0 },
  fuerza: { type: Number, default: 0 },
  fuerza_exp: { type: Number, default: 0 },
  agricultura: { type: Number, default: 0 },
  agricultura_exp: { type: Number, default: 0 },
  misiones: { type: Number, default: 0 },
  inventory: { type: Array, default: [] },
  chest: { type: Array, default: [] }
});
const Player = mongoose.model('Player', playerSchema);

const adminSchema = new mongoose.Schema({
  _id: { type: String, default: 'config' },
  hora: { type: String, default: '00:00' },
  dia_noche: { type: String, default: 'dia' }
});
const Admin = mongoose.model('Admin', adminSchema);

const listingSchema = new mongoose.Schema({
  owner: { type: String, required: true },
  inventoryId: { type: String, required: true },
  name: { type: String, required: true },
  type: { type: String, required: true },
  qty: { type: Number, required: true, min: 1 },
  price: { type: Number, required: true, min: 0 },
  imageUrl: { type: String, default: '' },
  createdAt: { type: Date, default: Date.now }
});
const Listing = mongoose.model('Listing', listingSchema);

const commissionRates = { seeds: 0.01, tools: 0.02, containers: 0.015, default: 0.02 };

// ─────────── AUTENTICACIÓN ───────────
function authenticateJWT(req, res, next) {
  let token = req.cookies.token;
  if (!token) {
    const auth = req.header('Authorization') || '';
    if (auth.startsWith('Bearer ')) token = auth.split(' ')[1];
  }
  if (!token) return res.status(401).json({ error: 'No autenticado' });

  jwt.verify(token, process.env.JWT_SECRET, (err, payload) => {
    if (err) return res.status(403).json({ error: 'Token inválido' });
    req.user = payload;
    next();
  });
}

// ─────────── RUTAS ───────────

// 🔐 Ruta /auth (crea cookie HttpOnly y también devuelve el token opcionalmente)
app.post('/auth', body('playerName').isString().notEmpty(), async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

  const { playerName } = req.body;
  const token = jwt.sign({ playerName }, process.env.JWT_SECRET, { expiresIn: process.env.JWT_EXPIRES_IN || '1h' });

  // ✅ Cookie HttpOnly
  res.cookie('token', token, {
    httpOnly: true,
    sameSite: 'None', // ← mejor para dev, usa 'None' solo con HTTPS
    secure: true,   // ← en producción: true (HTTPS)
    path: '/',
    maxAge: 3600000
  });

  res.json({ success: true, token }); // ← por compatibilidad también lo retorna
});

// 💾 Guardar progreso
app.post('/save/:playerName', apiLimiter, authenticateJWT,
  param('playerName').isString().notEmpty(),
  body('inventory').isArray(),
  body('chest').isArray(),
  async (req, res) => {
    const { playerName } = req.params;
    if (req.user.playerName !== playerName)
      return res.status(403).json({ error: 'No autorizado' });

    const update = req.body;
    try {
      let p = await Player.findOne({ playerName });
      if (p) { Object.assign(p, update); await p.save(); }
      else { p = new Player({ playerName, ...update }); await p.save(); }
      res.json({ success: true });
    } catch (e) {
      console.error(e);
      res.status(500).json({ error: e.message });
    }
  }
);

// 📦 Cargar datos
app.get('/load/:playerName', apiLimiter, authenticateJWT,
  param('playerName').isString().notEmpty(),
  async (req, res) => {
    const { playerName } = req.params;
    if (req.user.playerName !== playerName)
      return res.status(403).json({ error: 'No autorizado' });

    try {
      let p = await Player.findOne({ playerName });
      if (!p) { p = new Player({ playerName }); await p.save(); }

      let a = await Admin.findById('config');
      if (!a) { a = new Admin(); await a.save(); }

      res.json({ ...p.toObject(), hora: a.hora, dia_noche: a.dia_noche });
    } catch (e) {
      console.error(e);
      res.status(500).json({ error: e.message });
    }
  }
);

// ─────────── Marketplace ───────────
// 8) Rutas de Marketplace (Listings)
// GET /listings      → obtiene todas las listings (sin excluir a nadie)
app.get('/listingsx/:id', apiLimiter, authenticateJWT, async (req, res) => {
  try {
    const listings = await Listing.find().sort({ price: 1, createdAt: -1 }); 
    // Ordenamos por price asc, y si hay empate, por fecha descendente
    return res.json(listings);
  } catch (err) {
    console.error('Error en GET /listings:', err);
    return res.status(500).json({ error: err.message });
  }
});


// GET /listings/:id → obtener detalles de un listing propio (name, qty, etc.)
app.get('/listings/:id',
  apiLimiter,
  authenticateJWT,
  param('id').isMongoId(),
  async (req, res) => {
    // Validación de param
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }
    const listingId = req.params.id;

    try {
      const listing = await Listing.findById(listingId).lean();
      if (!listing) {
        return res.status(404).json({ error: 'Listing no encontrado' });
      }
      // Verificar propietario
      if (listing.owner !== req.user.playerName) {
        // Puedes devolver 403 o 404 según consideres (aquí 403)
        return res.status(403).json({ error: 'No tienes permiso para ver este listing' });
      }
      // Retornar solo los campos necesarios
      return res.json({
        id: listing._id,
        inventoryId: listing.inventoryId,
        name: listing.name,
        type: listing.type,
        quantity: listing.qty,
        price: listing.price,
        imageUrl: listing.imageUrl,
        createdAt: listing.createdAt
      });
    } catch (e) {
      console.error('Error en GET /listings/:id:', e);
      // Si ocurre CastError u otro, captúralo
      return res.status(500).json({ error: 'Error interno al obtener listing' });
    }
  }
);

// POST /listings     → publicar nuevo ítem
app.post(
  '/listingsx/:id',
  apiLimiter,
  authenticateJWT,
  [
    body('inventoryId').isString().notEmpty(),
    body('name').isString().notEmpty(),
    body('type').isString().notEmpty(),
    body('qty').isInt({ min: 1 }),
    body('price').isFloat({ min: 0 }),
    body('imageUrl').optional().isString()
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(422).json({ errors: errors.array() });

    const owner = req.user.playerName;
    const { inventoryId, name, type, qty, price, imageUrl } = req.body;

    try {
      const newListing = new Listing({
        owner,
        inventoryId,
        name,
        type,
        qty,
        price,
        imageUrl: imageUrl || ''
      });
      await newListing.save();
      return res.status(201).json(newListing);
    } catch (err) {
      console.error('Error en POST /listings:', err);
      return res.status(500).json({ error: err.message });
    }
  }
);



app.post(
  '/listings/:id/buy',
  apiLimiter,
  authenticateJWT,
  param('id').isMongoId(),            // 1) Validar que sea un ObjectId
  async (req, res) => {
    // 2) Revisa errores de validación del param
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const listingId = req.params.id;
    try {
      // 3) Obtener listing
      const listing = await Listing.findById(listingId);
      if (!listing) {
        return res.status(404).json({ error: 'Listing no encontrado' });
      }

      // 4) Prohibir auto-compra
      if (listing.owner === req.user.playerName) {
        return res.status(400).json({ error: 'No puedes comprar tu propio listing' });
      }

      // 5) Obtener buyer y seller
      const [buyer, seller] = await Promise.all([
        Player.findOne({ playerName: req.user.playerName }),
        Player.findOne({ playerName: listing.owner })
      ]);
      if (!buyer) {
        return res.status(404).json({ error: 'Comprador no existe' });
      }
      if (!seller) {
        return res.status(404).json({ error: 'Vendedor no existe' });
      }

      // 6) Cálculo
      const total = listing.price * listing.qty;
      const rate  = commissionRates[listing.type] ?? commissionRates.default;
      const comm  = total * rate;

      // 7) Fondos insuficientes
      if (buyer.moneda < total) {
        return res.status(400).json({ error: 'Fondos insuficientes' });
      }

      // 8) Ajustar balances
      buyer.moneda  -= total;
      seller.moneda += (total - comm);

      // 9) Guardar cambios y borrar listing
      await buyer.save();
      await seller.save();
      await Listing.findByIdAndDelete(listingId);

      // 10) Responder éxito
      return res.json({
        success:       true,
        totalCost:     total,
        commission:    comm,
        netToSeller:   total - comm,
        commissionRate: rate
      });
    } catch (e) {
      console.error('Error en POST /listings/:id/buy →', e);
      return res.status(500).json({ error: 'Error interno del servidor' });
    }
  }
);

app.delete(
  '/listings/:id',
  apiLimiter,
  authenticateJWT,
  // 1) Validamos que :id sea un ObjectId
  param('id').isMongoId(),
  async (req, res) => {
    // 2) Chequeo de errores de validación
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const listingId = req.params.id;
    try {
      // 3) Recuperamos el listing
      const l = await Listing.findById(listingId);
      if (!l) {
        return res.status(404).json({ error: 'Not found' });
      }

      // 4) Revisamos que el propietario coincida
      if (l.owner !== req.user.playerName) {
        return res.status(403).json({ error: 'No autorizado' });
      }

      // 5) Borramos usando findByIdAndDelete
      await Listing.findByIdAndDelete(listingId);

      return res.json({ success: true });
    } catch (e) {
      console.error('DELETE /listings/:id error:', e);
      return res.status(500).json({ error: 'Error interno del servidor' });
    }
  }
);


// 404 handler
app.use((req, res) => res.status(404).json({ error: `Ruta no encontrada: ${req.method} ${req.originalUrl}` }));

// Start server
app.listen(port, '0.0.0.0', () => console.log(`✅ Backend activo en http://0.0.0.0:${port}`));
