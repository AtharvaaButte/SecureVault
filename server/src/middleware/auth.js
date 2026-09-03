const jwt = require('jsonwebtoken');

function verifyToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  if (!authHeader) {
    return res.status(401).json({ message: 'Authentication required. No token provided.' });
  }

  const tokenParts = authHeader.split(' ');
  if (tokenParts.length !== 2 || tokenParts[0] !== 'Bearer') {
    return res.status(401).json({ message: 'Invalid Authorization header format. Expected "Bearer <token>"' });
  }

  const token = tokenParts[1];
  const secret = process.env.JWT_SECRET;

  if (!secret) {
    console.error('[Auth Middleware] JWT_SECRET is not configured.');
    return res.status(500).json({ message: 'Internal server configuration error.' });
  }

  try {
    const decoded = jwt.verify(token, secret);

    // Fail closed: Ensure required identity fields exist in verified token
    if (!decoded || !decoded.userId || !decoded.orgId || !decoded.role) {
      return res.status(401).json({ message: 'Invalid or incomplete identity token context.' });
    }

    // Basic Device/Session Context Check (Phase 9A)
    const clientDeviceId = req.headers['x-client-device-id'];
    if (clientDeviceId && decoded.deviceId && clientDeviceId !== decoded.deviceId) {
      return res.status(401).json({ message: 'Device context mismatch. Authentication token is invalid for this device.' });
    }

    // Server-side Identity Enforcement: Store verified claims strictly in req.user
    req.user = {
      userId: String(decoded.userId),
      orgId: String(decoded.orgId),
      email: String(decoded.email || ''),
      role: String(decoded.role),
      deviceId: decoded.deviceId ? String(decoded.deviceId) : null,
    };

    // Fail-safe: Prevent client-side body tampering from overriding verified server-side identity
    if (req.body && typeof req.body === 'object') {
      delete req.body.userId;
      delete req.body.ownerId;
      delete req.body.orgId;
      delete req.body.organizationId;
    }

    next();
  } catch (error) {
    return res.status(401).json({ message: 'Invalid or expired token.' });
  }
}

module.exports = {
  verifyToken,
};
