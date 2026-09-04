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
    if (!decoded || !decoded.userId || !decoded.orgId) {
      return res.status(401).json({ message: 'Invalid or incomplete identity token context.' });
    }

    // Server-side Identity Enforcement: Store verified claims strictly in req.user
    req.user = {
      userId: String(decoded.userId),
      orgId: String(decoded.orgId),
      email: String(decoded.email || ''),
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
