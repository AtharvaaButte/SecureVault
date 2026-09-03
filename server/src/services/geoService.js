/**
 * GeoContextual Location Service (Cycle 10.3)
 * Provides clean extraction and resolution of geographic location context (Country, State, City) from request headers / IP.
 */

function extractLocation(req) {
  const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress || '127.0.0.1';

  const country = req.headers['x-client-country']
    ? String(req.headers['x-client-country']).trim().toUpperCase()
    : 'IN';

  const state = req.headers['x-client-state']
    ? String(req.headers['x-client-state']).trim()
    : 'Maharashtra';

  const city = req.headers['x-client-city']
    ? String(req.headers['x-client-city']).trim()
    : 'Mumbai';

  const isLocal = !ip || ip === '127.0.0.1' || ip === '::1' || ip === '::ffff:127.0.0.1' || ip.startsWith('10.') || ip.startsWith('192.168.');
  const regionLabel = isLocal ? 'LOCAL/DEV' : `${city}, ${state}, ${country}`;

  return {
    ip,
    country,
    state,
    city,
    regionLabel,
    isLocal,
  };
}

function isLocationShift(prevLocation, currentLocation) {
  if (!prevLocation) return false;
  return (
    (prevLocation.country && prevLocation.country !== currentLocation.country) ||
    (prevLocation.state && prevLocation.state !== currentLocation.state) ||
    (prevLocation.city && prevLocation.city !== currentLocation.city)
  );
}

module.exports = {
  extractLocation,
  isLocationShift,
};
