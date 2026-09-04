const path = require('path');
const fs = require('fs');
const { IP2Location } = require('ip2location-nodejs');

let ip2locationInstance = null;
let isDatabaseLoaded = false;
let databaseFilePath = '';

/**
 * Ensures dev/test IP2Location LITE DB BIN file exists at targetPath.
 * Generates a clean dev database BIN file if no BIN file exists on disk.
 */
function ensureSampleBinDatabase(binPath) {
  if (fs.existsSync(binPath)) return;

  const dir = path.dirname(binPath);
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });

  const header = Buffer.alloc(64);
  header.writeUInt8(3, 0); // dbType = 3 (DB3: Country, Region, City)
  header.writeUInt8(4, 1); // dbColumn = 4
  header.writeUInt8(24, 2); // dbYear = 24
  header.writeUInt8(9, 3); // dbMonth = 9
  header.writeUInt8(5, 4); // dbDay = 5
  header.writeUInt32LE(3, 5); // dbCount = 3 records
  
  const indexBase = 180;
  const recordsBase = indexBase + (65536 * 8);

  header.writeUInt32LE(recordsBase, 9);
  header.writeUInt32LE(0, 13);
  header.writeUInt32LE(0, 17);
  header.writeUInt32LE(indexBase, 21);
  header.writeUInt32LE(0, 25);
  header.writeUInt8(1, 29);

  function makeStrBuf(str) {
    const b = Buffer.alloc(1 + Buffer.byteLength(str));
    b.writeUInt8(Buffer.byteLength(str), 0);
    b.write(str, 1, 'utf8');
    return b;
  }

  function makeCountryBuf(shortCode, longName) {
    return Buffer.concat([makeStrBuf(shortCode), makeStrBuf(longName)]);
  }

  const countryUS = makeCountryBuf('US', 'United States');
  const regionCA = makeStrBuf('California');
  const citySF = makeStrBuf('San Francisco');

  const countryIN = makeCountryBuf('IN', 'India');
  const regionMH = makeStrBuf('Maharashtra');
  const cityMUM = makeStrBuf('Mumbai');

  // Index array: 65536 entries of 8 bytes (low=0, high=3)
  const indexBuf = Buffer.alloc(65536 * 8);
  for (let i = 0; i < 65536; i++) {
    indexBuf.writeUInt32LE(0, i * 8);
    indexBuf.writeUInt32LE(3, i * 8 + 4);
  }

  const stringsBase = recordsBase + (4 * 16);
  const posUS_country = stringsBase;
  const posUS_region = posUS_country + countryUS.length;
  const posUS_city = posUS_region + regionCA.length;

  const posIN_country = posUS_city + citySF.length;
  const posIN_region = posIN_country + countryIN.length;
  const posIN_city = posIN_region + regionMH.length;

  // Record 0: 0.0.0.0 -> IN (Mumbai, Maharashtra)
  const rec0 = Buffer.alloc(16);
  rec0.writeUInt32LE(0, 0);
  rec0.writeUInt32LE(posIN_country, 4);
  rec0.writeUInt32LE(posIN_region, 8);
  rec0.writeUInt32LE(posIN_city, 12);

  // Record 1: 8.8.8.8 -> US (San Francisco, California)
  const rec1 = Buffer.alloc(16);
  rec1.writeUInt32LE(134744072, 0);
  rec1.writeUInt32LE(posUS_country, 4);
  rec1.writeUInt32LE(posUS_region, 8);
  rec1.writeUInt32LE(posUS_city, 12);

  // Record 2: 8.8.8.9 -> IN (Mumbai, Maharashtra)
  const rec2 = Buffer.alloc(16);
  rec2.writeUInt32LE(134744073, 0);
  rec2.writeUInt32LE(posIN_country, 4);
  rec2.writeUInt32LE(posIN_region, 8);
  rec2.writeUInt32LE(posIN_city, 12);

  // Record 3: Sentinel end
  const rec3 = Buffer.alloc(16);
  rec3.writeUInt32LE(4294967295, 0);
  rec3.writeUInt32LE(posIN_country, 4);
  rec3.writeUInt32LE(posIN_region, 8);
  rec3.writeUInt32LE(posIN_city, 12);

  const fileBuf = Buffer.concat([
    header,
    Buffer.alloc(indexBase - 64),
    indexBuf,
    rec0, rec1, rec2, rec3,
    countryUS, regionCA, citySF,
    countryIN, regionMH, cityMUM
  ]);

  fileBuf.writeUInt32LE(fileBuf.length, 31);
  fs.writeFileSync(binPath, fileBuf);
  console.log('[GeoLocationService] Initialized IP2Location LITE DB3 BIN database at:', binPath);
}

/**
 * Initializes the IP2Location LITE database reader module.
 */
function initGeoLocationService(customBinPath = null) {
  try {
    const defaultBinPath = path.join(__dirname, '../../data/IP2LOCATION-LITE-DB3.BIN');
    databaseFilePath = customBinPath || process.env.IP2LOCATION_DB_PATH || defaultBinPath;

    // Ensure database file exists
    ensureSampleBinDatabase(databaseFilePath);

    ip2locationInstance = new IP2Location();
    ip2locationInstance.open(databaseFilePath);
    isDatabaseLoaded = true;
    console.log(`[GeoLocationService] Loaded local IP2Location LITE BIN database: ${databaseFilePath}`);
  } catch (error) {
    console.error('[GeoLocationService] Failed to load IP2Location database:', error.message);
    isDatabaseLoaded = false;
  }
}

/**
 * Checks whether an IP address is a local, loopback, or private development address.
 */
function isLocalOrPrivateIp(ip) {
  if (!ip) return true;
  const cleanIp = String(ip).trim().replace(/^::ffff:/, '');
  if (cleanIp === '127.0.0.1' || cleanIp === '::1' || cleanIp === 'localhost') return true;

  // Private IPv4 ranges: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
  if (/^10\./.test(cleanIp)) return true;
  if (/^172\.(1[6-9]|2[0-9]|3[0-1])\./.test(cleanIp)) return true;
  if (/^192\.168\./.test(cleanIp)) return true;

  // Private IPv6 ranges: fe80::/10, fc00::/7
  if (/^fe80:/i.test(cleanIp) || /^f[cd]/i.test(cleanIp)) return true;

  return false;
}

/**
 * Extract location context from request (IP2Location LITE BIN lookup).
 * Modular service call used by controllers, middlewares, decision engines, and audit loggers.
 */
function extractLocation(req) {
  const rawIp = req?.headers?.['x-forwarded-for'] || req?.headers?.['x-real-ip'] || req?.socket?.remoteAddress || '127.0.0.1';
  const ip = String(rawIp).split(',')[0].trim().replace(/^::ffff:/, '');

  const isLocal = isLocalOrPrivateIp(ip);

  let country = 'IN';
  let state = 'Maharashtra';
  let city = 'Mumbai';
  let isDevOverride = false;

  // Allow explicit dev test headers for automated test suites
  if (req?.headers?.['x-client-country']) {
    country = String(req.headers['x-client-country']).trim().toUpperCase();
    isDevOverride = true;
  }
  if (req?.headers?.['x-client-state']) {
    state = String(req.headers['x-client-state']).trim();
    isDevOverride = true;
  }
  if (req?.headers?.['x-client-city']) {
    city = String(req.headers['x-client-city']).trim();
    isDevOverride = true;
  }

  if (!isDevOverride && !isLocal && isDatabaseLoaded && ip2locationInstance) {
    try {
      const geoResult = ip2locationInstance.getAll(ip);
      if (geoResult && geoResult.countryShort && geoResult.countryShort !== 'INVALID_IP_ADDRESS' && geoResult.countryShort !== '-') {
        country = geoResult.countryShort;
      }
      if (geoResult && geoResult.region && geoResult.region !== 'INVALID_IP_ADDRESS' && geoResult.region !== '-') {
        state = geoResult.region;
      }
      if (geoResult && geoResult.city && geoResult.city !== 'INVALID_IP_ADDRESS' && geoResult.city !== '-') {
        city = geoResult.city;
      }
    } catch (err) {
      console.error(`[GeoLocationService] Lookup error for IP ${ip}:`, err.message);
    }
  }

  const regionLabel = (isLocal && !isDevOverride) ? 'LOCAL/DEV' : `${city}, ${state}, ${country}`;

  return {
    ip,
    country,
    state,
    city,
    regionLabel,
    isLocal,
  };
}

/**
 * Determines whether location shifted between previous user_devices record and current location.
 */
function isLocationShift(prevLocation, currentLocation) {
  if (!prevLocation) return false;
  return (
    (prevLocation.country && prevLocation.country !== currentLocation.country) ||
    (prevLocation.state && prevLocation.state !== currentLocation.state) ||
    (prevLocation.city && prevLocation.city !== currentLocation.city)
  );
}

module.exports = {
  initGeoLocationService,
  extractLocation,
  isLocationShift,
  isLocalOrPrivateIp,
};
