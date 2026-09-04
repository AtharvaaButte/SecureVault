/**
 * GeoContextual Location Service (Phase 10.3 / IP2Location LITE Integration)
 * Delegates to dedicated geoLocationService.js for IP2Location LITE BIN database lookups.
 */

const geoLocationService = require('./geoLocationService');

module.exports = {
  extractLocation: geoLocationService.extractLocation,
  isLocationShift: geoLocationService.isLocationShift,
  initGeoLocationService: geoLocationService.initGeoLocationService,
  isLocalOrPrivateIp: geoLocationService.isLocalOrPrivateIp,
};
