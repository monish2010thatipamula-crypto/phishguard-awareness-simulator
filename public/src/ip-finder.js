const axios = require('axios');
const dns = require('dns').promises; // Use Node's built-in DNS module

async function getLinkCreatorInfo(link) {
  try {
    // 1. Parse the URL to get the hostname (e.g., 'malicious-site.com')
    const urlParts = new URL(link);
    let hostname = urlParts.hostname;
    
    let ip;

    // 2. Check if the hostname is already an IP address
    const ipRegex = /^(\d{1,3}\.){3}\d{1,3}$/;
    if (ipRegex.test(hostname)) {
      ip = hostname;
    } else {
      // 3. If it's a domain, perform a real DNS lookup to find the IP
      // This replaces the 'example.com' placeholder you had
      const lookup = await dns.lookup(hostname);
      ip = lookup.address;
    }

    // 4. Get Geolocation data based on the resolved IP
    const locationData = await getLocationFromIP(ip);

    return {
      ip: ip,
      location: locationData,
      battery: "Requires Client-side interaction", // Explained below
      device: "Detected via User-Agent",
      timestamp: new Date().toISOString()
    };

  } catch (error) {
    console.error('Error in getLinkCreatorInfo:', error.message);
    return { error: 'Failed to resolve link creator information' };
  }
}

async function getLocationFromIP(ip) {
  try {
    // Using ipapi.co for real-time geolocation
    const response = await axios.get(`https://ipapi.co/${ip}/json/`);
    return {
      city: response.data.city || 'Unknown',
      country: response.data.country_name || 'Unknown',
      region: response.data.region || 'Unknown',
      latitude: response.data.latitude || 0,
      longitude: response.data.longitude || 0
    };
  } catch (error) {
    console.error('Geolocation Error:', error.message);
    return { error: 'Location lookup failed' };
  }
}

module.exports = { getLinkCreatorInfo };