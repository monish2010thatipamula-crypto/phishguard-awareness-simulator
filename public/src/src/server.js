// 1. IMPORT BOTH (Make sure these are at the top of server.js)
const { analyzeLink } = require('./src/url-analyzer'); // Your existing function
const { getLinkCreatorInfo } = require('./src/ip-finder'); // The new intelligence function

// ... (Your existing routes like /login, /dashboard, etc.)

// 2. YOUR EXISTING ROUTE (Keep this as it is)
app.get('/api/link-info', async (req, res) => {
  const link = req.query.link;
  if (!link) {
    return res.status(400).json({ error: 'Link parameter required' });
  }
  
  try {
    // This calls your original phishing/threat analysis
    const result = await analyzeLink(link);
    res.json(result);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// 3. THE NEW INTELLIGENCE ROUTE (Add this below your old one)
// This is the "Deep Analysis" route for IP, Location, etc.
app.get('/api/analyze-creator', async (req, res) => {
  const { link } = req.query;

  if (!link) {
    return res.status(400).json({ error: 'No link provided' });
  }
  
  try {
    // This calls the NEW intelligence engine
    const intelligence = await getLinkCreatorInfo(link);
    
    res.json({
      success: true,
      data: intelligence
    });
  } catch (error) {
    console.error('Intelligence API Error:', error);
    res.status(500).json({ 
        success: false, 
        error: 'Internal Server Error during intelligence gathering' 
    });
  }
});