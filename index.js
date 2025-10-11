// Import các thư viện cần thiết
const express = require('express');
const { google } = require('googleapis');
require('dotenv').config(); // Tải các biến môi trường từ file .env

// Lấy thông tin credentials từ biến môi trường (an toàn hơn hard-code)
const { GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET, REDIRECT_URI, SHEET_ID } = process.env;

// Khởi tạo ứng dụng web bằng Express
const app = express();
const PORT = process.env.PORT || 3000;

// Tạo một "cache" đơn giản trong bộ nhớ để lưu mapping state -> userId
// LƯU Ý: Cache này sẽ bị xóa mỗi khi server khởi động lại. 
// Với ứng dụng thực tế, bạn nên dùng một giải pháp bền vững hơn như Redis.
const stateCache = new Map();

/**
 * Hàm trợ giúp để tạo một đối tượng OAuth2 client đã được cấu hình.
 */
function createOAuth2Client() {
  return new google.auth.OAuth2(
    GOOGLE_CLIENT_ID,
    GOOGLE_CLIENT_SECRET,
    REDIRECT_URI // Đây là URL callback trên chính server này
  );
}

// === ROUTE 1: Bắt đầu luồng xác thực (tương đương startAuthFlow) ===
app.get('/auth', (req, res) => {
  const userId = req.query.user || 'unknown_user';

  const oauth2Client = createOAuth2Client();

  // Tạo một state token ngẫu nhiên và an toàn
  const state = require('crypto').randomBytes(16).toString('hex');
  
  // Lưu mapping state -> userId vào cache, tồn tại trong 5 phút
  stateCache.set(state, { userId, timestamp: Date.now() });
  console.log(`[AUTH] State created for user '${userId}': ${state}`);

  const authUrl = oauth2Client.generateAuthUrl({
    access_type: 'offline', // Để nhận refresh_token
    prompt: 'consent',      // Luôn hiển thị màn hình đồng ý
    scope: ['https://www.googleapis.com/auth/adwords', 'https://www.googleapis.com/auth/spreadsheets'], // Thêm scope cho Google Sheets
    state: state // Gắn state vào URL
  });

  res.json({ auth_url: authUrl, state: state });
});


// === ROUTE 2: Xử lý callback từ Google (tương đương authCallback) ===
app.get('/callback', async (req, res) => {
  const { code, state } = req.query;

  // Kiểm tra state token
  const cachedData = stateCache.get(state);
  console.log(`[CALLBACK] Received state: ${state}`);

  if (!cachedData || Date.now() - cachedData.timestamp > 300000) { // Hết hạn sau 5 phút
    return res.status(400).send('⚠️ Invalid or expired state token. Please try again.');
  }
  
  const { userId } = cachedData;
  stateCache.delete(state); // Xóa state sau khi dùng để tránh tấn công

  try {
    const oauth2Client = createOAuth2Client();
    
    // Dùng 'code' để đổi lấy tokens
    const { tokens } = await oauth2Client.getToken(code);
    const refreshToken = tokens.refresh_token;
    const accessToken = tokens.access_token;
    
    console.log(`[CALLBACK] Tokens received for user '${userId}'.`);
    
    // Lưu token vào Google Sheet
    await saveTokenToSheet(userId, refreshToken, accessToken);

    res.send(`✅ Authorized for user: ${userId}. You can close this window.`);

  } catch (error) {
    console.error('Error during token exchange:', error);
    res.status(500).send('Error during authentication: ' + error.message);
  }
});

/**
 * Hàm lưu token vào Google Sheet bằng Google Sheets API.
 */
async function saveTokenToSheet(userId, refreshToken, accessToken) {
    const sheets = google.sheets({ version: 'v4' });
    
    // Để gọi API Sheets, chúng ta cần một client đã được xác thực.
    // Vì ta vừa nhận token, ta có thể tạo một client mới để dùng ngay.
    const authClient = createOAuth2Client();
    authClient.setCredentials({ refresh_token: refreshToken, access_token: accessToken });

    await sheets.spreadsheets.values.append({
        auth: authClient,
        spreadsheetId: SHEET_ID,
        range: 'Tokens!A1',
        valueInputOption: 'USER_ENTERED',
        resource: {
            values: [[new Date().toISOString(), userId, refreshToken, accessToken]],
        },
    });
    console.log(`[SHEETS] Successfully saved tokens for user '${userId}'.`);
}


// Khởi động server
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
