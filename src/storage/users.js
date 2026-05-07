const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { usersDir } = require('../config/config');
const { logAudit } = require('../helpers/audit');

/**
 * Get safe filename for email
 */
function emailToFilename(email) {
  return email.toLowerCase().replace(/[^a-z0-9@._-]/g, '_');
}

/**
 * Get user data file path
 */
function getUserPath(email) {
  return path.join(usersDir, `${emailToFilename(email)}.json`);
}

/**
 * Create or get user by email
 */
function getOrCreateUser(email, displayName = null) {
  const emailLower = email.toLowerCase().trim();
  const userPath = getUserPath(emailLower);
  
  if (fs.existsSync(userPath)) {
    try {
      const data = JSON.parse(fs.readFileSync(userPath, 'utf8'));
      return data;
    } catch (e) {
      console.warn('Failed to read user file for', emailLower, e.message);
    }
  }
  
  // Create new user
  const userId = crypto.randomUUID();
  const userData = {
    user_id: userId,
    email: emailLower,
    display_name: displayName || emailLower,
    created_at: new Date().toISOString(),
    last_login: new Date().toISOString(),
    is_active: true
  };
  
  try {
    fs.writeFileSync(userPath, JSON.stringify(userData, null, 2), { encoding: 'utf8', mode: 0o600 });
    console.log('Created user:', emailLower);
    return userData;
  } catch (e) {
    console.error('Failed to create user file:', e.message);
    throw e;
  }
}

/**
 * Get user by email (returns null if not exists)
 */
function getUserByEmail(email) {
  const emailLower = email.toLowerCase().trim();
  const userPath = getUserPath(emailLower);
  
  if (!fs.existsSync(userPath)) {
    return null;
  }
  
  try {
    return JSON.parse(fs.readFileSync(userPath, 'utf8'));
  } catch (e) {
    console.warn('Failed to read user file for', emailLower, e.message);
    return null;
  }
}

/**
 * Update user's last login
 */
function updateLastLogin(email) {
  const user = getUserByEmail(email);
  if (!user) return;
  
  user.last_login = new Date().toISOString();
  const userPath = getUserPath(email);
  
  try {
    fs.writeFileSync(userPath, JSON.stringify(user, null, 2), { encoding: 'utf8', mode: 0o600 });
  } catch (e) {
    console.warn('Failed to update last login:', e.message);
  }
}

module.exports = {
  emailToFilename,
  getUserPath,
  getOrCreateUser,
  getUserByEmail,
  updateLastLogin
};
