# RefLink Secure - WhatsApp Referral Tracking Tool

A **production-ready, security-hardened** referral tracking system for WhatsApp groups.

## Security Features

### Authentication & Authorization
- **bcrypt password hashing** (12 rounds)
- **JWT tokens** with database-backed sessions
- **Account lockout** after 5 failed login attempts (15-minute lock)
- **Session management** - view/revoke active sessions
- **Password requirements** - 12+ chars, mixed case, numbers, symbols
- **Logout all sessions** functionality

### Rate Limiting
- Global API rate limiting (100 req/15min)
- Strict auth endpoint limiting (5 req/15min)
- Code generation limits (10/hour per IP, 20/day per IP)
- Referral logging limits (10/hour per referrer code)
- Minimum 1-minute gap between referrals for same code

### Anti-Manipulation
- **All validation is server-side** - DevTools manipulation won't work
- Suspicious activity auto-flagging (50+ referrals/day)
- Banned code patterns (ADMIN, ROOT, SQL keywords)
- IP and user-agent tracking
- Complete audit logging

### Data Security
- HttpOnly, Secure, SameSite cookies
- CSRF protection via origin validation
- Helmet.js security headers (CSP, HSTS, X-Frame-Options, etc.)
- Input sanitization and validation
- SQL injection prevention (parameterized queries)
- XSS prevention

### Audit Trail
- All admin actions logged
- Login attempts (success/failure) logged
- Referral creation/deletion logged
- Password changes logged
- 90-day log retention

## Installation

```bash
# Clone the repository
git clone <your-repo>
cd reflink-secure

# Install dependencies
npm install

# Create environment file
cp .env.example .env

# Edit .env with secure values (see below)
nano .env

# Start server
npm start
```

## Configuration

**⚠️ CRITICAL: Change ALL default values before deployment**

Generate secure secrets:
```bash
# Generate JWT secrets (run twice for both secrets)
openssl rand -hex 32
```

Edit `.env`:
```env
NODE_ENV=production
PORT=3000
WHATSAPP_NUMBER=2349049845763

# CHANGE THESE!
ADMIN_USERNAME=yourusername
ADMIN_PASSWORD=YourSecureP@ssw0rd!
JWT_SECRET=<64-char-random-string>
JWT_REFRESH_SECRET=<different-64-char-random-string>
```

### Password Requirements
- Minimum 12 characters
- At least 1 uppercase letter
- At least 1 lowercase letter
- At least 1 number
- At least 1 special character (!@#$%^&*(),.?":{}|<>)

## Deployment

### Production Checklist

1. ☐ Set `NODE_ENV=production`
2. ☐ Use strong, unique `ADMIN_PASSWORD`
3. ☐ Generate random `JWT_SECRET` and `JWT_REFRESH_SECRET`
4. ☐ Set up HTTPS (SSL/TLS)
5. ☐ Configure reverse proxy (nginx/Caddy)
6. ☐ Set up firewall rules
7. ☐ Enable automatic backups for `reflink.db`

### Nginx Example

```nginx
server {
    listen 443 ssl http2;
    server_name yourdomain.com;
    
    ssl_certificate /path/to/cert.pem;
    ssl_certificate_key /path/to/key.pem;
    
    # Security headers (additional to app headers)
    add_header X-Frame-Options "DENY" always;
    add_header X-Content-Type-Options "nosniff" always;
    
    # Rate limiting
    limit_req_zone $binary_remote_addr zone=api:10m rate=10r/s;
    
    location / {
        proxy_pass http://127.0.0.1:3000;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        
        limit_req zone=api burst=20 nodelay;
    }
}
```

### Railway/Render

1. Connect GitHub repository
2. Set environment variables in dashboard
3. Deploy

### PM2 (VPS)

```bash
npm install -g pm2
pm2 start server.js --name reflink
pm2 save
pm2 startup
```

## API Reference

### Public Endpoints

| Method | Path | Description | Rate Limit |
|--------|------|-------------|------------|
| GET | `/api/config` | Get public config | Global |
| POST | `/api/referrers` | Generate referral code | 10/hr/IP |
| GET | `/api/leaderboard` | Top 20 referrers | Global |

### Admin Endpoints (auth required)

| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/admin/login` | Admin login |
| POST | `/api/admin/logout` | Logout current session |
| POST | `/api/admin/logout-all` | Logout all sessions |
| GET | `/api/admin/me` | Check auth status |
| POST | `/api/admin/change-password` | Change password |
| GET | `/api/admin/stats` | Dashboard statistics |
| GET | `/api/admin/referrers` | List all referrers |
| POST | `/api/admin/referrals` | Log new referral |
| DELETE | `/api/admin/referrals/:id` | Delete referral |
| PATCH | `/api/admin/referrers/:code/flag` | Flag/unflag referrer |
| DELETE | `/api/admin/referrers/:code` | Delete referrer |
| GET | `/api/admin/export/csv` | Export data |
| GET | `/api/admin/audit-log` | View audit log (superadmin) |
| GET | `/api/admin/sessions` | View active sessions |
| DELETE | `/api/admin/sessions/:id` | Revoke session |

## Database

SQLite with WAL mode for performance. File: `reflink.db`

### Tables
- `admins` - Admin users with roles
- `referrers` - Referral codes with tracking
- `referrals` - Individual referral records
- `sessions` - Active login sessions
- `audit_log` - Security audit trail
- `rate_limits` - Rate limiting tracking

### Backup

```bash
# Backup database
sqlite3 reflink.db ".backup backup.db"

# Or just copy (while app is stopped)
cp reflink.db backup.db
```

## Troubleshooting

### "Account locked"
Wait 15 minutes or manually unlock in database:
```sql
UPDATE admins SET locked_until = NULL, failed_login_attempts = 0 WHERE username = 'admin';
```

### "Too many requests"
Rate limiting active. Wait or adjust limits in server.js.

### "Session expired"
Re-login. Sessions expire after 8 hours by default.

### Reset admin password
```bash
node -e "
const bcrypt = require('bcryptjs');
const Database = require('better-sqlite3');
const db = new Database('./reflink.db');
const hash = bcrypt.hashSync('NewPassword123!@#', 12);
db.prepare('UPDATE admins SET password_hash = ? WHERE username = ?').run(hash, 'admin');
console.log('Password reset!');
"
```

## Security Recommendations

1. **Use HTTPS** - Always run behind TLS in production
2. **Regular updates** - Keep dependencies updated (`npm audit fix`)
3. **Monitor audit logs** - Check for suspicious activity
4. **Backup database** - Regular automated backups
5. **Restrict access** - Use firewall to limit direct server access
6. **Rotate secrets** - Periodically change JWT secrets (invalidates all sessions)

## License

MIT
