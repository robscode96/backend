"""
RouteLog Backend — Phase 2
Flask + PostgreSQL + Magic Link Auth
"""

import os
import secrets
import hashlib
from datetime import datetime, timezone, timedelta
from functools import wraps

from flask import Flask, jsonify, request, session
import psycopg2
from psycopg2.extras import RealDictCursor
import json
import requests

app = Flask(__name__)
app.secret_key = os.environ['SECRET_KEY']

app.config.update(
    SESSION_COOKIE_SAMESITE='None',
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_HTTPONLY=True,
)

DATABASE_URL = os.environ['DATABASE_URL']
RESEND_API_KEY = os.environ['RESEND_API_KEY']
FROM_EMAIL = os.environ.get('FROM_EMAIL', 'onboarding@resend.dev')
FRONTEND_URL = os.environ.get('FRONTEND_URL', 'https://robscode96.github.io/routelog')

_allowed_origins = [
    o.strip()
    for o in os.environ.get('ALLOWED_ORIGINS', 'https://robscode96.github.io').split(',')
    if o.strip()
]


@app.after_request
def add_cors_headers(response):
    origin = request.headers.get('Origin', '')
    if origin in _allowed_origins:
        response.headers['Access-Control-Allow-Origin'] = origin
        response.headers['Access-Control-Allow-Credentials'] = 'true'
        response.headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization'
        response.headers['Access-Control-Allow-Methods'] = 'GET, POST, PUT, DELETE, OPTIONS'
    return response


@app.before_request
def handle_options():
    if request.method == 'OPTIONS':
        response = app.make_default_options_response()
        add_cors_headers(response)
        return response


# ===================== DATABASE =====================

def get_db():
    conn = psycopg2.connect(DATABASE_URL, cursor_factory=RealDictCursor)
    return conn


def init_db():
    conn = get_db()
    cur = conn.cursor()
    cur.execute("""
        CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

        CREATE TABLE IF NOT EXISTS users (
            id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
            email TEXT UNIQUE NOT NULL,
            display_name TEXT,
            created_at TIMESTAMPTZ DEFAULT NOW()
        );

        CREATE TABLE IF NOT EXISTS magic_links (
            id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
            user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            token TEXT UNIQUE NOT NULL,
            expires_at TIMESTAMPTZ NOT NULL,
            used BOOLEAN DEFAULT FALSE,
            created_at TIMESTAMPTZ DEFAULT NOW()
        );

        CREATE TABLE IF NOT EXISTS routes (
            id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
            user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            date DATE NOT NULL,
            earnings DECIMAL(8,2) NOT NULL,
            miles DECIMAL(7,1),
            start_time TIME,
            end_time TIME,
            type TEXT NOT NULL DEFAULT 'Flex',
            notes TEXT,
            created_at TIMESTAMPTZ DEFAULT NOW(),
            updated_at TIMESTAMPTZ DEFAULT NOW()
        );

        CREATE TABLE IF NOT EXISTS settings (
            user_id UUID PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
            weekly_goal DECIMAL(8,2) DEFAULT 800,
            monthly_goal DECIMAL(8,2) DEFAULT 3200,
            mileage_rate DECIMAL(4,2) DEFAULT 70,
            fed_bracket DECIMAL(4,2) DEFAULT 22,
            state_rate DECIMAL(4,2) DEFAULT 4.25,
            route_types JSONB DEFAULT '["Flex","DSP","DoorDash","Instacart","Other"]',
            updated_at TIMESTAMPTZ DEFAULT NOW()
        );
    """)
    conn.commit()
    cur.close()
    conn.close()


# ===================== AUTH =====================

def require_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            uid = request.args.get('uid')
            if uid:
                conn = get_db()
                cur = conn.cursor()
                cur.execute("SELECT id FROM users WHERE id = %s", (uid,))
                user = cur.fetchone()
                cur.close()
                conn.close()
                if user:
                    session['user_id'] = str(user['id'])
                else:
                    return jsonify({'error': 'Unauthorized'}), 401
            else:
                return jsonify({'error': 'Unauthorized'}), 401
        return f(*args, **kwargs)
    return decorated


@app.route('/api/auth/request-link', methods=['POST'])
def request_magic_link():
    data = request.get_json()
    email = data.get('email', '').strip().lower()
    if not email or '@' not in email:
        return jsonify({'error': 'Valid email required'}), 400

    conn = get_db()
    cur = conn.cursor()

    # Create user if they don't exist
    cur.execute("""
        INSERT INTO users (email, display_name)
        VALUES (%s, %s)
        ON CONFLICT (email) DO UPDATE SET email = EXCLUDED.email
        RETURNING id, email, display_name
    """, (email, email.split('@')[0]))
    user = cur.fetchone()

    # Create default settings if first time
    cur.execute("""
        INSERT INTO settings (user_id)
        VALUES (%s)
        ON CONFLICT (user_id) DO NOTHING
    """, (str(user['id']),))

    # Generate magic link token
    token = secrets.token_urlsafe(32)
    expires_at = datetime.now(timezone.utc) + timedelta(minutes=15)

    cur.execute("""
        INSERT INTO magic_links (user_id, token, expires_at)
        VALUES (%s, %s, %s)
    """, (str(user['id']), token, expires_at))

    conn.commit()
    cur.close()
    conn.close()

    # Send email via Resend
    magic_url = f"{FRONTEND_URL}?token={token}"
    
    resp = requests.post(
        'https://api.resend.com/emails',
        headers={
            'Authorization': f'Bearer {RESEND_API_KEY}',
            'Content-Type': 'application/json',
        },
        json={
            'from': FROM_EMAIL,
            'to': email,
            'subject': 'Sign in to RouteLog',
            'html': f'''
                <div style="font-family:sans-serif;max-width:400px;margin:0 auto;padding:40px 20px;">
                    <h2 style="color:#00e5a0;font-family:monospace;">RouteLog</h2>
                    <p>Tap the button below to sign in. This link expires in 15 minutes.</p>
                    <a href="{magic_url}" style="display:inline-block;background:#00e5a0;color:#0d0f14;padding:14px 28px;border-radius:8px;text-decoration:none;font-weight:bold;margin:16px 0;">
                        Sign in to RouteLog
                    </a>
                    <p style="color:#888;font-size:13px;">If you didn't request this, ignore this email.</p>
                </div>
            '''
        }
    )

    if resp.status_code not in (200, 201):
        return jsonify({'error': 'Failed to send email'}), 500

    return jsonify({'ok': True})


@app.route('/api/auth/verify-token', methods=['POST'])
def verify_magic_token():
    data = request.get_json()
    token = data.get('token', '').strip()
    if not token:
        return jsonify({'error': 'Token required'}), 400

    conn = get_db()
    cur = conn.cursor()

    cur.execute("""
        SELECT ml.id, ml.user_id, ml.expires_at, ml.used,
               u.email, u.display_name
        FROM magic_links ml
        JOIN users u ON u.id = ml.user_id
        WHERE ml.token = %s
    """, (token,))
    link = cur.fetchone()

    if not link:
        cur.close()
        conn.close()
        return jsonify({'error': 'Invalid link'}), 401

    if link['used']:
        cur.close()
        conn.close()
        return jsonify({'error': 'Link already used'}), 401

    if link['expires_at'] < datetime.now(timezone.utc):
        cur.close()
        conn.close()
        return jsonify({'error': 'Link expired'}), 401

    # Mark token as used
    cur.execute("UPDATE magic_links SET used = TRUE WHERE id = %s", (str(link['id']),))
    conn.commit()
    cur.close()
    conn.close()

    session['user_id'] = str(link['user_id'])
    session.permanent = True

    return jsonify({
        'user': {
            'id': str(link['user_id']),
            'email': link['email'],
            'display_name': link['display_name'] or link['email'],
        }
    })


@app.route('/api/auth/logout', methods=['POST'])
def logout():
    session.clear()
    return jsonify({'ok': True})


@app.route('/api/auth/me', methods=['GET'])
@require_auth
def me():
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT id, email, display_name FROM users WHERE id = %s", (session['user_id'],))
    user = cur.fetchone()
    cur.close()
    conn.close()
    if not user:
        session.clear()
        return jsonify({'error': 'User not found'}), 404
    return jsonify({'user': {
        'id': str(user['id']),
        'email': user['email'],
        'display_name': user['display_name'] or user['email'],
    }})


# ===================== ROUTES =====================

@app.route('/api/routes', methods=['GET'])
@require_auth
def get_routes():
    conn = get_db()
    cur = conn.cursor()
    cur.execute("""
        SELECT id, date, earnings, miles, start_time, end_time, type, notes
        FROM routes WHERE user_id = %s
        ORDER BY date DESC, created_at DESC
    """, (session['user_id'],))
    rows = cur.fetchall()
    cur.close()
    conn.close()
    routes = []
    for r in rows:
        routes.append({
            'id': str(r['id']),
            'date': r['date'].isoformat(),
            'earnings': float(r['earnings']),
            'miles': float(r['miles']) if r['miles'] is not None else 0,
            'startTime': str(r['start_time'])[:5] if r['start_time'] else '',
            'endTime': str(r['end_time'])[:5] if r['end_time'] else '',
            'type': r['type'],
            'notes': r['notes'] or '',
        })
    return jsonify(routes)


@app.route('/api/routes', methods=['POST'])
@require_auth
def create_route():
    data = request.get_json()
    earnings = data.get('earnings')
    if not earnings or float(earnings) <= 0:
        return jsonify({'error': 'earnings must be > 0'}), 400
    conn = get_db()
    cur = conn.cursor()
    cur.execute("""
        INSERT INTO routes (user_id, date, earnings, miles, start_time, end_time, type, notes)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s) RETURNING id
    """, (
        session['user_id'], data.get('date'), float(earnings),
        float(data['miles']) if data.get('miles') else None,
        data.get('startTime') or None, data.get('endTime') or None,
        data.get('type', 'Flex'), data.get('notes') or None,
    ))
    new_id = cur.fetchone()['id']
    conn.commit()
    cur.close()
    conn.close()
    return jsonify({'id': str(new_id)}), 201


@app.route('/api/routes/<route_id>', methods=['PUT'])
@require_auth
def update_route(route_id):
    data = request.get_json()
    conn = get_db()
    cur = conn.cursor()
    cur.execute("""
        UPDATE routes SET date=%s, earnings=%s, miles=%s, start_time=%s,
        end_time=%s, type=%s, notes=%s, updated_at=NOW()
        WHERE id=%s AND user_id=%s RETURNING id
    """, (
        data.get('date'), float(data.get('earnings', 0)),
        float(data['miles']) if data.get('miles') else None,
        data.get('startTime') or None, data.get('endTime') or None,
        data.get('type', 'Flex'), data.get('notes') or None,
        route_id, session['user_id'],
    ))
    updated = cur.fetchone()
    conn.commit()
    cur.close()
    conn.close()
    if not updated:
        return jsonify({'error': 'Route not found'}), 404
    return jsonify({'ok': True})


@app.route('/api/routes/<route_id>', methods=['DELETE'])
@require_auth
def delete_route(route_id):
    conn = get_db()
    cur = conn.cursor()
    cur.execute("DELETE FROM routes WHERE id=%s AND user_id=%s RETURNING id",
                (route_id, session['user_id']))
    deleted = cur.fetchone()
    conn.commit()
    cur.close()
    conn.close()
    if not deleted:
        return jsonify({'error': 'Route not found'}), 404
    return jsonify({'ok': True})


# ===================== SETTINGS =====================

@app.route('/api/settings', methods=['GET'])
@require_auth
def get_settings():
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT * FROM settings WHERE user_id = %s", (session['user_id'],))
    row = cur.fetchone()
    cur.close()
    conn.close()
    if not row:
        return jsonify({'error': 'Settings not found'}), 404
    return jsonify({
        'weeklyGoal': float(row['weekly_goal']),
        'monthlyGoal': float(row['monthly_goal']),
        'mileageRate': float(row['mileage_rate']),
        'fedBracket': float(row['fed_bracket']),
        'stateRate': float(row['state_rate']),
        'routeTypes': row['route_types'],
    })


@app.route('/api/settings', methods=['PUT'])
@require_auth
def update_settings():
    data = request.get_json()
    conn = get_db()
    cur = conn.cursor()
    cur.execute("""
        UPDATE settings SET weekly_goal=%s, monthly_goal=%s, mileage_rate=%s,
        fed_bracket=%s, state_rate=%s, route_types=%s, updated_at=NOW()
        WHERE user_id=%s
    """, (
        data.get('weeklyGoal', 800), data.get('monthlyGoal', 3200),
        data.get('mileageRate', 70), data.get('fedBracket', 22),
        data.get('stateRate', 4.25),
        json.dumps(data.get('routeTypes', ['Flex', 'DSP', 'DoorDash', 'Instacart', 'Other'])),
        session['user_id'],
    ))
    conn.commit()
    cur.close()
    conn.close()
    return jsonify({'ok': True})


# ===================== IMPORT =====================

@app.route('/api/import', methods=['POST'])
@require_auth
def import_routes():
    data = request.get_json()
    routes = data.get('routes', [])
    settings = data.get('settings')
    conn = get_db()
    cur = conn.cursor()
    imported = 0
    for r in routes:
        try:
            cur.execute("""
                INSERT INTO routes (user_id, date, earnings, miles, start_time, end_time, type, notes)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
            """, (
                session['user_id'], r.get('date'), float(r.get('earnings', 0)),
                float(r['miles']) if r.get('miles') else None,
                r.get('startTime') or None, r.get('endTime') or None,
                r.get('type', 'Flex'), r.get('notes') or None,
            ))
            imported += 1
        except Exception:
            continue
    if settings:
        cur.execute("""
            UPDATE settings SET weekly_goal=%s, monthly_goal=%s, mileage_rate=%s,
            fed_bracket=%s, state_rate=%s, route_types=%s, updated_at=NOW()
            WHERE user_id=%s
        """, (
            settings.get('weeklyGoal', 800), settings.get('monthlyGoal', 3200),
            settings.get('mileageRate', 70), settings.get('fedBracket', 22),
            settings.get('stateRate', 4.25),
            json.dumps(settings.get('routeTypes', ['Flex', 'DSP', 'DoorDash', 'Instacart', 'Other'])),
            session['user_id'],
        ))
    conn.commit()
    cur.close()
    conn.close()
    return jsonify({'imported': imported})


# ===================== HEALTH =====================

@app.route('/api/health', methods=['GET'])
def health():
    return jsonify({'status': 'ok', 'version': '2.1.0'})


# ===================== STARTUP =====================

if __name__ == '__main__':
    init_db()
    app.run(host='0.0.0.0', port=5000, debug=os.environ.get('FLASK_DEBUG', 'false') == 'true')
