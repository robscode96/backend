"""
RouteLog Backend — Phase 2
Flask + PostgreSQL + Email/Password Auth
"""

import os
import hashlib
import secrets
from functools import wraps

from flask import Flask, jsonify, request, session
import psycopg2
from psycopg2.extras import RealDictCursor
import json

app = Flask(__name__)
app.secret_key = os.environ['SECRET_KEY']

app.config.update(
    SESSION_COOKIE_SAMESITE='None',
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_HTTPONLY=True,
)

DATABASE_URL = os.environ['DATABASE_URL']

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


def hash_password(password, salt=None):
    if salt is None:
        salt = secrets.token_hex(32)
    hashed = hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 260000)
    return salt, hashed.hex()


def init_db():
    conn = get_db()
    cur = conn.cursor()
    cur.execute("""
        CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

        CREATE TABLE IF NOT EXISTS users (
            id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
            email TEXT UNIQUE NOT NULL,
            display_name TEXT,
            password_hash TEXT,
            password_salt TEXT,
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


@app.route('/api/auth/register', methods=['POST'])
def register():
    data = request.get_json()
    email = data.get('email', '').strip().lower()
    password = data.get('password', '')
    display_name = data.get('displayName', '').strip() or email.split('@')[0]

    if not email or '@' not in email:
        return jsonify({'error': 'Valid email required'}), 400
    if len(password) < 6:
        return jsonify({'error': 'Password must be at least 6 characters'}), 400

    salt, hashed = hash_password(password)

    conn = get_db()
    cur = conn.cursor()
    try:
        cur.execute("""
            INSERT INTO users (email, display_name, password_hash, password_salt)
            VALUES (%s, %s, %s, %s)
            RETURNING id, email, display_name
        """, (email, display_name, hashed, salt))
        user = cur.fetchone()
        cur.execute("INSERT INTO settings (user_id) VALUES (%s) ON CONFLICT DO NOTHING", (str(user['id']),))
        conn.commit()
    except Exception as e:
        conn.rollback()
        cur.close()
        conn.close()
        if 'unique' in str(e).lower():
            return jsonify({'error': 'An account with this email already exists'}), 409
        return jsonify({'error': 'Registration failed'}), 500

    cur.close()
    conn.close()

    session['user_id'] = str(user['id'])
    session.permanent = True

    return jsonify({'user': {
        'id': str(user['id']),
        'email': user['email'],
        'display_name': user['display_name'],
    }}), 201


@app.route('/api/auth/login', methods=['POST'])
def login():
    data = request.get_json()
    email = data.get('email', '').strip().lower()
    password = data.get('password', '')

    if not email or not password:
        return jsonify({'error': 'Email and password required'}), 400

    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT id, email, display_name, password_hash, password_salt FROM users WHERE email = %s", (email,))
    user = cur.fetchone()
    cur.close()
    conn.close()

    if not user or not user['password_hash']:
        return jsonify({'error': 'Invalid email or password'}), 401

    _, hashed = hash_password(password, user['password_salt'])
    if hashed != user['password_hash']:
        return jsonify({'error': 'Invalid email or password'}), 401

    session['user_id'] = str(user['id'])
    session.permanent = True

    return jsonify({'user': {
        'id': str(user['id']),
        'email': user['email'],
        'display_name': user['display_name'],
    }})


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
    return jsonify({'status': 'ok', 'version': '2.2.0'})


# ===================== STARTUP =====================

if __name__ == '__main__':
    init_db()
    app.run(host='0.0.0.0', port=5000, debug=os.environ.get('FLASK_DEBUG', 'false') == 'true')
