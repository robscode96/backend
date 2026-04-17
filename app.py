"""
RouteLog Backend — Phase 2
Flask + PostgreSQL + Google OAuth
"""

import os
import uuid
from datetime import datetime, timezone
from functools import wraps

from flask import Flask, jsonify, request, session
from flask_cors import CORS
from google.oauth2 import id_token
from google.auth.transport import requests as google_requests
import psycopg2
from psycopg2.extras import RealDictCursor
import json

app = Flask(__name__)
app.secret_key = os.environ['SECRET_KEY']

# Session cookies must be SameSite=None; Secure so the browser sends them
# on cross-origin requests (GitHub Pages → Railway over HTTPS).
app.config.update(
    SESSION_COOKIE_SAMESITE='None',
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_HTTPONLY=True,
)

# CORS: wildcard '*' is rejected by browsers when credentials:true is set.
# Always list explicit origins. Set ALLOWED_ORIGINS in Railway as a
# comma-separated string, e.g.:
#   https://robscode96.github.io,http://localhost:5500
_raw_origins = os.environ.get(
    'ALLOWED_ORIGINS',
    'https://robscode96.github.io'
)
_allowed_origins = [o.strip() for o in _raw_origins.split(',') if o.strip()]

CORS(
    app,
    origins=_allowed_origins,
    supports_credentials=True,
    allow_headers=['Content-Type', 'Authorization'],
    expose_headers=['Content-Type'],
    methods=['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
)

GOOGLE_CLIENT_ID = os.environ['GOOGLE_CLIENT_ID']
DATABASE_URL = os.environ['DATABASE_URL']


# ===================== DATABASE =====================

def get_db():
    conn = psycopg2.connect(DATABASE_URL, cursor_factory=RealDictCursor)
    return conn


def init_db():
    """Create tables if they don't exist."""
    conn = get_db()
    cur = conn.cursor()
    cur.execute("""
        CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

        CREATE TABLE IF NOT EXISTS users (
            id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
            google_id TEXT UNIQUE NOT NULL,
            email TEXT NOT NULL,
            display_name TEXT,
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
    """Decorator: reject requests without a valid session."""
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            return jsonify({'error': 'Unauthorized'}), 401
        return f(*args, **kwargs)
    return decorated


@app.route('/api/auth/google', methods=['POST'])
def google_auth():
    """
    Receive a Google ID token from the frontend, verify it,
    create or update the user record, and start a session.
    """
    data = request.get_json()
    token = data.get('credential')
    if not token:
        return jsonify({'error': 'No credential provided'}), 400

    try:
        id_info = id_token.verify_oauth2_token(
            token,
            google_requests.Request(),
            GOOGLE_CLIENT_ID
        )
    except ValueError as e:
        return jsonify({'error': f'Invalid token: {e}'}), 401

    google_id = id_info['sub']
    email = id_info['email']
    display_name = id_info.get('name', email)

    conn = get_db()
    cur = conn.cursor()

    # Upsert user
    cur.execute("""
        INSERT INTO users (google_id, email, display_name)
        VALUES (%s, %s, %s)
        ON CONFLICT (google_id) DO UPDATE
            SET email = EXCLUDED.email,
                display_name = EXCLUDED.display_name
        RETURNING id, email, display_name
    """, (google_id, email, display_name))
    user = cur.fetchone()

    # Create default settings row if first login
    cur.execute("""
        INSERT INTO settings (user_id)
        VALUES (%s)
        ON CONFLICT (user_id) DO NOTHING
    """, (str(user['id']),))

    conn.commit()
    cur.close()
    conn.close()

    session['user_id'] = str(user['id'])
    session.permanent = True

    return jsonify({
        'user': {
            'id': str(user['id']),
            'email': user['email'],
            'display_name': user['display_name']
        }
    })


@app.route('/api/auth/logout', methods=['POST'])
def logout():
    session.clear()
    return jsonify({'ok': True})


@app.route('/api/auth/me', methods=['GET'])
@require_auth
def me():
    """Return current user info — used by frontend on page load to check login state."""
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
        'display_name': user['display_name']
    }})


# ===================== ROUTES =====================

@app.route('/api/routes', methods=['GET'])
@require_auth
def get_routes():
    conn = get_db()
    cur = conn.cursor()
    cur.execute("""
        SELECT id, date, earnings, miles, start_time, end_time, type, notes, created_at
        FROM routes
        WHERE user_id = %s
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
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
        RETURNING id
    """, (
        session['user_id'],
        data.get('date'),
        float(earnings),
        float(data['miles']) if data.get('miles') else None,
        data.get('startTime') or None,
        data.get('endTime') or None,
        data.get('type', 'Flex'),
        data.get('notes') or None,
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
        UPDATE routes
        SET date = %s,
            earnings = %s,
            miles = %s,
            start_time = %s,
            end_time = %s,
            type = %s,
            notes = %s,
            updated_at = NOW()
        WHERE id = %s AND user_id = %s
        RETURNING id
    """, (
        data.get('date'),
        float(data.get('earnings', 0)),
        float(data['miles']) if data.get('miles') else None,
        data.get('startTime') or None,
        data.get('endTime') or None,
        data.get('type', 'Flex'),
        data.get('notes') or None,
        route_id,
        session['user_id'],
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
    cur.execute("""
        DELETE FROM routes WHERE id = %s AND user_id = %s RETURNING id
    """, (route_id, session['user_id']))
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
        UPDATE settings
        SET weekly_goal = %s,
            monthly_goal = %s,
            mileage_rate = %s,
            fed_bracket = %s,
            state_rate = %s,
            route_types = %s,
            updated_at = NOW()
        WHERE user_id = %s
    """, (
        data.get('weeklyGoal', 800),
        data.get('monthlyGoal', 3200),
        data.get('mileageRate', 70),
        data.get('fedBracket', 22),
        data.get('stateRate', 4.25),
        json.dumps(data.get('routeTypes', ['Flex', 'DSP', 'DoorDash', 'Instacart', 'Other'])),
        session['user_id'],
    ))
    conn.commit()
    cur.close()
    conn.close()
    return jsonify({'ok': True})


# ===================== IMPORT (localStorage migration) =====================

@app.route('/api/import', methods=['POST'])
@require_auth
def import_routes():
    """
    One-time migration endpoint. Accepts the user's localStorage data
    and bulk-inserts it into the database. Safe to call multiple times
    (duplicate dates/earnings on same day will still insert — user can
    delete dupes manually).
    """
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
                session['user_id'],
                r.get('date'),
                float(r.get('earnings', 0)),
                float(r['miles']) if r.get('miles') else None,
                r.get('startTime') or None,
                r.get('endTime') or None,
                r.get('type', 'Flex'),
                r.get('notes') or None,
            ))
            imported += 1
        except Exception:
            continue  # skip malformed records

    if settings:
        cur.execute("""
            UPDATE settings
            SET weekly_goal = %s, monthly_goal = %s, mileage_rate = %s,
                fed_bracket = %s, state_rate = %s, route_types = %s,
                updated_at = NOW()
            WHERE user_id = %s
        """, (
            settings.get('weeklyGoal', 800),
            settings.get('monthlyGoal', 3200),
            settings.get('mileageRate', 70),
            settings.get('fedBracket', 22),
            settings.get('stateRate', 4.25),
            json.dumps(settings.get('routeTypes', ['Flex', 'DSP', 'DoorDash', 'Instacart', 'Other'])),
            session['user_id'],
        ))

    conn.commit()
    cur.close()
    conn.close()

    return jsonify({'imported': imported})


# ===================== HEALTH CHECK =====================

@app.route('/api/health', methods=['GET'])
def health():
    return jsonify({'status': 'ok', 'version': '2.0.0'})


# ===================== STARTUP =====================

if __name__ == '__main__':
    init_db()
    app.run(host='0.0.0.0', port=5000, debug=os.environ.get('FLASK_DEBUG', 'false') == 'true')
