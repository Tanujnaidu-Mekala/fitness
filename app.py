from flask import Flask, request, jsonify, render_template, redirect, url_for, session
from flask_cors import CORS
import requests
import os
from datetime import datetime, timezone, timedelta
from pymongo import MongoClient, errors
from werkzeug.security import generate_password_hash, check_password_hash
import json
from bson import ObjectId
import logging
from flask_mail import Mail, Message
import random
import string
import re

# Configure logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# --- Correctly configure the Flask app to find templates and static files ---
app = Flask(__name__, template_folder='templates', static_folder='static')
app.secret_key = os.environ.get('FLASK_SECRET_KEY', 'a_very_secret_key_that_is_not_secure')
CORS(app, supports_credentials=True)

# Email Configuration
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'rishik1074@gmail.com'
app.config['MAIL_PASSWORD'] = 'uore hdzo kxmz xtaa'
app.config['MAIL_DEFAULT_SENDER'] = ('Elite Performance', 'rishik1074@gmail.com')

mail = Mail(app)

# MongoDB Configuration
MONGO_URI = "mongodb://localhost:27017/"
DB_NAME = "fitness"

# Global variables for collections
client = None
db = None
users_collection = None
workout_logs = None
user_data_collection = None
sleep_logs = None

def is_mongodb_connected():
    try:
        if client is None:
            return False
        client.admin.command('ping')
        return True
    except:
        return False

try:
    # Increase the timeout for the connection
    client = MongoClient(MONGO_URI, serverSelectionTimeoutMS=10000, connectTimeoutMS=10000, socketTimeoutMS=10000)
    client.admin.command('ping')
    logger.info("Successfully connected to MongoDB")
    
    db = client[DB_NAME]
    users_collection = db.users
    workout_logs = db.workout_logs
    user_data_collection = db.user_data
    sleep_logs = db.sleep_logs
    
    workout_logs.create_index([("user_email", 1), ("date", -1)])
    
    required_collections = ['users', 'workout_logs', 'user_data', 'sleep_logs']
    existing_collections = db.list_collection_names()
    
    for coll in required_collections:
        if coll not in existing_collections:
            db.create_collection(coll)
            logger.info(f"Created collection: {coll}")
    
    logger.info("Database and collections initialized")
    
except errors.ServerSelectionTimeoutError as err:
    logger.error(f"MongoDB connection error: {err}")
    logger.warning("Running without MongoDB connection. Database operations will not work.")
except Exception as e:
    logger.error(f"Unexpected error initializing database: {e}")
    logger.warning("Running without MongoDB connection. Database operations will not work.")

# =============================================================
# Frontend Page Routes
# =============================================================
@app.route('/')
def index_page():
    return render_template('index.html')

@app.route('/login')
def login_page():
    return render_template('login.html')

@app.route('/forgot-password-page')
def forgot_password_page():
    return render_template('forgot_password.html')

@app.route('/goal')
def goal_page():
    return render_template('goal.html')

# =============================================================
# Helper Functions for OTP
# =============================================================
def generate_otp(length=6):
    characters = string.digits
    return ''.join(random.choice(characters) for i in range(length))

def send_otp_email(recipient_email, otp):
    try:
        msg = Message("Your OTP for Elite Performance",
                      sender=app.config['MAIL_DEFAULT_SENDER'],
                      recipients=[recipient_email])
        msg.body = f"Your OTP is: {otp}"
        mail.send(msg)
        return True
    except Exception as e:
        logger.error(f"Failed to send email: {e}")
        return False

# =============================================================
# AI API Endpoint
# =============================================================
IASK_API_KEY = os.getenv("IASK_API_KEY", "XydXdZXD9JteJzkrh_7PJ0r1Gn_IFWulASb34ih-szQ")
IASK_API_URL = "https://api.iask.ai/v1/query"

@app.route('/api/generate-plan', methods=['POST'])
def generate_plan():
    try:
        data = request.json or {}
        logger.debug(f"Frontend request payload: {data}")

        # Build the prompt with user selections
        prompt = (
            "You are a fitness plan generator. Your ONLY output must be a single, valid JSON object. "
            "Do not include any text, explanation, or markdown formatting before or after the JSON. "
            "The JSON object must have three top-level keys: 'workout_plan', 'diet_plan', 'sleep_schedule'.\n"
            "- 'workout_plan' must be an array of objects with keys: 'd' (day), 't' (title), 'dur' (duration), 'ex' (array of exercises).\n"
            "- Each exercise object must have: 'n' (name), 's' (sets), 'r' (reps), 'desc' (description), 'icon'.\n"
            "- 'diet_plan' must be an array of objects with: 'd' (day), 'mt' (meal type), 't' (title), 'det' (details).\n"
            "⚠️ Each meal must list specific foods (e.g., 'Oatmeal with banana', 'Paneer tikka with brown rice'). "
            "Do NOT use placeholders like 'Healthy Breakfast'.\n"
            "- 'sleep_schedule' must be an object with keys 'hrs' and 'rt'.\n"
            f"User details:\n"
            f"- Goal: {data.get('goal', 'general fitness')}\n"
            f"- Stats: {data.get('stats', 'N/A')}\n"
            f"- Body Type: {data.get('bodyType', 'average')}\n"
            f"- Level: {data.get('fitnessLevel', 'beginner')}\n"
            f"- Equipment & Mode: {data.get('equipment', 'minimal')}\n"
            f"- Diet & Health: {data.get('diet', 'balanced')}\n"
            f"- Age: {data.get('age', 25)}\n"
            f"- Weight: {data.get('weight', 70)} kg\n"
        )

        headers = {"Authorization": f"Bearer {IASK_API_KEY}", "Content-Type": "application/json"}
        payload = {"prompt": prompt, "detail_level": "detailed", "stream": False}

        response = requests.post(IASK_API_URL, headers=headers, json=payload, timeout=60)
        logger.debug(f"Raw AI API HTTP status: {response.status_code}")
        logger.debug(f"Raw AI API response: {response.text}")

        response_json = response.json()

        # Extract the plan data from the response
        if isinstance(response_json.get("data"), str):
            response_text = response_json["data"]
        elif isinstance(response_json.get("answer"), str):
            response_text = response_json["answer"]
        elif isinstance(response_json.get("response"), dict) and isinstance(response_json["response"].get("message"), str):
            response_text = response_json["response"]["message"]
        elif isinstance(response_json.get("response"), str):
            response_text = response_json["response"]
        else:
            response_text = "{}"

        # Clean markdown fences if present
        if isinstance(response_text, str):
            response_text = re.sub(r"^```(?:json)?", "", response_text.strip(), flags=re.MULTILINE)
            response_text = re.sub(r"```$", "", response_text.strip(), flags=re.MULTILINE)
        else:
            response_text = "{}"

        # Try parsing JSON directly
        try:
            plan_data = json.loads(response_text)
        except json.JSONDecodeError:
            logger.warning("Direct JSON parse failed, trying regex extraction...")
            json_match = re.search(r"\{.*\}", response_text, re.DOTALL)
            if json_match:
                clean_json_text = json_match.group(0)
                try:
                    plan_data = json.loads(clean_json_text)
                except Exception as e:
                    logger.error(f"Regex parse failed: {e}")
                    plan_data = {}
            else:
                plan_data = {}

        # If still broken → fallback dummy
        if not plan_data.get("workout_plan") or not plan_data.get("diet_plan") or not plan_data.get("sleep_schedule"):
            logger.warning("AI response invalid or incomplete, falling back to dummy plan.")
            plan_data = {
                "workout_plan": [
                    {
                        "d": day,
                        "t": "Full Body Workout",
                        "dur": "60 min",
                        "ex": [
                            {"n": "Push-ups", "s": 4, "r": 15, "desc": "Standard push-ups", "icon": "fas fa-dumbbell"},
                            {"n": "Squats", "s": 4, "r": 20, "desc": "Bodyweight squats", "icon": "fas fa-dumbbell"},
                            {"n": "Plank", "s": 3, "r": "60 sec", "desc": "Core stability", "icon": "fas fa-dumbbell"}
                        ]
                    }
                    for day in ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"]
                ],
                "diet_plan": [
                    {
                        "d": day,
                        "mt": mt,
                        "t": f"{mt} meal",
                        "det": f"Healthy {mt} with protein, carbs, and fats."
                    }
                    for day in ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"]
                    for mt in ["Breakfast", "Lunch", "Dinner", "Snacks"]
                ],
                "sleep_schedule": {
                    "hrs": 8,
                    "rt": "Go to bed at 10 PM, wake up at 6 AM"
                }
            }

        # Always include weight back in response
        plan_data["weight"] = data.get("weight", 70)

        return jsonify(plan_data)

    except Exception as e:
        logger.exception("Unexpected error in generate_plan")
        return jsonify({"message": f"Backend error: {str(e)}"}), 500

@app.route('/api/log-workout', methods=['POST'])
def log_workout():
    if not session.get('logged_in'):
        return jsonify({"success": False, "message": "User not logged in"}), 401

    # Check if MongoDB is connected
    if not is_mongodb_connected():
        return jsonify({"success": False, "message": "Database not connected. Please try again later."}), 503

    try:
        data = request.json
        user_email = session.get('user_email')
        
        logger.debug(f"Received log workout request: {data}")
        
        # Create a complete workout entry with all plan details
        workout_entry = {
            "user_email": user_email,
            "date": datetime.now(timezone.utc),
            "goal": data.get("goal", ""),
            "age": data.get("age", ""),
            "weight": data.get("weight", ""),
            "height": data.get("height", {}),
            "fitnessLevel": data.get("fitnessLevel", ""),
            "bodyType": data.get("bodyType", ""),
            "equipment": data.get("equipment", []),
            "workoutMode": data.get("workoutMode", ""),
            "dietaryPreferences": data.get("dietaryPreferences", []),
            "avoidFoods": data.get("avoidFoods", []),
            "hasHealthIssues": data.get("hasHealthIssues", ""),
            "healthConditions": data.get("healthConditions", []),
            # Save the complete plan
            "plan": {
                "workout_plan": data.get("plan", {}).get("workout_plan", []),
                "diet_plan": data.get("plan", {}).get("diet_plan", []),
                "sleep_schedule": data.get("plan", {}).get("sleep_schedule", {}),
                "weight": data.get("weight", 70)
            }
        }
        
        logger.debug(f"Workout entry to save: {workout_entry}")
        
        # Insert into MongoDB
        result = workout_logs.insert_one(workout_entry)
        logger.debug(f"Inserted document with ID: {result.inserted_id}")
        
        return jsonify({
            "success": True, 
            "message": "Workout logged successfully.",
            "id": str(result.inserted_id)
        }), 200
    except Exception as e:
        logger.error(f"Error logging workout: {str(e)}")
        return jsonify({"success": False, "message": f"Error: {str(e)}"}), 500

@app.route('/api/get-workout-history', methods=['GET'])
def get_workout_history():
    if not session.get('logged_in'):
        return jsonify({"success": False, "message": "User not logged in"}), 401

    # Check if MongoDB is connected
    if not is_mongodb_connected():
        return jsonify({"success": False, "message": "Database not connected. Please try again later."}), 503

    try:
        user_email = session.get('user_email')
        logger.debug(f"Fetching workout history for user: {user_email}")
        
        history = list(workout_logs.find({"user_email": user_email}).sort("date", -1))
        logger.debug(f"Found {len(history)} workout entries")

        # Convert ObjectId and datetime for JSON
        for entry in history:
            entry["_id"] = str(entry["_id"])
            entry["date"] = entry["date"].strftime("%Y-%m-%d %H:%M")
            
            # Ensure plan data is properly formatted
            if "plan" in entry:
                plan_data = entry["plan"]
                
                # If plan is stored as a string (which can happen with some MongoDB configurations)
                if isinstance(plan_data, str):
                    try:
                        plan_data = json.loads(plan_data)
                        entry["plan"] = plan_data
                    except json.JSONDecodeError:
                        logger.error(f"Failed to parse plan data for entry {entry['_id']}")
                        entry["plan"] = {
                            "workout_plan": [],
                            "diet_plan": [],
                            "sleep_schedule": {}
                        }
                
                # Ensure plan has required fields
                if not isinstance(plan_data, dict):
                    plan_data = {}
                    entry["plan"] = plan_data
                
                if "workout_plan" not in plan_data or not isinstance(plan_data["workout_plan"], list):
                    plan_data["workout_plan"] = []
                
                if "diet_plan" not in plan_data or not isinstance(plan_data["diet_plan"], list):
                    plan_data["diet_plan"] = []
                
                if "sleep_schedule" not in plan_data or not isinstance(plan_data["sleep_schedule"], dict):
                    plan_data["sleep_schedule"] = {}
                
                # Ensure weight is included
                if "weight" not in plan_data:
                    plan_data["weight"] = entry.get("weight", 70)

        return jsonify(history), 200
    except Exception as e:
        logger.error(f"Error fetching workout history: {str(e)}")
        return jsonify({"success": False, "message": f"Error: {str(e)}"}), 500

@app.route('/api/test-mongo', methods=['GET'])
def test_mongo():
    try:
        # Test connection
        client.admin.command('ping')
        
        # Test collection
        test_doc = {"test": "value", "date": datetime.now(timezone.utc)}
        result = workout_logs.insert_one(test_doc)
        inserted_id = result.inserted_id
        
        # Retrieve the document
        retrieved_doc = workout_logs.find_one({"_id": inserted_id})
        
        # Delete the test document
        workout_logs.delete_one({"_id": inserted_id})
        
        return jsonify({
            "success": True,
            "message": "MongoDB connection test successful",
            "inserted_id": str(inserted_id),
            "retrieved_doc": {
                "test": retrieved_doc.get("test"),
                "date": retrieved_doc.get("date").isoformat()
            }
        })
    except Exception as e:
        return jsonify({
            "success": False,
            "message": f"MongoDB test failed: {str(e)}"
        }), 500

@app.route('/api/check-auth', methods=['GET'])
def check_auth():
    logged_in = session.get('logged_in', False)
    user_email = session.get('user_email', None)
    return jsonify({
        "logged_in": logged_in,
        "user_email": user_email
    })

# =============================================================
# Chatbot Route
# =============================================================
@app.route('/api/askAI', methods=['POST'])
def ask_ai_chat():
    try:
        data = request.json or {}
        user_msg = data.get("message", "")
        language = data.get("language", "en-US")

        # Dictionary of more intelligent prompts for different languages
        prompts = {
            "en": (
                "ROLE: You are 'Elite AI Coach', a motivating fitness assistant. "
                "TASK: Directly and enthusiastically answer user questions about fitness, workouts, nutrition, and your role as their coach. "
                "RULES: "
                "1. BE CONCISE: Answers MUST be 1-2 sentences. "
                "2. GREETING & PURPOSE: If the user asks who you are or what you do (e.g., 'who are you?', 'can you help me?'), respond positively and state your purpose. For example: 'Of course! I am the Elite AI Coach, here to help you with your fitness and nutrition goals.' "
                "3. OFF-TOPIC REFUSAL: If a question is CLEARLY not about fitness (e.g., 'how do I cook lasagna?', 'what is the capital of France?'), you MUST respond with ONLY this exact phrase: 'My expertise is in fitness and nutrition, so I can't answer that. How can I help with your workout?' "
                "4. NO FORMATTING: Your entire response must be plain text. Do NOT use markdown, asterisks, headers, or lists. "
                "5. NO CITATIONS: NEVER include sources, links, or URLs."
            ),
            "hi": (
                "भूमिका: आप 'एलीट एआई कोच' हैं, जो एक प्रेरक फिटनेस सहायक है। "
                "कार्य: फिटनेस, वर्कआउट, पोषण, और एक कोच के रूप में आपकी भूमिका के बारे में उपयोगकर्ता के सवालों का सीधे और उत्साह से जवाब दें। "
                "नियम: "
                "1. संक्षिप्त रहें: उत्तर 1-2 वाक्यों में होने चाहिए। "
                "2. अभिवादन और उद्देश्य: यदि उपयोगकर्ता पूछता है कि आप कौन हैं या आप क्या करते हैं, तो सकारात्मक रूप से जवाब दें और अपना उद्देश्य बताएं। उदाहरण के लिए: 'बिल्कुल! मैं एलीट एआई कोच हूं, जो आपके फिटनेस और पोषण लक्ष्यों में आपकी मदद करने के लिए तैयार है।' "
                "3. विषय से बाहर इनकार: यदि कोई प्रश्न स्पष्ट रूप से फिटनेस के बारे में नहीं है (उदाहरण के लिए, 'लज़ान्या कैसे पकाएं?'), तो आपको केवल इसी सटीक वाक्यांश के साथ जवाब देना होगा: 'मेरी विशेषज्ञता फिटनेस और पोषण में है, इसलिए मैं इसका जवाब नहीं दे सकता। मैं आपकी कसरत में कैसे मदद कर सकता हूं?' "
                "4. कोई फ़ॉर्मेटिंग नहीं: आपकी पूरी प्रतिक्रिया सादे पाठ में होनी चाहिए। मार्कडाउन, तारांकन, हेडर या सूचियों का उपयोग न करें। "
                "5. कोई उद्धरण नहीं: कभी भी स्रोत, लिंक या यूआरएल शामिल न करें।"
            )
        }
        
        lang_prefix = language.split('-')[0]
        system_prompt = prompts.get(lang_prefix, prompts["en"])
        
        full_prompt = f"{system_prompt}\n\nUser question: {user_msg}"

        headers = {
            "Authorization": f"Bearer {IASK_API_KEY}",
            "Content-Type": "application/json"
        }
        payload = {
            "prompt": full_prompt,
            "detail_level": "concise",
            "stream": False
        }

        response = requests.post(IASK_API_URL, headers=headers, json=payload, timeout=60)
        logger.debug(f"Chatbot raw response: {response.text}")
        response.raise_for_status()
        resp_json = response.json()

        ai_reply = (
            resp_json.get("answer")
            or resp_json.get("response", {}).get("message")
            or resp_json.get("data")
            or "Sorry, I couldn't understand that."
        )

        # Final, robust cleanup logic
        cleaned_reply = re.sub(r'\[\[.*?\]\(https?:\/\/.*?\)\]', '', ai_reply)
        cleaned_reply = cleaned_reply.replace('**', '').replace('##', '')
        cleaned_reply = re.sub(r'\[\^\d+\]', '', cleaned_reply)
        
        lines = cleaned_reply.split('\n')
        cleaned_lines = [
            line for line in lines 
            if not line.strip().startswith(':') and 'http' not in line and '.com' not in line and '.org' not in line
        ]
        cleaned_reply = '\n'.join(cleaned_lines)

        return jsonify({"success": True, "answer": cleaned_reply.strip()})

    except Exception as e:
        logger.exception("Error in ask_ai_chat")
        return jsonify({"success": False, "message": f"An error occurred: {str(e)}"}), 500

# =============================================================
# Login & OTP Flow
# =============================================================
@app.route('/api/login', methods=['POST'])
def login():
    data = request.json
    email = data.get('email')
    password = data.get('password')
    
    user = users_collection.find_one({"email": email})
    if user and check_password_hash(user['password'], password):
        otp = generate_otp()
        if send_otp_email(email, otp):
            session['otp'] = otp
            session['otp_timestamp'] = datetime.now(timezone.utc)
            session['temp_user_email'] = email
            session['resend_count'] = 0
            return jsonify({"success": True, "message": "OTP sent to your email."}), 200
        else:
            return jsonify({"success": False, "message": "Failed to send OTP. Please try again."}), 500
    else:
        return jsonify({"success": False, "message": "Invalid email or password."}), 401

@app.route('/api/verify-login-otp', methods=['POST'])
def verify_login_otp():
    data = request.json
    otp = data.get('otp')
    
    stored_otp = session.get('otp')
    otp_timestamp = session.get('otp_timestamp')
    
    if not stored_otp or not otp_timestamp:
        return jsonify({"success": False, "message": "OTP not found or expired. Please try again."}), 400
        
    if datetime.now(timezone.utc) - otp_timestamp > timedelta(minutes=5):
        session.pop('otp', None)
        session.pop('otp_timestamp', None)
        session.pop('resend_count', None)
        return jsonify({"success": False, "message": "OTP has expired. Please try again."}), 400
        
    if otp == stored_otp:
        user_email = session.get('temp_user_email')
        user = users_collection.find_one({"email": user_email})
        
        for key in ['otp', 'otp_timestamp', 'temp_user_email', 'resend_count']:
            session.pop(key, None)
        
        session['logged_in'] = True
        session['user_email'] = user['email']
        session['user_name'] = user['name']
        return jsonify({"success": True, "name": user['name'], "message": "Login successful."}), 200
    else:
        return jsonify({"success": False, "message": "Invalid OTP."}), 401

# =============================================================
# Forgot Password Flow
# =============================================================
@app.route('/api/forgot-password', methods=['POST'])
def forgot_password():
    data = request.json
    email = data.get('email')

    if not email:
        return jsonify({"success": False, "message": "Email is required."}), 400

    user = users_collection.find_one({"email": email})
    if not user:
        return jsonify({"success": False, "message": "Username not found."}), 404

    otp = generate_otp()
    if send_otp_email(email, otp):
        session['otp'] = otp
        session['otp_timestamp'] = datetime.now(timezone.utc)
        session['reset_email'] = email
        session['resend_count'] = 0
        return jsonify({"success": True, "message": "OTP sent to your email."}), 200
    else:
        return jsonify({"success": False, "message": "Failed to send OTP. Please try again."}), 500

@app.route('/api/verify-forgot-password-otp', methods=['POST'])
def verify_forgot_password_otp():
    data = request.json
    otp = data.get('otp')
    new_password = data.get('new_password')

    stored_otp = session.get('otp')
    otp_timestamp = session.get('otp_timestamp')
    email = session.get('reset_email')
    
    if not stored_otp or not otp_timestamp or not email:
        return jsonify({"success": False, "message": "OTP not found or expired. Please try again."}), 400
        
    if datetime.now(timezone.utc) - otp_timestamp > timedelta(minutes=5):
        for key in ['otp', 'otp_timestamp', 'reset_email', 'resend_count']:
            session.pop(key, None)
        return jsonify({"success": False, "message": "OTP has expired. Please try again."}), 400
        
    if otp == stored_otp:
        for key in ['otp', 'otp_timestamp', 'reset_email', 'resend_count']:
            session.pop(key, None)
        
        new_hashed_password = generate_password_hash(new_password)
        users_collection.update_one({"email": email}, {"$set": {"password": new_hashed_password}})
        return jsonify({"success": True, "message": "Password updated successfully."}), 200
    else:
        return jsonify({"success": False, "message": "Invalid OTP."}), 401

# =============================================================
# Resend OTP Endpoint
# =============================================================
@app.route('/api/resend-otp', methods=['POST'])
def resend_otp():
    otp_timestamp = session.get('otp_timestamp')
    user_email = session.get('temp_user_email') or session.get('reset_email')

    if not otp_timestamp or not user_email:
        return jsonify({"success": False, "message": "No active OTP session. Please start over."}), 400

    is_expired = (datetime.now(timezone.utc) - otp_timestamp) > timedelta(minutes=5)

    if is_expired:
        new_otp = generate_otp()
        if send_otp_email(user_email, new_otp):
            session['otp'] = new_otp
            session['otp_timestamp'] = datetime.now(timezone.utc)
            session['resend_count'] = 0
            return jsonify({"success": True, "message": "Your previous OTP expired. A new one has been sent."})
        else:
            return jsonify({"success": False, "message": "Failed to send a new OTP. Please try again."}), 500
    else:
        resend_count = session.get('resend_count', 0)
        if resend_count >= 3:
            return jsonify({"success": False, "message": "Max resend attempts reached. Please wait 5 minutes for a new OTP."}), 429
        
        current_otp = session.get('otp')
        if send_otp_email(user_email, current_otp):
            session['resend_count'] = resend_count + 1
            remaining = 3 - session['resend_count']
            return jsonify({"success": True, "message": f"OTP has been resent. You have {remaining} attempts remaining."})
        else:
            return jsonify({"success": False, "message": "Failed to resend OTP. Please try again."}), 500

# =============================================================
# Reset Password (Logged-in Users)
# =============================================================
@app.route('/api/reset-password', methods=['POST'])
def reset_password():
    if not session.get('logged_in'):
        return jsonify({"success": False, "message": "User not logged in"}), 401
    
    data = request.json
    old_password = data.get('old_password')
    new_password = data.get('new_password')
    user_email = session.get('user_email')
    
    user = users_collection.find_one({"email": user_email})
    if user and check_password_hash(user['password'], old_password):
        new_hashed_password = generate_password_hash(new_password)
        users_collection.update_one({"email": user_email}, {"$set": {"password": new_hashed_password}})
        return jsonify({"success": True, "message": "Password updated successfully."}), 200
    else:
        return jsonify({"success": False, "message": "Incorrect old password."}), 401

@app.route('/api/log', methods=['POST'])
def log_plan():
    if not session.get('logged_in'):
        return jsonify({"success": False, "message": "User not logged in"}), 401

    data = request.json or {}
    log_entry = {
        "user_email": session.get("user_email"),
        "date": datetime.now(timezone.utc),
        "workouts": data.get("workouts", []),
        "diet_plan": data.get("diet_plan", []),
        "water_intake": data.get("water_intake", 0),
        "sleep_schedule": data.get("sleep_schedule", {})
    }
    workout_logs.insert_one(log_entry)
    return jsonify({"success": True, "message": "Plan logged successfully"})


if __name__ == '__main__':
    app.run(host='127.0.0.1', port=5000, debug=True)