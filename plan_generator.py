# C:\Users\rishi\Desktop\fitness\plan_generator.py

from flask import Blueprint, request, jsonify, session
from flask_cors import CORS
from pymongo import MongoClient
import requests
import json
import asyncio
import os

plan_blueprint = Blueprint('plan', __name__)
CORS(plan_blueprint)

# MongoDB setup
MONGO_URI = "mongodb://localhost:27017/"
client = MongoClient(MONGO_URI)
db = client.fitness_app
user_data_collection = db.user_data

# iAsk.Ai API Setup (load from environment variable for safety)
IASK_API_KEY = os.getenv("IASK_API_KEY", "FoJetXlvAytv2N6gasj5UlulhTuIMdESP50fan5JqIg")
IASK_API_URL = "https://api.iask.ai/v1/query"


def calculate_bmi(weight_kg, height_ft, height_in):
    height_m = (height_ft * 0.3048) + (height_in * 0.0254)
    if height_m == 0:
        return 0
    return round(weight_kg / (height_m ** 2), 2)


async def get_dynamic_plan(program_type, age, weight, height, fitness_level, dietary_preferences):
    """Generates a fitness plan using the iAsk.ai API within subscription limits."""

    prompt = (
        f"7-day {program_type} plan for age {age}, {weight}kg, "
        f"{height['ft']}ft {height['in']}in, level {fitness_level}, "
        f"diet {dietary_preferences or 'none'}. "
        f"Return JSON with: "
        f"workout_plan: array of days [{{d: day, t: title, dur: duration, "
        f"ex: [{{n: name, s: sets, r: reps, desc: short description}}]}}], "
        f"diet_plan: array of 3 meals/day [{{mt: meal_time, t: title, det: short details}}], "
        f"sleep_schedule: {{hrs: recommended_hours, rt: short routine}}. "
        f"Keep under 1000 characters, JSON only."
    )

    headers = {
        "Authorization": f"Bearer {IASK_API_KEY}",
        "Content-Type": "application/json"
    }

    data = {
        "prompt": prompt,
        "detail_level": "concise",  # concise mode to save tokens
        "stream": False
    }

    try:
        response = requests.post(IASK_API_URL, headers=headers, json=data, timeout=60)
        response.raise_for_status()

        response_json = response.json()
        print("Full API response:", response_json)  # Debug log

        # Extract text from possible keys
        response_text = (
            response_json.get('data') or
            response_json.get('answer') or
            response_json.get('output') or
            response_json.get('response', {}).get('message', '') or
            ''
        ).strip()

        # Remove code fences if present
        if response_text.startswith("```json"):
            response_text = response_text.strip('```json').strip('```').strip()

        try:
            plan_data = json.loads(response_text)
        except json.JSONDecodeError:
            print("Warning: API did not return valid JSON, wrapping in raw_response.")
            plan_data = {"raw_response": response_text}

        return {"success": True, "plan": plan_data}

    except requests.exceptions.RequestException as e:
        print("-------------------- ERROR LOG START --------------------")
        if hasattr(e, "response") and e.response is not None:
            print(f"Status code: {e.response.status_code}")
            print("Response text:", e.response.text)
        print(f"Error calling iask.ai API: {e}")
        print("-------------------- ERROR LOG END --------------------")
        return {"success": False, "error": str(e)}


@plan_blueprint.route('/generate-plan', methods=['POST'])
async def generate_plan():
    data = request.json
    program_type = data.get('programType') or data.get('goal', 'general')
    age = int(data.get('age', 0))
    weight_kg = float(data.get('weight', 0))
    height_ft = int(data.get('height', {}).get('ft', 0))
    height_in = int(data.get('height', {}).get('in', 0))
    fitness_level = data.get('fitnessLevel', 'beginner')
    dietary_preferences = data.get('dietaryPreferences', '')

    bmi = calculate_bmi(weight_kg, height_ft, height_in)

    plan_result = await get_dynamic_plan(
        program_type,
        age,
        weight_kg,
        {"ft": height_ft, "in": height_in},
        fitness_level,
        dietary_preferences
    )

    if not plan_result['success']:
        return jsonify({"success": False, "message": "Failed to generate plan."}), 500

    plan_data = plan_result['plan']

    # Store in MongoDB
    user_email = session.get('user_email')
    if user_email:
        user_data_collection.update_one(
            {"user_email": user_email},
            {"$set": {
                "program_type": program_type,
                "plan": plan_data,
                "stats": {
                    "age": age,
                    "weight": weight_kg,
                    "height_ft": height_ft,
                    "height_in": height_in,
                    "bmi": bmi,
                    "fitness_level": fitness_level
                }
            }},
            upsert=True
        )

    response_data = {
        "bmi": bmi,
        "workout_plan": plan_data.get('workout_plan', []),
        "diet_plan": plan_data.get('diet_plan', []),
        "sleep_schedule": plan_data.get('sleep_schedule', {})
    }

    return jsonify(response_data)
