# NOTE: You must install Flask and CORS: pip install Flask flask-cors
from flask import Flask, jsonify, request, render_template  # <-- Flask and render_template must be here

# ... rest of your imports
from flask_cors import CORS
import win32evtlog

from datetime import datetime

import pywintypes

import math

import sqlite3



# --- Flask Setup ---

app = Flask(__name__)

# Enable CORS for all routes so the frontend can communicate with the backend

CORS(app)



# --- Database Setup (from original code12.py) ---

def create_database():

    """Creates an SQLite database and a table for storing event logs."""

    try:

        conn = sqlite3.connect('event_logs.db')

        cursor = conn.cursor()

        cursor.execute('''

            CREATE TABLE IF NOT EXISTS logs (

                id INTEGER PRIMARY KEY AUTOINCREMENT,

                event_time TEXT,

                event_id INTEGER,

                event_source TEXT,

                event_message TEXT

            )

        ''')

        conn.commit()

        conn.close()

    except sqlite3.Error as e:

        print(f"Database error: {e}")

create_database() # Initialize DB on server start



# --- Core Logic Functions (Adapted from original code12.py) ---



def set_priority(log_type_name):

    """Sets a priority value for each log type."""

    if log_type_name == "Security":

        return 3 # High Priority

    elif log_type_name == "System":

        return 2 # Medium Priority

    elif log_type_name == "Application":

        return 1 # Low Priority

    elif log_type_name == "File Log":

        return 0 # No Priority

    else:

        return 0 # No



def fetch_and_process_logs(log_type_name, start_date_str=None, end_date_str=None, risk_filter=None, event_id_filter=None, server_name=None):

    """Fetches, classifies, and formats event logs based on parameters."""

   

    events_data = []

    high_risk_count, low_risk_count, no_risk_count = 0, 0, 0

    log_priority = set_priority(log_type_name)



    # Convert string dates to datetime objects for comparison

    start_date, end_date = None, None

    try:

        if start_date_str:

            start_date = datetime.strptime(start_date_str, "%Y-%m-%d").replace(hour=0, minute=0, second=0)

        if end_date_str:

            end_date = datetime.strptime(end_date_str, "%Y-%m-%d").replace(hour=23, minute=59, second=59)

    except ValueError:

        return {"error": "Invalid Date Format. Please use YYYY-MM-DD."}, 400

   

    # Try to convert event_id_filter to an integer if it's not empty

    try:

        if event_id_filter:

            event_id_filter = int(event_id_filter)

    except ValueError:

        return {"error": "Invalid Event ID. Event ID must be a number."}, 400



    try:

        hand = win32evtlog.OpenEventLog(server_name, log_type_name)

        flags = win32evtlog.EVENTLOG_FORWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ

       

        events = 1

        while events:

            events = win32evtlog.ReadEventLog(hand, flags, 0)

            if not events:

                break

           

            for event in events:

                event_datetime = datetime.fromtimestamp(event.TimeGenerated.timestamp())



                # Apply date filter

                if (start_date and event_datetime < start_date) or (end_date and event_datetime > end_date):

                    continue

               

                # Apply Event ID filter

                if event_id_filter and event.EventID != event_id_filter:

                    continue



                # Classify event for the chart (counts all events that pass date/ID filters)

                event_risk_type = 'no'

                if event.EventType == win32evtlog.EVENTLOG_ERROR_TYPE:

                    high_risk_count += 1

                    event_risk_type = 'high'

                elif event.EventType == win32evtlog.EVENTLOG_WARNING_TYPE:

                    low_risk_count += 1

                    event_risk_type = 'low'

                else: # Covers Information and other types

                    no_risk_count += 1



                # Apply the risk filter for display

                if risk_filter and risk_filter != event_risk_type:

                    continue

               

                # Format event data for JSON output

                events_data.append({

                    "time": event_datetime.strftime('%Y-%m-%d %H:%M:%S'),

                    "source": event.SourceName,

                    "event_id": event.EventID,

                    "risk_type": event_risk_type.capitalize(),

                    "log_type": log_type_name

                })

               

    except Exception as e:

        # Check if the error is due to log type not existing or access denied

        if "The specified log does not exist" in str(e) or "Access is denied" in str(e):

             return {"error": f"Failed to read event logs: {e}. Check log type, server name, or permissions."}, 500

        return {"error": f"Failed to read event logs: {e}"}, 500

    finally:

        if 'hand' in locals():

            win32evtlog.CloseEventLog(hand)



    # Return all results

    return {

        "logs": events_data,

        "summary": {

            "high_risk": high_risk_count,

            "low_risk": low_risk_count,

            "no_risk": no_risk_count,

            "priority": log_priority

        }

    }, 200



# --- API Endpoints ---



@app.route('/api/fetch_logs', methods=['POST'])

def fetch_logs():

    """Endpoint to fetch and analyze logs based on POST data."""

    data = request.get_json()

   

    log_type = data.get('log_type', 'System')

    start_date = data.get('start_date')

    end_date = data.get('end_date')

    risk_filter = data.get('risk_filter')

    event_id = data.get('event_id')

    server_name = data.get('server_name')



    result, status_code = fetch_and_process_logs(

        log_type,

        start_date,

        end_date,

        risk_filter,

        event_id,

        server_name

    )

    return jsonify(result), status_code





@app.route('/api/priority_logs', methods=['POST'])

def priority_logs():

    """Endpoint to fetch only high-priority, high-risk logs."""

    data = request.get_json()

    remote_computer = data.get('server_name')

   

    priority_logs_data = []

   

    # Define high-priority log types (from original code12.py)

    high_priority_logs = ["Security", "System"]



    for log_type_name in high_priority_logs:

        try:

            hand = win32evtlog.OpenEventLog(remote_computer, log_type_name)

            flags = win32evtlog.EVENTLOG_FORWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ

           

            events = 1

            while events:

                events = win32evtlog.ReadEventLog(hand, flags, 0)

                if not events:

                    break

               

                for event in events:

                    # Filter for high-risk (error) events

                    if event.EventType == win32evtlog.EVENTLOG_ERROR_TYPE:

                        priority_logs_data.append({

                            "time": datetime.fromtimestamp(event.TimeGenerated.timestamp()).strftime('%Y-%m-%d %H:%M:%S'),

                            "source": event.SourceName,

                            "event_id": event.EventID,

                            "risk_type": "High",

                            "log_type": log_type_name

                        })

        except Exception as e:

            print(f"Error reading {log_type_name} logs: {e}")

        finally:

            if 'hand' in locals():

                win32evtlog.CloseEventLog(hand)



    return jsonify({

        "logs": priority_logs_data,

        "message": "Fetched high-priority, high-risk logs."

    })



@app.route('/api/upload_log', methods=['POST'])

def upload_log():

    """MOCK Endpoint to receive a log file upload."""

    if 'log_file' not in request.files:

        return jsonify({"error": "No file part in the request."}), 400

   

    log_file = request.files['log_file']

   

    if log_file.filename == '':

        return jsonify({"error": "No selected file."}), 400

   

    # In a real application, you would save and process the file here.

    # For this mock, we just confirm receipt of a file.

   

    # Simulate log analysis results for a file

    mock_logs = [

        {"time": "2024-01-01 10:00:00", "source": "FileAnalyzer", "event_id": 1000, "risk_type": "High", "log_type": "File Log"},

        {"time": "2024-01-01 10:01:30", "source": "FileAnalyzer", "event_id": 1001, "risk_type": "Low", "log_type": "File Log"},

        {"time": "2024-01-01 10:03:15", "source": "FileAnalyzer", "event_id": 1002, "risk_type": "No", "log_type": "File Log"}

    ]



    mock_summary = {

        "high_risk": 1,

        "low_risk": 1,

        "no_risk": 1,

        "priority": 0 # File logs have lowest priority score

    }



    return jsonify({

        "message": f"Successfully received and analyzed file: {log_file.filename}",

        "logs": mock_logs,

        "summary": mock_summary

    }), 200



if __name__ == '__main__':

    # NOTE: The server must be run separately on a port (e.g., 5000)

    # The frontend is configured to call http://127.0.0.1:5000/

    print("Starting Flask server on http://127.0.0.1:5000")

    app.run(debug=True, port=5000)