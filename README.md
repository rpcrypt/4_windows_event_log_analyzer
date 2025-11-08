Windows Event Log Analyzer 💻

The Windows Event Log Analyzer is a robust, self-contained desktop tool designed for system administrators and IT analysts. It solves the critical problem of information overload by moving beyond slow, native Windows log viewers to provide real-time visualization and risk prioritization of event data1.

It transforms raw Windows Event Log entries into actionable security and operational intelligence2.


🚀 Key Features

Native Log Retrieval: Utilizes the win32evtlog module (via Pywin32) for direct, low-level access to all Windows log channels (System, Security, Application)3333.


Risk Classification: Events are automatically classified into High, Low, and No Risk categories based on native severity4.


Web Dashboard: Delivers a modern, responsive interface via a local web browser, built with HTML, JavaScript, and Tailwind CSS5.


Serverless Persistence (SQLite3): Stores all analyzed logs persistently in a local SQLite3 database file6. This ensures the application is self-contained and portable7.


Advanced Filtering: Supports complex querying by Event ID, date range, log type, and remote computer name for precision targeting of events8888.


Dynamic Visualization: Generates dynamic JavaScript bar charts to visually quantify event volume across risk categories, quickly highlighting critical areas9999.
![Uploading image.png…]()




🛠️ Technical Stack

Component
Role
Technology Used
Backend / API
Core logic, routing, and data processing.
Python 3.x, Flask
Windows Access
Native OS API interaction.
Pywin32 (win32evtlog)
Data Persistence
Local, file-based database for storage.
SQLite3
Frontend / UI
Dashboard structure and responsiveness.
HTML, JavaScript, Tailwind CSS


▶️ Setup and Running the Application


Prerequisites

Windows OS: Required to run the native win32evtlog module.
Python 3.x: Must be installed.
Dependencies: Flask, Flask-CORS, and Pywin32 must be installed (pip install -r requirements.txt).

Installation and Launch

Initialize Git (if not done):
Bash
git init


Run the Server (CRITICAL STEP): You must run the server with elevated privileges to access the Security Log.
Open Command Prompt (CMD) as Administrator.
Navigate to the project root directory.
Execute the application:
Bash
python your_main_app_file.py 


Access the Dashboard: Open your web browser and navigate to the address shown in the console:
http://127.0.0.1:5000/
