# RealTime Traffic Classifier

---

## Overview
A RealTime Traffic Classifier that captures live packet flows, analyzes features using a pre-trained CNN model, and classifies flows as **Normal** or **Malicious**. Built with Flask-SocketIO, Scapy, and TensorFlow, this tool offers live visualization and detailed flow insights.

## Features
- **Real-time Packet Sniffing**: Captures TCP packets using Scapy.
- **Flow Extraction**: Groups packets into flows and extracts 54 statistical features.
- **Machine Learning Classification**: Uses a Keras CNN model (`rescnn_reptile_plus_plus_best_model.h5`) to classify flows.
- **Live Dashboard**: Displays top IP traffic chart and recent flow table in the browser.
- **Detailed Flow View**: View comprehensive statistics and risk level for each flow.
- **Logging**: Saves raw input and classification results into timestamped CSV logs.

## Project Structure
```
flow/                   # Core flow processing modules
  ├── __init__.py       # Package initializer
  ├── Flow.py           # Flow feature extraction logic
  └── PacketInfo.py     # Packet metadata parser

logs/                   # Generated runtime logs (auto-created)
static/                 # Frontend assets
  ├── css/              # Stylesheets
  ├── js/               # JavaScript (e.g., application.js)

templates/              # Flask HTML templates
  ├── index.html        # Dashboard main view
  

application.py          # Flask-SocketIO application entry point
rescnn_reptile_plus_plus_best_model.h5  # Pre-trained Keras model
requirements.txt        # Python dependencies
``` 

## Installation
1. Clone the repository:
   
2. Create and activate a virtual environment:
   ```bash
   python3 -m venv venv
   source venv/bin/activate   # On Windows: venv\Scripts\activate
   ```
3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
4. Place your CNN model (`*.h5`) in the project root.

## Usage
1. Ensure you have permissions to sniff packets (run as root or configure capabilities).
2. Start the application:
   ```bash
   python application.py
   ```
3. Open your browser and navigate to `http://localhost:5001`.
4. Watch live traffic and click on a flow to see detailed analysis.

## Configuration
- **Interface**: Modify the `iface` variable in `application.py` (default: `"Wi-Fi"`).
- **Protocol Filter**: Change `filter="tcp"` in `sniff()` to capture other protocols.
- **Threshold**: Adjust the classification threshold (`0.65`) in `classify()`.

## Logs
- **Input Logs**: `logs/input_logs_<timestamp>.csv` – raw normalized features.
- **Output Logs**: `logs/output_logs_<timestamp>.csv` – classification results per flow.


