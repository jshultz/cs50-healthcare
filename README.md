# CS50 Final Project
A healthcare web application for the final project of [CS50](https://cs50.harvard.edu)
## Features
- Patients can register though the site
- Doctors and other medical staff can be registered though the add staff route
- Admin can assign patients a medical team
- Registered patients can send and recieve messages from their medical team
- Registered patients can see their upcomming appointments
- Doctors can setup appointemnts for patients
## Planned Features
- Medical staff can send radiology images for analysis to a neural network for rapid diagnoses.
## Installation and Setup
Python 3.x is required
Create a FLASK_APP environment variable to point to clinic.py:
    $ export FLASK_APP="clinic.py"
Start a Flask local server:
    $ flask run
