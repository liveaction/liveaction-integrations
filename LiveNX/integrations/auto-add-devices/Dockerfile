# Use the official Python image from the Docker Hub
FROM python:3.11-slim

# Set the working directory in the container
WORKDIR /usr/src/app

# Copy the requirements file into the container
COPY requirements.txt ./

# Install any needed packages specified in requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of the working directory contents into the container
COPY . .

# Set permissions for the /tmp folder (allow container to write to /tmp)
VOLUME ["/data/livenx-server/data/log"]

# Set the entry point to the Python script
ENTRYPOINT ["python", "./monitor_logfile_adddevice.py"]
