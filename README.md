# PrettyTop - Modern System Monitoring Dashboard

PrettyTop is a web-based system monitoring application that provides real-time insights into system performance metrics, process management, and user activities. Built with modern web technologies and a clean, responsive interface, PrettyTop offers a comprehensive view of your system's health and performance.

## Features

- **Secure Authentication**
  - Password-protected access
  - Configurable credentials through environment variables

- **Real-time System Statistics**
  - CPU usage with historical graph
  - Memory utilization visualization
  - Disk usage monitoring
  - System load averages
  - Process management with sorting capabilities
  - System uptime tracking

- **Process Management**
  - Complete list of system processes
  - Dynamic sorting by CPU, Memory, PID, or Status
  - Process status visualization
  - Detailed process summary statistics

- **User Activity Monitoring**
  - Current logged-in users with resource usage
  - Last 10 login history
  - Per-user CPU and memory utilization
  - User session details

- **System Logs**
  - Real-time monitoring of system logs
  - Last 50 lines of system logs
  - Clean terminal-style log presentation

- **Modern UI/UX**
  - Responsive design for all screen sizes
  - Real-time data updates
  - Interactive charts and visualizations
  - Clean and intuitive interface
  - Dark/Light theme support

## Prerequisites

- Docker
- SSL certificate and key

## Installation

1. Clone the repository:

   ```bash
   git clone https://github.com/turgaybulut/System-Monitoring-Application.git
   cd System-Monitoring-Application
   ```

2. Configure SSL certificates:
   - Place your SSL certificate and key files in the `cert` directory:

     ```plaintext
     cert/
     ├── localhost.crt
     ├── localhost.key
     ```

     Note: If you don't have SSL certificates, you can generate self-signed certificates using `mkcert`:

     ```bash
     mkcert -key-file cert/localhost.key -cert-file cert/localhost.crt localhost
     ```

3. Configure environment variables:
   - Update the following variables in the `.env` file:

     ```plaintext
     MONITOR_USERNAME=your_username
     MONITOR_PASSWORD=your_password
     MONITOR_PORT=8765
     EXPOSED_PORT=your_user_id
     ```

    **Default Credentials:**
    - Username: `admin`
    - Password: `admin`
    - Monitor Port: `8765`
    - Exposed Port: `1031`

4. Build and run with Docker compose:

   ```bash
   docker compose up -d --build
   ```

## Usage

1. Access the dashboard:

   ```plaintext
   https://cs395.org/<your_user_id>/monitor
   ```

2. Log in with your configured credentials

3. Monitor your system in real-time:
   - View system resource usage
   - Monitor processes
   - Track user activities
   - Check system logs

## Development

The project structure is organized as follows:

```text
System-Monitoring-Application/
├── cert/               # SSL certificates
├── src/                # Source code
│   ├── monitor.html    # Frontend dashboard
│   └── server.py       # Backend server
├── .env                # Environment configuration
├── config.py           # Application configuration
├── docker-compose.yml  # Docker Compose configuration
├── Dockerfile          # Docker build configuration
└── requirements.txt    # Python dependencies
```

## Technical Details

- **Frontend**:
  - HTML5, CSS3 (Tailwind CSS)
  - JavaScript (ES6+)
  - Chart.js for visualizations
  - WebSocket for real-time updates

- **Backend**:
  - Python 3.10
  - aiohttp for async web server
  - psutil for system metrics
  - WebSocket for real-time communication

- **Deployment**:
  - Docker containerization
  - Docker compose for service orchestration
  - SSL/TLS encryption

## Authors

- [**Turgay Bulut**](https://github.com/turgaybulut)
- [**Emin Şahin Mektepli**](https://github.com/Sahin-Mektepli)

## GitHub Repository

[System-Monitoring-Application](https://github.com/turgaybulut/System-Monitoring-Application)

## License

This project is licensed under the MIT License - see the LICENSE file for details.
