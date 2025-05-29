# Security Management System

## Overview 
This security management system is a cloud-native security platform that monitors network threats, manages IT assets, and provides reporting/logging for the most common threats. Although currently a work in-progress platform, it provides the most basic blueprints for cybersecurity platforms through Flask, PostgreSQL for structured event storage and Redis for fast, low-latency access to real-time data. Once completed, it should be a full stack application that can perform threat detection and have a ticketing system for the user. 

## Tech Stack

| Layer        | Technology                                   |
|-------------|----------------------------------------------|
| **Backend** | Python (Flask), C++ (for future modules)     |
| **Database**| PostgreSQL (AWS RDS), Redis (ElastiCache)    |
| **Frontend**| React (real-time dashboard - in Phase 4)     |
| **Cloud**   | AWS (EC2, ECS, S3, VPC, CloudWatch)          |
| **DevOps**  | Docker, Terraform                            |


## ROADMAP

## COMPLETED PHASES

### **Phase 1: Local Development Foundation**

- [x] Flask API with PostgreSQL (local)
- [x] Security event models (ORM)
- [x] REST endpoints for CRUD and statistics
- [x] Dockerized development setup
- [x] Health checks for PostgreSQL and Redis

### **Phase 2: AWS Cloud Migration**

- [x] PostgreSQL migrated to AWS RDS
- [x] Redis set up via ElastiCache
- [x] Flask API deployed to EC2 with Docker
- [x] Redis caching of recent events
- [x] VPC with secure subnets, Security Groups
- [x] Infrastructure-as-Code via Terraform (WIP)

---

## WORK IN-PROGRESS

### **Phase 3: Core Security Features**

- C++ modules for:
  - Packet capture and analysis
  - Anomaly detection
  - Port scanning
- Python modules for:
  - Vulnerability scanning
  - CVE integration
  - Threat intelligence feeds
- Alerting system and resolution workflow

### **Phase 4: Dashboard and Visualization**

- React Frontend:
  - Real-time Security Dashboard
  - Network Topology Visualization
  - Incident Resposne Interface
- AWS Integration:
  - CloudFront Distribution
  - S3 Static Hosting
  - API Gateway

### **Phase 5: Future/Advanced Features**

- Role-Based Access Control (RBAC)
- Audit Logging
- Backup/Disaster Recovery
- Performance Monitoring
- Ticketing System

---

## Docker Setup 

To start the development environment locally:

# Clone the repository
git clone https://github.com/your-username/SecuritySystem.git
cd SecuritySystem

# Build and run with Docker Compose
docker compose up --build

# Services
- PostgreSQL: 5432
- Redis: 6379
- FlaskAPI: 5000
