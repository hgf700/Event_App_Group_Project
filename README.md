# Group Project

This is our group project – a web application built with **ASP.NET** and **Angular**

## 📦 Older Version

A older version of this project can be found here: https://github.com/hgf700/Old_Event_App_Group_Project

## ☁️ Hosting and Deployment

The application is currently hosted on **AWS**:

- **EC2 (Amazon Linux)** instance serves as the web server.  
- The application is fully **Dockerized** and container images are stored in **Amazon ECR**.  
- The database was migrated from **MSSQL Database** to **PostgreSQL**, hosted on **Amazon RDS (Relational Database Service)**.  
- The Docker container is deployed and runs on the **EC2** instance, exposing the web application to the public.  
- CI/CD automation is handled using **GitHub Actions**.

## 🌐 Live Demo

The project will remain available until the AWS Free Tier expires:
http://13.217.97.150/

## ✨ Features

- Authentication and authorization using **JWT (JSON Web Tokens)**.
- User registration and login with **ASP.NET Identity** and **OAuth external providers**.
- Integration with the **Ticketmaster API** to fetch event data.
- **Pagination** and **event search functionality** via form or query parameters.
- Integration with **Stripe Payments** for ticket purchasing.

### 💳 After successful payment:
- A **QR code** containing the event URL is generated using **QRCoder**.
- A **PDF file** with event details is generated using **QuestPDF**.
- A confirmation **email with PDF attachment** is sent via **SMTP**.
- An **SMS notification** containing the event URL is sent using **Twilio**.

## 🧠 Backend

- Logging system for diagnostics and error tracking.
- Database access and ORM handled using **Entity Framework Core**.
- API security with **rate limiting**.
- Structured logging using **Serilog**.

## 📊 Observability

- **Prometheus** – metrics collection from backend services.
- **Loki** – centralized log aggregation.
- **Grafana** – dashboards for logs and metrics visualization.

## 🧱 Architecture

### Frontend
- Angular
- Unit Tests

### Backend
- ASP.NET Web API
- Entity Framework
- ASP.NET Identity
- JWT Authentication
- Unit Tests
- Serilog Logging

### DevOps / Infrastructure
- AWS EC2 – application hosting
- AWS ECR – container registry
- AWS RDS – managed database
- Docker
- GitHub Actions – CI/CD pipelines
- Grafana + Loki – logging and visualization
- Prometheus – metrics monitoring

### External Services & APIs
- Ticketmaster API
- Stripe Payments API
- Twilio SMS API
- SMTP Email Service API
- PDF Generation Service
- QR Code Generation Service
- Google OAuth

## 🌍 Local Development Endpoints

| Service     | URL |
|------------|-----|
| Frontend   | http://localhost:4200 |
| Backend    | http://localhost:5000/swagger |
| Grafana    | http://localhost:3000 |
| Prometheus | http://localhost:9090 |
| Loki       | http://localhost:3100 |

# Future Potential Improvements
- Improve application security
- Add unit and integration tests
- Add Kubernetes deployment
- Add distributed tracing (OpenTelemetry)