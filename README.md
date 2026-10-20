# Group Project

This is our group project – a web application built with **ASP.NET** and **Angular**

## 📦 Older Version

A older version of this project can be found here: https://github.com/hgf700/Old_Event_App_Group_Project

## ☁️ Hosting and Deployment

The application hosted on **AWS**:

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
- Secure session management using JWT access tokens and **refresh tokens**.
- **Role-based (RBAC)** authentication and authorization.
- User registration and login with **ASP.NET Identity** and **Google OAuth** external providers.
- Integration with the **Ticketmaster API** to fetch event data using **forms and query parameters**.
- **Pagination** and **event search functionality** via form or query parameters.
- Integration with **Stripe Payments** for ticket purchase using **Stripe Webhook**.
- Generation and display of **QR codes** for purchased tickets directly in the application.
- Email notifications sent via **SMTP**, including QR codes and PDF attachments.
- Interactive **event details view** displayed in a modal subwindow.
- **Admin Panel** for managing users, events, and tickets. 
- **Data caching** for public views.
- **HTTP status codes** returned according to the outcome of API requests.

### 💳 Post-Payment Workflow:
After a successful payment, the application automatically performs the following actions:
- A **QR code** containing the event URL is generated using **QRCoder**.
- A **PDF file** with event details is generated using **Playwright**.
- A confirmation **email with PDF attachment** is sent via **SMTP**.
- An **SMS notification** containing the event URL is sent using **Twilio**.

## 🧠 Backend

- **ASP.NET Web API** for backend services and RESTful endpoints.
- Database access and ORM handled using **Entity Framework Core**.
- **Logging** system for diagnostics and error tracking.
- **ASP.NET Identity** for user management and authentication.
- API security with **rate limiting**.
- Structured logging using **Serilog**.
- **Role-based** authentication and authorization.
- **Health checks** to monitor application health and readiness.

## 📊 Observability

- **Prometheus** – metrics collection from backend services.
- **Loki** – centralized log aggregation.
- **Grafana** – dashboards for logs and metrics visualization.

## 🧱 Architecture

### Frontend
- Angular
- Unit Tests Vitest

### Backend
- ASP.NET Web API
- Entity Framework
- ASP.NET Identity
- JWT Authentication and authorization
- Unit Tests and Integration Tests NUnit 
- Serilog Logging
- Health checks

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
| Swagger    | http://localhost:5000/swagger |
| Grafana    | http://localhost:3000 |
| Prometheus | http://localhost:9090 |
| Loki       | http://localhost:3100 |
| Frontend   | http://localhost:4200 |
| Backend    | http://localhost:7051 |
| Liveness Probe | https://localhost:7051/health/live |
| Readiness Probe | https://localhost:7051/health/ready |

## 🐳 Docker Commands
- check if required .env are fullfilled:
```bash
docker compose config -q
```
- Run the container:
```bash
docker compose up -d --build
```
- Run with monitoring: (grafana + prometheus + loki)
```bash
docker compose --profile monitoring up -d --build
```

## 🌐 Docker Endpoints

| Service     | URL |
|------------|-----|
| Backend    | http://localhost:5000 |
| Frontend    | http://localhost:8080 |
| Grafana    | http://localhost:3000 |
| Prometheus | http://localhost:9090 |
| Loki       | http://localhost:3100 |

## 🚀 Future Potential Improvements
- Strengthen application security.
- Introduce Kubernetes for container orchestration and deployment.
- Implement distributed tracing using OpenTelemetry.