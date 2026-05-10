# Projekt Grupowy

This is our group project – a web application built with **ASP.NET** and **Angular**

## Hosting and Deployment

The application is currently hosted on **AWS**:

- **EC2 (Amazon Linux)** instance serves as the web server.  
- The application is fully **Dockerized** and container images are stored in **Amazon ECR**.  
- The database was migrated from **MSSQL Database** to **PostgreSQL**, hosted on **Amazon RDS (Relational Database Service)**.  
- The Docker container is deployed and runs on the **EC2** instance, exposing the web application to the public.  
- CI/CD automation is handled using **GitHub Actions**.
## Live Demo

The project will remain available until the AWS Free Tier expires:
http://13.217.97.150/

## Description

The application includes the following features:

- Authentication and authorization using **JWT (JSON Web Tokens)**.
- User registration and login with **ASP.NET Identity** and **OAuth external providers**.
- Integration with the **Ticketmaster API** to fetch event data.  
- **Pagination** and **event search** functionality via query.  
- Integration with **Stripe Payments** for ticket purchasing.
- After successful payment:  
  - A **QR code** containing the event URL is generated using **QRCoder**.
  - A **PDF file** with event details is generated using **QuestPDF**.  
  - A confirmation **email with the PDF attachment** is sent via **SMTP**.  
  - An **SMS notification** containing the event URL is sent using **Twilio**.  
- **Logging system** for diagnostics and error tracking.
- Database access and ORM handled using **Entity Framework**.
- **Rate limiting** implemented for API protection and security.

## Technologies Used

## Frontend
- Angular
- Jasmine Unit Tests

## Backend
- ASP.NET Web API
- Entity Framework
- ASP.NET Identity
- JWT Authentication
- xUnit Unit Tests

## DevOps / Infrastructure
- AWS EC2
- AWS ECR
- AWS RDS
- Docker
- GitHub Actions
- Logging

## External Services & APIs
- Ticketmaster API
- Stripe Payments
- Twilio SMS API
- SMTP Email Service
- PDF Generation Service
- QR Code Generation Service
- Google OAuth

# Future Improvements
- Add monitoring with Prometheus and Grafana
- Improve application security
- Add unit and integration tests
- Improve UI/UX
- Add Kubernetes deployment
