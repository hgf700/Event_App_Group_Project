using EventApp.Domain.Model;
using EventApp.Infrastructure.Db;
using EventApp.Services.Dto.RelAuth;
using EventApp.Services.Interfaces;
using EventApp.Services.Services.Interfaces;
using EventApp.Services.Services.model;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Text;

namespace EventApp.Services.Services;

public class PaymentService : IPaymentService
{
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly IJwtService _jwtService;
    private readonly ILogger<AuthService> _logger;
    private readonly ApplicationDbContext _context;
    private readonly IQrCodeService _qrCodeService;
    private readonly ISmsService _smsservice;
    private readonly IEmailService _emailService;
    private readonly string YOUR_DOMAIN = "http://localhost:4200";


    public PaymentService(UserManager<ApplicationUser> userManager,
        IJwtService jwtService,
        ILogger<AuthService> logger,
        ApplicationDbContext dbContext
        )
    {
        _userManager = userManager;
        _jwtService = jwtService;
        _logger = logger;
        _context = dbContext;
    }

    public async Task BuyTicket()
    {

    }

    public async Task PaymentSuccess()
    {

    }
}
