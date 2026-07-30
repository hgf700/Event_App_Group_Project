using Backend.Controllers;
using Backend.Identity;
using Backend.Models.Dto.RelAuth;
using Backend.Services;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using Moq;
using TestProject1.TestHelper;
using System;
using System.Collections.Generic;
using System.Text;
using Backend.Interfaces;
using Backend.Dto.RelAuth;

namespace TestProject1.TestControllers;

public class TestRegisterNorm
{
    [Fact]
    public async Task RegisterUserNormal_ShouldReturnOk_WhenUserIsCreated_200()
    {
        // Arrange
        var dto = new postCreateUserNormDto
        {
            email = "test@test.pl",
            password = "Password123!"
        };

        var userManagerMock = IdentityMockHelper.MockUserManager();

        userManagerMock
            .Setup(x => x.FindByEmailAsync(dto.email))
            .ReturnsAsync((ApplicationUser)null);

        userManagerMock
            .Setup(x => x.CreateAsync(It.IsAny<ApplicationUser>(), dto.password))
            .ReturnsAsync(IdentityResult.Success);

        var jwtServiceMock = new Mock<IJwtService>();
        jwtServiceMock
            .Setup(x => x.GenerateToken(It.IsAny<ApplicationUser>()))
            .Returns("fake-jwt-token");

        var loggerMock = new Mock<ILogger<AuthController>>();

        var controller = new AuthController(
            userManagerMock.Object,
            jwtServiceMock.Object,
            loggerMock.Object);

        // Act
        var result = await controller.RegisterUserNormal(dto);

        // Assert
        var okResult = Assert.IsType<OkObjectResult>(result.Result);

        var value = Assert.IsType<AuthResponseDto>(okResult.Value);

        Assert.Equal("fake-jwt-token", value.jwt);
    }
}
