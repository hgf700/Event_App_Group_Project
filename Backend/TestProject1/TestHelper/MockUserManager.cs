using Backend.Identity;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Moq;
using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using System.Text;

namespace TestProject1.TestHelper;

public static class IdentityMockHelper
{
    public static Mock<UserManager<ApplicationUser>> MockUserManager()
    {
        var store = new Mock<IUserStore<ApplicationUser>>();

        var options = new Mock<IOptions<IdentityOptions>>();
        var idOptions = new IdentityOptions();

        options.Setup(o => o.Value).Returns(idOptions);

        var userValidators = new List<IUserValidator<ApplicationUser>>();
        var passwordValidators = new List<IPasswordValidator<ApplicationUser>>();

        var userManagerMock = new Mock<UserManager<ApplicationUser>>(
            store.Object,
            options.Object,
            new PasswordHasher<ApplicationUser>(),
            userValidators,
            passwordValidators,
            new UpperInvariantLookupNormalizer(),
            new IdentityErrorDescriber(),
            null,
            new Mock<ILogger<UserManager<ApplicationUser>>>().Object
        );

        return userManagerMock;
    }
}