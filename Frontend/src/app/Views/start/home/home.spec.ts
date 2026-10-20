import { ComponentFixture, TestBed } from '@angular/core/testing';
import { vi, describe, it, expect, beforeEach } from 'vitest';
import { of } from 'rxjs';
import { Router } from '@angular/router';

import { Home } from './home';
import { AuthService } from '../../../Services/AuthService';
import { EventService } from '../../../Services/EventService';

describe('Home', () => {
  let component: Home;
  let fixture: ComponentFixture<Home>;

  const routerMock = {
    navigate: vi.fn().mockResolvedValue(true),
  };

  const authServiceMock = {
    loginWithGoogleOauth: vi.fn(),
  };

  const eventServiceMock = {
    getPublicEvents: vi.fn().mockReturnValue(
      of({
        data: [],
        totalCount: 0,
      }),
    ),
  };

  beforeEach(async () => {
    vi.clearAllMocks();

    eventServiceMock.getPublicEvents.mockReturnValue(
      of({
        data: [],
        totalCount: 0,
      }),
    );

    await TestBed.configureTestingModule({
      imports: [Home],
      providers: [
        { provide: Router, useValue: routerMock },
        { provide: AuthService, useValue: authServiceMock },
        { provide: EventService, useValue: eventServiceMock },
      ],
    }).compileComponents();

    fixture = TestBed.createComponent(Home);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });

  it('should navigate to register page', () => {
    component.registerUserView();

    expect(routerMock.navigate).toHaveBeenCalledWith(['/register-user']);
  });

  it('should navigate to login page', () => {
    component.loginUserView();

    expect(routerMock.navigate).toHaveBeenCalledWith(['/login-user']);
  });

  it('should call Google OAuth login', () => {
    component.loginWithGoogle();

    expect(authServiceMock.loginWithGoogleOauth).toHaveBeenCalled();
  });
});
