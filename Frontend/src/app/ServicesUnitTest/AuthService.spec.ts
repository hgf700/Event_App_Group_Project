// auth.service.spec.ts
import { TestBed } from '@angular/core/testing';
import { provideHttpClient } from '@angular/common/http';
import {
  HttpTestingController,
  provideHttpClientTesting,
} from '@angular/common/http/testing';
import { AuthService } from '../Services/AuthService';
import { vi, describe, it, expect, beforeEach, afterEach } from 'vitest';
import { authResponseDto } from '../Dto/authResponseDto';
import { postRefreshTokenResponse } from '../Dto/postRefreshTokenResponse';

describe('AuthService', () => {
  let service: AuthService;
  let httpMock: HttpTestingController;

  const apiUrl = 'https://localhost:7051/api/v1/auth';

  // Mock localStorage
  const localStorageMock = (() => {
    let store: Record<string, string> = {};
    return {
      getItem: vi.fn((key: string) => store[key] ?? null),
      setItem: vi.fn((key: string, value: string) => {
        store[key] = value;
      }),
      removeItem: vi.fn((key: string) => {
        delete store[key];
      }),
      clear: vi.fn(() => {
        store = {};
      }),
    };
  })();

  beforeEach(() => {
    // Reset localStorage mock
    localStorageMock.clear();
    Object.defineProperty(window, 'localStorage', {
      value: localStorageMock,
      writable: true,
    });

    // Mock window.location
    Object.defineProperty(window, 'location', {
      value: { href: '' },
      writable: true,
    });

    TestBed.configureTestingModule({
      providers: [
        AuthService,
        provideHttpClient(),
        provideHttpClientTesting(),
      ],
    });

    service = TestBed.inject(AuthService);
    httpMock = TestBed.inject(HttpTestingController);
  });

  afterEach(() => {
    httpMock.verify();
    vi.clearAllMocks();
  });

  it('should be created', () => {
    expect(service).toBeTruthy();
  });

  // ========== registerUserNorm ==========
  describe('registerUserNorm', () => {
    it('should send POST request with email and password', () => {
      const mockResponse: authResponseDto = {
          email: 'test@example.com',
          userRole: 'user',
          jwt: '',
          refreshToken: ''
      };

      service.registerUserNorm('test@example.com', 'password123').subscribe((res) => {
        expect(res).toEqual(mockResponse);
      });

      const req = httpMock.expectOne(`${apiUrl}/register-norm`);
      expect(req.request.method).toBe('POST');
      expect(req.request.body).toEqual({
        email: 'test@example.com',
        password: 'password123',
      });
      expect(req.request.withCredentials).toBe(true);

      req.flush(mockResponse);
    });
  });

  // ========== loginUserNorm ==========
  describe('loginUserNorm', () => {
    it('should send POST request with email and password', () => {
      const mockResponse: authResponseDto = {
          email: 'test@example.com',
          userRole: 'user',
          jwt: '',
          refreshToken: ''
      };

      service.loginUserNorm('test@example.com', 'password123').subscribe((res) => {
        expect(res).toEqual(mockResponse);
      });

      const req = httpMock.expectOne(`${apiUrl}/login-norm`);
      expect(req.request.method).toBe('POST');
      expect(req.request.body).toEqual({
        email: 'test@example.com',
        password: 'password123',
      });
      expect(req.request.withCredentials).toBe(true);

      req.flush(mockResponse);
    });
  });

  // ========== setAuthData ==========
  describe('setAuthData', () => {
    it('should save email and role to localStorage and update signals', () => {
      service.setAuthData('test@example.com', 'user');

      expect(localStorage.setItem).toHaveBeenCalledWith('email', 'test@example.com');
      expect(localStorage.setItem).toHaveBeenCalledWith('userRole', 'user');
      expect(service.userEmail()).toBe('test@example.com');
      expect(service.userRole()).toBe('user');
    });
  });

  // ========== logout ==========
  describe('logout', () => {
    it('should call logout endpoint and clear auth data on success', () => {
      service.setAuthData('test@example.com', 'user');

      service.logout();

      const req = httpMock.expectOne(`${apiUrl}/logout`);
      expect(req.request.method).toBe('POST');
      expect(req.request.withCredentials).toBe(true);

      req.flush({}); // success

      expect(localStorage.removeItem).toHaveBeenCalledWith('email');
      expect(localStorage.removeItem).toHaveBeenCalledWith('userRole');
      expect(localStorage.removeItem).toHaveBeenCalledWith('jwt');
      expect(service.userEmail()).toBe('');
      expect(service.userRole()).toBe('');
      expect(window.location.href).toBe('/');
    });

    it('should clear auth data even if logout request fails', () => {
      service.setAuthData('test@example.com', 'admin');

      service.logout();

      const req = httpMock.expectOne(`${apiUrl}/logout`);
      req.flush('Error', { status: 500, statusText: 'Server Error' });

      expect(localStorage.removeItem).toHaveBeenCalledWith('email');
      expect(localStorage.removeItem).toHaveBeenCalledWith('userRole');
      expect(localStorage.removeItem).toHaveBeenCalledWith('jwt');
      expect(service.userEmail()).toBe('');
      expect(service.userRole()).toBe('');
      expect(window.location.href).toBe('/');
    });
  });

  // ========== refreshToken ==========
  describe('refreshToken', () => {
    it('should send POST request to refresh endpoint', () => {
      const mockResponse: postRefreshTokenResponse = {
        // dostosuj do swojego DTO
        accessToken: 'new-token',
      } as postRefreshTokenResponse;

      service.refreshToken().subscribe((res) => {
        expect(res).toEqual(mockResponse);
      });

      const req = httpMock.expectOne(`${apiUrl}/refresh`);
      expect(req.request.method).toBe('POST');
      expect(req.request.body).toEqual({});
      expect(req.request.withCredentials).toBe(true);

      req.flush(mockResponse);
    });
  });

  // ========== loginWithGoogleOauth ==========
  describe('loginWithGoogleOauth', () => {
    it('should redirect to Google OAuth endpoint', () => {
      service.loginWithGoogleOauth();

      expect(window.location.href).toBe(`${apiUrl}/sign-in-google`);
    });
  });

  // ========== isLogged (computed) ==========
  describe('isLogged', () => {
    it('should return true when role is "user"', () => {
      service.userRole.set('user');
      expect(service.isLogged()).toBe(true);
    });

    it('should return true when role is "admin"', () => {
      service.userRole.set('admin');
      expect(service.isLogged()).toBe(true);
    });

    it('should return false when role is null or empty', () => {
      service.userRole.set(null);
      expect(service.isLogged()).toBe(false);

      service.userRole.set('');
      expect(service.isLogged()).toBe(false);
    });

    it('should return false for unknown role', () => {
      service.userRole.set('guest');
      expect(service.isLogged()).toBe(false);
    });
  });

  // ========== isAdmin (computed) ==========
  describe('isAdmin', () => {
    it('should return true only when role is "admin"', () => {
      service.userRole.set('admin');
      expect(service.isAdmin()).toBe(true);
    });

    it('should return false for other roles', () => {
      service.userRole.set('user');
      expect(service.isAdmin()).toBe(false);

      service.userRole.set(null);
      expect(service.isAdmin()).toBe(false);
    });
  });

  // ========== checkAuth ==========
  describe('checkAuth', () => {
    it('should send GET request to check endpoint', () => {
      service.checkAuth().subscribe((res) => {
        expect(res).toBe(true);
      });

      const req = httpMock.expectOne(`${apiUrl}/check`);
      expect(req.request.method).toBe('GET');
      expect(req.request.withCredentials).toBe(true);

      req.flush(true);
    });
  });
});