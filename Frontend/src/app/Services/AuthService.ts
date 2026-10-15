import { HttpClient } from '@angular/common/http';
import { computed, Injectable, signal } from '@angular/core';
import { authResponseDto } from '../Dto/authResponseDto';
import { Observable } from 'rxjs';
import { postRefreshTokenResponse } from '../Dto/postRefreshTokenResponse';

@Injectable({ providedIn: 'root' })
export class AuthService {
  private apiUrl = 'https://localhost:7051/api/v1/auth';

  userEmail = signal<string | null>(localStorage.getItem('email'));
  userRole = signal<string | null>(localStorage.getItem('userRole'));

  constructor(private http: HttpClient) {}

  registerUserNorm(email: string, password: string) {
    return this.http.post<authResponseDto>(`${this.apiUrl}/register-norm`, {
      email,
      password,
    },
    {withCredentials: true}
    );
  }

  loginUserNorm(email: string, password: string) {
    return this.http.post<authResponseDto>(`${this.apiUrl}/login-norm`, {
      email,
      password,
    },
    {withCredentials: true}
    );
  }

  logout(): void {
    this.http.post(`${this.apiUrl}/logout`, 
      {},
      { withCredentials: true }
    ).subscribe({
      next: () => this.clearAuthData(),
      error: () => this.clearAuthData()
    });
  }

  setAuthData(email: string, role: string): void {
    localStorage.setItem('email', email);
    localStorage.setItem('userRole', role);

    this.userEmail.set(email);
    this.userRole.set(role);
  }

  refreshToken(): Observable<postRefreshTokenResponse> {
    return this.http.post<postRefreshTokenResponse>(
      `${this.apiUrl}/refresh`,
      {},
      { withCredentials: true },
    )
  }

  loginWithGoogleOauth() {
    window.location.href = `${this.apiUrl}/sign-in-google`;
  }

  isLogged = computed(() => {
    const role = this.userRole();
    return role === 'user' || role === 'admin';
  });

  isAdmin = computed(() => this.userRole() === 'admin');

  private clearAuthData(): void {
    localStorage.removeItem('email');
    localStorage.removeItem('userRole');
    localStorage.removeItem('jwt');

    this.userEmail.set('');
    this.userRole.set('');

    window.location.href = '/';
  }

  checkAuth() {
    return this.http.get<boolean>(`${this.apiUrl}/check`,
      { withCredentials: true }
    );
  }

}
