import { HttpClient } from '@angular/common/http';
import { computed, Injectable, signal } from '@angular/core';
import { authResponseDto } from '../Dto/authResponseDto';

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
    });
  }

  loginUserNorm(email: string, password: string) {
    return this.http.post<authResponseDto>(`${this.apiUrl}/login-norm`, {
      email,
      password,
    });
  }

  setAuthData(jwt: string, email: string, role: string): void {
    localStorage.setItem('jwt', jwt);
    localStorage.setItem('email', email);
    localStorage.setItem('userRole', role);

    this.userEmail.set(email);
    this.userRole.set(role);
  }

  isLogged = computed(() => {
    const role = this.userRole();
    return role === 'user' || role === 'admin';
  });

  isAdmin = computed(() => this.userRole() === 'admin');

  logout(): void {
    localStorage.removeItem('jwt');
    localStorage.removeItem('email');
    localStorage.removeItem('userRole');

    window.location.href = '/';
  }

  loginWithGoogleOauth() {
    window.location.href = `${this.apiUrl}/sign-in-google`;
  }
}
