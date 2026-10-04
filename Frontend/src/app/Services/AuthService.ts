import { HttpClient } from '@angular/common/http';
import { computed, Injectable, signal } from '@angular/core';
import { authResponseDto } from '../Dto/authResponseDto';

@Injectable({ providedIn: 'root' })
export class AuthService {
  private apiUrl = 'https://localhost:7051/api/v1/auth';

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

  userRole = signal(localStorage.getItem('userRole'));

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

  // isAuthenticated(): boolean {
  //   return !!localStorage.getItem('jwt');
  // }
}
