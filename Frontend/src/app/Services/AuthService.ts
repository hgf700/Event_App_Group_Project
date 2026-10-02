import { HttpClient } from '@angular/common/http';
import { computed, Injectable, signal } from '@angular/core';
import { getAuthHeaders } from '../helpers/GetAuthHeaders';
import { authResponseDto } from '../Dto/authResponseDto';

@Injectable({ providedIn: 'root' })
export class AuthService {
  private apiUrl = 'https://localhost:7051/api/v1/auth';

  userRole = signal(localStorage.getItem('userRole'));

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

  isLogged = computed(() => {
    const role = this.userRole();
    return role === 'user' || role === 'admin';
  });

  isAdmin = computed(() => this.userRole() === 'admin');

  loginWithGoogleOauth() {
    window.location.href = `${this.apiUrl}/sign-in-google`;
  }
}
