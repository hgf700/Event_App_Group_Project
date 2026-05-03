import { HttpClient } from '@angular/common/http';
import { Injectable } from '@angular/core';
import { getAuthHeaders } from '../helpers/GetAuthHeaders';

@Injectable({ providedIn: 'root' })
export class AuthService {
  private apiUrl = 'https://localhost:7051/api/v1/auth';

  constructor(
    private http: HttpClient
  ) {}

  registerUserNorm(email: string, password: string, repeatPassword: string) {
    if (password !== repeatPassword) {
      throw new Error('Hasła nie są identyczne');
    }
    
    return this.http.post<{ token: string }>(
      `${this.apiUrl}/register-norm`, {
      email,
      password
    });
  }

  loginUserNorm(email: string, password: string) {
    return this.http.post<{ token: string }>(
      `${this.apiUrl}/login-norm`, {
      email,
      password
    });
  }

  loginWithGoogleOauth() {
    window.location.href = `${this.apiUrl}/sign-in-google`;
  }
}